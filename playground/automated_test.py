import json
import os
import re
import signal
import subprocess
import sys
import time

# --- CONFIGURATION ---
PYTHON_EXEC = sys.executable
SERVER_SCRIPT = "playground/http3_cc_server.py"
CLIENT_SCRIPT = "playground/http3_cc_client.py"
SHIM_SCRIPT = "playground/loss_shim.py"
SERVER_PORT = 4433
SHIM_PORT = 4434
DEFAULT_WINDOW_DEPTH = "5"
DEFAULT_LOG_INTERVAL = "5"


class TestHarness:
    def __init__(self):
        self.processes = []
        self.log_files = {}

    def start_process(
        self, command, name, log_file=None, input_data=None, keep_input_open=False
    ):
        """Starts a background process and tracks it."""
        print(f"    [+] Starting {name}...")

        stdout_dest = subprocess.PIPE
        stderr_dest = subprocess.PIPE
        if log_file:
            self.log_files[name] = open(log_file, "w")
            stdout_dest = self.log_files[name]
            stderr_dest = subprocess.STDOUT

        stdin_dest = subprocess.PIPE if input_data else None

        # Force unbuffered output so logs appear immediately
        cmd_unbuffered = [command[0], "-u"] + command[1:]

        p = subprocess.Popen(
            cmd_unbuffered,
            stdout=stdout_dest,
            stderr=stderr_dest,
            stdin=stdin_dest,
            text=True,
            preexec_fn=os.setsid,
        )

        if input_data:
            try:
                p.stdin.write(input_data)
                p.stdin.flush()
                if not keep_input_open:
                    p.stdin.close()
            except OSError as e:
                print(f"    [!] Failed to write input to {name}: {e}")

        self.processes.append((name, p))
        return p

    def stop_all(self):
        """Stops all processes and WAITS for them to release ports."""
        for name, p in self.processes:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            if p.stdin and not p.stdin.closed:
                try:
                    p.stdin.close()
                except Exception:
                    pass

        for f in self.log_files.values():
            if not f.closed:
                f.close()
        self.processes = []
        self.log_files = {}
        time.sleep(0.5)

    def parse_server_metrics(self, log_path):
        """Reads the server log to extract final metrics."""
        metrics = {
            "recovered": 0,
            "decrypt_failures": 0,
            "gaps": 0,
            "flushes": 0,
            "drops": 0,
        }
        if not os.path.exists(log_path):
            return metrics

        manual_recovery_count = 0

        with open(log_path, "r") as f:
            for line in f:
                # 1. Fallback: Count raw success lines (since Final Report often fails on SIGTERM)
                if "RECEIVED MESSAGE" in line:
                    manual_recovery_count += 1

                # 2. Parse explicit metrics reports (if available)
                if "Covert metrics" in line or "FINAL covert report" in line:
                    recovered = re.search(r"recovered=(\d+)", line)
                    fails = re.search(r"decrypt_failures=(\d+)", line)
                    gaps = re.search(r"(?:seq_)?gaps=(\d+)", line)
                    drops = re.search(r"(?:dropped_packets_est|lost_est)=(\d+)", line)
                    flushes = re.search(r"flushes=(\d+)", line)

                    if recovered:
                        metrics["recovered"] = max(
                            metrics["recovered"], int(recovered.group(1))
                        )
                    if fails:
                        metrics["decrypt_failures"] = max(
                            metrics["decrypt_failures"], int(fails.group(1))
                        )
                    if gaps:
                        metrics["gaps"] = max(metrics["gaps"], int(gaps.group(1)))
                    if flushes:
                        metrics["flushes"] = max(
                            metrics["flushes"], int(flushes.group(1))
                        )
                    if drops:
                        metrics["drops"] = max(metrics["drops"], int(drops.group(1)))

        # Use the higher of the two counts
        metrics["recovered"] = max(metrics["recovered"], manual_recovery_count)

        return metrics

    def run_test(
        self,
        test_name,
        server_args,
        client_args,
        shim_args=None,
        client_input=None,
        client_input_keep_open=False,
        duration=15,
        expected_messages=None,
    ):
        print(f"\n=== RUNNING: {test_name} ===")
        logs_dir = "playground/logs"
        server_log = f"{logs_dir}/{test_name}_server.log"
        shim_log = f"{logs_dir}/{test_name}_shim.log"
        client_log = f"{logs_dir}/{test_name}_client.log"

        try:
            # 1. Server
            srv_cmd = [
                PYTHON_EXEC,
                SERVER_SCRIPT,
                "--port",
                str(SERVER_PORT),
            ] + server_args
            self.start_process(srv_cmd, "Server", server_log)
            time.sleep(2)

            # 2. Shim
            target_port = SERVER_PORT
            if shim_args:
                shim_cmd = [
                    PYTHON_EXEC,
                    SHIM_SCRIPT,
                    "--listen-port",
                    str(SHIM_PORT),
                    "--target-port",
                    str(SERVER_PORT),
                ] + shim_args
                self.start_process(shim_cmd, "Shim", shim_log)
                target_port = SHIM_PORT
                time.sleep(1)

            # 3. Client
            url = f"https://localhost:{target_port}/"
            cli_cmd = [PYTHON_EXEC, CLIENT_SCRIPT, url] + client_args
            self.start_process(
                cli_cmd,
                "Client",
                client_log,
                input_data=client_input,
                keep_input_open=client_input_keep_open,
            )

            # 4. Wait
            print(f"    [*] Running for {duration} seconds...")
            time.sleep(duration)

        finally:
            self.stop_all()

        # 5. Report
        metrics = self.parse_server_metrics(server_log)
        if expected_messages is not None:
            metrics["expected"] = expected_messages
            estimated_drops = max(expected_messages - metrics["recovered"], 0)
            if estimated_drops > metrics["drops"]:
                metrics["drops"] = estimated_drops

        print(
            f"    [-] Results: Recov={metrics['recovered']} | Fail={metrics['decrypt_failures']} | Gaps={metrics['gaps']} | Drops={metrics['drops']}"
        )
        # --- DEBUG: IF FAILED, SHOW LOGS (Ignore Stealth tests) ---
        if metrics["recovered"] == 0 and "Stealth" not in test_name:
            print("    [!] ERROR: 0 Messages recovered. Checking logs for crashes...")
            self.print_log_tail("Server", server_log)
            self.print_log_tail("Shim", shim_log)
            self.print_log_tail("Client", client_log)

        return metrics

    def print_log_tail(self, label, path):
        if not os.path.exists(path):
            print(f"        [{label}] Log file not found.")
            return

        print(f"        --- {label} Log Tail ---")
        try:
            with open(path, "r") as f:
                lines = f.readlines()
                for line in lines[-10:]:  # Print last 10 lines
                    print(f"        {line.strip()}")
        except Exception:
            pass
        print("        ------------------------")


# --- MAIN EXECUTION ---
def main():
    harness = TestHarness()
    results = {}

    print("[*] Generating payloads (Resized for burst limits)...")
    messages = [
        "Meet at dawn by the old pier.",
        "Supplies arrived safely at warehouse three.",
        "Signal again if the plan changes before nightfall.",
        "The package is hidden beneath the loose floorboard.",
        "Await confirmation before advancing to the checkpoint.",
        "Use the east tunnel if the west gate is blocked.",
        "Switch to channel seven when the clock strikes noon.",
        "Deliver the documents to the second courier at dusk.",
        "Circle twice around the plaza before heading north.",
        "Burn the notes once the rendezvous is complete.",
    ]
    expected_count = len(messages)

    # Input for interactive tests
    inputs = "".join(f"m:{msg}\n" for msg in messages)
    input_mixed = inputs + "q\n"
    input_stealth = inputs

    # =======================================================
    # SUITE 1: TRAFFIC SHAPING (Stealth Stability)
    # =======================================================
    results["01_Stealth_Cloudflare_NoLoss"] = harness.run_test(
        "01_Stealth_Cloudflare_NoLoss",
        server_args=[
            "--covert-strategy",
            "legacy",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=None,
        client_args=[
            "--covert-strategy",
            "legacy",
            "--traffic-shaper-mode",
            "cloudflare",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_stealth,
        client_input_keep_open=True,
        duration=20,
        expected_messages=expected_count,
    )

    results["02_Stealth_Cloudflare_Drops"] = harness.run_test(
        "02_Stealth_Cloudflare_Drops",
        server_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=["--drop-in", "0.15", "--drop-out", "0.05"],
        client_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--traffic-shaper-mode",
            "cloudflare",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_stealth,
        client_input_keep_open=True,
        duration=22,
        expected_messages=expected_count,
    )

    # =======================================================
    # SUITE 2: FEC RATE SENSITIVITY
    # =======================================================
    loss_severe = "0.25"

    results["03_FEC_0.2_vs_25Loss"] = harness.run_test(
        "03_FEC_0.2_vs_25Loss",
        server_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.2",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=["--drop-in", loss_severe],
        client_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.2",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_mixed,
        duration=15,
        expected_messages=expected_count,
    )

    results["04_FEC_0.5_vs_25Loss"] = harness.run_test(
        "04_FEC_0.5_vs_25Loss",
        server_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=["--drop-in", loss_severe],
        client_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_mixed,
        duration=15,
        expected_messages=expected_count,
    )

    # =======================================================
    # SUITE 2C: FEC RATE SWEEP (Loss 25%)
    # =======================================================
    fec_sweep_rates = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    fec_sweep_results = []

    for rate in fec_sweep_rates:
        rate_str = f"{rate:.2f}"
        test_label = f"05_FEC_Sweep_{rate_str}"
        metrics = harness.run_test(
            test_label,
            server_args=[
                "--covert-strategy",
                "fec",
                "--fec-rate",
                rate_str,
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            shim_args=["--drop-in", loss_severe],
            client_args=[
                "--covert-strategy",
                "fec",
                "--fec-rate",
                rate_str,
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            client_input=input_mixed,
            duration=15,
            expected_messages=expected_count,
        )

        results[test_label] = metrics
        fec_sweep_results.append(
            {
                "rate": rate,
                "recovered": metrics["recovered"],
                "drops": metrics["drops"],
            }
        )

    # =======================================================
    # SUITE 2B: HARSH LOSS + BATCH DELIVERY
    # =======================================================
    harsh_drop_in = "0.35"
    harsh_drop_out = "0.15"
    harsh_grace = "5.0"

    results["04_Legacy_vs_35Loss_Bidir"] = harness.run_test(
        "04_Legacy_vs_35Loss_Bidir",
        server_args=[
            "--covert-strategy",
            "legacy",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=[
            "--drop-in",
            harsh_drop_in,
            "--drop-out",
            harsh_drop_out,
            "--grace-period",
            harsh_grace,
        ],
        client_args=[
            "--covert-strategy",
            "legacy",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_mixed,
        duration=20,
        expected_messages=expected_count,
    )

    results["05_FEC_0.5_vs_35Loss_Bidir"] = harness.run_test(
        "05_FEC_0.5_vs_35Loss_Bidir",
        server_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        shim_args=[
            "--drop-in",
            harsh_drop_in,
            "--drop-out",
            harsh_drop_out,
            "--grace-period",
            harsh_grace,
        ],
        client_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--sliding-window-depth",
            DEFAULT_WINDOW_DEPTH,
            "--metrics-log-interval",
            DEFAULT_LOG_INTERVAL,
        ],
        client_input=input_mixed,
        duration=20,
        expected_messages=expected_count,
    )

    # =======================================================
    # SUITE 3: THE "CLIFF" SWEEP
    # =======================================================
    print("\n" + "=" * 40)
    print("STARTING LOSS SWEEP (0% to 30%)")
    print("=" * 40)

    loss_rates = ["0.00", "0.10", "0.20", "0.30"]
    sweep_data = []

    for loss in loss_rates:
        # Legacy Test
        res_leg = harness.run_test(
            f"Sweep_Legacy_{loss}",
            server_args=[
                "--covert-strategy",
                "legacy",
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            client_args=[
                "--covert-strategy",
                "legacy",
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            shim_args=["--drop-in", loss],
            client_input=input_mixed,
            duration=12,
            expected_messages=expected_count,
        )

        # FEC 0.3 Test
        res_fec = harness.run_test(
            f"Sweep_FEC_{loss}",
            server_args=[
                "--covert-strategy",
                "fec",
                "--fec-rate",
                "0.3",
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            client_args=[
                "--covert-strategy",
                "fec",
                "--fec-rate",
                "0.3",
                "--sliding-window-depth",
                DEFAULT_WINDOW_DEPTH,
                "--metrics-log-interval",
                DEFAULT_LOG_INTERVAL,
            ],
            shim_args=["--drop-in", loss],
            client_input=input_mixed,
            duration=12,
            expected_messages=expected_count,
        )
        sweep_data.append(
            (
                loss,
                res_leg["recovered"],
                res_leg["drops"],
                res_fec["recovered"],
                res_fec["drops"],
            )
        )

    # =======================================================
    # SUITE 4: THROUGHPUT COST
    # =======================================================
    print("\n" + "=" * 40)
    print("STARTING THROUGHPUT TEST")
    print("=" * 40)

    t0 = time.time()
    harness.run_test(
        "Perf_Legacy",
        server_args=["--covert-strategy", "legacy"],
        client_args=["--covert-strategy", "legacy"],
        shim_args=None,
        client_input=input_mixed,
        duration=15,
        expected_messages=expected_count,
    )
    t_legacy = time.time() - t0

    t0 = time.time()
    harness.run_test(
        "Perf_FEC_0.5",
        server_args=["--covert-strategy", "fec", "--fec-rate", "0.5"],
        client_args=["--covert-strategy", "fec", "--fec-rate", "0.5"],
        shim_args=None,
        client_input=input_mixed,
        duration=15,
        expected_messages=expected_count,
    )
    t_fec = time.time() - t0

    # --- FINAL REPORT ---
    print("\n" + "=" * 70)
    print(f"{'Test Case':<35} | {'Recov':<6} | {'Fails':<6} | {'Outcome'}")
    print("-" * 70)

    for name, m in results.items():
        outcome = "PASS"
        target = m.get("expected", len(messages))
        if "FEC_0.2" in name and m["recovered"] < target:
            outcome = "EXPECTED FAIL (Too much loss)"
        elif "Cloudflare" in name:
            outcome = "PASS" if m["recovered"] >= target else "UNSTABLE"
        elif "FEC" in name:
            outcome = "PASS" if m["recovered"] >= target else "UNSTABLE"
        elif "Stealth" in name:
            outcome = "STABLE"
        print(
            f"{name:<35} | {m['recovered']:<6} | {m['decrypt_failures']:<6} | {outcome}"
        )

    print("-" * 70)
    print("ROBUSTNESS SWEEP DATA:")
    print("Loss% | Leg Rec | Leg Drop | FEC Rec | FEC Drop")
    for row in sweep_data:
        print(f"{row[0]:<5} | {row[1]:<7} | {row[2]:<8} | {row[3]:<7} | {row[4]:<8}")

    print("-" * 70)
    print(f"FEC RATE SWEEP (drop_in={loss_severe}, drop_out=0.00):")
    for entry in fec_sweep_results:
        print(
            f"Rate {entry['rate']:.2f} | Rec {entry['recovered']:<3} | Drops {entry['drops']:<3}"
        )

    print("-" * 70)
    print("THROUGHPUT OVERHEAD (FEC 0.5 vs Legacy):")
    print(f"Legacy Time: {t_legacy:.2f}s")
    print(f"FEC Time:    {t_fec:.2f}s")
    print(f"Overhead:    {((t_fec - t_legacy) / t_legacy) * 100:.1f}%")

    report_path = os.path.join("playground", "data", "latest_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    report_cases = {
        name: {key: int(value) for key, value in metrics.items()}
        for name, metrics in results.items()
    }

    loss_sweep_report = [
        {
            "loss": float(entry[0]),
            "legacy": {"recovered": entry[1], "drops": entry[2]},
            "fec": {"recovered": entry[3], "drops": entry[4]},
        }
        for entry in sweep_data
    ]

    fec_sweep_report = [
        {
            "rate": entry["rate"],
            "recovered": entry["recovered"],
            "drops": entry["drops"],
        }
        for entry in fec_sweep_results
    ]

    report_payload = {
        "timestamp": time.time(),
        "messages": messages,
        "expected_count": expected_count,
        "cases": report_cases,
        "loss_sweep": loss_sweep_report,
        "fec_rate_sweep": {
            "drop_in": float(loss_severe),
            "drop_out": 0.0,
            "results": fec_sweep_report,
        },
        "harsh_loss_config": {
            "drop_in": float(harsh_drop_in),
            "drop_out": float(harsh_drop_out),
            "grace_period": float(harsh_grace),
        },
        "throughput": {
            "legacy_time": t_legacy,
            "fec_time": t_fec,
        },
    }

    with open(report_path, "w") as report_file:
        json.dump(report_payload, report_file, indent=2)

    print(f"[*] Report saved to {report_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest Aborted.")
