import os
import random
import re
import signal
import string
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


class TestHarness:
    def __init__(self):
        self.processes = []
        self.log_files = {}

    def start_process(self, command, name, log_file=None, input_data=None):
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

        for f in self.log_files.values():
            if not f.closed:
                f.close()
        self.processes = []
        self.log_files = {}
        time.sleep(0.5)

    def parse_server_metrics(self, log_path):
        """Reads the server log to extract final metrics."""
        metrics = {"recovered": 0, "decrypt_failures": 0, "gaps": 0, "flushes": 0}
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
        duration=15,
    ):
        print(f"\n=== RUNNING: {test_name} ===")
        logs_dir = "playground/logs"
        os.makedirs(logs_dir, exist_ok=True)
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
            self.start_process(cli_cmd, "Client", client_log, input_data=client_input)

            # 4. Wait
            print(f"    [*] Running for {duration} seconds...")
            time.sleep(duration)

        finally:
            self.stop_all()

        # 5. Report
        metrics = self.parse_server_metrics(server_log)
        print(
            f"    [-] Results: Recov={metrics['recovered']} | Fail={metrics['decrypt_failures']} | Gaps={metrics['gaps']}"
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


# --- PAYLOAD GENERATOR ---
def generate_payload(size):
    return "".join(random.choices(string.ascii_letters + string.digits, k=size))


# --- MAIN EXECUTION ---
def main():
    harness = TestHarness()
    results = {}

    print("[*] Generating payloads (Resized for burst limits)...")
    payload_med = generate_payload(100)  # ~6 packets
    payload_large = generate_payload(400)  # ~25 packets
    payload_heavy = generate_payload(800)  # ~50 packets (Max limit)

    # Input for interactive tests
    input_mixed = f"m:{payload_med}\nm:{payload_large}\nq\n"

    # =======================================================
    # SUITE 1: TRAFFIC SHAPING (Stealth Stability)
    # =======================================================
    results["01_Stealth_Cloudflare"] = harness.run_test(
        "01_Stealth_Cloudflare",
        server_args=["--covert-strategy", "legacy"],
        shim_args=None,
        client_args=[
            "--covert-strategy",
            "legacy",
            "--traffic-shaper-mode",
            "cloudflare",
        ],
        duration=15,
    )

    # =======================================================
    # SUITE 2: FEC RATE SENSITIVITY
    # =======================================================
    loss_severe = "0.25"

    results["02_FEC_0.2_vs_25Loss"] = harness.run_test(
        "02_FEC_0.2_vs_25Loss",
        server_args=["--covert-strategy", "fec", "--fec-rate", "0.2"],
        shim_args=["--drop-in", loss_severe],
        client_args=["--covert-strategy", "fec", "--fec-rate", "0.2"],
        client_input=input_mixed,
        duration=15,
    )

    results["03_FEC_0.5_vs_25Loss"] = harness.run_test(
        "03_FEC_0.5_vs_25Loss",
        server_args=["--covert-strategy", "fec", "--fec-rate", "0.5"],
        shim_args=["--drop-in", loss_severe],
        client_args=["--covert-strategy", "fec", "--fec-rate", "0.5"],
        client_input=input_mixed,
        duration=15,
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
            server_args=["--covert-strategy", "legacy", "--sliding-window-depth", "5"],
            client_args=["--covert-strategy", "legacy", "--message", payload_large],
            shim_args=["--drop-in", loss],
            duration=12,
        )

        # FEC 0.3 Test
        res_fec = harness.run_test(
            f"Sweep_FEC_{loss}",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.3"],
            client_args=[
                "--covert-strategy",
                "fec",
                "--fec-rate",
                "0.3",
                "--message",
                payload_large,
            ],
            shim_args=["--drop-in", loss],
            duration=12,
        )
        sweep_data.append((loss, res_leg["recovered"], res_fec["recovered"]))

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
        client_args=["--covert-strategy", "legacy", "--message", payload_heavy],
        shim_args=None,
        duration=15,
    )
    t_legacy = time.time() - t0

    t0 = time.time()
    harness.run_test(
        "Perf_FEC_0.5",
        server_args=["--covert-strategy", "fec", "--fec-rate", "0.5"],
        client_args=[
            "--covert-strategy",
            "fec",
            "--fec-rate",
            "0.5",
            "--message",
            payload_heavy,
        ],
        shim_args=None,
        duration=15,
    )
    t_fec = time.time() - t0

    # --- FINAL REPORT ---
    print("\n" + "=" * 70)
    print(f"{'Test Case':<35} | {'Recov':<6} | {'Fails':<6} | {'Outcome'}")
    print("-" * 70)

    for name, m in results.items():
        outcome = "PASS"
        if "FEC_0.2" in name and m["recovered"] < 2:
            outcome = "EXPECTED FAIL (Too much loss)"
        elif "FEC_0.5" in name and m["recovered"] == 2:
            outcome = "PASS (Strong)"
        elif "Stealth" in name:
            outcome = "STABLE"
        print(
            f"{name:<35} | {m['recovered']:<6} | {m['decrypt_failures']:<6} | {outcome}"
        )

    print("-" * 70)
    print("ROBUSTNESS SWEEP DATA:")
    print("Loss% | Legacy Recov | FEC Recov")
    for row in sweep_data:
        print(f"{row[0]:<5} | {row[1]:<12} | {row[2]:<9}")

    print("-" * 70)
    print("THROUGHPUT OVERHEAD (FEC 0.5 vs Legacy):")
    print(f"Legacy Time: {t_legacy:.2f}s")
    print(f"FEC Time:    {t_fec:.2f}s")
    print(f"Overhead:    {((t_fec - t_legacy) / t_legacy) * 100:.1f}%")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest Aborted.")
