import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

# --- CONFIGURATION ---
PYTHON_EXEC = sys.executable
SERVER_SCRIPT = "playground/http3_cc_server.py"
CLIENT_SCRIPT = "playground/http3_cc_client.py"
SHIM_SCRIPT = "playground/loss_shim.py"
SERVER_PORT = 4433
SHIM_PORT = 4434
LOGS_DIR = "playground/logs"


@dataclass
class TestResult:
    name: str
    duration: float
    recovered: int
    expected: int
    drops_detected: int
    throughput_mps: float  # Messages per second
    outcome: str


class LogMonitor:
    """Reads log files in real-time to detect events without blocking."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.stop_event = threading.Event()
        self.lines = []
        self._thread = threading.Thread(target=self._tail)
        self._thread.daemon = True
        self._thread.start()

    def _tail(self):
        # Wait for file to be created
        while not os.path.exists(self.filepath):
            if self.stop_event.is_set():
                return
            time.sleep(0.1)

        with open(self.filepath, "r") as f:
            while not self.stop_event.is_set():
                line = f.readline()
                if line:
                    self.lines.append(line)
                else:
                    time.sleep(0.1)

    def wait_for_regex(self, pattern, timeout=10):
        """Waits until a regex pattern appears in the log."""
        start = time.time()
        regex = re.compile(pattern)
        offset = 0
        while time.time() - start < timeout:
            # Only check new lines
            current_len = len(self.lines)
            for i in range(offset, current_len):
                if regex.search(self.lines[i]):
                    return True
            offset = current_len
            time.sleep(0.1)
        return False

    def stop(self):
        self.stop_event.set()


class TestHarness:
    def __init__(self):
        self.processes = []
        os.makedirs(LOGS_DIR, exist_ok=True)

    def start_process(self, command, name, log_file, input_data=None):
        print(f"    [+] Starting {name}...")

        # Use line buffering for real-time monitoring
        stdout_f = open(log_file, "w", buffering=1)

        stdin_pipe = subprocess.PIPE if input_data else None

        # -u forces unbuffered python output
        cmd = [command[0], "-u"] + command[1:]

        p = subprocess.Popen(
            cmd,
            stdout=stdout_f,
            stderr=subprocess.STDOUT,
            stdin=stdin_pipe,
            text=True,
            preexec_fn=os.setsid,
        )

        if input_data:
            try:
                p.stdin.write(input_data)
                p.stdin.flush()
                # Do NOT close stdin immediately if we want to simulate an interactive session
                # But for this automation, closing signals EOF which might be needed.
                # We'll keep it open for "client_input_keep_open" logic if needed.
            except Exception as e:
                print(f"    [!] Error writing input: {e}")

        self.processes.append((p, stdout_f))
        return p

    def cleanup(self):
        for p, f in self.processes:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except:
                pass
            if not f.closed:
                f.close()
        self.processes = []

    def run_test(
        self,
        test_name,
        server_args,
        client_args,
        shim_args=None,
        messages=[],
    ):
        print(f"\n=== TEST: {test_name} ===")
        server_log = f"{LOGS_DIR}/{test_name}_server.log"
        client_log = f"{LOGS_DIR}/{test_name}_client.log"
        shim_log = f"{LOGS_DIR}/{test_name}_shim.log"

        for log_path in [server_log, client_log, shim_log]:
            if os.path.exists(log_path):
                os.remove(log_path)

        # 1. Start Server
        srv_cmd = [PYTHON_EXEC, SERVER_SCRIPT, "--port", str(SERVER_PORT)] + server_args
        self.start_process(srv_cmd, "Server", server_log)
        server_mon = LogMonitor(server_log)

        # Wait for server to be ready
        if not server_mon.wait_for_regex(r"Server listening", timeout=5):
            print("    [!] Server failed to start.")
            self.cleanup()
            return None

        # 2. Start Shim (if needed)
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
            time.sleep(0.5)

        # 3. Start Client
        # Prepare input: messages + quit command
        client_input = "".join(f"m:{msg}\n" for msg in messages) + "q\n"
        url = f"https://localhost:{target_port}/"

        cli_cmd = [PYTHON_EXEC, CLIENT_SCRIPT, url] + client_args
        # Note: We rely on the client scripts to send immediately upon startup
        self.start_process(cli_cmd, "Client", client_log, input_data=client_input)
        client_mon = LogMonitor(client_log)

        # --- EVENT DRIVEN TIMING ---
        print("    [*] Waiting for Handshake...")

        # 1. Wait for Connection (Start of Test)
        # We look for the client sending the handshake
        if not client_mon.wait_for_regex(r"Handshake chunks", timeout=5):
            print("    [!] Client failed to initiate handshake.")
            self.cleanup()
            return None

        start_time = time.time()

        # 2. Wait for Completion (End of Test)
        # We wait for the Client to say "Queue drained" OR Server to receive all messages
        # A generous timeout prevents hanging, but we exit EARLY if successful.
        expected = len(messages)
        success = False

        # Dynamic polling loop
        max_wait = 30  # Max seconds to wait for transfer
        while time.time() - start_time < max_wait:
            # Check Server for recovery count
            current_recovered = 0
            for line in server_mon.lines:
                if "=== RECEIVED MESSAGE" in line:
                    current_recovered += 1

            # Update status in place
            print(
                f"    [>] Progress: {current_recovered}/{expected} messages...",
                end="\r",
            )

            if current_recovered >= expected:
                success = True
                break

            # Check if client crashed or finished early
            if client_mon.wait_for_regex(r"Exiting", timeout=0.1):
                # Give server a split second to flush logs
                time.sleep(1)
                break

        duration = time.time() - start_time
        print(f"\n    [*] Finished in {duration:.2f} seconds.")

        # --- ANALYSIS ---
        self.cleanup()
        server_mon.stop()
        client_mon.stop()

        # Parse final stats from Server Log
        final_recovered = 0
        decrypt_fails = 0
        for line in server_mon.lines:
            if "=== RECEIVED MESSAGE" in line:
                final_recovered += 1
            if "Integrity check failed" in line:
                # Only count warnings, debugs are noise in legacy mode
                if "WARNING" in line:
                    decrypt_fails += 1

        return TestResult(
            name=test_name,
            duration=duration,
            recovered=final_recovered,
            expected=expected,
            drops_detected=decrypt_fails,  # Rough proxy
            throughput_mps=final_recovered / duration if duration > 0 else 0,
            outcome="PASS" if final_recovered >= expected else "FAIL",
        )


def main():
    harness = TestHarness()
    messages = [f"Payload_Message_{i}" for i in range(10)]

    results = []

    # 1. Baseline: Legacy vs FEC (No Loss)
    results.append(
        harness.run_test(
            "Baseline_Legacy",
            server_args=["--covert-strategy", "legacy", "-v"],  # <--- Added -v
            client_args=["--covert-strategy", "legacy", "-v"],  # <--- Added -v
            messages=messages,
        )
    )

    results.append(
        harness.run_test(
            "Baseline_FEC_Rate0.3",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            client_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            messages=messages,
        )
    )

    # 2. Stress: Legacy vs FEC (20% Loss)
    loss_20_arg = ["--drop-in", "0.20"]

    results.append(
        harness.run_test(
            "Stress_Legacy_20Loss",
            server_args=["--covert-strategy", "legacy", "-v"],
            client_args=["--covert-strategy", "legacy", "-v"],
            shim_args=loss_20_arg,
            messages=messages,
        )
    )

    results.append(
        harness.run_test(
            "Stress_FEC_20Loss_Rate0.3",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            client_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            shim_args=loss_20_arg,
            messages=messages,
        )
    )

    results.append(
        harness.run_test(
            "Stress_FEC_20Loss_Rate0.5",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.5", "-v"],
            client_args=["--covert-strategy", "fec", "--fec-rate", "0.5", "-v"],
            shim_args=loss_20_arg,
            messages=messages,
        )
    )

    # 3. Stress: Legacy vs FEC (50% Loss)
    loss_50_arg = ["--drop-in", "0.50"]

    results.append(
        harness.run_test(
            "Stress_Legacy_50Loss",
            server_args=["--covert-strategy", "legacy", "-v"],
            client_args=["--covert-strategy", "legacy", "-v"],
            shim_args=loss_50_arg,
            messages=messages,
        )
    )

    results.append(
        harness.run_test(
            "Stress_FEC_50Loss",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            client_args=["--covert-strategy", "fec", "--fec-rate", "0.3", "-v"],
            shim_args=loss_50_arg,
            messages=messages,
        )
    )

    results.append(
        harness.run_test(
            "Stress_FEC_50Loss_Rate0.5",
            server_args=["--covert-strategy", "fec", "--fec-rate", "0.5", "-v"],
            client_args=["--covert-strategy", "fec", "--fec-rate", "0.5", "-v"],
            shim_args=loss_50_arg,
            messages=messages,
        )
    )

    # --- REPORT GENERATION ---
    print("\n" + "=" * 80)
    print(
        f"{'TEST NAME':<25} | {'TIME (s)':<10} | {'MSGS':<5} | {'RATE (msg/s)':<12} | {'RESULT'}"
    )
    print("-" * 80)
    for r in results:
        if r:
            print(
                f"{r.name:<25} | {r.duration:<10.2f} | {r.recovered:<5} | {r.throughput_mps:<12.2f} | {r.outcome}"
            )
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
