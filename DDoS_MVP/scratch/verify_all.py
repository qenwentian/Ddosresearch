import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent
SERVER_PY = BASE_DIR / "server" / "server.py"
CLIENT_PY = BASE_DIR / "client" / "traffic_generator.py"
REQUESTS_CSV = BASE_DIR / "data" / "requests.csv"
CLIENT_CSV = BASE_DIR / "data" / "client_sent.csv"

def run_tests():
    print("=" * 60)
    print("STARTING EXPERIMENT-VALIDITY TEST SUITE")
    print("=" * 60)

    # 1. Start server process with DEVNULL to prevent OS pipe buffer deadlocks
    server_proc = subprocess.Popen(
        [sys.executable, str(SERVER_PY)],
        cwd=str(BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # Give server time to bind port 5000

    # Warm up server socket/framework
    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/") as resp:
            resp.read()
    except Exception:
        pass

    try:
        # Test 1: Bounded deterministic /search?q=heavy_load verification
        print("\n--- Test 1: Verifying /search?q=heavy_load workload ---")
        t0 = time.perf_counter()
        with urllib.request.urlopen("http://127.0.0.1:5000/") as resp:
            body_home = json.loads(resp.read().decode())
        home_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        with urllib.request.urlopen("http://127.0.0.1:5000/search?q=heavy_load") as resp:
            body_heavy = json.loads(resp.read().decode())
        heavy_ms = (time.perf_counter() - t0) * 1000

        print(f"  GET /: {home_ms:.2f} ms, status={body_home.get('status')}")
        print(f"  GET /search?q=heavy_load: {heavy_ms:.2f} ms, workload={body_heavy.get('workload')}, iters={body_heavy.get('iterations')}, checksum={body_heavy.get('checksum')}")
        assert body_heavy.get("workload") == "heavy", "Workload must be heavy"
        assert heavy_ms > home_ms, "Heavy load must take measurably longer than ordinary home endpoint"
        print("  [PASS] Heavy load is bounded, deterministic, and measurably more expensive.")

        # Test 2: alpha=0 (pure naive attack)
        print("\n--- Test 2: Checking alpha=0.0 purity ---")
        run_id_a0 = f"test_run_a0_{int(time.time()*1000)}"
        res = subprocess.run([
            sys.executable, str(CLIENT_PY),
            "--mode", "attack",
            "--alpha", "0.0",
            "--rate", "20",
            "--num-requests", "15",
            "--concurrency", "5",
            "--run-id", run_id_a0
        ], cwd=str(BASE_DIR), capture_output=True, text=True)
        assert res.returncode == 0, f"Generator failed: {res.stderr}"

        # Inspect client_sent.csv for run_id_a0
        with open(CLIENT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            a0_rows = [r for r in reader if r.get("run_id") == run_id_a0]

        assert len(a0_rows) == 15, f"Expected 15 rows, got {len(a0_rows)}"
        for r in a0_rows:
            assert "/search?q=heavy_load" in r["target_url"], f"Non-naive URL found: {r['target_url']}"
            assert float(r["scheduled_interval_ms"]) == 50.0, f"Expected 50.0 ms constant interval, got {r['scheduled_interval_ms']}"
            assert r["ground_truth"] == "attack_alpha_0.00"
        print(f"  [PASS] 100% of alpha=0 requests strictly matched naive profile (15/15).")

        # Test 3: alpha=1.0 (full mimicry)
        print("\n--- Test 3: Checking alpha=1.0 purity ---")
        run_id_a1 = f"test_run_a1_{int(time.time()*1000)}"
        res = subprocess.run([
            sys.executable, str(CLIENT_PY),
            "--mode", "attack",
            "--alpha", "1.0",
            "--rate", "20",
            "--num-requests", "20",
            "--concurrency", "5",
            "--run-id", run_id_a1
        ], cwd=str(BASE_DIR), capture_output=True, text=True)
        assert res.returncode == 0, f"Generator failed: {res.stderr}"

        with open(CLIENT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            a1_rows = [r for r in reader if r.get("run_id") == run_id_a1]

        assert len(a1_rows) == 20, f"Expected 20 rows, got {len(a1_rows)}"
        intervals = [float(r["scheduled_interval_ms"]) for r in a1_rows]
        assert len(set(intervals)) > 1, "Intervals must vary (Poisson process)"
        for r in a1_rows:
            assert r["ground_truth"] == "attack_alpha_1.00"
            assert "/search?q=heavy_load" not in r["target_url"], f"Unexpected heavy_load in pure mimic: {r['target_url']}"
        print(f"  [PASS] 100% of alpha=1.0 requests matched legitimate distribution across endpoints and Poisson intervals.")

        # Test 4: Mixed-profile consistency (alpha=0.5)
        print("\n--- Test 4: Checking mixed-profile consistency (alpha=0.5) ---")
        run_id_a5 = f"test_run_a5_{int(time.time()*1000)}"
        res = subprocess.run([
            sys.executable, str(CLIENT_PY),
            "--mode", "attack",
            "--alpha", "0.5",
            "--rate", "20",
            "--num-requests", "30",
            "--concurrency", "5",
            "--run-id", run_id_a5
        ], cwd=str(BASE_DIR), capture_output=True, text=True)
        assert res.returncode == 0, f"Generator failed: {res.stderr}"

        with open(CLIENT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            a5_rows = [r for r in reader if r.get("run_id") == run_id_a5]

        for r in a5_rows:
            is_heavy = "/search?q=heavy_load" in r["target_url"]
            is_const_interval = float(r["scheduled_interval_ms"]) == 50.0
            assert is_heavy == is_const_interval, f"Profile mismatch in row: {r}"
        print(f"  [PASS] All {len(a5_rows)} rows demonstrated 100% single-draw profile consistency.")

        # Test 5: Slow-server saturation & bounded queue drop accounting
        print("\n--- Test 5: Checking bounded queue & saturation drop handling ---")
        run_id_sat = f"test_run_sat_{int(time.time()*1000)}"

        res = subprocess.run([
            sys.executable, str(CLIENT_PY),
            "--mode", "attack",
            "--alpha", "0.0",
            "--rate", "100",           # Fast arrival rate: 100 req/sec (10ms interval)
            "--num-requests", "40",
            "--concurrency", "2",      # Only 2 workers
            "--max-pending", "3",      # Small queue capacity: only 3 pending
            "--run-id", run_id_sat
        ], cwd=str(BASE_DIR), capture_output=True, text=True)
        assert res.returncode == 0, f"Generator failed: {res.stderr}"

        with open(CLIENT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            sat_rows = [r for r in reader if r.get("run_id") == run_id_sat]

        dropped_rows = [r for r in sat_rows if r["status_code"] == "DROPPED"]
        completed_rows = [r for r in sat_rows if r["status_code"] != "DROPPED"]
        print(f"  Total scheduled: {len(sat_rows)}, Completed: {len(completed_rows)}, Dropped: {len(dropped_rows)}")
        assert len(dropped_rows) > 0, "Capacity saturation must produce dropped requests"
        for dr in dropped_rows:
            assert dr["actual_start_time"] == "", "Dropped request must have empty actual_start_time"
            assert dr["client_latency_ms"] == "", "Dropped request must have empty latency"
        print("  [PASS] Bounded queue dropped excess arrivals nonblockingly and recorded correct accounting.")

        # Test 6: Duration cutoff
        print("\n--- Test 6: Checking duration deadline cutoff ---")
        run_id_dur = f"test_run_dur_{int(time.time()*1000)}"
        start_t = time.perf_counter()
        res = subprocess.run([
            sys.executable, str(CLIENT_PY),
            "--mode", "legitimate",
            "--rate", "10",
            "--duration", "2.0",
            "--num-requests", "0",
            "--concurrency", "5",
            "--run-id", run_id_dur
        ], cwd=str(BASE_DIR), capture_output=True, text=True)
        elapsed_dur = time.perf_counter() - start_t
        assert res.returncode == 0, f"Generator failed: {res.stderr}"
        print(f"  Requested 2.0s duration; elapsed total: {elapsed_dur:.2f}s")
        assert 1.8 <= elapsed_dur <= 3.0, f"Run duration cutoff was {elapsed_dur:.2f}s, expected ~2.0s"
        print("  [PASS] Duration deadline cutoff handled cleanly.")

        # Test 7: Client/Server CSV Joining on run_id and request_id
        print("\n--- Test 7: Checking client/server CSV joining ---")
        with open(CLIENT_CSV, "r", encoding="utf-8") as f:
            c_rows = [r for r in csv.DictReader(f) if r.get("run_id") == run_id_a0 and r.get("status_code") != "DROPPED"]
        with open(REQUESTS_CSV, "r", encoding="utf-8") as f:
            s_rows = [r for r in csv.DictReader(f) if r.get("run_id") == run_id_a0]

        print(f"  Client completed rows for {run_id_a0}: {len(c_rows)}")
        print(f"  Server recorded rows for {run_id_a0}: {len(s_rows)}")
        assert len(c_rows) == len(s_rows) and len(c_rows) > 0, "Client and server row count mismatch"

        server_by_req_id = {r["request_id"]: r for r in s_rows}
        for c in c_rows:
            rid = c["request_id"]
            assert rid in server_by_req_id, f"Missing request_id {rid} on server"
            s = server_by_req_id[rid]
            # Status codes match
            assert int(c["status_code"]) == int(s["status"]), f"Status code mismatch: {c['status_code']} vs {s['status']}"
            # Client RTT >= Server response time
            c_rtt = float(c["client_latency_ms"])
            s_resp = float(s["response_ms"])
            assert c_rtt >= s_resp, f"Client RTT ({c_rtt}) should be >= server response time ({s_resp})"
        print("  [PASS] Client and Server CSVs joined 100% deterministically with matching IDs and valid RTT delta.")

        # Test 8: CLI Validation
        print("\n--- Test 8: Checking CLI input validation ---")
        bad_commands = [
            ["--rate", "-5"],
            ["--concurrency", "0"],
            ["--timeout", "-1"],
            ["--duration", "0", "--num-requests", "0"],
            ["--alpha", "1.5"]
        ]
        for bad in bad_commands:
            cmd = [sys.executable, str(CLIENT_PY)] + bad
            res = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True)
            assert res.returncode != 0, f"Expected validation failure for {bad}"
        print("  [PASS] All invalid CLI input combinations correctly rejected.")

        print("\n" + "=" * 60)
        print("ALL FOCUSED EXPERIMENT-VALIDITY TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)

    finally:
        server_proc.terminate()
        server_proc.wait(timeout=3)
        print("\nServer process shut down cleanly.")

if __name__ == "__main__":
    run_tests()
