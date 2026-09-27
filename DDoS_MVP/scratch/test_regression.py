"""
Regression Test Suite for DDoS Research MVP.

Verifies:
1. CSV migration by column name for server and client (preserving original 8-col inter_arrival_ms without renaming).
2. Schema rejection of unknown columns with ValueError.
3. --duration override and dual-termination policy (count vs duration).
4. Real interruption (Ctrl+C / KeyboardInterrupt) with final accounting:
   every scheduled arrival ends as completed, capacity-dropped, or cancelled/unfinished with a matching CSV row.
   Daemon workers do not continue after final counts are read.
5. Accurate rate measurement strictly over the scheduling window, excluding worker drain.
6. Unique Run ID enforcement and rejection of reused --run-id.
7. Heavy endpoint actual clamped iteration count reporting.
8. Detection and repair of misaligned rows and exclusion of duplicate (run_id, request_id) keys.
9. Runs completely in isolation using an available local port and temporary file paths;
   verifies that tracked CSVs in data/ are NOT modified.
"""

import _thread
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

BASE_DIR = Path(__file__).resolve().parent.parent
SERVER_PY = BASE_DIR / "server" / "server.py"
CLIENT_PY = BASE_DIR / "client" / "traffic_generator.py"
MIGRATION_PY = BASE_DIR / "scripts" / "migrate_client_csv.py"
TRACKED_CLIENT_CSV = BASE_DIR / "data" / "client_sent.csv"
TRACKED_REQUESTS_CSV = BASE_DIR / "data" / "requests.csv"


def find_free_port():
    """Finds an available local port dynamically."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_regression_tests():
    print("=" * 68)
    print("RUNNING REGRESSION TEST SUITE (DYNAMIC PORT & ISOLATED TEMPORARY PATHS)")
    print("=" * 68)

    # Snapshot tracked CSV contents to ensure the test does not change them.
    tracked_snapshots = {}
    for path in (TRACKED_CLIENT_CSV, TRACKED_REQUESTS_CSV):
        if path.exists():
            tracked_snapshots[path] = hashlib.sha256(path.read_bytes()).digest()

    free_port = find_free_port()
    print(f"Allocated ephemeral local port: {free_port}")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        temp_requests_csv = temp_path / "requests.csv"
        temp_client_csv = temp_path / "client_sent.csv"

        # Start isolated server pointing to temp_requests_csv on free_port
        env = os.environ.copy()
        env["REQUEST_LOG_PATH"] = str(temp_requests_csv)
        env["SERVER_PORT"] = str(free_port)

        server_proc = subprocess.Popen(
            [sys.executable, str(SERVER_PY), str(free_port)],
            cwd=str(BASE_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Confirm its own server started via healthcheck retry loop
        server_ready = False
        start_poll = time.perf_counter()
        while time.perf_counter() - start_poll < 10.0:
            if server_proc.poll() is not None:
                raise RuntimeError(f"Server process terminated prematurely with code {server_proc.returncode}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/", timeout=0.5) as resp:
                    if resp.status == 200:
                        server_ready = True
                        break
            except Exception:
                time.sleep(0.1)

        assert server_ready, f"Server failed to start on port {free_port} within 10 seconds"
        print(f"Confirmed isolated server is running and responding on http://127.0.0.1:{free_port}")

        try:
            # -------------------------------------------------------------
            # Test 1: CSV Migration by Column Name + Backup + Schema Rejection
            # -------------------------------------------------------------
            print("\n--- Test 1: CSV Migration by column name, backup, and rejection ---")

            # 1a. Server CSV migration with scrambled legacy columns
            scrambled_server_csv = temp_path / "scrambled_requests.csv"
            with open(scrambled_server_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["path", "source_ip", "timestamp", "status", "response_ms", "user_agent", "method", "query_string"])
                writer.writerow(["/news", "127.0.0.1", "2026-09-27T00:00:00+00:00", "200", "1.23", "TestAgent", "GET", "foo=bar"])

            sys.path.insert(0, str(BASE_DIR / "server"))
            import server as srv_module
            srv_module.REQUEST_LOG_PATH = scrambled_server_csv
            srv_module.init_csv()

            backups = list(temp_path.glob("scrambled_requests*.bak*"))
            assert len(backups) >= 1, "Server backup file must be created before migration"
            print(f"  [PASS] Server backup created: {backups[0].name}")

            with open(scrambled_server_csv, "r", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
                assert row["path"] == "/news"
                assert row["status"] == "200"
                assert row["method"] == "GET"
                assert row["query_string"] == "foo=bar"
                assert row["run_id"] == ""
                assert row["request_id"] == ""
            print("  [PASS] Server CSV migrated accurately by column name; historical values preserved.")

            # 1b. Server CSV rejection of unknown columns
            corrupted_server_csv = temp_path / "corrupted_requests.csv"
            with open(corrupted_server_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "source_ip", "unknown_foreign_col", "status"])

            srv_module.REQUEST_LOG_PATH = corrupted_server_csv
            rejected_srv = False
            try:
                srv_module.init_csv()
            except ValueError as e:
                rejected_srv = True
                print(f"  [PASS] Unknown server schema correctly rejected: {e}")
            assert rejected_srv, "Unknown server schema must be rejected with ValueError"

            # 1c. Client CSV migration from the repository's original eight-column client CSV
            # Must preserve historical inter_arrival_ms and NOT rename it to scheduled_interval_ms
            legacy_8col_csv = temp_path / "legacy_8col_client.csv"
            with open(legacy_8col_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "client_timestamp", "request_id", "mode", "alpha",
                    "target_url", "inter_arrival_ms", "client_latency_ms", "status_code"
                ])
                for batch in range(4):
                    for request_id in range(1, 6):
                        writer.writerow([
                            f"2026-09-27T04:{batch:02d}:{request_id:02d}+00:00",
                            request_id, "legitimate", "1.0",
                            f"http://127.0.0.1:{free_port}/dashboard", "75.717", "46.287", "200"
                        ])

            sys.path.insert(0, str(BASE_DIR / "client"))
            import traffic_generator as cli_module
            cli_module.init_client_log(legacy_8col_csv)

            client_backups = list(temp_path.glob("legacy_8col_client*.bak*"))
            assert len(client_backups) >= 1, "Client backup file must be created before migration"
            with open(legacy_8col_csv, "r", encoding="utf-8") as f:
                migrated_legacy = list(csv.DictReader(f))
                assert len(migrated_legacy) == 20
                assert len({(r["run_id"], r["request_id"]) for r in migrated_legacy}) == 20
                assert len({r["run_id"] for r in migrated_legacy}) == 4
                c_row = migrated_legacy[0]
                # Verify inter_arrival_ms was preserved and not renamed to scheduled_interval_ms
                assert c_row["inter_arrival_ms"] == "75.717", f"inter_arrival_ms not preserved: {c_row['inter_arrival_ms']}"
                assert c_row["scheduled_interval_ms"] == "", f"scheduled_interval_ms must be empty for 8-col legacy: {c_row['scheduled_interval_ms']}"
                assert c_row["scheduled_time"] == "2026-09-27T04:44:11.488806+00:00"
                assert c_row["actual_start_time"] == "2026-09-27T04:44:11.488806+00:00"
                assert c_row["ground_truth"] == "legitimate"
            print("  [PASS] Original 8-column client CSV migrated by column name: inter_arrival_ms preserved without renaming to scheduled_interval_ms.")

            # 1d. Client CSV rejection of unknown columns
            corrupted_client_csv = temp_path / "corrupted_client.csv"
            with open(corrupted_client_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["run_id", "invalid_foreign_column", "mode"])
            rejected_cli = False
            try:
                cli_module.init_client_log(corrupted_client_csv)
            except ValueError as e:
                rejected_cli = True
                print(f"  [PASS] Unknown client schema correctly rejected: {e}")
            assert rejected_cli, "Unknown client schema must be rejected with ValueError"

            # -------------------------------------------------------------
            # Test 2: --duration Override and Dual-Termination Semantics
            # -------------------------------------------------------------
            print("\n--- Test 2: --duration override and dual-termination policy ---")

            # 2a. Duration only: overrides default request count of 50
            t_start = time.perf_counter()
            res = cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="legitimate",
                alpha=1.0,
                rate=20.0,
                num_requests=None,    # duration only
                duration=1.5,
                concurrency=5,
                max_pending=20,
                timeout=5.0,
                log_file=str(temp_client_csv)
            )
            elapsed = time.perf_counter() - t_start
            print(f"  Duration-only run: elapsed={elapsed:.2f}s, scheduled={res['scheduled']}")
            assert 1.4 <= elapsed <= 2.2, f"Duration-only run elapsed was {elapsed:.2f}s, expected ~1.5s"
            assert res['scheduled'] != 50, "Duration must override default count 50"
            print("  [PASS] Duration-only run cleanly overrode default request count.")

            # 2b. Both supplied: count hits first
            res_dual_count = cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="legitimate",
                alpha=1.0,
                rate=25.0,
                num_requests=10,      # Hits first at ~0.4s
                duration=10.0,        # Far deadline
                concurrency=5,
                max_pending=20,
                timeout=5.0,
                log_file=str(temp_client_csv)
            )
            assert res_dual_count['scheduled'] == 10, f"Expected 10 requests, got {res_dual_count['scheduled']}"
            print("  [PASS] Dual-termination stopped when count was reached first.")

            # 2c. Both supplied: duration hits first
            t_start = time.perf_counter()
            res_dual_dur = cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="legitimate",
                alpha=1.0,
                rate=10.0,
                num_requests=500,     # Huge count
                duration=1.2,         # Hits first at 1.2s
                concurrency=5,
                max_pending=20,
                timeout=5.0,
                log_file=str(temp_client_csv)
            )
            elapsed = time.perf_counter() - t_start
            assert 1.1 <= elapsed <= 2.2, f"Duration cutoff failed: {elapsed:.2f}s"
            assert res_dual_dur['scheduled'] < 500, "Should have cut off before reaching 500 requests"
            print("  [PASS] Dual-termination stopped when duration elapsed first.")

            # -------------------------------------------------------------
            # Test 3: Real Interruption & Final Accounting
            # -------------------------------------------------------------
            print("\n--- Test 3: Real Interruption and Final Accounting ---")
            ctrl_c_client_csv = temp_path / "ctrl_c_client.csv"

            def trigger_interrupt():
                time.sleep(0.35)
                print("  [Trigger] Firing real KeyboardInterrupt to main thread...")
                _thread.interrupt_main()

            # Schedule interrupt during active traffic generation
            timer_thread = threading.Thread(target=trigger_interrupt, daemon=True)
            timer_thread.start()

            res_interrupt = cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="attack",
                alpha=0.0,
                rate=25.0,
                num_requests=100,
                duration=10.0,
                concurrency=4,
                max_pending=20,
                timeout=5.0,
                log_file=str(ctrl_c_client_csv)
            )

            assert res_interrupt["interrupted"] is True, "Generator must record interrupted=True on Ctrl+C"
            sched = res_interrupt["scheduled"]
            comp = res_interrupt["completed"]
            drop = res_interrupt["dropped_capacity"]
            canc = res_interrupt["cancelled_queue"]
            unfin = res_interrupt["unfinished"]

            print(f"  Interrupt results: scheduled={sched}, completed={comp}, dropped={drop}, cancelled={canc}, unfinished={unfin}")
            # Strict mathematical conservation law
            assert sched == comp + drop + canc + unfin, (
                f"Conservation mismatch: {sched} != {comp} + {drop} + {canc} + {unfin}"
            )

            # Confirm every scheduled arrival has an exact matching CSV row
            with open(ctrl_c_client_csv, "r", encoding="utf-8") as f:
                csv_rows = list(csv.DictReader(f))
            assert len(csv_rows) == sched, f"CSV row count ({len(csv_rows)}) != scheduled arrivals ({sched})"

            # Verify that cancelled rows have empty actual_start_time and empty client_latency_ms
            cancelled_rows = [r for r in csv_rows if r["status_code"] == "CANCELLED"]
            for cr in cancelled_rows:
                assert cr["actual_start_time"] == "", "Cancelled row must have empty actual_start_time"
                assert cr["client_latency_ms"] == "", "Cancelled row must have empty client_latency_ms"

            # Verify daemon workers did not continue writing after final counts
            time.sleep(0.5)
            with open(ctrl_c_client_csv, "r", encoding="utf-8") as f:
                csv_rows_after = list(csv.DictReader(f))
            assert len(csv_rows_after) == len(csv_rows), "No daemon workers may write after final counts!"
            print("  [PASS] Real interruption handled cleanly: every scheduled arrival is final and accounted for with matching CSV row.")

            # -------------------------------------------------------------
            # Test 4: Rate Measurement Window (Scheduling vs. Drain)
            # -------------------------------------------------------------
            print("\n--- Test 4: Scheduled rate over scheduling window vs. drain ---")
            res_rate = cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="attack",
                alpha=0.0,
                rate=25.0,
                num_requests=15,
                duration=None,
                concurrency=2,        # Small concurrency on heavy endpoint causes drain time
                max_pending=20,
                timeout=5.0,
                log_file=str(temp_client_csv)
            )
            sched_win = res_rate["scheduling_window_sec"]
            tot_win = res_rate["total_elapsed"]
            print(f"  Scheduling Window: {sched_win:.3f}s, Total Window (with drain): {tot_win:.3f}s")
            assert sched_win <= tot_win, "Scheduling window must be <= total run window"
            target_scheduled_rate = round(res_rate["scheduled"] / sched_win, 2)
            print(f"  Calculated Scheduled Rate over scheduling window: {target_scheduled_rate} req/sec (target: 25.0)")
            assert 20.0 <= target_scheduled_rate <= 35.0, f"Scheduled rate {target_scheduled_rate} deviated significantly from target 25.0"
            print("  [PASS] Scheduled rate measured strictly over scheduling window, excluding drain time.")

            # -------------------------------------------------------------
            # Test 5: Unique Run ID Enforcement
            # -------------------------------------------------------------
            print("\n--- Test 5: Reused --run-id rejection ---")
            fixed_run_id = "unique_fixed_run_123"
            cli_module.run_traffic_generator(
                target_host="127.0.0.1",
                target_port=free_port,
                mode="legitimate",
                alpha=1.0,
                rate=20.0,
                num_requests=5,
                duration=None,
                concurrency=5,
                max_pending=20,
                timeout=5.0,
                log_file=str(temp_client_csv),
                run_id=fixed_run_id
            )
            rejected_run_id = False
            try:
                cli_module.run_traffic_generator(
                    target_host="127.0.0.1",
                    target_port=free_port,
                    mode="legitimate",
                    alpha=1.0,
                    rate=20.0,
                    num_requests=5,
                    duration=None,
                    concurrency=5,
                    max_pending=20,
                    timeout=5.0,
                    log_file=str(temp_client_csv),
                    run_id=fixed_run_id
                )
            except ValueError as e:
                rejected_run_id = True
                print(f"  [PASS] Reused --run-id successfully rejected: {e}")
            assert rejected_run_id, "Reused run-id must raise ValueError"

            with open(temp_client_csv, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                pairs = [(r["run_id"], r["request_id"]) for r in reader]
                assert len(pairs) == len(set(pairs)), "Duplicate (run_id, request_id) found in client log!"
            print(f"  [PASS] All {len(pairs)} client log records are strictly unique on (run_id, request_id).")

            # -------------------------------------------------------------
            # Test 6: Actual Clamped Iteration Count from Heavy Endpoint
            # -------------------------------------------------------------
            print("\n--- Test 6: Actual clamped iteration count reporting ---")
            with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/search?q=heavy_load") as resp:
                data_default = json.loads(resp.read().decode())
                assert data_default["iterations"] == 50000, f"Expected 50000, got {data_default['iterations']}"
            print("  [PASS] Default iterations reported as 50000.")

            with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/search?q=heavy_load&iterations=999999") as resp:
                data_max = json.loads(resp.read().decode())
                assert data_max["iterations"] == 200000, f"Expected 200000, got {data_max['iterations']}"
            print("  [PASS] High iteration count (999999) correctly clamped and reported as 200000.")

            with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/search?q=heavy_load&iterations=-50") as resp:
                data_min = json.loads(resp.read().decode())
                assert data_min["iterations"] == 1, f"Expected 1, got {data_min['iterations']}"
            print("  [PASS] Low iteration count (-50) correctly clamped and reported as 1.")

            # -------------------------------------------------------------
            # Test 7: Misaligned Row Detection & Repair + Duplicate Key Exclusion
            # -------------------------------------------------------------
            print("\n--- Test 7: Misaligned Row Detection, Repair, and Duplicate Key Exclusion ---")
            sys.path.insert(0, str(BASE_DIR / "scripts"))
            import migrate_client_csv as mig_module

            synthetic_test_csv = temp_path / "synthetic_client.csv"
            with open(synthetic_test_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([c for c in cli_module.CLIENT_CSV_HEADER if c != "inter_arrival_ms"])
                # 20 misaligned rows (2 batches of 10)
                for i in range(1, 11):
                    writer.writerow([f"2026-09-27T05:05:{i:02d}.000+00:00", str(i), "legitimate", "1.0", "legitimate", f"http://127.0.0.1:{free_port}/dashboard", "80.0", "20.0", "200", "", ""])
                for i in range(1, 11):
                    writer.writerow([f"2026-09-27T05:05:{i+10:02d}.000+00:00", str(i), "attack", "0.0", "attack_alpha_0.00", f"http://127.0.0.1:{free_port}/search?q=heavy_load", "40.0", "25.0", "200", "", ""])
                # 5 normal rows with run_id 'test_run_dup'
                for i in range(1, 6):
                    writer.writerow(["test_run_dup", str(i), "2026-09-27T06:00:00+00:00", "2026-09-27T06:00:00+00:00", "attack", "0.0", "attack_alpha_0.00", f"http://127.0.0.1:{free_port}/", "50.0", "30.0", "200"])
                # 5 duplicate rows with same run_id 'test_run_dup' and req_id 1..5
                for i in range(1, 6):
                    writer.writerow(["test_run_dup", str(i), "2026-09-27T06:01:00+00:00", "2026-09-27T06:01:00+00:00", "attack", "0.0", "attack_alpha_0.00", f"http://127.0.0.1:{free_port}/", "50.0", "35.0", "200"])

            mig_stats = mig_module.migrate_csv_file(synthetic_test_csv)
            print(f"  Migration stats on synthetic file: {mig_stats}")
            assert mig_stats["misaligned_repaired"] == 20, f"Expected 20 misaligned repaired, got {mig_stats['misaligned_repaired']}"
            assert mig_stats["excluded_duplicates"] == 5, f"Expected 5 duplicates excluded, got {mig_stats['excluded_duplicates']}"
            assert mig_stats["migrated_rows"] == 25, f"Expected 25 unique rows (20 legacy + 5 original), got {mig_stats['migrated_rows']}"

            with open(synthetic_test_csv, "r", encoding="utf-8") as f:
                syn_rows = list(csv.DictReader(f))
                syn_keys = [(r["run_id"], r["request_id"]) for r in syn_rows]
                assert len(syn_keys) == len(set(syn_keys)), "All keys in migrated CSV must be 1-to-1 unique!"
                assert syn_rows[0]["run_id"] == "legacy_run_01_legit"
                assert syn_rows[10]["run_id"] == "legacy_run_02_attack_a00"
            print("  [PASS] Misaligned rows accurately detected and repaired; duplicates excluded for 1-to-1 joins.")

            print("\n" + "=" * 68)
            print("ALL 7 REGRESSION CHECKS PASSED IN COMPLETE ISOLATION!")
            print("=" * 68)

        finally:
            server_proc.terminate()
            server_proc.wait(timeout=3)
            print("Isolated test server terminated.")

    # Final check: Ensure NO tracked files were modified during the test suite
    for path, digest in tracked_snapshots.items():
        assert path.exists(), f"Tracked file {path} must exist"
        assert hashlib.sha256(path.read_bytes()).digest() == digest, f"Tracked file {path} was modified"
        print(f"Verified tracked file {path.name} was preserved untouched.")


if __name__ == "__main__":
    run_regression_tests()
