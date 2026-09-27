"""Client checks that run without Flask or network traffic."""

import _thread
import contextlib
import csv
import io
from pathlib import Path
import queue
import sys
import tempfile
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "client"))
import traffic_generator as generator


def test_legacy_runs():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "client_sent.csv"
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "client_timestamp", "request_id", "mode", "alpha",
                "target_url", "inter_arrival_ms", "client_latency_ms", "status_code"
            ])
            for batch in range(4):
                for request_id in range(1, 6):
                    writer.writerow([
                        f"2026-09-27T04:{batch:02d}:{request_id:02d}+00:00",
                        request_id, "attack", "0.0", "http://127.0.0.1:5000/",
                        "50.0", "1.0", "200"
                    ])
        generator.init_client_log(path)
        with path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        assert len(rows) == 20
        assert len({(row["run_id"], row["request_id"]) for row in rows}) == 20
        assert len({row["run_id"] for row in rows}) == 4
        assert all(row["inter_arrival_ms"] == "50.0" for row in rows)


def test_cli_safety():
    def parses(*arguments):
        with patch.object(sys, "argv", ["traffic_generator.py", *arguments]):
            with contextlib.redirect_stderr(io.StringIO()):
                return generator.parse_args()

    for arguments in [
        ("--target-host", "8.8.8.8"),
        ("--rate", "100"),
        ("--duration", "300"),
    ]:
        try:
            parses(*arguments)
        except SystemExit as error:
            assert error.code == 2
        else:
            raise AssertionError(f"Unsafe CLI arguments accepted: {arguments}")
    assert parses("--target-host", "192.168.1.2").target_host == "192.168.1.2"
    assert parses("--rate", "100", "--allow-intensive-run").rate == 100
    assert parses("--rate", "50", "--duration", "120").num_requests == 5000
    assert parses("--rate", "50", "--duration", "120", "--allow-intensive-run").num_requests is None


def test_completion_waits_for_csv():
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            pass

        def read(self):
            return b"ok"

    class SlowWorkerCsvLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if threading.current_thread() is not threading.main_thread():
                time.sleep(1.5)
            self.lock.acquire()

        def __exit__(self, *arguments):
            self.lock.release()

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "client_sent.csv"
        slow_lock = SlowWorkerCsvLock()
        timer = threading.Timer(0.05, _thread.interrupt_main)
        with patch.object(generator, "csv_lock", slow_lock), \
             patch.object(generator.urllib.request, "urlopen", return_value=Response()), \
             contextlib.redirect_stdout(io.StringIO()):
            timer.start()
            try:
                result = generator.run_traffic_generator(
                    "127.0.0.1", 5000, "attack", 0.0, 10.0,
                    100, None, 1, 2, 0.1, str(path)
                )
            finally:
                timer.join()
        with path.open(newline="", encoding="utf-8") as file:
            row_count = sum(1 for _ in csv.DictReader(file))
        assert result["interrupted"]
        assert row_count == result["scheduled"]
        time.sleep(0.2)
        with path.open(newline="", encoding="utf-8") as file:
            assert sum(1 for _ in csv.DictReader(file)) == row_count


def test_interrupt_during_drain():
    class SlowResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            pass

        def read(self):
            time.sleep(0.5)
            return b"ok"

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "client_sent.csv"
        timer = threading.Timer(0.1, _thread.interrupt_main)
        with patch.object(generator.urllib.request, "urlopen", return_value=SlowResponse()), \
             contextlib.redirect_stdout(io.StringIO()):
            timer.start()
            try:
                result = generator.run_traffic_generator(
                    "127.0.0.1", 5000, "attack", 0.0, 10.0,
                    1, None, 1, 2, 0.1, str(path)
                )
            finally:
                timer.join()
        with path.open(newline="", encoding="utf-8") as file:
            assert sum(1 for _ in csv.DictReader(file)) == 1
        assert result["interrupted"] and result["completed"] == 1


def test_interrupt_after_worker_claim():
    claimed = threading.Event()
    release_claim = threading.Event()
    base_queue = queue.Queue

    class InterruptDrainQueue(base_queue):
        def get(self, *arguments, **kwargs):
            task = super().get(*arguments, **kwargs)
            if task is not None and threading.current_thread() is not threading.main_thread():
                claimed.set()
                release_claim.wait(3)
            return task

        def join(self):
            assert claimed.wait(2)
            raise KeyboardInterrupt

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "client_sent.csv"
        try:
            with patch.object(generator.queue, "Queue", InterruptDrainQueue), \
                 patch.object(generator.urllib.request, "urlopen", side_effect=AssertionError("unexpected HTTP request")), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = generator.run_traffic_generator(
                    "127.0.0.1", 5000, "attack", 0.0, 10.0,
                    1, None, 1, 1, 0.1, str(path)
                )
        finally:
            release_claim.set()
        with path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
        assert result["interrupted"]
        assert result["scheduled"] == result["cancelled_queue"] == 1
        assert len(rows) == 1 and rows[0]["status_code"] == "CANCELLED"


def test_slow_csv_does_not_delay_schedule():
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            pass

        def read(self):
            return b"ok"

    class SlowWorkerCsvLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if threading.current_thread() is not threading.main_thread():
                time.sleep(0.1)
            self.lock.acquire()

        def __exit__(self, *arguments):
            self.lock.release()

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "client_sent.csv"
        with patch.object(generator, "csv_lock", SlowWorkerCsvLock()), \
             patch.object(generator.urllib.request, "urlopen", return_value=Response()), \
             contextlib.redirect_stdout(io.StringIO()):
            result = generator.run_traffic_generator(
                "127.0.0.1", 5000, "attack", 0.0, 50.0,
                30, None, 1, 5, 1, str(path)
            )
        with path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
    assert result["scheduled"] == result["completed"] + result["dropped_capacity"] == 30
    assert result["dropped_capacity"] > 0
    assert len(rows) == result["scheduled"]
    assert result["scheduling_window_sec"] < 1.5


if __name__ == "__main__":
    test_legacy_runs()
    test_cli_safety()
    test_completion_waits_for_csv()
    test_interrupt_during_drain()
    test_interrupt_after_worker_claim()
    test_slow_csv_does_not_delay_schedule()
    print("client fixes passed")
