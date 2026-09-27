"""
Traffic Generator for DDoS Research MVP (Laptop 2)
Simulates legitimate flash crowds and controlled mimicry attacks with configurable alpha parameter.
Designed to run on Laptop 2 targeting Laptop 1 over the private LAN.

Traffic Model:
  D_traffic(alpha) = alpha * D_legitimate + (1 - alpha) * D_naive_attack
  - Single Draw Profile Consistency: For each request, the profile (legitimate vs. naive) is
    drawn ONCE using alpha, determining its endpoint, User-Agent, arrival interval, and ground truth.
  - alpha = 0.0: Pure naive attack (deterministic timing, single fixed high-cost target, fixed bot header)
  - alpha = 0.5: Partial mimicry (50/50 mixture of legitimate and naive distributions)
  - alpha = 1.0: Full mimicry (Poisson arrivals, Zipfian endpoint distribution, realistic user agents)

Key Research Features:
  - Absolute Arrival Schedule: Advances deadlines from the previous scheduled deadline, not clock time.
  - Nonblocking Bounded Queue: Scheduler never blocks on server lag; drops arrivals when capacity saturates.
  - Distinct Interruption Semantics: Distinguishes cancelled queued work from capacity drops on Ctrl+C.
  - Accurate Rate Measurement: Measures scheduled rate over the scheduling window, excluding drain time.
  - Unique Run ID & Request ID: Reused run IDs are strictly rejected to guarantee deterministic 1-to-1 joins.
  - Named Schema Migration: Migrates CSV files by column name with automatic backup and unknown schema rejection.
"""

import argparse
import csv
from datetime import datetime, timezone
import ipaddress
import math
from pathlib import Path
import queue
import random
import shutil
import sys
import threading
import time
import urllib.request
import urllib.error
import uuid

# Resolve paths relative to project root
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOG_PATH = BASE_DIR / "data" / "client_sent.csv"
SAFE_MAX_RATE = 50.0
SAFE_MAX_CONCURRENCY = 20
SAFE_MAX_DURATION = 120.0
SAFE_MAX_REQUESTS = 5000

# Empirical legitimate endpoint weights (Zipfian-like popularity distribution)
LEGITIMATE_ENDPOINTS = [
    ("/", 0.35),
    ("/news", 0.30),
    ("/dashboard", 0.15),
    ("/profile", 0.10),
    ("/search", 0.10),
]

SEARCH_QUERIES = [
    "network", "security", "metrics", "research", "ddos",
    "analysis", "performance", "throughput", "status", "report"
]

# Fixed naive attack target: concentrated on deterministic heavy search endpoint (zero entropy)
NAIVE_ATTACK_ENDPOINT = "/search?q=heavy_load"

USER_AGENTS_LEGITIMATE = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

NAIVE_ATTACK_USER_AGENT = "PrototypeBot/1.0 (Automated; NaiveAttack)"

CLIENT_CSV_HEADER = [
    "run_id",
    "request_id",
    "scheduled_time",
    "actual_start_time",
    "mode",
    "alpha",
    "ground_truth",
    "target_url",
    "scheduled_interval_ms",
    "inter_arrival_ms",
    "client_latency_ms",
    "status_code"
]

KNOWN_CLIENT_COLUMNS = set(CLIENT_CSV_HEADER) | {"client_timestamp"}

# Synchronization locks
print_lock = threading.Lock()
csv_lock = threading.Lock()


def pick_legitimate_endpoint():
    endpoints, weights = zip(*LEGITIMATE_ENDPOINTS)
    path = random.choices(endpoints, weights=weights, k=1)[0]
    if path == "/search":
        path = f"/search?q={random.choice(SEARCH_QUERIES)}"
    return path


def draw_request_profile(mode, alpha, rate):
    """
    Requirement 1: Draw the legitimate or naive profile ONCE using alpha.
    Use that same profile for endpoint, User-Agent, and arrival interval.
    The ground-truth condition reflects the experiment condition (legitimate vs. attack_alpha).
    """
    is_legitimate = (mode == "legitimate") or (random.random() < alpha)

    if is_legitimate:
        profile = "legitimate"
        path = pick_legitimate_endpoint()
        user_agent = random.choice(USER_AGENTS_LEGITIMATE)
        interval_sec = random.expovariate(rate) if rate > 0 else 0.0
    else:
        profile = "naive"
        path = NAIVE_ATTACK_ENDPOINT
        user_agent = NAIVE_ATTACK_USER_AGENT
        interval_sec = (1.0 / rate) if rate > 0 else 0.0

    ground_truth = "legitimate" if mode == "legitimate" else f"attack_alpha_{alpha:.2f}"

    return profile, path, user_agent, interval_sec, ground_truth


def get_existing_run_ids(csv_path):
    """Returns a set of run_ids already present in the target CSV log."""
    if not csv_path or not csv_path.exists():
        return set()
    run_ids = set()
    try:
        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rid = row.get("run_id")
                if rid:
                    run_ids.add(rid)
    except Exception:
        pass
    return run_ids


def is_misaligned_row(row):
    """Detects historical rows shifted left into newer headers."""
    return (
        len(row) >= 9
        and row[0].startswith("2026-")
        and row[2] in ("legitimate", "attack")
    )


def repair_misaligned_row(row, batch_num):
    """Repairs shifted legacy row and assigns reproducible legacy run IDs."""
    mode_label = "legit" if row[2] == "legitimate" else f"attack_a{str(row[3]).replace('.', '')[:2]}"
    run_id = f"legacy_run_{batch_num:02d}_{mode_label}"
    timestamp = row[0]
    request_id = row[1]
    mode = row[2]
    alpha = row[3]
    ground_truth = row[4]
    target_url = row[5]
    scheduled_interval_ms = row[6]
    inter_arrival_ms = ""
    client_latency_ms = row[7]
    status_code = row[8] if len(row) > 8 and row[8] else "200"

    return [
        run_id,
        request_id,
        timestamp,
        timestamp,
        mode,
        alpha,
        ground_truth,
        target_url,
        scheduled_interval_ms,
        inter_arrival_ms,
        client_latency_ms,
        status_code
    ]


def init_client_log(csv_path):
    """
    Ensure client CSV exists, migrating existing legacy schemas by column name,
    preserving historical values (including inter_arrival_ms without renaming it to scheduled_interval_ms),
    repairing misaligned rows, excluding duplicate (run_id, request_id) keys,
    backing up before rewriting, and rejecting unknown schemas.
    """
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_lock:
        if not csv_path.exists():
            with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CLIENT_CSV_HEADER)
            return

        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            try:
                current_header = next(reader)
            except StopIteration:
                current_header = []
            raw_rows = list(reader)

        if not current_header:
            with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CLIENT_CSV_HEADER)
            return

        has_misaligned = any(is_misaligned_row(r) for r in raw_rows)
        if current_header == CLIENT_CSV_HEADER and not has_misaligned:
            return  # Schema and rows are already current

        # Reject unknown schemas
        unknown_cols = [c for c in current_header if c not in KNOWN_CLIENT_COLUMNS]
        if unknown_cols:
            raise ValueError(
                f"Unknown CSV schema in {csv_path}: unrecognized columns {unknown_cols}"
            )

        # Back up existing file before rewriting
        backup_path = csv_path.with_suffix(f".csv.bak_{int(time.time())}")
        shutil.copy2(csv_path, backup_path)

        migrated_rows = []
        legacy_batch = 0
        legacy_request_ids = set()
        seen_keys = set()
        excluded_duplicates = []

        is_original_8col = (
            current_header == [
                "client_timestamp", "request_id", "mode", "alpha",
                "target_url", "inter_arrival_ms", "client_latency_ms", "status_code"
            ]
        )

        for row in raw_rows:
            if is_misaligned_row(row):
                if row[1] in legacy_request_ids:
                    legacy_batch += 1
                    legacy_request_ids.clear()
                elif legacy_batch == 0:
                    legacy_batch = 1
                legacy_request_ids.add(row[1])
                repaired = repair_misaligned_row(row, legacy_batch)
                key = (repaired[0], repaired[1])
                if key in seen_keys:
                    excluded_duplicates.append(repaired)
                else:
                    seen_keys.add(key)
                    migrated_rows.append(repaired)
            elif is_original_8col:
                row_dict = dict(zip(current_header, row))
                ts = row_dict.get("client_timestamp", "")
                req_id = row_dict.get("request_id", "")
                if req_id in legacy_request_ids:
                    legacy_batch += 1
                    legacy_request_ids.clear()
                elif legacy_batch == 0:
                    legacy_batch = 1
                legacy_request_ids.add(req_id)
                mode = row_dict.get("mode", "")
                alpha = row_dict.get("alpha", "")
                gt = "legitimate" if mode == "legitimate" else (f"attack_alpha_{float(alpha):.2f}" if alpha else "attack")
                repaired = [
                    f"legacy_run_original_{legacy_batch:02d}",
                    req_id,
                    ts,
                    ts,
                    mode,
                    alpha,
                    gt,
                    row_dict.get("target_url", ""),
                    "",  # scheduled_interval_ms was not present
                    row_dict.get("inter_arrival_ms", ""),  # historical actual inter_arrival_ms preserved
                    row_dict.get("client_latency_ms", ""),
                    row_dict.get("status_code", "")
                ]
                key = (repaired[0], repaired[1])
                if key in seen_keys:
                    excluded_duplicates.append(repaired)
                else:
                    seen_keys.add(key)
                    migrated_rows.append(repaired)
            else:
                row_dict = dict(zip(current_header, row))
                run_id = row_dict.get("run_id", "")
                req_id = row_dict.get("request_id", "")
                key = (run_id, req_id)

                sched_t = row_dict.get("scheduled_time") or row_dict.get("client_timestamp", "")
                actual_t = row_dict.get("actual_start_time") or row_dict.get("client_timestamp", "")
                mode = row_dict.get("mode", "")
                alpha = row_dict.get("alpha", "")
                gt = row_dict.get("ground_truth", "")
                if not gt and mode:
                    gt = "legitimate" if mode == "legitimate" else (f"attack_alpha_{float(alpha):.2f}" if alpha else "attack")

                formatted_row = [
                    run_id,
                    req_id,
                    sched_t,
                    actual_t,
                    mode,
                    alpha,
                    gt,
                    row_dict.get("target_url", ""),
                    row_dict.get("scheduled_interval_ms", ""),
                    row_dict.get("inter_arrival_ms", ""),
                    row_dict.get("client_latency_ms", ""),
                    row_dict.get("status_code", "")
                ]

                if key in seen_keys:
                    excluded_duplicates.append(formatted_row)
                    continue
                seen_keys.add(key)
                migrated_rows.append(formatted_row)

        if excluded_duplicates:
            dup_file = csv_path.parent / f"{csv_path.stem}_duplicates.csv"
            with open(dup_file, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CLIENT_CSV_HEADER)
                writer.writerows(excluded_duplicates)

        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CLIENT_CSV_HEADER)
            writer.writerows(migrated_rows)


def worker_loop(work_queue, base_url, timeout, log_path, stats, stop_event,
                active_tasks, outstanding_tasks, start_allowed_event,
                workers_allowed_event):
    """
    Worker thread that pulls requests from the bounded queue and executes them over HTTP.
    Respects workers_allowed_event to guarantee no daemon thread continues writing after final counts.
    """
    while not stop_event.is_set():
        try:
            task = work_queue.get(timeout=0.2)
        except queue.Empty:
            continue

        if task is None:
            work_queue.task_done()
            break

        (run_id, req_id, path, user_agent, ground_truth,
         scheduled_interval_ms, actual_inter_arrival_ms,
         scheduled_time_iso, mode, alpha) = task

        # Check permission before starting work
        with stats["lock"]:
            if not start_allowed_event.is_set():
                work_queue.task_done()
                break
            actual_start_iso = datetime.now(timezone.utc).isoformat()
            stats["started"] += 1
            active_tasks[req_id] = (task, actual_start_iso)

        full_url = f"{base_url}{path}"
        req = urllib.request.Request(
            full_url,
            headers={
                "User-Agent": user_agent,
                "X-Run-ID": run_id,
                "X-Request-ID": str(req_id),
                "X-Ground-Truth": ground_truth
            }
        )

        status_code = None
        start_perf = time.perf_counter()

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.status
                response.read()  # drain response body
        except urllib.error.HTTPError as e:
            status_code = e.code
        except urllib.error.URLError as e:
            status_code = f"ERR_{type(e.reason).__name__}"
        except Exception as e:
            status_code = f"ERR_{type(e).__name__}"

        latency_ms = round((time.perf_counter() - start_perf) * 1000, 3)

        # Finalization takes csv_lock before closing worker access. Keep the
        # write and counter update inside that lock, without blocking arrivals
        # on disk I/O through stats["lock"].
        try:
            with csv_lock:
                can_log = workers_allowed_event.is_set()
                if can_log:
                    if log_path:
                        with open(log_path, mode="a", newline="", encoding="utf-8") as f:
                            csv.writer(f).writerow([
                                run_id, req_id, scheduled_time_iso, actual_start_iso,
                                mode, alpha if mode == "attack" else 1.0,
                                ground_truth, full_url, scheduled_interval_ms,
                                actual_inter_arrival_ms, latency_ms, status_code
                            ])
                    with stats["lock"]:
                        stats["completed"] += 1
                        stats["latencies"].append(latency_ms)
                        if isinstance(status_code, int) and 200 <= status_code <= 299:
                            stats["success_2xx"] += 1
                        else:
                            stats["errors"] += 1
                        outstanding_tasks.pop(req_id, None)
                        active_tasks.pop(req_id, None)
            if can_log:
                with print_lock:
                    print(f"[{req_id:04d}] {path:<28} -> {str(status_code):<12} (RTT: {latency_ms:>7.2f} ms)")
        finally:
            work_queue.task_done()


def log_special_status(log_path, run_id, req_id, scheduled_time_iso, mode, alpha, ground_truth,
                       full_url, scheduled_interval_ms, actual_inter_arrival_ms, status_label,
                       actual_start_time=""):
    """Log an arrival that was DROPPED (queue capacity), CANCELLED (Ctrl+C), or UNFINISHED."""
    if not log_path:
        return
    with csv_lock:
        with open(log_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                run_id,
                req_id,
                scheduled_time_iso,
                actual_start_time,
                mode,
                alpha if mode == "attack" else 1.0,
                ground_truth,
                full_url,
                scheduled_interval_ms,
                actual_inter_arrival_ms,
                "",  # client_latency_ms is empty
                status_label
            ])


def run_traffic_generator(target_host, target_port, mode, alpha, rate, num_requests, duration,
                          concurrency, max_pending, timeout, log_file, run_id=None):
    """
    Executes open-loop traffic generation.
    - Uses an absolute arrival schedule.
    - Never blocks scheduler on server lag; drops arrivals when bounded queue is full.
    - Handles Ctrl+C cleanly: marks unsent work CANCELLED, waits for active workers to complete.
    - Final Ctrl+C accounting: every scheduled arrival ends as completed, capacity-dropped, or cancelled/unfinished.
    - Active daemon workers do not continue writing after final counts are read.
    - Measures scheduled rate strictly over the scheduling window, excluding worker drain time.
    """
    log_path = Path(log_file) if log_file else None

    if log_path:
        init_client_log(log_path)
        existing_run_ids = get_existing_run_ids(log_path)
        if run_id:
            # Requirement 5: Reject reused --run-id
            if run_id in existing_run_ids:
                raise ValueError(
                    f"Run ID '{run_id}' has already been used in {log_path}. "
                    "Each experiment run must have a globally unique Run ID."
                )
        else:
            # Auto-generate unique Run ID
            while True:
                candidate = f"run_{uuid.uuid4().hex[:12]}"
                if candidate not in existing_run_ids:
                    run_id = candidate
                    break
    elif not run_id:
        run_id = f"run_{uuid.uuid4().hex[:12]}"

    base_url = f"http://{target_host}:{target_port}"
    ground_truth_label = "legitimate" if mode == "legitimate" else f"attack_alpha_{alpha:.2f}"

    if num_requests and duration:
        limit_str = f"{num_requests} requests OR {duration}s duration (first reached)"
    elif duration:
        limit_str = f"{duration} seconds (time-bounded)"
    else:
        limit_str = f"{num_requests} requests (count-bounded)"

    print("==================================================")
    print("      DDoS Research MVP — Traffic Generator       ")
    print("==================================================")
    print(f"Run ID:          {run_id}")
    print(f"Target Server:   {base_url}")
    print(f"Traffic Mode:    {mode.upper()}")
    if mode == "attack":
        print(f"Mimicry Alpha:   {alpha:.2f}")
    print(f"Ground Truth:    {ground_truth_label}")
    print(f"Target Rate:     {rate} req/sec")
    print(f"Run Limit:       {limit_str}")
    print(f"Concurrency:     {concurrency} workers (queue capacity: {max_pending})")
    print(f"Request Timeout: {timeout} seconds")
    if log_path:
        print(f"Client Log:      {log_path.resolve()}")
    print("==================================================\n")

    stats = {
        "lock": threading.Lock(),
        "scheduled": 0,
        "started": 0,
        "dropped_capacity": 0,
        "cancelled_queue": 0,
        "unfinished": 0,
        "completed": 0,
        "success_2xx": 0,
        "errors": 0,
        "latencies": []
    }

    # Bounded queue prevents unbounded RAM growth during server degradation
    work_queue = queue.Queue(maxsize=max_pending)
    stop_event = threading.Event()
    start_allowed_event = threading.Event()
    start_allowed_event.set()
    workers_allowed_event = threading.Event()
    workers_allowed_event.set()
    active_tasks = {}
    outstanding_tasks = {}

    workers = []
    for _ in range(concurrency):
        t = threading.Thread(
            target=worker_loop,
            args=(work_queue, base_url, timeout, log_path, stats, stop_event,
                  active_tasks, outstanding_tasks, start_allowed_event,
                  workers_allowed_event),
            daemon=True
        )
        t.start()
        workers.append(t)

    scheduling_start_perf = time.perf_counter()
    scheduled_deadline = scheduling_start_perf
    last_arrival_perf = scheduling_start_perf
    req_id = 0
    interrupted = False
    pending_scheduled_task = None
    dropped_rows = []

    def cancel_queued_work():
        nonlocal pending_scheduled_task
        cancelled_tasks = []
        if pending_scheduled_task is not None:
            cancelled_tasks.append(pending_scheduled_task)
            pending_scheduled_task = None
        while True:
            try:
                task = work_queue.get_nowait()
            except queue.Empty:
                break
            if task is not None:
                cancelled_tasks.append(task)
            work_queue.task_done()
        for task in cancelled_tasks:
            (r_id, q_id, pth, u_agent, g_truth, sched_int_ms, actual_int_ms, sched_iso, mde, al) = task
            with stats["lock"]:
                stats["cancelled_queue"] += 1
                outstanding_tasks.pop(q_id, None)
            log_special_status(
                log_path, r_id, q_id, sched_iso, mde, al,
                g_truth, f"{base_url}{pth}", sched_int_ms, actual_int_ms, "CANCELLED"
            )

    try:
        while True:
            # Termination check
            if num_requests and req_id >= num_requests:
                break
            now = time.perf_counter()
            if duration and (now - scheduling_start_perf) >= duration:
                break

            # Requirement 2: Absolute arrival schedule
            wait_sec = scheduled_deadline - now
            if duration:
                rem_sec = duration - (now - scheduling_start_perf)
                if rem_sec <= 0:
                    break
                if wait_sec > 0:
                    time.sleep(min(wait_sec, rem_sec))
            else:
                if wait_sec > 0:
                    time.sleep(wait_sec)

            if duration and (time.perf_counter() - scheduling_start_perf) >= duration:
                break

            req_id += 1
            scheduled_time_iso = datetime.now(timezone.utc).isoformat()
            now_arrival_perf = time.perf_counter()
            actual_inter_arrival_ms = round((now_arrival_perf - last_arrival_perf) * 1000, 3) if req_id > 1 else 0.0
            last_arrival_perf = now_arrival_perf

            # Requirement 1: Draw profile once
            profile, path, user_agent, interval_sec, ground_truth = draw_request_profile(mode, alpha, rate)
            scheduled_interval_ms = round(interval_sec * 1000, 3)

            # Advance deadline from previous scheduled deadline
            scheduled_deadline += interval_sec

            task = (
                run_id,
                req_id,
                path,
                user_agent,
                ground_truth,
                scheduled_interval_ms,
                actual_inter_arrival_ms,
                scheduled_time_iso,
                mode,
                alpha
            )

            with stats["lock"]:
                stats["scheduled"] += 1
                outstanding_tasks[req_id] = task

            # Requirement 3: Nonblocking attempt; record dropped on capacity saturation
            pending_scheduled_task = task
            try:
                work_queue.put_nowait(task)
                pending_scheduled_task = None
            except queue.Full:
                pending_scheduled_task = None
                with stats["lock"]:
                    stats["dropped_capacity"] += 1
                    outstanding_tasks.pop(req_id, None)
                dropped_rows.append((
                    run_id, req_id, scheduled_time_iso, mode, alpha,
                    ground_truth, f"{base_url}{path}", scheduled_interval_ms,
                    actual_inter_arrival_ms, "DROPPED"
                ))

    except KeyboardInterrupt:
        interrupted = True
        start_allowed_event.clear()
        print("\nCtrl+C detected. Cancelling pending queue and waiting for active workers to complete...")
        cancel_queued_work()

    # Requirement 4: Measure scheduling window strictly before worker drain time
    scheduling_end_perf = time.perf_counter()
    scheduling_window_sec = round(scheduling_end_perf - scheduling_start_perf, 3)

    # Disk latency must not delay scheduled arrivals when the queue is full.
    for dropped_row in dropped_rows:
        while True:
            try:
                log_special_status(log_path, *dropped_row)
                break
            except KeyboardInterrupt:
                interrupted = True
                start_allowed_event.clear()
                if not log_path:
                    continue
                # The interrupt can arrive after the row was written. Check
                # before retrying so that run/request IDs remain unique.
                with csv_lock:
                    with open(log_path, newline="", encoding="utf-8") as f:
                        already_logged = any(
                            row.get("run_id") == dropped_row[0]
                            and row.get("request_id") == str(dropped_row[1])
                            and row.get("status_code") == "DROPPED"
                            for row in csv.DictReader(f)
                        )
                if already_logged:
                    break

    if dropped_rows:
        print(f"Capacity exhausted: {len(dropped_rows)} arrivals dropped during scheduling.")
    if interrupted:
        cancel_queued_work()

    if not interrupted:
        print("\nArrival schedule finished. Draining in-flight requests...")
        try:
            work_queue.join()
        except KeyboardInterrupt:
            interrupted = True
            start_allowed_event.clear()
            print("\nCtrl+C detected during drain. Cancelling queued requests...")
            cancel_queued_work()

    # No final report can be issued while a worker may still start a request.
    stop_event.set()
    start_allowed_event.clear()
    for _ in workers:
        try:
            work_queue.put_nowait(None)
        except queue.Full:
            pass
    for t in workers:
        t.join()

    # A worker may have claimed a task but not yet registered it as active.
    # Account for every scheduled task still outstanding before reporting.
    with csv_lock:
        with stats["lock"]:
            workers_allowed_event.clear()
            final_status_rows = []
            for pending_id, pending_task in outstanding_tasks.items():
                started = active_tasks.get(pending_id)
                if started:
                    status_label = "UNFINISHED"
                    actual_start_iso = started[1]
                    stats["unfinished"] += 1
                else:
                    status_label = "CANCELLED"
                    actual_start_iso = ""
                    stats["cancelled_queue"] += 1
                final_status_rows.append((pending_task, status_label, actual_start_iso))
            outstanding_tasks.clear()
            active_tasks.clear()

            scheduled_cnt = stats["scheduled"]
            started_cnt = stats["started"]
            dropped_cnt = stats["dropped_capacity"]
            cancelled_cnt = stats["cancelled_queue"]
            unfinished_cnt = stats["unfinished"]
            completed_cnt = stats["completed"]
            success_cnt = stats["success_2xx"]
            error_cnt = stats["errors"]

    for pending_task, status_label, actual_start_iso in final_status_rows:
        (r_id, q_id, pth, u_agent, g_truth, sched_int_ms, actual_int_ms, sched_iso, mde, al) = pending_task
        log_special_status(
            log_path, r_id, q_id, sched_iso, mde, al,
            g_truth, f"{base_url}{pth}", sched_int_ms, actual_int_ms,
            status_label, actual_start_iso
        )

    # Verify mathematical conservation: every scheduled arrival is accounted for
    assert scheduled_cnt == completed_cnt + dropped_cnt + cancelled_cnt + unfinished_cnt, (
        f"Accounting mismatch: scheduled({scheduled_cnt}) != completed({completed_cnt}) + "
        f"dropped({dropped_cnt}) + cancelled({cancelled_cnt}) + unfinished({unfinished_cnt})"
    )

    total_elapsed = round(time.perf_counter() - scheduling_start_perf, 3)

    # Requirement 4: Scheduled rate over scheduling window; completion rate over total window
    scheduled_rate = round(scheduled_cnt / scheduling_window_sec, 2) if scheduling_window_sec > 0 else 0.0
    transmit_rate = round(started_cnt / total_elapsed, 2) if total_elapsed > 0 else 0.0
    completion_rate = round(completed_cnt / total_elapsed, 2) if total_elapsed > 0 else 0.0

    latencies = stats["latencies"]
    mean_rtt = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    min_rtt = round(min(latencies), 2) if latencies else 0.0
    max_rtt = round(max(latencies), 2) if latencies else 0.0

    print("\n==================================================")
    print("             TRAFFIC GENERATION REPORT            ")
    print("==================================================")
    print(f"Run ID:              {run_id}")
    print(f"Scheduling Window:   {scheduling_window_sec} s (excluding drain)")
    print(f"Total Run Window:    {total_elapsed} s (including drain)")
    print(f"Scheduled:           {scheduled_cnt} arrivals")
    print(f"Started:             {started_cnt} requests (transmitted to network)")
    print(f"Dropped (Capacity):  {dropped_cnt} arrivals (queue saturated)")
    print(f"Cancelled (Ctrl+C):  {cancelled_cnt} arrivals (before transmission)")
    if unfinished_cnt > 0:
        print(f"Unfinished:          {unfinished_cnt} arrivals (interrupted in-flight)")
    print(f"Completed:           {completed_cnt} requests")
    print(f"Success (2xx):       {success_cnt} requests (HTTP 200-299)")
    print(f"Errors/Non-2xx:      {error_cnt} requests")
    print("--------------------------------------------------")
    print(f"Scheduled Rate:      {scheduled_rate} req/sec (target: {rate})")
    print(f"Transmit Rate:       {transmit_rate} req/sec")
    print(f"Completion Rate:     {completion_rate} req/sec")
    print(f"Mean Client RTT:     {mean_rtt} ms (min: {min_rtt} ms, max: {max_rtt} ms)")
    print(f"Accounting:          FINAL ({scheduled_cnt} scheduled = {completed_cnt} completed + {dropped_cnt} dropped + {cancelled_cnt + unfinished_cnt} cancelled/unfinished)")
    if log_path:
        print(f"Saved Output:        {log_path.resolve()}")
    print("==================================================\n")

    return {
        "run_id": run_id,
        "scheduled": scheduled_cnt,
        "started": started_cnt,
        "dropped_capacity": dropped_cnt,
        "cancelled_queue": cancelled_cnt,
        "unfinished": unfinished_cnt,
        "completed": completed_cnt,

        "success_2xx": success_cnt,
        "errors": error_cnt,
        "mean_rtt": mean_rtt,
        "scheduling_window_sec": scheduling_window_sec,
        "total_elapsed": total_elapsed,
        "interrupted": interrupted
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="DDoS Research Traffic Generator — Open-Loop Multi-Threaded Generator for Legitimate & Alpha-Mimic Traffic."
    )
    parser.add_argument("--target-host", default="127.0.0.1",
                        help="Target server IP (default: 127.0.0.1)")
    parser.add_argument("--target-port", type=int, default=5000,
                        help="Target server port (default: 5000)")
    parser.add_argument("--mode", choices=["legitimate", "attack"], default="legitimate",
                        help="Traffic mode: 'legitimate' or 'attack' (default: legitimate)")
    parser.add_argument("--alpha", type=float, default=0.0,
                        help="Mimicry parameter between 0.0 and 1.0 (default: 0.0)")
    parser.add_argument("--rate", type=float, default=10.0,
                        help="Target request rate lambda in requests/sec (must be > 0, default: 10.0)")
    parser.add_argument("--num-requests", type=int, default=None,
                        help="Total number of requests to transmit (default: 50 if --duration is not set)")
    parser.add_argument("--duration", type=float, default=None,
                        help="Run duration in seconds. If set without --num-requests, overrides default request count.")
    parser.add_argument("--concurrency", type=int, default=10,
                        help="Max concurrent worker threads (must be >= 1, default: 10)")
    parser.add_argument("--max-pending", type=int, default=20,
                        help="Bounded pending queue capacity before arrivals are dropped (default: 20)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Per-request HTTP timeout in seconds (must be > 0, default: 5.0)")
    parser.add_argument("--log-file", default=str(DEFAULT_LOG_PATH),
                        help="Path to save client-side CSV metrics (default: data/client_sent.csv)")
    parser.add_argument("--run-id", default=None,
                        help="Optional unique Run ID (rejected if already present in log-file)")
    parser.add_argument("--allow-intensive-run", action="store_true",
                        help="Explicitly allow rates, concurrency, counts, or durations above the local safety limits")

    args = parser.parse_args()

    # CLI input validation
    if not math.isfinite(args.rate) or args.rate <= 0:
        parser.error("--rate must be a positive number (> 0)")
    if args.concurrency < 1:
        parser.error("--concurrency must be an integer >= 1")
    if args.max_pending < 1:
        parser.error("--max-pending must be an integer >= 1")
    if not 1 <= args.target_port <= 65535:
        parser.error("--target-port must be between 1 and 65535")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a positive number (> 0)")
    if not math.isfinite(args.alpha) or args.alpha < 0.0 or args.alpha > 1.0:
        parser.error("--alpha must be between 0.0 and 1.0")

    # Requirement 2: Duration and Request Count resolution semantics
    if args.duration is not None and (not math.isfinite(args.duration) or args.duration <= 0):
        parser.error("--duration must be a positive number (> 0)")
    if args.num_requests is not None and args.num_requests <= 0:
        parser.error("--num-requests must be a positive integer (> 0)")

    if args.duration is None and args.num_requests is None:
        args.num_requests = 50

    if args.target_host != "localhost":
        try:
            target_ip = ipaddress.IPv4Address(args.target_host)
        except ipaddress.AddressValueError:
            parser.error("--target-host must be localhost or a private IPv4 address")
        if target_ip.is_unspecified or target_ip.is_multicast or target_ip.is_reserved or not (
            target_ip.is_private or target_ip.is_loopback
        ):
            parser.error("--target-host must be localhost or a private IPv4 address")

    if not args.allow_intensive_run and (
        args.rate > SAFE_MAX_RATE
        or args.concurrency > SAFE_MAX_CONCURRENCY
        or (args.duration is not None and args.duration > SAFE_MAX_DURATION)
        or (args.num_requests is not None and args.num_requests > SAFE_MAX_REQUESTS)
    ):
        parser.error(
            "Run exceeds local safety limits (50 req/s, 20 workers, 120 s, 5000 requests); "
            "pass --allow-intensive-run for an intentional larger experiment"
        )
    if args.duration is not None and args.num_requests is None and not args.allow_intensive_run:
        args.num_requests = SAFE_MAX_REQUESTS
    # Duration-only runs use the safety count as a second termination condition.

    return args


if __name__ == "__main__":
    cli_args = parse_args()
    try:
        run_traffic_generator(
            target_host=cli_args.target_host,
            target_port=cli_args.target_port,
            mode=cli_args.mode,
            alpha=cli_args.alpha,
            rate=cli_args.rate,
            num_requests=cli_args.num_requests,
            duration=cli_args.duration,
            concurrency=cli_args.concurrency,
            max_pending=cli_args.max_pending,
            timeout=cli_args.timeout,
            log_file=cli_args.log_file,
            run_id=cli_args.run_id
        )
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
