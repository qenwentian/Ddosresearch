import csv
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sys
import threading
import time
from flask import Flask, jsonify, request, g

# Resolve paths relative to the project root (DDoS_MVP/), allow override via env var
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REQUEST_LOG_PATH = Path(os.environ.get("REQUEST_LOG_PATH", str(DATA_DIR / "requests.csv")))

# Thread lock to ensure thread-safe CSV writes and schema migrations
log_lock = threading.Lock()

# Configurable bounded workload for /search?q=heavy_load
DEFAULT_HEAVY_ITERATIONS = int(os.environ.get("HEAVY_LOAD_ITERATIONS", "50000"))
MAX_HEAVY_ITERATIONS = 200000

CSV_HEADER = [
    "timestamp",
    "source_ip",
    "method",
    "path",
    "query_string",
    "user_agent",
    "response_ms",
    "status",
    "run_id",
    "request_id"
]

KNOWN_SERVER_COLUMNS = set(CSV_HEADER)

app = Flask(__name__)


def clamp_heavy_iterations(iterations):
    """Clamp heavy iterations to bounded range [1, MAX_HEAVY_ITERATIONS]."""
    return min(max(1, iterations), MAX_HEAVY_ITERATIONS)


def do_heavy_workload(iterations):
    """
    Bounded, deterministic CPU workload for testing detection degradation.
    Performs chained SHA-256 iterations to simulate an expensive application-layer transaction.
    """
    val = b"ddos_mvp_heavy_workload_seed"
    for _ in range(iterations):
        val = hashlib.sha256(val).digest()
    return val.hex()[:8]


def init_csv():
    """
    Ensure data directory and requests.csv header exist.
    Requirement 1: Migrates legacy schemas by column name (not position), creates a backup
    before rewriting, and rejects unknown schemas rather than silently corrupting them.
    """
    REQUEST_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with log_lock:
        if not REQUEST_LOG_PATH.exists():
            with open(REQUEST_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
            return

        with open(REQUEST_LOG_PATH, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            try:
                current_header = next(reader)
            except StopIteration:
                current_header = []

        if not current_header:
            with open(REQUEST_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
            return

        if current_header == CSV_HEADER:
            return  # Schema is already current

        # Reject unknown schemas
        unknown_cols = [c for c in current_header if c not in KNOWN_SERVER_COLUMNS]
        if unknown_cols:
            raise ValueError(
                f"Unknown CSV schema in {REQUEST_LOG_PATH}: unrecognized columns {unknown_cols}"
            )

        # Back up existing file before rewriting
        backup_path = REQUEST_LOG_PATH.with_suffix(f".csv.bak_{int(time.time())}")
        shutil.copy2(REQUEST_LOG_PATH, backup_path)

        # Migrate by column name preserving historical data
        with open(REQUEST_LOG_PATH, mode="r", newline="", encoding="utf-8") as f:
            dict_reader = csv.DictReader(f)
            migrated_rows = []
            for row in dict_reader:
                migrated_rows.append([row.get(col, "") for col in CSV_HEADER])

        with open(REQUEST_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            writer.writerows(migrated_rows)


@app.before_request
def before_request():
    """Start timing the request before handling."""
    g.start_time = time.perf_counter()


@app.after_request
def after_request(response):
    """Log request details, latency, and experiment run/request IDs to CSV."""
    if hasattr(g, "start_time"):
        response_ms = round((time.perf_counter() - g.start_time) * 1000, 3)
    else:
        response_ms = 0.0

    timestamp = datetime.now(timezone.utc).isoformat()
    source_ip = request.remote_addr or ""
    method = request.method
    path = request.path
    query_string = request.query_string.decode("utf-8", errors="replace")
    user_agent = request.headers.get("User-Agent", "")
    status = response.status_code
    run_id = request.headers.get("X-Run-ID", "")
    request_id = request.headers.get("X-Request-ID", "")

    with log_lock:
        with open(REQUEST_LOG_PATH, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                source_ip,
                method,
                path,
                query_string,
                user_agent,
                response_ms,
                status,
                run_id,
                request_id
            ])

    return response


@app.route("/", methods=["GET"])
def home():
    return jsonify({"page": "home", "status": "ok"})


@app.route("/news", methods=["GET"])
def news():
    return jsonify({"page": "news", "articles": 10, "status": "ok"})


@app.route("/profile", methods=["GET"])
def profile():
    return jsonify({"page": "profile", "status": "ok"})


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return jsonify({"page": "dashboard", "status": "ok"})


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    if query == "heavy_load":
        custom_iters = request.args.get("iterations", type=int)
        req_iters = custom_iters if custom_iters is not None else DEFAULT_HEAVY_ITERATIONS
        actual_iters = clamp_heavy_iterations(req_iters)
        digest = do_heavy_workload(actual_iters)
        return jsonify({
            "page": "search",
            "query": query,
            "status": "ok",
            "workload": "heavy",
            "iterations": actual_iters,
            "checksum": digest
        })
    return jsonify({"page": "search", "query": query, "status": "ok"})


if __name__ == "__main__":
    init_csv()
    port = int(os.environ.get("SERVER_PORT", 5000))
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    print("MVP Server starting...")
    print(f"Listening on 0.0.0.0:{port}")
    print(f"Request log: {REQUEST_LOG_PATH.resolve()}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
