import csv
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from flask import Flask, jsonify, request, g

# Resolve paths relative to the project root (DDoS_MVP/)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REQUEST_LOG_PATH = DATA_DIR / "requests.csv"

# Thread lock to ensure thread-safe CSV writes across concurrent requests
log_lock = threading.Lock()

app = Flask(__name__)

def init_csv():
    """Ensure data directory and requests.csv header exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with log_lock:
        if not REQUEST_LOG_PATH.exists():
            with open(REQUEST_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "source_ip",
                    "method",
                    "path",
                    "query_string",
                    "user_agent",
                    "response_ms",
                    "status"
                ])

@app.before_request
def before_request():
    """Start timing the request before handling."""
    g.start_time = time.perf_counter()

@app.after_request
def after_request(response):
    """Log request details and duration to CSV after request execution."""
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
                status
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
    return jsonify({"page": "search", "query": query, "status": "ok"})

if __name__ == "__main__":
    init_csv()
    print("MVP Server starting...")
    print("Listening on 0.0.0.0:5000")
    print(f"Request log: {REQUEST_LOG_PATH.resolve()}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
