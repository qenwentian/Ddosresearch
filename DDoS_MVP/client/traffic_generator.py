"""
Traffic Generator for DDoS Research MVP (Laptop 2)
Simulates legitimate traffic and controlled mimicry attacks with configurable alpha parameter.
Designed to run on Laptop 2 targeting Laptop 1 over the private LAN.

Traffic Model:
  D_traffic(alpha) = alpha * D_legitimate + (1 - alpha) * D_naive_attack
  - alpha = 0.0: Pure naive attack (deterministic timing, high-cost endpoint focus)
  - alpha = 0.5: Partial mimicry (blended timing and endpoint distributions)
  - alpha = 1.0: Full mimicry (Poisson arrivals, Zipfian endpoint distribution)
"""

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
import random
import sys
import time
import urllib.request
import urllib.error

# Resolve paths relative to project root
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOG_PATH = BASE_DIR / "data" / "client_sent.csv"

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

USER_AGENTS_LEGITIMATE = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

NAIVE_ATTACK_USER_AGENT = "PrototypeBot/1.0 (Automated Script; AttackCondition)"


def pick_endpoint(mode, alpha):
    """
    Selects request endpoint based on mode and alpha parameter.
    alpha = 0.0 -> 100% naive attack behavior (targets high-cost search endpoint)
    alpha = 1.0 -> 100% legitimate behavior (Zipfian web traffic distribution)
    """
    if mode == "legitimate":
        use_legit = True
    else:
        # In attack mode, alpha determines the probability of choosing legitimate behavior
        use_legit = (random.random() < alpha)

    if use_legit:
        endpoints, weights = zip(*LEGITIMATE_ENDPOINTS)
        path = random.choices(endpoints, weights=weights, k=1)[0]
        if path == "/search":
            path = f"/search?q={random.choice(SEARCH_QUERIES)}"
        return path
    else:
        # Naive attack concentrates heavily on the dynamic search query endpoint
        query = f"heavy_query_{random.randint(1000, 9999)}"
        return f"/search?q={query}"


def pick_user_agent(mode, alpha):
    """Selects User-Agent string based on mode and alpha."""
    if mode == "legitimate" or (random.random() < alpha):
        return random.choice(USER_AGENTS_LEGITIMATE)
    return NAIVE_ATTACK_USER_AGENT


def get_inter_arrival_time(rate, mode, alpha):
    """
    Calculates inter-arrival time (in seconds) between requests.
    - Legitimate / Mimic (alpha = 1.0): Exponential distribution (Poisson point process)
    - Naive attack (alpha = 0.0): Deterministic interval (constant delta_t)
    - Blended (0 < alpha < 1): Mixture model
    """
    if rate <= 0:
        return 0.0

    mean_interval = 1.0 / rate

    if mode == "legitimate" or (random.random() < alpha):
        # Exponential inter-arrival -> Poisson process
        return random.expovariate(rate)
    else:
        # Constant / periodic interval typical of unshaped bot floods
        return mean_interval


def init_client_log(csv_path):
    """Ensures client-side log directory and header exist."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    if not csv_path.exists():
        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "client_timestamp",
                "request_id",
                "mode",
                "alpha",
                "target_url",
                "inter_arrival_ms",
                "client_latency_ms",
                "status_code"
            ])


def run_traffic_generator(target_host, target_port, mode, alpha, rate, num_requests, log_file):
    """Executes the traffic generation sequence."""
    base_url = f"http://{target_host}:{target_port}"
    log_path = Path(log_file) if log_file else None

    if log_path:
        init_client_log(log_path)

    condition_label = f"mode={mode}" + (f", alpha={alpha:.2f}" if mode == "attack" else "")
    print(f"=== Starting Traffic Generator ===")
    print(f"Target:       {base_url}")
    print(f"Condition:    {condition_label}")
    print(f"Target Rate:  {rate} req/sec")
    print(f"Total Count:  {num_requests} requests")
    if log_path:
        print(f"Client Log:   {log_path.resolve()}")
    print("==================================\n")

    last_request_time = time.perf_counter()

    for req_id in range(1, num_requests + 1):
        # Determine path and user agent according to alpha model
        path = pick_endpoint(mode, alpha)
        user_agent = pick_user_agent(mode, alpha)
        full_url = f"{base_url}{path}"

        # Measure inter-arrival time from previous request
        now_perf = time.perf_counter()
        actual_inter_arrival_ms = round((now_perf - last_request_time) * 1000, 3) if req_id > 1 else 0.0
        last_request_time = now_perf

        # Execute HTTP request
        client_timestamp = datetime.now(timezone.utc).isoformat()
        req = urllib.request.Request(full_url, headers={"User-Agent": user_agent})
        status_code = None
        start_time = time.perf_counter()

        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.status
                response.read()  # drain response body
        except urllib.error.HTTPError as e:
            status_code = e.code
        except urllib.error.URLError as e:
            status_code = f"ERR_{type(e.reason).__name__}"
        except Exception as e:
            status_code = f"ERR_{type(e).__name__}"

        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        print(f"[{req_id:03d}/{num_requests:03d}] {path:<28} -> {status_code:<12} (RTT: {latency_ms:>6.2f} ms)")

        # Record to client-side CSV
        if log_path:
            with open(log_path, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    client_timestamp,
                    req_id,
                    mode,
                    alpha if mode == "attack" else 1.0,
                    full_url,
                    actual_inter_arrival_ms,
                    latency_ms,
                    status_code
                ])

        # Sleep according to inter-arrival distribution
        if req_id < num_requests:
            wait_sec = get_inter_arrival_time(rate, mode, alpha)
            time.sleep(wait_sec)

    print("\nTraffic generation complete.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="DDoS Research Traffic Generator — Simulates legitimate and alpha-mimic traffic."
    )
    parser.add_argument("--target-host", default="127.0.0.1", help="Target server IP (e.g. Laptop 1 IP)")
    parser.add_argument("--target-port", type=int, default=5000, help="Target server port (default: 5000)")
    parser.add_argument("--mode", choices=["legitimate", "attack"], default="legitimate",
                        help="Traffic mode: 'legitimate' or 'attack'")
    parser.add_argument("--alpha", type=float, default=0.0,
                        help="Mimicry parameter (0.0 = naive attack, 0.5 = partial mimicry, 1.0 = full mimicry)")
    parser.add_argument("--rate", type=float, default=2.0,
                        help="Average request rate lambda (requests per second, default: 2.0)")
    parser.add_argument("--num-requests", type=int, default=30,
                        help="Total number of requests to transmit (default: 30)")
    parser.add_argument("--log-file", default=str(DEFAULT_LOG_PATH),
                        help="Path to save client-side CSV transmission metrics (default: data/client_sent.csv)")

    args = parser.parse_args()

    if args.alpha < 0.0 or args.alpha > 1.0:
        parser.error("--alpha must be between 0.0 and 1.0")

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
            log_file=cli_args.log_file
        )
    except KeyboardInterrupt:
        print("\nTraffic generation aborted by user (Ctrl+C).")
        sys.exit(0)
