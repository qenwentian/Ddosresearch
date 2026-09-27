import csv
from datetime import datetime, timezone
from pathlib import Path
import sys
import psutil

# Resolve paths relative to the project root (DDoS_MVP/)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
METRICS_LOG_PATH = DATA_DIR / "system_metrics.csv"

def init_csv():
    """Ensure data directory and system_metrics.csv header exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not METRICS_LOG_PATH.exists():
        with open(METRICS_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "cpu_percent",
                "ram_percent",
                "bytes_sent",
                "bytes_received"
            ])

def monitor():
    """Continuously record system resource metrics every second."""
    init_csv()
    print("System monitoring started...")
    print(f"Metrics log: {METRICS_LOG_PATH.resolve()}")
    print("Recording every 1 second. Press Ctrl+C to stop.")

    try:
        while True:
            # cpu_percent with interval=1.0 blocks for 1 second, sampling CPU accurately
            cpu = psutil.cpu_percent(interval=1.0)
            ram = psutil.virtual_memory().percent
            net = psutil.net_io_counters()
            timestamp = datetime.now(timezone.utc).isoformat()

            with open(METRICS_LOG_PATH, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    cpu,
                    ram,
                    net.bytes_sent,
                    net.bytes_recv
                ])
    except KeyboardInterrupt:
        print("\nSystem monitoring stopped.")
        sys.exit(0)

if __name__ == "__main__":
    monitor()
