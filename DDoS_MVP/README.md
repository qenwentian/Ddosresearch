# DDoS Research MVP — Laptop 1 (Server & Monitor) & Laptop 2 (Traffic Generator)

## Project Overview
This project provides the core experimental testbed for research evaluating **application-layer DDoS detection degradation as malicious traffic increasingly resembles legitimate flash-crowd traffic**.

**Architecture & Responsibilities:**
- **Laptop 1 (Server & Monitor):**
  - High-resolution Flask test server listening on `0.0.0.0:5000` with threaded request handling.
  - Exposes standard pages (`/`, `/news`, `/profile`, `/dashboard`, `/search`) plus a bounded deterministic heavy workload endpoint: `/search?q=heavy_load`.
  - Appends incoming request telemetry to `data/requests.csv` with unique experiment `run_id` and `request_id` tracking.
  - Background resource monitor (`server/system_monitor.py`) recording CPU, RAM, and network I/O every second to `data/system_metrics.csv`.
- **Laptop 2 (Traffic Generator):**
  - Open-loop, multi-threaded traffic generator (`client/traffic_generator.py`) using only the Python standard library.
  - Generates legitimate flash crowds and controlled mimicry attacks parameterized by $\alpha \in [0.0, 1.0]$.
  - Enforces joint-profile consistency (single draw per request for endpoint, User-Agent, and arrival interval).
  - Uses an absolute arrival schedule and a bounded pending queue to prevent server degradation from throttling the generator.
  - Records transmission metrics to `data/client_sent.csv` for offline correlation.

---

## Folder Structure
```text
DDoS_MVP/
│
├── server/
│   ├── server.py              # Flask HTTP server with threaded request logging & heavy workload
│   └── system_monitor.py       # Standalone background system resource monitor
│
├── client/
│   └── traffic_generator.py   # Open-loop traffic generator with alpha-mimicry & bounded queue
│
├── data/
│   ├── requests.csv           # Server request log (includes run_id and request_id)
│   ├── system_metrics.csv     # 1-second system resource measurements
│   └── client_sent.csv        # Client transmission log (includes run_id, request_id, RTT, drops)
│
├── results/                   # Destination for future benchmark & analysis results
│
├── requirements.txt           # Minimal dependencies (flask, psutil)
│
└── README.md                  # Comprehensive setup, operational, and schema guide
```

---

## CSV Data Schemas & Correlation Joining

Both the server and client record headers that allow deterministic, 1-to-1 offline joining without leaking ground-truth labels to anomaly detectors:

### 1. `data/requests.csv` (Server-side Log, 10 columns)
| Column | Description |
| :--- | :--- |
| `timestamp` | ISO-8601 UTC timestamp of request handling completion on server |
| `source_ip` | Client IP address seen by Flask |
| `method` | HTTP method (e.g. `GET`) |
| `path` | Request URI path |
| `query_string` | Decoded query parameters |
| `user_agent` | Client User-Agent header |
| `response_ms` | Server internal processing latency measured via monotonic `time.perf_counter()` |
| `status` | HTTP response code (e.g. `200`, `404`) |
| `run_id` | Unique ID of the experimental run (from `X-Run-ID` header) |
| `request_id` | Sequential request ID (from `X-Request-ID` header) |

### 2. `data/client_sent.csv` (Client-side Log, 12 columns)
| Column | Description |
| :--- | :--- |
| `run_id` | Unique experiment run identifier |
| `request_id` | Sequential sequence number (1..N) |
| `scheduled_time` | ISO-8601 UTC timestamp when arrival was scheduled |
| `actual_start_time` | ISO-8601 UTC timestamp when worker began transmitting (empty if dropped/cancelled) |
| `mode` | Traffic mode (`legitimate` or `attack`) |
| `alpha` | Mimicry parameter ($0.0 \le \alpha \le 1.0$) |
| `ground_truth` | Ground truth label (e.g. `legitimate`, `attack_alpha_0.00`, `attack_alpha_0.50`) |
| `target_url` | Full HTTP target URL |
| `scheduled_interval_ms` | Scheduled inter-arrival interval $\Delta t$ drawn from distribution (empty for legacy 8-col) |
| `inter_arrival_ms` | Measured actual inter-arrival interval elapsed between arrival events (preserved from legacy 8-col) |
| `client_latency_ms` | End-to-end round trip time (RTT) in milliseconds (empty if dropped/cancelled) |
| `status_code` | HTTP code (`200`), network error (`ERR_...`), `DROPPED` (capacity), `CANCELLED` (before transmission), or `UNFINISHED` |

*Join only unambiguous rows in Pandas:*
```python
import pandas as pd
server_df = pd.read_csv("data/requests.csv")
client_df = pd.read_csv("data/client_sent.csv")
keys = ["run_id", "request_id"]
client_df = client_df.dropna(subset=keys)
server_df = server_df.dropna(subset=keys)
client_df = client_df[~client_df.duplicated(keys, keep=False)]
server_df = server_df[~server_df.duplicated(keys, keep=False)]
joined_df = pd.merge(client_df, server_df, on=keys, validate="one_to_one")
```

Historical requests made before the server recorded IDs cannot be joined by ID. Some old test runs also reused an ID; their original values remain in the timestamped CSV backups. Run `python scripts/audit_csv_join.py` to count unique matches, ambiguous keys, and unmatched rows before analysis. The client migration preserves separate old runs when request IDs repeat and keeps any excluded duplicate rows in a review file.

The two recorded `test_run_a0` test runs were reconciled using client start and server completion timestamps. Both CSVs were backed up before assigning `test_run_a0_part1` and `test_run_a0_part2`; `scripts/reconcile_reused_run.py` reproduces this repair on the backed-up inputs. Older rows without server IDs remain unmatched and should not be used for paired analysis.
In the current sample logs, 66 client-only rows are intentional capacity drops, 40 older client rows predate server IDs, and five server-only test rows have no matching client record. Keep these out of paired analyses.

*Final Ctrl+C Accounting & Conservation Law:*
Upon interrupt, every scheduled arrival is finalized before reporting:
$$\text{scheduled} = \text{completed} + \text{dropped\_capacity} + \text{cancelled\_queue} + \text{unfinished}$$
Every scheduled arrival has a matching row in `client_sent.csv`, and active daemon workers are blocked from writing late results.


---

## Server Setup & Execution (Laptop 1)

### 1. Requirements Installation
Run using system Python:
```powershell
python -m pip install -r requirements.txt
```

### 2. Terminal 1: Run the Flask Server
```powershell
python server/server.py
```
*Startup output:*
```text
MVP Server starting...
Listening on 0.0.0.0:5000
Request log: C:\Users\aldwin\ResearchProject\DDoS_MVP\data\requests.csv
```

#### Deterministic Heavy Workload Endpoint
The endpoint `/search?q=heavy_load` performs bounded, deterministic SHA-256 iterations (default: 50,000 iterations, ~25 ms CPU time), making it measurably more expensive than standard endpoints (~0.1 ms). The default workload can be customized via the `HEAVY_LOAD_ITERATIONS` environment variable:
```powershell
$env:HEAVY_LOAD_ITERATIONS="75000"; python server/server.py
```

### 3. Terminal 2: Run the System Monitor
Open a second terminal on Laptop 1:
```powershell
python server/system_monitor.py
```
Stop monitoring at any time with **Ctrl+C**.

---

## Traffic Generator Execution (Laptop 2)

Copy `DDoS_MVP/` (or `client/traffic_generator.py`) to Laptop 2. It requires only standard Python.

### Traffic Conditions & Alpha Parameter ($\alpha$)
For every request, the generator draws its profile **once** using probability $\alpha$:
- **Legitimate ($\alpha = 1.0$):** Zipfian endpoint selection across valid pages (`/`, `/news`, `/dashboard`, `/profile`, `/search?q=...`), diverse browser User-Agents, and exponential Poisson inter-arrival intervals ($\text{Exp}(\lambda)$).
- **Naive Attack ($\alpha = 0.0$):** 100% concentrated on `/search?q=heavy_load`, fixed bot User-Agent, and deterministic constant intervals ($\Delta t = 1/\lambda$).
- **Partial Mimicry ($\alpha = 0.5$):** 50% legitimate profile, 50% naive attack profile.

### Example Commands

#### 1. Legitimate Baseline (Flash-Crowd Simulation)
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode legitimate --rate 15 --num-requests 150 --concurrency 10
```

#### 2. Pure Naive DDoS Attack ($\alpha = 0.0$)
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.0 --rate 30 --num-requests 300 --concurrency 15
```

#### 3. Partial Mimicry Attack ($\alpha = 0.5$)
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.5 --rate 30 --num-requests 300 --concurrency 15
```

#### 4. Full Mimicry Attack ($\alpha = 1.0$)
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 1.0 --rate 30 --num-requests 300 --concurrency 15
```

#### 5. Run Limit & Duration Precedence Semantics
The generator supports flexible termination modes:
- **Duration Only (`--duration 60`):** Overrides the default 50-request count and schedules for up to 60 seconds, with a 5,000-request cap unless `--allow-intensive-run` is set. In-flight requests may finish after scheduling stops.
- **Count Only (`--num-requests 200`):** Runs until 200 requests have been scheduled (unbounded duration).
- **Both (`--duration 60 --num-requests 200`):** Uses a **first-reached dual-termination policy**: the run stops as soon as either 200 requests are reached OR 60 seconds have elapsed.
- **Neither (Default):** Defaults to `--num-requests 50`.

```powershell
# Run for 60 seconds (duration overrides default count)
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.5 --rate 25 --duration 60

# Run up to 500 requests, but cap at 30 seconds
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.5 --rate 25 --num-requests 500 --duration 30
```

---

## Absolute Scheduling, Bounded Queue, & Interruption Handling

1. **Absolute Arrival Schedule:** Deadlines advance strictly from the previous scheduled deadline:
   $$\text{Deadline}_{i+1} = \text{Deadline}_i + \Delta t_{i+1}$$
   Clock time drift does not accumulate, and server latency degradation cannot throttle the scheduled arrival rate.
2. **Scheduled Rate vs. Completion Rate:**
   - **Scheduled Rate:** Measured strictly over the active scheduling window (`scheduling_end - scheduling_start`), excluding worker drain time.
   - **Transmit & Completion Rates:** Measured over total elapsed time, including in-flight request completion.
3. **Bounded Queue Capacity:** The generator maintains a bounded queue (`--max-pending`, default: 20). If server latency spikes and all worker threads are occupied, excess scheduled arrivals are counted as **Dropped** (`status_code="DROPPED"`) rather than queuing unboundedly in RAM.
4. **Ctrl+C Interruption Handling:**
   - Queued arrivals waiting in memory when interrupted are cleanly drained, logged to CSV with `status_code="CANCELLED"`, and counted separately from capacity drops.
   - Active worker threads are given time to complete in-flight requests before the final report is generated.
5. **Run ID Uniqueness Enforcement:**
   - Run IDs must be globally unique within the client log. If a user supplies `--run-id` with an ID that already exists in `data/client_sent.csv`, the generator rejects the command immediately to prevent corrupted joins.
6. **Robust Schema Migration:**
   - Client and server CSVs are migrated strictly **by column name** (never by index/position).
   - Before any schema rewrite, the original file is backed up as `.csv.bak_<timestamp>`.
   - Unknown or unrecognized column headers are rejected with a `ValueError` rather than corrupted.
7. **Structured Metrics Report:** At completion, the generator outputs precise counts:
   - **Scheduled:** Total arrivals produced by the schedule.
   - **Started:** Requests transmitted onto the network by workers.
   - **Dropped (Capacity):** Arrivals rejected due to client capacity saturation.
   - **Cancelled (Ctrl+C):** Arrivals cancelled before transmission upon user interrupt.
   - **Completed:** Requests finished (`Success_2xx + Errors`).
   - **Success (2xx):** Completed requests strictly with HTTP status 200–299.
   - **Errors / Non-2xx:** Completed requests with 4xx, 5xx, or network timeouts.


---

## Network Configuration & Firewall

### Finding Laptop 1's Private IP
On Laptop 1:
```powershell
ipconfig
```
Locate the IPv4 address (e.g. `192.168.1.X` or `10.0.0.X`).

### Windows Firewall Rule (Laptop 1)
If Laptop 2 cannot connect, add an Inbound Rule on Laptop 1 (Run PowerShell as Administrator):
```powershell
New-NetFirewallRule -DisplayName "DDoS_MVP_Port_5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow -Profile Private
```

---

## Critical Safety & Ethics Rules

The generator CLI accepts only `localhost` or a private IPv4 target. To reduce accidental load on a shared Wi-Fi network, it requires `--allow-intensive-run` above 50 requests/second, 20 workers, 120 seconds, or 5,000 scheduled requests. Duration-only runs stop at 5,000 scheduled requests unless explicitly overridden. This is an explicit override for a planned experiment, not a guarantee of zero network impact. Start at the default 10 requests/second and stop if other devices become sluggish.

For a first LAN check, use `python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode legitimate --rate 5 --num-requests 50`. The generator stops scheduling on Ctrl+C and finishes or records already scheduled work before reporting.

> [!WARNING]
> **Strict Experimental Safety Guidelines:**
> 1. **Do NOT port-forward port 5000** on your router. The test server must never be exposed to the public Internet.
> 2. **Keep all traffic on the private experimental LAN.** All tests must remain strictly between Laptop 1 and Laptop 2.
> 3. **Do not test traffic generation against any systems you do not own.** All generator scripts must target only Laptop 1's private IP address.
