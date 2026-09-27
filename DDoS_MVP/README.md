# DDoS Research MVP — Laptop 1 (Server & Monitor)

## Project Overview
This project represents the **Laptop 1** side of an MVP designed for research on application-layer DDoS detection degradation as malicious traffic increasingly resembles legitimate flash-crowd traffic.

**Role of Laptop 1:**
- Serves as the local HTTP test server handling requests over the private local network.
- High-resolution request logger recording all incoming HTTP requests to CSV.
- Continuous background system monitor recording CPU, RAM, and network I/O metrics to CSV.
- Target host for subsequent traffic condition experiments (legitimate baseline and $\alpha = 0.0, 0.5, 1.0$ mimic traffic) generated from Laptop 2, and the future evaluation host for Jensen-Shannon Divergence, Wasserstein Distance, and detection algorithms.

---

## Folder Structure
```text
DDoS_MVP/
│
├── server/
│   ├── server.py              # Flask HTTP server with threaded request logging
│   └── system_monitor.py       # Background resource monitor (CPU, RAM, network I/O)
│
├── client/
│   └── traffic_generator.py   # Traffic generator supporting legitimate and alpha-mimic conditions
│
├── data/
│   ├── requests.csv           # Request log with timestamps, IPs, routes, and latency
│   ├── system_metrics.csv     # 1-second system resource measurements
│   └── client_sent.csv        # Client transmission log (RTT, inter-arrival, status)
│
├── results/                   # Destination for future benchmark & analysis results
│
├── requirements.txt           # Minimal dependencies (flask, psutil)
│
└── README.md                  # Instructions and security guidelines
```

---

## Setup & Installation

### 1. Requirements Installation
Run the following command using system Python to install the required dependencies (`flask`, `psutil`):

```powershell
python -m pip install -r requirements.txt
```

*(Note: Per setup preference, this project runs directly on system Python without a virtual environment).*

---

## Running the MVP

The server and the system monitor run independently in separate terminal windows.

### Terminal 1: Run the Flask Server
Navigate to `DDoS_MVP` and start the server:

```powershell
python server/server.py
```

On startup, it displays:
```text
MVP Server starting...
Listening on 0.0.0.0:5000
Request log: <path-to-DDoS_MVP>\data\requests.csv
```

### Terminal 2: Run the System Monitor
Open a second terminal, navigate to `DDoS_MVP`, and start system resource logging:

```powershell
python server/system_monitor.py
```

On startup, it displays:
```text
System monitoring started...
Metrics log: <path-to-DDoS_MVP>\data\system_metrics.csv
Recording every 1 second. Press Ctrl+C to stop.
```

To stop monitoring, press **Ctrl+C**. It will exit cleanly and display:
```text
System monitoring stopped.
```

---

## Network Configuration & Multi-Laptop Testing

### Finding Laptop 1's Private IP
On Laptop 1, open PowerShell or Command Prompt and run:

```powershell
ipconfig
```

Look for the **IPv4 Address** under your active network adapter (Wi-Fi or Ethernet), typically something like `192.168.1.X` or `10.0.0.X`.

### Windows Firewall Configuration
If Laptop 2 cannot connect to Laptop 1:
1. Ensure both laptops are connected to the same private local network (LAN / Wi-Fi).
2. Check Windows Firewall on Laptop 1. You may need to create an **Inbound Rule**:
   - Rule Type: **Port**
   - Protocol: **TCP**
   - Specific local ports: **5000**
   - Action: **Allow the connection**
   - Profile: Check **Private** network profile only.
   - Name: `DDoS_MVP_Port_5000`
3. *Note: Do not modify Windows Firewall programmatically from Python.*

### Running Traffic Generation from Laptop 2
Copy the `DDoS_MVP/` folder (or `client/traffic_generator.py`) to Laptop 2. The traffic generator uses only the Python standard library.

#### Condition 1: Legitimate Baseline (Flash-Crowd Behavior)
Exponential inter-arrival times (Poisson process) and Zipfian endpoint distribution:
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode legitimate --rate 5 --num-requests 100
```

#### Condition 2: Pure Naive DDoS Attack ($\alpha = 0.0$)
Deterministic constant inter-arrival timing and concentrated heavy endpoint targeting:
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.0 --rate 20 --num-requests 200
```

#### Condition 3: Partial Mimicry Attack ($\alpha = 0.5$)
50/50 convex mixture of legitimate and naive attack distributions:
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 0.5 --rate 20 --num-requests 200
```

#### Condition 4: Full Mimicry Attack ($\alpha = 1.0$)
Full mimicry matching the legitimate empirical distribution:
```powershell
python client/traffic_generator.py --target-host <LAPTOP1_IP> --mode attack --alpha 1.0 --rate 20 --num-requests 200
```

*All transmission statistics (RTT, inter-arrival times, response codes) are recorded to `data/client_sent.csv` on the client for direct comparison with Laptop 1's `data/requests.csv`.*

---

## Critical Safety & Ethics Rules

> [!WARNING]
> **Experimental Safety Guidelines:**
> 1. **Do NOT port-forward port 5000** on your router. The test server must never be exposed to the public Internet.
> 2. **Keep all traffic on the private experimental LAN.** All tests must remain strictly between Laptop 1 and Laptop 2.
> 3. **Do not test traffic generation against any systems you do not own.** All generator scripts must target only Laptop 1's private IP address.

