# HNG Stage 3 — Anomaly Detection & DDoS Protection Engine

## Live URLs
- **Metrics Dashboard:** http://psitdev.duckdns.org
- **Server IP:** 107.21.30.194 (Nextcloud accessible via IP only)
- **GitHub:** https://github.com/travispocr/hng-stage3-devops

---

## Language Choice
**Python** — chosen for:
- Rich standard library (`collections.deque`, `threading`, `subprocess`)
- Clean implementation of statistical operations without external libs
- Fast iteration for log parsing and real-time processing
- `psutil` for system metrics, `Flask` for dashboard

---

## How the Sliding Window Works

Two deque-based windows track request rates:

### Per-IP Window
```python
self.ip_windows[ip].append(now)  # append timestamp
while self.ip_windows[ip][0] < cutoff:
    self.ip_windows[ip].popleft()  # evict expired
```

### Global Window
```python
self.global_window.append(now)
while self.global_window[0] < cutoff:
    self.global_window.popleft()
```

- **Window size:** 60 seconds
- **Eviction logic:** On every new request, timestamps older than `now - 60s` are popped from the left of the deque
- **Rate = len(deque)** — count of timestamps in window = requests in last 60 seconds
- No libraries used — pure `collections.deque`

---

## How the Baseline Works

- **Window size:** 30 minutes of per-second request counts
- **Recalculation interval:** Every 60 seconds
- **Storage:** Rolling deque of `(timestamp, count)` tuples
- **Eviction:** Entries older than 30 minutes are popped on each addition
- **Floor values:** `mean=1.0`, `stddev=1.0` until enough data exists
- **Hourly slots:** Each recalculation stores results in `hourly_slots[hour]`
- **Preference:** Current hour's slot is used as effective baseline when it has enough samples (`min_requests_for_baseline=10`)
- **Stats:** Mean and sample stddev computed from scratch — no external stats libraries

```python
mean = sum(values) / n
variance = sum((x - mean) ** 2 for x in values) / (n - 1)
stddev = sqrt(variance)
```

---

## Detection Logic

An anomaly is flagged when **either** condition fires first:

1. **Z-score:** `(rate - mean) / stddev > 3.0`
2. **Rate multiplier:** `rate > 5.0 × mean`

### Error Surge Tightening
If an IP's 4xx/5xx rate exceeds `3x` the baseline error rate:
- Z-score threshold drops from `3.0` to `1.5`
- Rate multiplier drops from `5.0x` to `2.5x`

---

## How iptables Blocking Works

When an anomaly is detected for a specific IP:

```python
subprocess.run([
    "iptables", "-A", "INPUT",
    "-s", ip,
    "-j", "DROP"
])
```

- Rule is added within **10 seconds** of detection
- Drops all incoming packets from the offending IP at kernel level
- Auto-unban schedule: **10 min → 30 min → 2 hours → permanent**
- Unban removes the rule: `iptables -D INPUT -s ip -j DROP`

---

## Setup Instructions (Fresh VPS)

### Prerequisites
- Ubuntu 22.04+
- Docker + Docker Compose
- Port 80 and 8080 open in security group

### 1. Install Docker
```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone the repository
```bash
git clone https://github.com/travispocr/hng-stage3-devops.git
cd hng-stage3-devops
```

### 3. Start the stack
```bash
docker compose up -d
```

### 4. Verify all services are running
```bash
docker compose ps
docker compose logs -f detector
```

### Successful startup looks like:

hng-nginx      running
hng-nextcloud  running
hng-db         running
hng-detector   running
[main] Config loaded
[main] Started thread: monitor
[main] Started thread: baseline
[main] Started thread: detector
[main] Started thread: unbanner
[main] Started thread: dashboard
All systems running!

---

## Repository Structure

├── detector/
│   ├── main.py        # Entry point, thread orchestration
│   ├── monitor.py     # Nginx log tailer and parser
│   ├── baseline.py    # Rolling 30-min baseline manager
│   ├── detector.py    # Z-score + rate anomaly detection
│   ├── blocker.py     # iptables ban management
│   ├── unbanner.py    # Backoff unban scheduler
│   ├── notifier.py    # Slack webhook alerts
│   ├── dashboard.py   # Flask live metrics UI
│   ├── config.yaml    # All thresholds and config
│   └── requirements.txt
├── nginx/
│   └── nginx.conf     # JSON logging, reverse proxy
├── docs/
│   └── architecture.png
├── screenshots/
└── README.md

---

## Blog Post
Published on Dev.to:
**https://dev.to/devops_journey_4b18fb2ab9/how-i-built-a-real-time-ddos-detection-engine-from-scratch-no-fail2ban-allowed-2e59**

---

## Slack Alerts
All alerts sent to `#all-hng-monitoring` channel including:
- 🚨 IP ban with condition, rate, baseline, timestamp
- ✅ IP unban with duration and next ban schedule
- ⚠️ Global traffic anomaly alerts
