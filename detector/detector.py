"""
detector.py - Anomaly detection using sliding windows and z-score.
Two deque-based windows: per-IP and global over last 60 seconds.
Flags anomaly if z-score > 3.0 OR rate > 5x baseline mean.
Tightens thresholds if IP error rate is 3x baseline error rate.
"""

import time
import threading
from collections import deque, defaultdict
from datetime import datetime


class SharedState:
    """Central state shared between all detector components."""

    def __init__(self, config):
        self.config = config
        self.window_seconds = config["detection"]["window_seconds"]
        self.lock = threading.Lock()

        # Global sliding window: deque of timestamps
        self.global_window = deque()

        # Per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows = defaultdict(deque)

        # Per-IP error windows: {ip: deque of timestamps}
        self.ip_error_windows = defaultdict(deque)

        # Banned IPs: {ip: {"banned_at": t, "count": n, "reason": str}}
        self.banned_ips = {}

        # Top IPs tracking: {ip: count}
        self.ip_counts = defaultdict(int)

        # Global request rate history for baseline
        self.per_second_counts = deque()
        self.per_second_errors = deque()
        self._current_second = int(time.time())
        self._current_count = 0
        self._current_errors = 0

        # Uptime
        self.start_time = time.time()

        print("[state] SharedState initialized")

    def add_request(self, entry):
        """Add a parsed log entry to all sliding windows."""
        now = time.time()
        ip = entry["source_ip"]
        is_error = entry["status"] >= 400
        cutoff = now - self.window_seconds

        with self.lock:
            # Global window
            self.global_window.append(now)
            while self.global_window and self.global_window[0] < cutoff:
                self.global_window.popleft()

            # Per-IP window
            self.ip_windows[ip].append(now)
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()

            # Per-IP error window
            if is_error:
                self.ip_error_windows[ip].append(now)
            while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
                self.ip_error_windows[ip].popleft()

            # IP count tracking
            self.ip_counts[ip] += 1

            # Per-second aggregation for baseline
            second = int(now)
            if second != self._current_second:
                self.per_second_counts.append(
                    (self._current_second, self._current_count)
                )
                self.per_second_errors.append(
                    (self._current_second, self._current_errors)
                )
                self._current_second = second
                self._current_count = 0
                self._current_errors = 0
            self._current_count += 1
            if is_error:
                self._current_errors += 1

    def get_global_rate(self):
        """Return current global requests per second."""
        with self.lock:
            return len(self.global_window)

    def get_ip_rate(self, ip):
        """Return current requests per second for an IP."""
        with self.lock:
            return len(self.ip_windows.get(ip, []))

    def get_ip_error_rate(self, ip):
        """Return current error rate for an IP."""
        with self.lock:
            return len(self.ip_error_windows.get(ip, []))

    def get_top_ips(self, n=10):
        """Return top N IPs by request count."""
        with self.lock:
            sorted_ips = sorted(
                self.ip_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:n]

    def get_active_ips(self):
        """Return all IPs with requests in the current window."""
        with self.lock:
            return list(self.ip_windows.keys())

    def get_second_counts(self):
        """Return per-second counts for baseline feeding."""
        with self.lock:
            counts = list(self.per_second_counts)
            errors = list(self.per_second_errors)
            self.per_second_counts.clear()
            self.per_second_errors.clear()
            return counts, errors


class AnomalyDetector:
    """
    Detects anomalies using z-score and rate multiplier.
    Checks both per-IP and global traffic levels.
    """

    def __init__(self, config, state, baseline, blocker, notifier, audit):
        self.config = config
        self.state = state
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit

        self.zscore_threshold = config["detection"]["zscore_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier"]
        self.error_multiplier = config["detection"]["error_rate_multiplier"]

        print("[detector] AnomalyDetector initialized")

    def _zscore(self, value, mean, stddev):
        """Calculate z-score."""
        if stddev == 0:
            return 0
        return (value - mean) / stddev

    def _check_ip(self, ip, mean, stddev, error_mean, error_stddev):
        """Check if a single IP is anomalous."""
        if ip in self.state.banned_ips:
            return

        ip_rate = self.state.get_ip_rate(ip)
        ip_error_rate = self.state.get_ip_error_rate(ip)

        # Tighten thresholds if error rate is elevated
        threshold_multiplier = 1.0
        if error_mean > 0 and ip_error_rate >= self.error_multiplier * error_mean:
            threshold_multiplier = 0.5
            print(f"[detector] Tightened thresholds for {ip} due to high error rate")

        effective_zscore = self.zscore_threshold * threshold_multiplier
        effective_rate = self.rate_multiplier * threshold_multiplier

        zscore = self._zscore(ip_rate, mean, stddev)
        is_anomalous = (
            zscore > effective_zscore or
            (mean > 0 and ip_rate > effective_rate * mean)
        )

        if is_anomalous:
            condition = (
                f"z-score={zscore:.2f} > {effective_zscore}"
                if zscore > effective_zscore
                else f"rate={ip_rate} > {effective_rate}x mean={mean:.2f}"
            )
            print(f"[detector] IP anomaly detected: {ip} — {condition}")
            self.blocker.ban_ip(ip, condition, ip_rate, mean)
            self.notifier.send_ban_alert(ip, condition, ip_rate, mean)
            self.audit.log_ban(ip, condition, ip_rate, mean)

    def _check_global(self, mean, stddev):
        """Check if global traffic is anomalous."""
        global_rate = self.state.get_global_rate()
        zscore = self._zscore(global_rate, mean, stddev)

        is_anomalous = (
            zscore > self.zscore_threshold or
            (mean > 0 and global_rate > self.rate_multiplier * mean)
        )

        if is_anomalous:
            condition = (
                f"global z-score={zscore:.2f} > {self.zscore_threshold}"
                if zscore > self.zscore_threshold
                else f"global rate={global_rate} > {self.rate_multiplier}x mean={mean:.2f}"
            )
            print(f"[detector] Global anomaly detected — {condition}")
            self.notifier.send_global_alert(condition, global_rate, mean)
            self.audit.log_event("GLOBAL_ANOMALY", "-", condition, global_rate, mean)

    def run(self, stop_event):
        """Continuously check for anomalies every second."""
        print("[detector] Detection thread started")
        while not stop_event.is_set():
            mean, stddev = self.baseline.get_baseline()
            error_mean, error_stddev = self.baseline.get_error_baseline()

            # Feed per-second counts to baseline
            counts, errors = self.state.get_second_counts()
            for _, count in counts:
                error_count = 0
                self.baseline.add_second_count(count, error_count)

            # Check all active IPs
            active_ips = self.state.get_active_ips()
            for ip in active_ips:
                self._check_ip(ip, mean, stddev, error_mean, error_stddev)

            # Check global traffic
            self._check_global(mean, stddev)

            time.sleep(1)