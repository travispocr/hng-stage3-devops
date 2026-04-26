"""
baseline.py - Rolling 30-minute baseline computation.
Tracks per-second request counts in a deque.
Recalculates mean and stddev every 60 seconds.
Maintains per-hour slots, prefers current hour when enough data exists.
"""

import time
import math
import threading
from collections import deque
from datetime import datetime


class BaselineManager:
    def __init__(self, config):
        self.window_minutes = config["detection"]["baseline_window_minutes"]
        self.recalc_seconds = config["detection"]["baseline_recalc_seconds"]
        self.min_requests = config["detection"]["min_requests_for_baseline"]

        # Rolling window of (timestamp, count) tuples — 30 min of per-second counts
        self.window = deque()
        self.lock = threading.Lock()

        # Per-hour baseline slots: {hour: {"mean": x, "stddev": y, "samples": n}}
        self.hourly_slots = {}

        # Current effective baseline
        self.effective_mean = 1.0   # Floor value — never hardcoded as final
        self.effective_stddev = 1.0
        self.last_recalc = 0

        # Error rate baseline
        self.error_window = deque()
        self.effective_error_mean = 0.1
        self.effective_error_stddev = 0.1

        print("[baseline] BaselineManager initialized")

    def add_second_count(self, count, error_count=0):
        """Add a per-second request count to the rolling window."""
        now = time.time()
        cutoff = now - (self.window_minutes * 60)

        with self.lock:
            self.window.append((now, count))
            self.error_window.append((now, error_count))

            # Evict entries older than window
            while self.window and self.window[0][0] < cutoff:
                self.window.popleft()
            while self.error_window and self.error_window[0][0] < cutoff:
                self.error_window.popleft()

    def _compute_stats(self, values):
        """Compute mean and stddev from a list of values."""
        if not values:
            return 1.0, 1.0
        n = len(values)
        mean = sum(values) / n
        if n < 2:
            return mean, 1.0
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        stddev = math.sqrt(variance)
        return mean, max(stddev, 0.1)  # Floor stddev at 0.1

    def recalculate(self):
        """
        Recalculate baseline from rolling window.
        Store result in current hour slot.
        Prefer current hour slot if it has enough data.
        """
        now = time.time()
        if now - self.last_recalc < self.recalc_seconds:
            return

        with self.lock:
            counts = [c for _, c in self.window]
            error_counts = [c for _, c in self.error_window]

        if len(counts) < self.min_requests:
            print(f"[baseline] Not enough data yet ({len(counts)} samples), using floor values")
            self.last_recalc = now
            return

        mean, stddev = self._compute_stats(counts)
        error_mean, error_stddev = self._compute_stats(error_counts)

        # Store in hourly slot
        hour = datetime.utcnow().hour
        self.hourly_slots[hour] = {
            "mean": mean,
            "stddev": stddev,
            "samples": len(counts),
            "timestamp": now,
        }

        # Use current hour slot as effective baseline
        self.effective_mean = mean
        self.effective_stddev = stddev
        self.effective_error_mean = error_mean
        self.effective_error_stddev = error_stddev
        self.last_recalc = now

        print(
            f"[baseline] Recalculated — hour={hour} "
            f"mean={mean:.3f} stddev={stddev:.3f} "
            f"samples={len(counts)}"
        )

    def get_baseline(self):
        """Return current effective mean and stddev."""
        return self.effective_mean, self.effective_stddev

    def get_error_baseline(self):
        """Return current effective error mean and stddev."""
        return self.effective_error_mean, self.effective_error_stddev

    def get_hourly_slots(self):
        """Return all hourly slots for dashboard display."""
        with self.lock:
            return dict(self.hourly_slots)

    def run(self, stop_event):
        """Continuously recalculate baseline every recalc_seconds."""
        print("[baseline] Baseline recalculation thread started")
        while not stop_event.is_set():
            self.recalculate()
            time.sleep(10)