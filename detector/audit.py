"""
audit.py - Structured audit logging.
Writes log entries for every ban, unban, and baseline recalculation.
Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""

import os
import threading
from datetime import datetime, timezone


class AuditLogger:
    def __init__(self, config):
        self.log_path = config["logging"]["audit_log"]
        self.lock = threading.Lock()

        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except PermissionError:
                # Fallback to local log if /var/log not writable
                self.log_path = "/tmp/detector-audit.log"
                print(
                    f"[audit] Cannot write to {config['logging']['audit_log']}, "
                    f"falling back to {self.log_path}"
                )

        print(f"[audit] AuditLogger initialized — log={self.log_path}")

    def _write(self, line):
        """Write a single line to the audit log."""
        with self.lock:
            try:
                with open(self.log_path, "a") as f:
                    f.write(line + "\n")
                    f.flush()
            except Exception as e:
                print(f"[audit] Failed to write log: {e}")

    def _timestamp(self):
        """Return current UTC timestamp string."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def log_ban(self, ip, condition, rate, baseline_mean):
        """Log a ban event."""
        line = (
            f"[{self._timestamp()}] BAN {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline_mean:.3f} | "
            f"duration=see_unban_schedule"
        )
        self._write(line)
        print(f"[audit] {line}")

    def log_unban(self, ip, condition, rate, baseline_mean, duration):
        """Log an unban event."""
        duration_str = f"{duration}min" if duration > 0 else "permanent"
        line = (
            f"[{self._timestamp()}] UNBAN {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline_mean:.3f} | "
            f"duration={duration_str}"
        )
        self._write(line)
        print(f"[audit] {line}")

    def log_baseline_recalc(self, mean, stddev, samples, hour):
        """Log a baseline recalculation event."""
        line = (
            f"[{self._timestamp()}] BASELINE_RECALC - | "
            f"condition=recalculation | "
            f"rate=mean={mean:.3f},stddev={stddev:.3f} | "
            f"baseline=samples={samples} | "
            f"duration=hour={hour}"
        )
        self._write(line)
        print(f"[audit] {line}")

    def log_event(self, action, ip, condition, rate, baseline_mean):
        """Log a generic event."""
        line = (
            f"[{self._timestamp()}] {action} {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline_mean:.3f} | "
            f"duration=N/A"
        )
        self._write(line)
        print(f"[audit] {line}")