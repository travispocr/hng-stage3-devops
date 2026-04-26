"""
unbanner.py - Automatic unban scheduler with backoff.
Unban schedule: 10 min → 30 min → 2 hours → permanent.
Sends Slack notification on every unban.
"""

import time
import threading
from datetime import datetime


class Unbanner:
    def __init__(self, config, state, blocker, notifier, audit):
        self.config = config
        self.state = state
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit
        self.lock = threading.Lock()
        print("[unbanner] Unbanner initialized")

    def _check_unbans(self):
        """
        Check all banned IPs and unban those whose duration has expired.
        Permanent bans (duration=-1) are never automatically unbanned.
        """
        now = time.time()

        # Get snapshot to avoid modifying dict during iteration
        with self.lock:
            banned_snapshot = dict(self.state.banned_ips)

        for ip, info in banned_snapshot.items():
            duration = info.get("duration", -1)

            # Permanent ban — never unban
            if duration == -1:
                continue

            banned_at = info.get("banned_at", now)
            duration_seconds = duration * 60
            elapsed = now - banned_at

            if elapsed >= duration_seconds:
                print(f"[unbanner] Unbanning {ip} after {duration} min")

                # Determine next ban duration for notification
                ban_count = info.get("count", 1)
                schedule = self.config["blocking"]["unban_schedule"]
                next_duration = (
                    schedule[ban_count]
                    if ban_count < len(schedule)
                    else -1
                )
                next_str = (
                    f"{next_duration} min"
                    if next_duration > 0
                    else "permanent"
                )

                # Unban
                success = self.blocker.unban_ip(ip)

                if success:
                    # Send Slack notification
                    self.notifier.send_unban_alert(
                        ip,
                        duration,
                        info.get("condition", "unknown"),
                        info.get("rate", 0),
                        info.get("baseline", 0),
                        next_str,
                    )

                    # Audit log
                    self.audit.log_unban(
                        ip,
                        info.get("condition", "unknown"),
                        info.get("rate", 0),
                        info.get("baseline", 0),
                        duration,
                    )

    def run(self, stop_event):
        """Continuously check for IPs to unban every 30 seconds."""
        print("[unbanner] Unban scheduler thread started")
        while not stop_event.is_set():
            try:
                self._check_unbans()
            except Exception as e:
                print(f"[unbanner] Error during unban check: {e}")
            time.sleep(30)