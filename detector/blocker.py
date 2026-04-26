"""
blocker.py - Manages iptables DROP rules for banned IPs.
Adds rules within 10 seconds of anomaly detection.
Tracks ban count per IP for backoff unban schedule.
"""

import subprocess
import threading
import time
from datetime import datetime


class Blocker:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.lock = threading.Lock()
        self.unban_schedule = config["blocking"]["unban_schedule"]
        print("[blocker] Blocker initialized")

    def _run_iptables(self, args):
        """Run an iptables command safely."""
        try:
            result = subprocess.run(
                ["iptables"] + args,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                print(f"[blocker] iptables error: {result.stderr.strip()}")
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("[blocker] iptables command timed out")
            return False
        except Exception as e:
            print(f"[blocker] iptables exception: {e}")
            return False

    def ban_ip(self, ip, condition, rate, baseline_mean):
        """
        Add iptables DROP rule for the given IP.
        Must complete within 10 seconds of detection.
        """
        with self.lock:
            if ip in self.state.banned_ips:
                return

            # Get ban count for backoff schedule
            ban_count = self.state.banned_ips.get(ip, {}).get("count", 0)
            duration = self._get_duration(ban_count)

            # Add iptables rule
            success = self._run_iptables([
                "-A", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ])

            if success:
                self.state.banned_ips[ip] = {
                    "banned_at": time.time(),
                    "count": ban_count + 1,
                    "condition": condition,
                    "rate": rate,
                    "baseline": baseline_mean,
                    "duration": duration,
                }
                duration_str = (
                    f"{duration} min" if duration > 0 else "permanent"
                )
                print(
                    f"[blocker] Banned {ip} — "
                    f"condition={condition} "
                    f"duration={duration_str}"
                )
            else:
                print(f"[blocker] Failed to ban {ip}")

    def unban_ip(self, ip):
        """Remove iptables DROP rule for the given IP."""
        with self.lock:
            success = self._run_iptables([
                "-D", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ])

            if success and ip in self.state.banned_ips:
                del self.state.banned_ips[ip]
                print(f"[blocker] Unbanned {ip}")
            return success

    def _get_duration(self, ban_count):
        """
        Return ban duration in minutes based on ban count.
        -1 means permanent.
        """
        schedule = self.unban_schedule
        if ban_count < len(schedule):
            return schedule[ban_count]
        return -1

    def get_banned_ips(self):
        """Return current banned IPs dict."""
        with self.lock:
            return dict(self.state.banned_ips)

    def is_banned(self, ip):
        """Check if an IP is currently banned."""
        with self.lock:
            return ip in self.state.banned_ips