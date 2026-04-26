"""
notifier.py - Slack webhook notifications.
Sends alerts for: ban, unban, global anomaly.
Each alert includes condition, rate, baseline, timestamp, duration.
"""

import requests
import json
from datetime import datetime, timezone


class Notifier:
    def __init__(self, config):
        self.webhook_url = config["slack"]["webhook_url"]
        print("[notifier] Notifier initialized")

    def _send(self, message):
        """Send a message to Slack via webhook."""
        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps({"text": message}),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if response.status_code != 200:
                print(
                    f"[notifier] Slack error: "
                    f"{response.status_code} {response.text}"
                )
        except requests.exceptions.RequestException as e:
            print(f"[notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, ip, condition, rate, baseline_mean):
        """Send a Slack alert when an IP is banned."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = (
            f":rotating_light: *IP BAN ALERT*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate} req/60s\n"
            f"*Baseline Mean:* {baseline_mean:.3f} req/s\n"
            f"*Timestamp:* {timestamp}\n"
            f"*Action:* iptables DROP rule added"
        )
        self._send(message)
        print(f"[notifier] Ban alert sent for {ip}")

    def send_unban_alert(
        self, ip, duration, condition, rate, baseline_mean, next_duration
    ):
        """Send a Slack alert when an IP is unbanned."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = (
            f":white_check_mark: *IP UNBAN NOTIFICATION*\n"
            f"*IP:* `{ip}`\n"
            f"*Original Condition:* {condition}\n"
            f"*Original Rate:* {rate} req/60s\n"
            f"*Baseline Mean:* {baseline_mean:.3f} req/s\n"
            f"*Ban Duration:* {duration} min\n"
            f"*Next Ban Duration:* {next_duration}\n"
            f"*Timestamp:* {timestamp}\n"
            f"*Action:* iptables DROP rule removed"
        )
        self._send(message)
        print(f"[notifier] Unban alert sent for {ip}")

    def send_global_alert(self, condition, rate, baseline_mean):
        """Send a Slack alert for global traffic anomaly."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Current Global Rate:* {rate} req/60s\n"
            f"*Baseline Mean:* {baseline_mean:.3f} req/s\n"
            f"*Timestamp:* {timestamp}\n"
            f"*Action:* Monitoring — no IP-level block (global spike)"
        )
        self._send(message)
        print(f"[notifier] Global anomaly alert sent")

    def send_test_alert(self):
        """Send a test alert to verify webhook is working."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = (
            f":white_check_mark: *HNG Anomaly Detector Started*\n"
            f"*Timestamp:* {timestamp}\n"
            f"*Status:* All systems operational\n"
            f"*Monitoring:* Nginx access log"
        )
        self._send(message)
        print("[notifier] Test alert sent")