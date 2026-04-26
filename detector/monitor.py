"""
monitor.py - Continuously tails and parses the Nginx JSON access log.
Feeds parsed log entries into shared state for detection.
"""

import json
import time
import os
from datetime import datetime


def parse_log_line(line):
    """Parse a single JSON log line from Nginx."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return {
            "source_ip": data.get("source_ip", "-"),
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
            "method": data.get("method", "-"),
            "path": data.get("path", "-"),
            "status": int(data.get("status", 0)),
            "response_size": int(data.get("response_size", 0)),
        }
    except (json.JSONDecodeError, ValueError):
        return None


def tail_log(log_path, state, stop_event):
    """
    Continuously tail the Nginx log file line by line.
    Uses seek to track position — no rate-limiting libraries.
    Feeds each parsed entry into state for the detector.
    """
    # Wait for log file to exist
    while not stop_event.is_set():
        if os.path.exists(log_path):
            break
        print(f"[monitor] Waiting for log file: {log_path}")
        time.sleep(2)

    print(f"[monitor] Tailing log file: {log_path}")

    with open(log_path, "r") as f:
        # Seek to end of file on startup
        f.seek(0, 2)

        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            entry = parse_log_line(line)
            if entry:
                # Feed into shared state
                state.add_request(entry)