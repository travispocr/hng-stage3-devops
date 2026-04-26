"""
main.py - Entry point for the HNG Anomaly Detection Engine.
Starts all threads: monitor, baseline, detector, unbanner, dashboard.
Handles graceful shutdown on SIGTERM/SIGINT.
"""

import threading
import signal
import sys
import time
import yaml
import os


def load_config(path="config.yaml"):
    """Load configuration from YAML file."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    print("=" * 60)
    print(" HNG Anomaly Detection Engine")
    print(" Starting up...")
    print("=" * 60)

    # Load config
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    config = load_config(config_path)
    print(f"[main] Config loaded from {config_path}")

    # Import all components
    from monitor import tail_log
    from baseline import BaselineManager
    from detector import SharedState, AnomalyDetector
    from blocker import Blocker
    from unbanner import Unbanner
    from notifier import Notifier
    from audit import AuditLogger
    from dashboard import Dashboard

    # Initialize shared state
    state = SharedState(config)

    # Initialize components
    audit = AuditLogger(config)
    notifier = Notifier(config)
    baseline = BaselineManager(config)
    blocker = Blocker(config, state)
    unbanner = Unbanner(config, state, blocker, notifier, audit)
    detector = AnomalyDetector(
        config, state, baseline, blocker, notifier, audit
    )
    dashboard = Dashboard(config, state, baseline)

    # Stop event for graceful shutdown
    stop_event = threading.Event()

    # Define all threads
    threads = [
        threading.Thread(
            target=tail_log,
            args=(config["logging"]["nginx_log"], state, stop_event),
            name="monitor",
            daemon=True,
        ),
        threading.Thread(
            target=baseline.run,
            args=(stop_event,),
            name="baseline",
            daemon=True,
        ),
        threading.Thread(
            target=detector.run,
            args=(stop_event,),
            name="detector",
            daemon=True,
        ),
        threading.Thread(
            target=unbanner.run,
            args=(stop_event,),
            name="unbanner",
            daemon=True,
        ),
        threading.Thread(
            target=dashboard.run,
            args=(stop_event,),
            name="dashboard",
            daemon=True,
        ),
    ]

    # Graceful shutdown handler
    def shutdown(signum, frame):
        print("\n[main] Shutdown signal received — stopping all threads...")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Start all threads
    for t in threads:
        t.start()
        print(f"[main] Started thread: {t.name}")

    # Send startup Slack notification
    try:
        notifier.send_test_alert()
    except Exception as e:
        print(f"[main] Could not send startup alert: {e}")

    print("=" * 60)
    print(" All systems running!")
    print(f" Dashboard: http://0.0.0.0:{config['dashboard']['port']}")
    print(f" Monitoring: {config['logging']['nginx_log']}")
    print("=" * 60)

    # Keep main thread alive
    while not stop_event.is_set():
        time.sleep(1)


if __name__ == "__main__":
    main()