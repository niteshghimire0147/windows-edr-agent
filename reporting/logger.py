"""
logger.py — JSON-Lines structured logging for the monitoring agent.
"""

import json
import os
from utils.helpers import timestamp_now, timestamp_for_filename
from modules.alert_engine import Alert


class MonitorLogger:
    """
    Writes timestamped structured log entries (JSON Lines format) to a .jsonl file.
    Each call to log_alert() or log_info() appends exactly one JSON object per line.
    """

    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        filename = f"monitor_{timestamp_for_filename()}.jsonl"
        self.log_path = os.path.join(log_dir, filename)
        self._file = open(self.log_path, "a", encoding="utf-8")
        self.log_info("MonitorLogger initialized", extra={"log_file": self.log_path})

    def log_alert(self, alert: Alert) -> None:
        """Append an alert as a single JSON line."""
        entry = {"type": "ALERT", **alert.to_dict()}
        self._write(entry)

    def log_info(self, message: str, extra: dict = None) -> None:
        """Append an informational message as a single JSON line."""
        entry = {
            "type":      "INFO",
            "timestamp": timestamp_now(),
            "message":   message,
        }
        if extra:
            entry.update(extra)
        self._write(entry)

    def _write(self, entry: dict) -> None:
        self._file.write(json.dumps(entry, default=str) + "\n")
        self._file.flush()

    def close(self) -> None:
        """Flush and close the log file."""
        self.log_info("MonitorLogger closed")
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
