"""
response_engine.py — Automated incident response: terminate confirmed malicious processes.

Only kills HIGH-severity alerts in: BLACKLIST, HASH_MATCH, TYPOSQUAT, SUSPICIOUS_PATH.
Never touches PIDs <= 4 (kernel/System) or system-account processes (unless BLACKLIST).
Every action is logged via MonitorLogger regardless of outcome.
"""

import psutil
from modules.alert_engine import Alert, SEVERITY_HIGH


class ResponseEngine:
    """Automated process termination for confirmed HIGH-severity threats."""

    # Categories whose processes may be killed
    KILLABLE_CATEGORIES = frozenset({"BLACKLIST", "HASH_MATCH", "TYPOSQUAT", "SUSPICIOUS_PATH"})

    # PIDs that are never touched regardless of anything
    PROTECTED_PIDS = frozenset({0, 1, 2, 3, 4})

    # Accounts that own critical OS processes — only blocked for non-BLACKLIST categories
    PROTECTED_USERS = frozenset({
        "nt authority\\system",
        "system",
        "nt authority\\localservice",
        "nt authority\\networkservice",
    })

    def __init__(self, logger=None):
        self.logger = logger
        self.results: list[dict] = []

    # ── Public API ────────────────────────────────────────────────────────

    def get_killable_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """Return the subset of alerts that are candidates for termination."""
        return [
            a for a in alerts
            if a.severity == SEVERITY_HIGH
            and a.category in self.KILLABLE_CATEGORIES
            and a.pid is not None
        ]

    def kill_process(self, alert: Alert, dry_run: bool = False) -> dict:
        """
        Attempt to terminate the process referenced by alert.pid.
        Returns a result dict describing the outcome.
        """
        result = {
            "pid":          alert.pid,
            "name":         alert.process_name or "unknown",
            "exe":          alert.exe_path or "",
            "category":     alert.category,
            "severity":     alert.severity,
            "score":        alert.score,
            "dry_run":      dry_run,
            "success":      False,
            "still_exists": None,
            "error":        None,
        }

        protected, reason = self._is_protected(alert)
        if protected:
            result["error"] = reason
            self._log(f"KILL_SKIPPED (PID {alert.pid} / {alert.process_name}): {reason}")
            return result

        if dry_run:
            result["success"]      = True
            result["still_exists"] = None
            self._log(
                f"[DRY-RUN] Would kill PID {alert.pid} ({alert.process_name}) "
                f"— category: {alert.category}, score: {alert.score}/100"
            )
            return result

        # Live kill
        try:
            proc = psutil.Process(alert.pid)
            proc.kill()
            result["success"]      = True
            result["still_exists"] = psutil.pid_exists(alert.pid)
            self._log(
                f"KILL_SUCCESS PID {alert.pid} ({alert.process_name}) "
                f"— still_exists={result['still_exists']}",
                extra=result,
            )
        except psutil.NoSuchProcess:
            result["error"]        = "Process no longer exists (already terminated)"
            result["success"]      = True   # goal achieved either way
            result["still_exists"] = False
            self._log(f"KILL_ALREADY_GONE PID {alert.pid} ({alert.process_name})")
        except psutil.AccessDenied:
            result["error"]        = "Access denied — insufficient privileges (run as Administrator)"
            result["still_exists"] = psutil.pid_exists(alert.pid)
            self._log(
                f"KILL_ACCESS_DENIED PID {alert.pid} ({alert.process_name})",
                extra=result,
            )
        except (psutil.ZombieProcess, OSError) as exc:
            result["error"]        = str(exc)
            result["still_exists"] = psutil.pid_exists(alert.pid)
            self._log(
                f"KILL_ERROR PID {alert.pid} ({alert.process_name}): {exc}",
                extra=result,
            )

        self.results.append(result)
        return result

    def kill_high_alerts(
        self,
        alerts: list[Alert],
        dry_run: bool = False,
    ) -> list[dict]:
        """
        Iterate killable HIGH alerts and call kill_process() for each.
        Returns list of result dicts.
        """
        targets = self.get_killable_alerts(alerts)
        results = []
        for alert in targets:
            results.append(self.kill_process(alert, dry_run=dry_run))
        return results

    def summary(self, results: list[dict]) -> dict:
        """Aggregate kill results into a summary dict."""
        return {
            "attempted":    len(results),
            "succeeded":    sum(1 for r in results if r["success"]),
            "failed":       sum(1 for r in results if not r["success"]),
            "still_alive":  sum(1 for r in results if r.get("still_exists")),
            "dry_run":      any(r["dry_run"] for r in results),
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    def _is_protected(self, alert: Alert) -> tuple[bool, str]:
        """
        Returns (is_protected, reason_string).
        Only BLACKLIST-category alerts may kill system-owned processes.
        """
        if alert.pid is None:
            return True, "No PID on alert"

        if alert.pid in self.PROTECTED_PIDS:
            return True, f"PID {alert.pid} is a protected kernel/system PID"

        if not psutil.pid_exists(alert.pid):
            return True, f"PID {alert.pid} no longer exists"

        # For non-BLACKLIST categories, protect system account processes
        if alert.category != "BLACKLIST":
            try:
                owner = psutil.Process(alert.pid).username().lower()
                if owner in self.PROTECTED_USERS:
                    return (
                        True,
                        f"Process owned by protected account '{owner}' "
                        f"(use BLACKLIST category to override)",
                    )
            except psutil.AccessDenied:
                return True, "Cannot determine process owner (access denied)"
            except psutil.NoSuchProcess:
                return True, f"PID {alert.pid} vanished during protection check"

        return False, ""

    def _recheck_exists(self, pid: int) -> bool:
        return psutil.pid_exists(pid)

    def _log(self, message: str, extra: dict = None) -> None:
        if self.logger:
            self.logger.log_info(message, extra=extra or {})
