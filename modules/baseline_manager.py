"""
baseline_manager.py — System state snapshot and drift detection.

First run: save a baseline (processes + services) to baseline/baseline.json.
Later runs: compare current state against the saved baseline and surface
            new, missing, or changed entries as diffs for alert injection.
"""

import json
import os
import socket

from utils.helpers import timestamp_now


class BaselineManager:
    """Save and compare system snapshots for drift-based detection."""

    DEFAULT_PATH = "baseline/baseline.json"

    # Service fields compared for tampering detection
    WATCHED_SERVICE_FIELDS = ("path", "start_mode", "start_name")

    def __init__(self, baseline_path: str = None):
        self.baseline_path = baseline_path or self.DEFAULT_PATH

    # ── Process key ───────────────────────────────────────────────────────
    @staticmethod
    def _proc_key(proc: dict) -> str:
        """
        Unique key per process: name + exe path (both lowercased).
        A renamed or relocated binary produces a different key even if the
        process name is unchanged.
        """
        name = (proc.get("name") or "").lower()
        exe  = (proc.get("exe")  or "").lower()
        return f"{name}|{exe}"

    @staticmethod
    def _svc_key(svc: dict) -> str:
        return (svc.get("name") or "").lower()

    # ── Save ──────────────────────────────────────────────────────────────

    def save(
        self,
        processes: list[dict],
        services: list[dict],
        path: str = None,
    ) -> str:
        """
        Serialize a snapshot of current processes and services to disk.
        Creates the directory if it does not exist.
        Returns the absolute path of the written file.
        """
        path = path or self.baseline_path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

        proc_map = {}
        for p in processes:
            key = self._proc_key(p)
            proc_map[key] = {
                "name":     p.get("name") or "",
                "exe":      p.get("exe")  or "",
                "username": p.get("username") or "",
                "status":   p.get("status") or "",
            }

        svc_map = {}
        for s in services:
            key = self._svc_key(s)
            svc_map[key] = {
                "name":         s.get("name")         or "",
                "display_name": s.get("display_name") or "",
                "path":         s.get("path")         or "",
                "start_mode":   s.get("start_mode")   or "",
                "state":        s.get("state")        or "",
                "start_name":   s.get("start_name")   or "",
            }

        data = {
            "metadata": {
                "created_at":    timestamp_now(),
                "hostname":      socket.gethostname(),
                "agent_version": "3.0",
                "process_count": len(proc_map),
                "service_count": len(svc_map),
            },
            "processes": proc_map,
            "services":  svc_map,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return os.path.abspath(path)

    # ── Load ──────────────────────────────────────────────────────────────

    def load(self, path: str = None) -> dict | None:
        """
        Load a saved baseline.
        Returns the parsed dict, or None if the file does not exist.
        Raises json.JSONDecodeError if the file is present but corrupt.
        """
        path = path or self.baseline_path
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ── Compare ───────────────────────────────────────────────────────────

    def compare_processes(
        self,
        current: list[dict],
        baseline_data: dict,
    ) -> dict:
        """
        Find processes that are new (not in baseline) or missing (in baseline
        but no longer running).

        Returns:
            {
                "new":     [proc_dict, ...],
                "missing": [{"key": str, "name": str, "exe": str}, ...],
            }
        """
        baseline_procs: dict = baseline_data.get("processes", {})

        current_keys: dict[str, dict] = {
            self._proc_key(p): p for p in current
        }

        new_procs = [
            proc for key, proc in current_keys.items()
            if key not in baseline_procs
        ]

        missing_procs = [
            {
                "key":  key,
                "name": info.get("name", ""),
                "exe":  info.get("exe",  ""),
            }
            for key, info in baseline_procs.items()
            if key not in current_keys
        ]

        return {"new": new_procs, "missing": missing_procs}

    def compare_services(
        self,
        current: list[dict],
        baseline_data: dict,
    ) -> dict:
        """
        Find services that are new, missing, or have had key fields changed.

        Changed detection covers: path, start_mode, start_name.
        Comparison is case-insensitive (Windows paths).

        Returns:
            {
                "new":     [svc_dict, ...],
                "missing": [{"name": str, "display_name": str}, ...],
                "changed": [
                    {
                        "name":         str,
                        "display_name": str,
                        "field":        str,
                        "old":          str,
                        "new":          str,
                    },
                    ...
                ],
            }
        """
        baseline_svcs: dict = baseline_data.get("services", {})

        current_map: dict[str, dict] = {
            self._svc_key(s): s for s in current
        }

        new_svcs = [
            svc for key, svc in current_map.items()
            if key not in baseline_svcs
        ]

        missing_svcs = [
            {
                "name":         info.get("name", ""),
                "display_name": info.get("display_name", ""),
            }
            for key, info in baseline_svcs.items()
            if key not in current_map
        ]

        changed_svcs = []
        for key, cur_svc in current_map.items():
            if key not in baseline_svcs:
                continue
            base_svc = baseline_svcs[key]
            for field in self.WATCHED_SERVICE_FIELDS:
                old_val = (base_svc.get(field) or "").lower()
                new_val = (cur_svc.get(field)  or "").lower()
                if old_val != new_val:
                    changed_svcs.append({
                        "name":         cur_svc.get("name", ""),
                        "display_name": cur_svc.get("display_name", ""),
                        "field":        field,
                        "old":          base_svc.get(field, ""),
                        "new":          cur_svc.get(field, ""),
                    })

        return {"new": new_svcs, "missing": missing_svcs, "changed": changed_svcs}

    def compare(
        self,
        current_processes: list[dict],
        current_services: list[dict],
        path: str = None,
    ) -> list[dict]:
        """
        Load the saved baseline and return a flat list of drift entries.
        Each entry is a dict with at least {"kind": "process"|"service", "change": "new"|"missing"|"changed", ...}.
        Returns an empty list if no baseline file exists.
        """
        baseline_data = self.load(path)
        if baseline_data is None:
            return []

        proc_diff = self.compare_processes(current_processes, baseline_data)
        svc_diff  = self.compare_services(current_services,  baseline_data)

        results: list[dict] = []
        for p in proc_diff.get("new", []):
            results.append({"kind": "process", "change": "new", **p})
        for p in proc_diff.get("missing", []):
            results.append({"kind": "process", "change": "missing", **p})
        for s in svc_diff.get("new", []):
            results.append({"kind": "service", "change": "new", **s})
        for s in svc_diff.get("missing", []):
            results.append({"kind": "service", "change": "missing", **s})
        for s in svc_diff.get("changed", []):
            results.append({"kind": "service", "change": "changed", **s})
        return results
