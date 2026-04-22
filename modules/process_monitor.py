"""
process_monitor.py — Process enumeration and parent-child anomaly detection.
Produces an annotated ASCII process tree with anomaly markers.
"""

import psutil
from modules.alert_engine import (
    Alert, AlertEngine,
    SEVERITY_SUSPICIOUS, CATEGORY_PARENT_CHILD,
)


class ProcessMonitor:
    """Enumerates running processes and detects suspicious parent-child relationships."""

    def enumerate_processes(self) -> list[dict]:
        """
        Capture a snapshot of all running processes.
        Returns a list of dicts: pid, ppid, name, exe, username, status, create_time.
        AccessDenied and NoSuchProcess exceptions are silently skipped.
        """
        processes = []
        attrs = ["pid", "ppid", "name", "exe", "username", "status", "create_time"]

        for proc in psutil.process_iter(attrs, ad_value=None):
            try:
                info = proc.info
                processes.append({
                    "pid":         info.get("pid"),
                    "ppid":        info.get("ppid"),
                    "name":        info.get("name") or "",
                    "exe":         info.get("exe") or "",
                    "username":    info.get("username") or "",
                    "status":      info.get("status") or "",
                    "create_time": info.get("create_time"),
                })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        return processes

    def build_process_tree(self, processes: list[dict]) -> dict:
        """
        Build a tree: { pid → { "info": {...}, "children": [child_pid, ...] } }
        """
        tree = {}
        for proc in processes:
            pid = proc["pid"]
            if pid is not None:
                tree[pid] = {"info": proc, "children": []}

        for proc in processes:
            ppid = proc.get("ppid")
            pid  = proc.get("pid")
            if ppid and ppid in tree and pid != ppid:
                tree[ppid]["children"].append(pid)

        return tree

    def detect_parent_child_anomalies(
        self, processes: list[dict], rules: dict, engine: AlertEngine
    ) -> set[int]:
        """
        Compare every (parent_name, child_name) pair against suspicious_parent_child rules.
        Fires HIGH alerts. Returns the set of anomalous child PIDs for tree annotation.
        """
        pid_to_name = {
            p["pid"]: p["name"].lower()
            for p in processes
            if p["pid"] is not None
        }

        # Build rule lookup: (parent_lower, child_lower) → rule dict
        rule_map = {
            (r["parent"].lower(), r["child"].lower()): r
            for r in rules.get("suspicious_parent_child", [])
        }

        anomalous_pids: set[int] = set()

        for proc in processes:
            child_name  = proc["name"].lower()
            ppid        = proc.get("ppid")
            parent_name = pid_to_name.get(ppid, "") if ppid else ""

            if not parent_name:
                continue

            key  = (parent_name, child_name)
            rule = rule_map.get(key)
            if rule:
                anomalous_pids.add(proc["pid"])
                engine.add(Alert(
                    severity=SEVERITY_SUSPICIOUS,
                    category=CATEGORY_PARENT_CHILD,
                    description=(
                        f"Suspicious parent-child: {parent_name} -> {proc['name']} "
                        f"| {rule.get('description', '')}"
                    ),
                    pid=proc["pid"],
                    process_name=proc["name"],
                    exe_path=proc["exe"],
                    mitre_id=rule.get("mitre_id"),
                    mitre_name=rule.get("mitre_name"),
                    mitre_tactic="Execution",
                    details={
                        "parent_pid":  ppid,
                        "parent_name": parent_name,
                        "child_pid":   proc["pid"],
                        "child_name":  proc["name"],
                        "rule":        rule.get("description", ""),
                    },
                ))

        return anomalous_pids

    def render_process_tree(
        self,
        tree: dict,
        anomalous_pids: set[int] = None,
        pid: int = None,
        indent: int = 0,
        is_last: bool = True,
        prefix: str = "",
    ) -> list[str]:
        """
        Recursively render the process tree as annotated ASCII art.
        Nodes with anomalous PIDs are marked with [!ALERT!].

        Example output:
            [4] System
            └─ [532] smss.exe
               └─ [620] csrss.exe
            [!ALERT!] └─ [1234] powershell.exe  ← winword.exe spawned this
        """
        if anomalous_pids is None:
            anomalous_pids = set()

        lines = []

        if pid is None:
            # Identify roots: processes whose parent is not in the tree
            all_pids = set(tree.keys())
            roots = [
                node_pid for node_pid, node in tree.items()
                if node["info"].get("ppid") not in all_pids
                or node["info"].get("ppid") == node_pid
            ]
            roots.sort()
            for i, root_pid in enumerate(roots):
                is_last_root = (i == len(roots) - 1)
                lines.extend(self.render_process_tree(
                    tree, anomalous_pids, root_pid, 0, is_last_root, ""
                ))
            return lines

        node = tree.get(pid)
        if not node:
            return lines

        info      = node["info"]
        children  = node["children"]
        connector = "└─ " if is_last else "├─ "
        branch    = prefix + (connector if indent > 0 else "")

        alert_tag = ""
        if pid in anomalous_pids:
            alert_tag = " << [!ALERT!]"

        user   = info.get("username") or "N/A"
        status = info.get("status") or ""
        exe    = info.get("exe") or ""

        line = (
            f"{branch}[{info['pid']}] {info['name']}"
            f"  (user: {user}, status: {status})"
            f"{alert_tag}"
        )
        if exe and alert_tag:
            line += f"\n{prefix}{'   ' if is_last else '│  '}    path: {exe}"

        lines.append(line)

        child_prefix = prefix + ("   " if is_last else "│  ")
        for i, child_pid in enumerate(sorted(children)):
            is_last_child = (i == len(children) - 1)
            lines.extend(self.render_process_tree(
                tree, anomalous_pids, child_pid, indent + 1, is_last_child, child_prefix
            ))

        return lines
