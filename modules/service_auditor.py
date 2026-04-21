"""
service_auditor.py — Windows service enumeration and anomaly detection.
Covers: suspicious paths, non-standard accounts, stealthy stopped services,
unquoted service paths (privilege escalation), and unsigned binaries.
"""

import re
import subprocess
from utils.helpers import normalize_path, is_suspicious_path, get_file_signature
from modules.alert_engine import (
    Alert, AlertEngine,
    SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    CATEGORY_SERVICE,
)

# MITRE reference for all service alerts
_SERVICE_MITRE = {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence / Privilege Escalation"}
# Unquoted service path is a classic privilege escalation technique
_UNQUOTED_MITRE = {"id": "T1574.009", "name": "Path Interception by Unquoted Path", "tactic": "Privilege Escalation"}


class ServiceAuditor:
    """Enumerates Windows services and flags suspicious configurations."""

    def enumerate_services(self) -> list[dict]:
        """
        Enumerate all Windows services via WMI (preferred) with an sc query fallback.
        Returns a list of service info dicts.
        """
        try:
            return self._enumerate_via_wmi()
        except Exception:
            pass
        try:
            return self._enumerate_via_sc()
        except Exception:
            return []

    def _enumerate_via_wmi(self) -> list[dict]:
        import wmi
        conn = wmi.WMI()
        services = []
        for svc in conn.Win32_Service():
            services.append({
                "name":         svc.Name        or "",
                "display_name": svc.DisplayName or "",
                "path":         svc.PathName    or "",
                "start_mode":   svc.StartMode   or "",
                "state":        svc.State       or "",
                "start_name":   svc.StartName   or "",
                "description":  svc.Description or "",
            })
        return services

    def _enumerate_via_sc(self) -> list[dict]:
        """Fallback: parse 'sc query type= all state= all' output."""
        result = subprocess.run(
            ["sc", "query", "type=", "all", "state=", "all"],
            capture_output=True, text=True, timeout=30,
        )
        services = []
        current: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if current:
                    services.append(current)
                current = {
                    "name": line.split(":", 1)[1].strip(),
                    "display_name": "", "path": "",
                    "start_mode": "", "state": "",
                    "start_name": "", "description": "",
                }
            elif line.startswith("DISPLAY_NAME:") and current:
                current["display_name"] = line.split(":", 1)[1].strip()
            elif "STATE" in line and current:
                m = re.search(r"STATE\s+:\s+\d+\s+(\w+)", line)
                if m:
                    current["state"] = m.group(1)
        if current:
            services.append(current)

        for svc in services:
            try:
                qc = subprocess.run(
                    ["sc", "qc", svc["name"]],
                    capture_output=True, text=True, timeout=10,
                )
                for qline in qc.stdout.splitlines():
                    qline = qline.strip()
                    if qline.startswith("BINARY_PATH_NAME"):
                        svc["path"] = qline.split(":", 1)[1].strip()
                    elif qline.startswith("START_TYPE"):
                        m = re.search(r"START_TYPE\s+:\s+\d+\s+(\w+)", qline)
                        if m:
                            svc["start_mode"] = m.group(1).title()
                    elif qline.startswith("SERVICE_START_NAME"):
                        svc["start_name"] = qline.split(":", 1)[1].strip()
            except Exception:
                pass

        return services

    # ── Audit ─────────────────────────────────────────────────────────────

    def audit_services(
        self,
        services: list[dict],
        rules: dict,
        engine: AlertEngine,
        verify_signatures: bool = False,
    ) -> None:
        """
        Analyze each service for suspicious indicators and add alerts to the engine.
        """
        suspicious_path_patterns = rules.get("suspicious_service_path_patterns", [])
        legitimate_accounts = [
            a.lower() for a in rules.get("legitimate_service_accounts", [])
        ]

        for svc in services:
            path       = svc.get("path", "")       or ""
            start_mode = svc.get("start_mode", "").lower()
            state      = svc.get("state", "").lower()
            start_name = svc.get("start_name", "").lower().strip()
            name       = svc.get("name", "")
            display    = svc.get("display_name", "")

            # Extract the actual binary path (strip arguments and quotes for analysis)
            binary_path = self._extract_binary_path(path)
            path_norm   = normalize_path(binary_path)

            # ── Check 1: Running from a suspicious directory ──────────────
            if binary_path and is_suspicious_path(binary_path, suspicious_path_patterns):
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_SERVICE,
                    description=f"Service '{name}' runs from a suspicious path: {binary_path}",
                    process_name=name,
                    exe_path=binary_path,
                    mitre_id=_SERVICE_MITRE["id"],
                    mitre_name=_SERVICE_MITRE["name"],
                    mitre_tactic=_SERVICE_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "path": path, "start_mode": svc.get("start_mode"),
                        "state": svc.get("state"), "start_name": svc.get("start_name"),
                        "reason": "Binary located in suspicious directory (Temp/AppData/Downloads)",
                    },
                ))

            # ── Check 2: Unquoted service path (privilege escalation) ─────
            # Only flag when the binary itself (not its arguments) contains spaces
            if self._is_unquoted_path(path) and " " in binary_path:
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_SERVICE,
                    description=f"Unquoted service path (privilege escalation risk): {name} -> {path}",
                    process_name=name,
                    exe_path=binary_path,
                    mitre_id=_UNQUOTED_MITRE["id"],
                    mitre_name=_UNQUOTED_MITRE["name"],
                    mitre_tactic=_UNQUOTED_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "raw_path": path,
                        "reason": "Path contains spaces but is not quoted - exploitable for privilege escalation",
                    },
                ))

            # ── Check 3: Unsigned binary (if signature verification enabled) ──
            if verify_signatures and binary_path:
                sig = get_file_signature(binary_path)
                if not sig.get("signed") and sig.get("status") not in ("FileNotFound", "CheckFailed", "Unknown"):
                    engine.add(Alert(
                        severity=SEVERITY_MEDIUM,
                        category=CATEGORY_SERVICE,
                        description=f"Service binary is unsigned or has invalid signature: {name}",
                        process_name=name,
                        exe_path=binary_path,
                        signed=False,
                        sign_subject=sig.get("subject", ""),
                        mitre_id=_SERVICE_MITRE["id"],
                        mitre_name=_SERVICE_MITRE["name"],
                        mitre_tactic=_SERVICE_MITRE["tactic"],
                        details={
                            "service_name":      name,
                            "display_name":      display,
                            "path":              binary_path,
                            "signature_status":  sig.get("status"),
                            "reason":            "Service binary failed Authenticode verification",
                        },
                    ))

            # ── Check 4: Auto-start with non-standard service account ─────
            if start_mode in ("auto", "automatic") and start_name:
                is_legit = any(start_name == acct for acct in legitimate_accounts)
                # Domain service accounts (user@domain or DOMAIN\user) are allowed
                if not is_legit and "\\" not in start_name and "@" not in start_name:
                    engine.add(Alert(
                        severity=SEVERITY_MEDIUM,
                        category=CATEGORY_SERVICE,
                        description=(
                            f"Auto-start service '{name}' runs under unusual account: "
                            f"'{svc.get('start_name')}'"
                        ),
                        process_name=name,
                        exe_path=binary_path,
                        mitre_id=_SERVICE_MITRE["id"],
                        mitre_name=_SERVICE_MITRE["name"],
                        mitre_tactic=_SERVICE_MITRE["tactic"],
                        details={
                            "service_name": name, "display_name": display,
                            "start_mode": svc.get("start_mode"),
                            "start_name": svc.get("start_name"),
                            "reason": "Non-standard account on auto-start service",
                        },
                    ))

            # ── Check 5: Auto-start but currently stopped (stealthy persistence) ──
            if start_mode in ("auto", "automatic") and state in ("stopped", "stop_pending"):
                engine.add(Alert(
                    severity=SEVERITY_LOW,
                    category=CATEGORY_SERVICE,
                    description=(
                        f"Auto-start service '{name}' is currently stopped "
                        f"(possible dormant persistence mechanism)"
                    ),
                    process_name=name,
                    exe_path=binary_path,
                    mitre_id=_SERVICE_MITRE["id"],
                    mitre_name=_SERVICE_MITRE["name"],
                    mitre_tactic=_SERVICE_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "start_mode": svc.get("start_mode"),
                        "state": svc.get("state"),
                        "reason": "Auto-start service found in stopped state",
                    },
                ))

            # ── Check 6: Non-standard path (not Windows / Program Files) ──
            name_lower = name.lower()
            suspicious_name_kws = ["temp", "update", "helper", "svc32", "svc64"]
            non_standard = path_norm and not any(
                loc in path_norm
                for loc in ["/windows/", "/program files/", "/program files (x86)/"]
            )
            if non_standard and path_norm and any(kw in name_lower for kw in suspicious_name_kws):
                engine.add(Alert(
                    severity=SEVERITY_MEDIUM,
                    category=CATEGORY_SERVICE,
                    description=f"Service '{name}' has generic name and non-standard path: {binary_path}",
                    process_name=name,
                    exe_path=binary_path,
                    mitre_id=_SERVICE_MITRE["id"],
                    mitre_name=_SERVICE_MITRE["name"],
                    mitre_tactic=_SERVICE_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "path": binary_path,
                        "reason": "Generic service name + non-standard binary path",
                    },
                ))

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_binary_path(raw_path: str) -> str:
        """
        Extract just the executable path from a service PathName string.
        Handles quoted paths (e.g. "C:\\foo bar\\svc.exe" /arg) and unquoted ones.
        """
        if not raw_path:
            return ""
        raw_path = raw_path.strip()
        if raw_path.startswith('"'):
            end = raw_path.find('"', 1)
            return raw_path[1:end] if end != -1 else raw_path[1:]
        # Take the token up to the first argument (starts with / or -)
        parts = raw_path.split()
        for i, part in enumerate(parts):
            if i > 0 and (part.startswith("/") or part.startswith("-")):
                return " ".join(parts[:i])
        return raw_path

    @staticmethod
    def _is_unquoted_path(raw_path: str) -> bool:
        """
        Return True if the path contains spaces and is not properly quoted.
        Standard Windows technique: svchost.exe paths with spaces that aren't
        quoted allow an attacker to plant C:\\Program.exe to hijack execution.
        """
        if not raw_path:
            return False
        raw_path = raw_path.strip()
        # If it starts with a quote it is properly quoted
        if raw_path.startswith('"'):
            return False
        # If path has spaces and contains a directory separator it's vulnerable
        # Exclude single-word executables and kernel drivers (e.g. just "System")
        if " " in raw_path and ("\\" in raw_path or "/" in raw_path):
            return True
        return False
