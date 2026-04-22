"""
service_auditor.py — Windows service enumeration and anomaly detection.

Only flags genuine Windows service abuse techniques:
  - Binary in Temp / AppData / Downloads        (T1543.003 — persistence abuse)
  - Unquoted service path with spaces            (T1574.009 — privilege escalation)
  - Unsigned binary (optional, with --signatures)
  - Auto-start under non-standard account
  - Auto-start but stopped — ONLY when binary is outside trusted install dirs
    (avoids noisy alerts on commercial software like brave, edgeupdate, Intel)

Commercial applications (browsers, OEM drivers, update agents) that run as
auto-start services but are normally stopped do NOT indicate malicious
persistence. They are filtered out by path and by a known-good name list.
"""

import re
import subprocess
from utils.helpers import normalize_path, is_suspicious_path, get_file_signature
from modules.alert_engine import (
    Alert, AlertEngine,
    SEVERITY_MALICIOUS, SEVERITY_SUSPICIOUS,
    SEVERITY_HIGH, SEVERITY_MEDIUM,   # backward-compat aliases
    CATEGORY_SERVICE,
)

_SERVICE_MITRE  = {"id": "T1543.003", "name": "Windows Service",
                   "tactic": "Persistence / Privilege Escalation"}
_UNQUOTED_MITRE = {"id": "T1574.009", "name": "Path Interception by Unquoted Path",
                   "tactic": "Privilege Escalation"}

# ── Trusted installation directories ─────────────────────────────────────────
# Services whose binaries live here are standard OS or commercial software.
# Do not fire "auto-start but stopped" for these — it is normal behavior.
_TRUSTED_SERVICE_DIRS = frozenset({
    "/windows/",
    "/program files/",
    "/program files (x86)/",
    "/programdata/microsoft/",
})

# ── Known-good commercial / OEM service names ────────────────────────────────
# Auto-start-but-stopped is expected for these; flagging them is noise.
_COMMERCIAL_SERVICES = frozenset({
    # Browsers & update agents
    "brave", "bravebrowserupdate", "bravebrowserupdateservice",
    "edgeupdate", "edgeupdatem", "microsoftedgeupdate", "microsoftedgeupdatem",
    "googleupdater", "googleupdaterservice", "googleupdateservice",
    "gupdate", "gupdatem",
    # Intel OEM services
    "intelaudiosvc", "intelaudioservice", "inteltpm", "intelpowerservice",
    "intelcpheciservice", "lms",
    # Realtek / DTS audio
    "rtkaudiosvc", "rtkauduservice", "dtssvc", "dtsaudioservice",
    # xTend / other OEM utility services
    "xtendaposervice", "xtendutilityservice", "xtendsoftapservice",
    # Common Windows optional/deferred services (frequently stopped, not malicious)
    "mapsbroker", "sppsvc", "wmpnetworksvc",
    "diagnosticshub.standardcollector.service",
    # VMware / VirtualBox host tools
    "vmware-usbarbitrationservice", "vmware-usbarbitrator64",
    "vboxservice",
})


def _binary_in_trusted_dir(binary_path: str) -> bool:
    """Return True if the service binary lives in a standard install location."""
    if not binary_path:
        return False
    norm = normalize_path(binary_path)
    return any(d in norm for d in _TRUSTED_SERVICE_DIRS)


class ServiceAuditor:
    """Enumerates Windows services and flags genuinely suspicious configurations."""

    def enumerate_services(self) -> list[dict]:
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

    # ── Audit ─────────────────────────────────────────────────────────────────

    def audit_services(
        self,
        services: list[dict],
        rules: dict,
        engine: AlertEngine,
        verify_signatures: bool = False,
    ) -> None:
        """
        Analyse each service for real Windows service abuse indicators.
        Commercial software services in trusted install paths are exempted
        from low-signal checks to prevent analyst alert fatigue.
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
            name_lower = name.lower()

            binary_path = self._extract_binary_path(path)
            path_norm   = normalize_path(binary_path)
            in_trusted  = _binary_in_trusted_dir(binary_path)

            # ── Check 1: Binary in a suspicious directory ─────────────────────
            # High-confidence: legitimate services never run from Temp/Downloads.
            if binary_path and is_suspicious_path(binary_path, suspicious_path_patterns):
                engine.add(Alert(
                    severity=SEVERITY_MALICIOUS,
                    category=CATEGORY_SERVICE,
                    description=(
                        f"Service '{name}' binary is in a suspicious "
                        f"directory: {binary_path}"
                    ),
                    process_name=name, exe_path=binary_path,
                    mitre_id=_SERVICE_MITRE["id"],
                    mitre_name=_SERVICE_MITRE["name"],
                    mitre_tactic=_SERVICE_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "path": path, "start_mode": svc.get("start_mode"),
                        "state": svc.get("state"),
                        "reason": "Binary in Temp/AppData/Downloads — classic persistence abuse",
                    },
                ))

            # ── Check 2: Unquoted service path (privilege escalation) ─────────
            # T1574.009 — attacker can plant C:\Program.exe to hijack execution.
            if self._is_unquoted_path(path) and " " in binary_path:
                engine.add(Alert(
                    severity=SEVERITY_MALICIOUS,
                    category=CATEGORY_SERVICE,
                    description=(
                        f"Unquoted service path (privilege escalation): "
                        f"{name} -> {path}"
                    ),
                    process_name=name, exe_path=binary_path,
                    mitre_id=_UNQUOTED_MITRE["id"],
                    mitre_name=_UNQUOTED_MITRE["name"],
                    mitre_tactic=_UNQUOTED_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "raw_path": path,
                        "reason": "Unquoted path with spaces — exploitable for privilege escalation",
                    },
                ))

            # ── Check 3: Unsigned binary (requires --signatures flag) ─────────
            if verify_signatures and binary_path:
                sig = get_file_signature(binary_path)
                if not sig.get("signed") and sig.get("status") not in (
                    "FileNotFound", "CheckFailed", "Unknown"
                ):
                    engine.add(Alert(
                        severity=SEVERITY_SUSPICIOUS,
                        category=CATEGORY_SERVICE,
                        description=(
                            f"Service binary unsigned / invalid signature: {name}"
                        ),
                        process_name=name, exe_path=binary_path,
                        signed=False, sign_subject=sig.get("subject", ""),
                        mitre_id=_SERVICE_MITRE["id"],
                        mitre_name=_SERVICE_MITRE["name"],
                        mitre_tactic=_SERVICE_MITRE["tactic"],
                        details={
                            "service_name":     name,
                            "display_name":     display,
                            "path":             binary_path,
                            "signature_status": sig.get("status"),
                            "reason":           "Failed Authenticode verification",
                        },
                    ))

            # ── Check 4: Auto-start under a non-standard service account ──────
            # Skip domain accounts (DOMAIN\user or user@domain) — those are legit.
            if start_mode in ("auto", "automatic") and start_name:
                is_legit = any(start_name == acct for acct in legitimate_accounts)
                if not is_legit and "\\" not in start_name and "@" not in start_name:
                    engine.add(Alert(
                        severity=SEVERITY_SUSPICIOUS,
                        category=CATEGORY_SERVICE,
                        description=(
                            f"Auto-start service '{name}' runs under "
                            f"non-standard account: '{svc.get('start_name')}'"
                        ),
                        process_name=name, exe_path=binary_path,
                        mitre_id=_SERVICE_MITRE["id"],
                        mitre_name=_SERVICE_MITRE["name"],
                        mitre_tactic=_SERVICE_MITRE["tactic"],
                        details={
                            "service_name": name, "display_name": display,
                            "start_mode": svc.get("start_mode"),
                            "start_name": svc.get("start_name"),
                            "reason": "Unusual account on auto-start service",
                        },
                    ))

            # ── Check 5: Auto-start but currently stopped ─────────────────────
            # Indicates dormant persistence — but ONLY flag when the service is
            # NOT commercial software (browser updaters, OEM drivers, etc. are
            # frequently stopped and that is perfectly normal behaviour).
            if start_mode in ("auto", "automatic") and state in ("stopped", "stop_pending"):
                is_commercial = (
                    name_lower in _COMMERCIAL_SERVICES
                    or in_trusted
                )
                if not is_commercial:
                    engine.add(Alert(
                        severity=SEVERITY_SUSPICIOUS,
                        category=CATEGORY_SERVICE,
                        description=(
                            f"Non-commercial auto-start service '{name}' is stopped "
                            f"(possible dormant persistence)"
                        ),
                        process_name=name, exe_path=binary_path,
                        mitre_id=_SERVICE_MITRE["id"],
                        mitre_name=_SERVICE_MITRE["name"],
                        mitre_tactic=_SERVICE_MITRE["tactic"],
                        details={
                            "service_name": name, "display_name": display,
                            "start_mode": svc.get("start_mode"),
                            "state": svc.get("state"),
                            "binary_path": binary_path,
                            "reason": "Auto-start service in stopped state outside standard dirs",
                        },
                    ))

            # ── Check 6: Generic name + non-standard install path ─────────────
            suspicious_name_kws = ["temp", "helper", "svc32", "svc64", "update32"]
            non_standard = path_norm and not in_trusted
            if non_standard and any(kw in name_lower for kw in suspicious_name_kws):
                engine.add(Alert(
                    severity=SEVERITY_SUSPICIOUS,
                    category=CATEGORY_SERVICE,
                    description=(
                        f"Service '{name}' has generic name and "
                        f"non-standard binary path: {binary_path}"
                    ),
                    process_name=name, exe_path=binary_path,
                    mitre_id=_SERVICE_MITRE["id"],
                    mitre_name=_SERVICE_MITRE["name"],
                    mitre_tactic=_SERVICE_MITRE["tactic"],
                    details={
                        "service_name": name, "display_name": display,
                        "path": binary_path,
                        "reason": "Generic service name + non-standard binary path",
                    },
                ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_binary_path(raw_path: str) -> str:
        if not raw_path:
            return ""
        raw_path = raw_path.strip()
        if raw_path.startswith('"'):
            end = raw_path.find('"', 1)
            return raw_path[1:end] if end != -1 else raw_path[1:]
        parts = raw_path.split()
        for i, part in enumerate(parts):
            if i > 0 and (part.startswith("/") or part.startswith("-")):
                return " ".join(parts[:i])
        return raw_path

    @staticmethod
    def _is_unquoted_path(raw_path: str) -> bool:
        if not raw_path:
            return False
        raw_path = raw_path.strip()
        if raw_path.startswith('"'):
            return False
        return " " in raw_path and ("\\" in raw_path or "/" in raw_path)
