"""
report_generator.py — Human-readable (.txt) and machine-readable (.json) report generation.
Includes MITRE ATT&CK coverage section and structured executive summary.
"""

import json
import os
import socket
import datetime
from tabulate import tabulate
from utils.helpers import timestamp_for_filename
from modules.alert_engine import Alert, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

SEPARATOR = "=" * 72
THIN_SEP  = "-" * 72

# ── Report quality threshold ──────────────────────────────────────────────────
# Alerts below this score are pure inventory observations (unlisted process,
# no behavioral signal).  They are counted in summary statistics but excluded
# from detailed report sections to keep output analyst-readable.
# Score 20 = base UNKNOWN with no risk modifiers.
# Score 25 = UNKNOWN with at least one elevating signal (system account, etc.).
# Tune upward (e.g. 30) for even quieter reports on busy systems.
MIN_REPORT_SCORE: int = 25


class ReportGenerator:
    """
    Generates two output files from collected alerts:
      reports/report_YYYYMMDD_HHMMSS.txt   — human-readable tabulated report
      reports/report_YYYYMMDD_HHMMSS.json  — structured machine-readable report
    """

    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def generate(self, alerts: list[Alert], stats: dict) -> tuple[str, str]:
        """
        Write both report files. Returns (txt_path, json_path).

        Only alerts at or above MIN_REPORT_SCORE appear in detailed report
        sections.  Summary statistics (passed via `stats`) are computed over
        ALL alerts by the engine and remain accurate regardless of this filter.
        """
        ts        = timestamp_for_filename()
        txt_path  = os.path.join(self.report_dir, f"report_{ts}.txt")
        json_path = os.path.join(self.report_dir, f"report_{ts}.json")

        # Threshold filter: drop pure inventory noise from report output
        reportable = [a for a in alerts if a.score >= MIN_REPORT_SCORE]

        with open(txt_path,  "w", encoding="utf-8") as f:
            f.write(self._build_text_report(reportable, stats))

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self._build_json_report(reportable, stats), f, indent=2, default=str)

        return txt_path, json_path

    # ──────────────────────────────────────────────────────────────────────
    # Text report
    # ──────────────────────────────────────────────────────────────────────

    def _build_text_report(self, alerts: list[Alert], stats: dict) -> str:
        now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = socket.gethostname()
        lines    = []

        # ── Header ────────────────────────────────────────────────────────
        lines += [
            SEPARATOR,
            "    WINDOWS SERVICE & PROCESS MONITORING AGENT",
            "    THREAT DETECTION REPORT",
            SEPARATOR,
            f"  Generated : {now}",
            f"  Hostname  : {hostname}",
            f"  Total Alerts : {stats.get('total', 0)}",
            SEPARATOR,
        ]

        # ── Executive Summary ─────────────────────────────────────────────
        lines += ["", "[ EXECUTIVE SUMMARY ]", THIN_SEP]
        by_sev = stats.get("by_severity", {})
        high   = by_sev.get(SEVERITY_HIGH, 0)
        medium = by_sev.get(SEVERITY_MEDIUM, 0)
        low    = by_sev.get(SEVERITY_LOW, 0)
        score  = stats.get("score", {})

        risk_label = (
            "CRITICAL" if high >= 5 else
            "HIGH"     if high >= 2 else
            "ELEVATED" if medium >= 5 else
            "MODERATE" if medium >= 1 else
            "LOW"
        )
        lines.append(f"  Overall Risk Level : {risk_label}")
        lines.append(f"  Max Alert Score    : {score.get('max', 0)}/100")
        lines.append(f"  Avg Alert Score    : {score.get('average', 0)}/100")
        lines.append("")

        sev_rows = [
            ["HIGH",   high,   "▓" * min(high,   20)],
            ["MEDIUM", medium, "▓" * min(medium, 20)],
            ["LOW",    low,    "▓" * min(low,    20)],
        ]
        lines.append(tabulate(sev_rows, headers=["Severity", "Count", "Bar"], tablefmt="simple"))

        # ── Category breakdown ────────────────────────────────────────────
        lines += ["", "[ DETECTION CATEGORY BREAKDOWN ]", THIN_SEP]
        by_cat  = stats.get("by_category", {})
        cat_rows = [[cat, cnt] for cat, cnt in by_cat.items() if cnt > 0]
        lines.append(
            tabulate(cat_rows, headers=["Category", "Count"], tablefmt="simple")
            if cat_rows else "  No alerts recorded."
        )

        # ── Top 10 highest-scoring alerts ─────────────────────────────────
        top10 = sorted(alerts, key=lambda a: a.score, reverse=True)[:10]
        lines += ["", SEPARATOR, f"[ TOP ALERTS BY RISK SCORE ]", SEPARATOR]
        if top10:
            top_rows = [
                [
                    a.score,
                    a.severity,
                    a.confidence,
                    a.category,
                    a.pid or "N/A",
                    a.process_name or "N/A",
                    (a.description[:50] + "...") if len(a.description) > 53 else a.description,
                ]
                for a in top10
            ]
            lines.append(tabulate(
                top_rows,
                headers=["Score", "Severity", "Confidence", "Category", "PID", "Process", "Description"],
                tablefmt="simple",
            ))
        else:
            lines.append("  None.")

        # ── Per-severity alert tables ──────────────────────────────────────
        for sev_label in [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
            sev_alerts = [a for a in alerts if a.severity == sev_label]
            lines += [
                "", SEPARATOR,
                f"[ {sev_label} SEVERITY ALERTS ]  ({len(sev_alerts)} found)",
                SEPARATOR,
            ]
            if sev_alerts:
                lines.append(self._format_alert_table(sev_alerts))
            else:
                lines.append("  None.")

        # ── MITRE ATT&CK Coverage ─────────────────────────────────────────
        lines += ["", SEPARATOR, "[ MITRE ATT&CK COVERAGE ]", SEPARATOR]
        mitre_seen: dict[str, dict] = {}
        for a in alerts:
            if a.mitre_id and a.mitre_id not in mitre_seen:
                mitre_seen[a.mitre_id] = {
                    "id":     a.mitre_id,
                    "name":   a.mitre_name   or "",
                    "tactic": a.mitre_tactic or "",
                    "count":  0,
                }
            if a.mitre_id:
                mitre_seen[a.mitre_id]["count"] += 1

        if mitre_seen:
            mitre_rows = [
                [v["id"], v["name"], v["tactic"], v["count"]]
                for v in sorted(mitre_seen.values(), key=lambda x: x["count"], reverse=True)
            ]
            lines.append(tabulate(
                mitre_rows,
                headers=["Technique ID", "Technique Name", "Tactic", "Alert Count"],
                tablefmt="simple",
            ))
            lines.append("")
            lines.append(
                "  Reference: https://attack.mitre.org/techniques/"
            )
        else:
            lines.append("  No MITRE-mapped alerts.")

        # ── Detailed findings per category ────────────────────────────────
        lines += ["", SEPARATOR, "[ DETAILED FINDINGS ]", SEPARATOR]

        category_labels = {
            "PARENT_CHILD":     "Parent-Child Relationship Anomalies",
            "BLACKLIST":        "Blacklisted Processes",
            "HASH_MATCH":       "Known-Bad Hash Matches",
            "TYPOSQUAT":        "Typosquatting / Name Masquerading",
            "SUSPICIOUS_PATH":  "Processes in Suspicious Paths",
            "SERVICE":          "Suspicious Service Configurations",
            "INCOMPLETE_DATA":  "No Executable Path (Access-Denied / Hollow Suspect)",
            "UNAUTHORIZED":     "Confirmed Injection Suspects (Multi-Signal)",
            "UNKNOWN":          "Unlisted Processes Outside Standard Install Dirs",
        }

        for cat_key, cat_label in category_labels.items():
            cat_alerts = [a for a in alerts if a.category == cat_key]
            if not cat_alerts:
                continue
            lines += ["", f"  ── {cat_label} ({len(cat_alerts)}) ──"]
            for alert in cat_alerts:
                lines.append(f"  [{alert.severity}] [Score: {alert.score}/100] [Confidence: {alert.confidence}] {alert.description}")
                lines.append(f"         Reason     : {getattr(alert, 'reason_code', 'N/A')}")
                lines.append(f"         Timestamp  : {alert.timestamp}")
                lines.append(f"         PID        : {alert.pid or 'N/A'}")
                lines.append(f"         Process    : {alert.process_name or 'N/A'}")
                lines.append(f"         Path       : {alert.exe_path or 'N/A'}")
                if alert.file_hash:
                    lines.append(f"         SHA-256    : {alert.file_hash}")
                if alert.signed is not None:
                    lines.append(f"         Signed     : {'Yes' if alert.signed else 'No'} ({alert.sign_subject or 'N/A'})")
                if alert.mitre_id:
                    lines.append(f"         MITRE      : {alert.mitre_id} — {alert.mitre_name} [{alert.mitre_tactic}]")
                for k, v in alert.details.items():
                    if k not in ("username", "exe_path"):
                        lines.append(f"         {k:<15}: {v}")
                lines.append("")

        lines += [SEPARATOR, "  END OF REPORT", SEPARATOR]
        return "\n".join(lines)

    def _format_alert_table(self, alerts: list[Alert]) -> str:
        rows = []
        for a in alerts:
            desc = a.description
            if len(desc) > 50:
                desc = desc[:47] + "..."
            rows.append([
                a.timestamp,
                a.score,
                a.confidence,
                a.category,
                a.pid or "N/A",
                a.process_name or "N/A",
                a.mitre_id or "—",
                desc,
            ])
        return tabulate(
            rows,
            headers=["Timestamp", "Score", "Confidence", "Category", "PID", "Process", "MITRE", "Description"],
            tablefmt="simple",
        )

    # ──────────────────────────────────────────────────────────────────────
    # JSON report
    # ──────────────────────────────────────────────────────────────────────

    def _build_json_report(self, alerts: list[Alert], stats: dict) -> dict:
        now      = datetime.datetime.now()
        hostname = socket.gethostname()

        # Collect unique MITRE techniques observed
        mitre_coverage: dict[str, dict] = {}
        for a in alerts:
            if a.mitre_id and a.mitre_id not in mitre_coverage:
                mitre_coverage[a.mitre_id] = {
                    "technique_id":   a.mitre_id,
                    "technique_name": a.mitre_name,
                    "tactic":         a.mitre_tactic,
                    "alert_count":    0,
                    "url":            f"https://attack.mitre.org/techniques/{a.mitre_id.replace('.', '/')}",
                }
            if a.mitre_id:
                mitre_coverage[a.mitre_id]["alert_count"] += 1

        # Risk classification
        high = stats.get("by_severity", {}).get(SEVERITY_HIGH, 0)
        med  = stats.get("by_severity", {}).get(SEVERITY_MEDIUM, 0)
        risk_level = (
            "CRITICAL" if high >= 5 else
            "HIGH"     if high >= 2 else
            "ELEVATED" if med >= 5  else
            "MODERATE" if med >= 1  else
            "LOW"
        )

        return {
            "report_metadata": {
                "generated_at": now.isoformat(),
                "generated_at_utc": now.utcnow().isoformat() + "Z",
                "hostname": hostname,
                "agent": "Windows Service & Process Monitoring Agent",
                "version": "2.0",
            },
            "executive_summary": {
                "overall_risk_level": risk_level,
                "total_alerts": stats.get("total", 0),
                "severity_breakdown": stats.get("by_severity", {}),
                "category_breakdown": stats.get("by_category", {}),
                "score_statistics": stats.get("score", {}),
            },
            "mitre_attack_coverage": {
                "total_techniques_observed": len(mitre_coverage),
                "techniques": list(mitre_coverage.values()),
            },
            "alerts_by_severity": {
                SEVERITY_HIGH:   [a.to_dict() for a in alerts if a.severity == SEVERITY_HIGH],
                SEVERITY_MEDIUM: [a.to_dict() for a in alerts if a.severity == SEVERITY_MEDIUM],
                SEVERITY_LOW:    [a.to_dict() for a in alerts if a.severity == SEVERITY_LOW],
            },
            "all_alerts": [a.to_dict() for a in alerts],
        }
