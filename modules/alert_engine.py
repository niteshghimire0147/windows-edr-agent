"""
alert_engine.py — Alert dataclass, severity scoring, and collection management.
"""

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from utils.helpers import timestamp_now


# ── Severity labels ────────────────────────────────────────────────────────
SEVERITY_HIGH   = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW    = "LOW"

# ── Category labels ────────────────────────────────────────────────────────
CATEGORY_PARENT_CHILD    = "PARENT_CHILD"
CATEGORY_SERVICE         = "SERVICE"
CATEGORY_UNAUTHORIZED    = "UNAUTHORIZED"
CATEGORY_TYPOSQUAT       = "TYPOSQUAT"
CATEGORY_BLACKLIST       = "BLACKLIST"
CATEGORY_SUSPICIOUS_PATH = "SUSPICIOUS_PATH"
CATEGORY_HASH_MATCH      = "HASH_MATCH"

SEVERITY_CRITICAL = "CRITICAL"

# ── Base severity scores (0–100) ───────────────────────────────────────────
_BASE_SCORES = {
    SEVERITY_CRITICAL: 90,
    SEVERITY_HIGH:     75,
    SEVERITY_MEDIUM:   45,
    SEVERITY_LOW:      15,
}

# ── Category score modifiers ───────────────────────────────────────────────
_CATEGORY_MODIFIERS = {
    CATEGORY_HASH_MATCH:      25,   # Confirmed known-bad hash → highest bonus
    CATEGORY_BLACKLIST:       20,
    CATEGORY_TYPOSQUAT:       15,
    CATEGORY_PARENT_CHILD:    10,
    CATEGORY_SUSPICIOUS_PATH: 10,
    CATEGORY_SERVICE:          5,
    CATEGORY_UNAUTHORIZED:     0,
}


def compute_score(severity: str, category: str) -> int:
    """
    Calculate a numeric risk score (0–100) from severity and category.
    Higher = more dangerous.
    """
    base     = _BASE_SCORES.get(severity, 15)
    modifier = _CATEGORY_MODIFIERS.get(category, 0)
    return min(100, base + modifier)


def alert_fingerprint(severity: str, category: str, description: str,
                      process_name: Optional[str]) -> str:
    """
    Produce a stable MD5 fingerprint for an alert, used to deduplicate alerts
    across real-time scan iterations.
    """
    key = f"{severity}|{category}|{description}|{process_name or ''}"
    return hashlib.md5(key.encode()).hexdigest()


@dataclass
class Alert:
    severity:      str
    category:      str
    description:   str
    timestamp:     str           = field(default_factory=timestamp_now)
    pid:           Optional[int] = None
    process_name:  Optional[str] = None
    exe_path:      Optional[str] = None
    file_hash:     Optional[str] = None      # SHA-256 of the executable (if computed)
    signed:        Optional[bool] = None     # Authenticode signature status
    sign_subject:  Optional[str] = None      # Certificate subject (if signed)
    mitre_id:      Optional[str] = None      # e.g. "T1059.001"
    mitre_name:    Optional[str] = None      # e.g. "PowerShell"
    mitre_tactic:  Optional[str] = None      # e.g. "Execution"
    score:         int           = 0         # Numeric risk score 0–100
    details:       dict          = field(default_factory=dict)

    def __post_init__(self):
        if self.score == 0:
            self.score = compute_score(self.severity, self.category)

    @property
    def fingerprint(self) -> str:
        return alert_fingerprint(
            self.severity, self.category, self.description, self.process_name
        )

    def to_dict(self) -> dict:
        return asdict(self)


class AlertEngine:
    """Collects, stores, and queries all alerts generated during a scan."""

    def __init__(self):
        self._alerts: list[Alert] = []

    def add(self, alert: Alert) -> None:
        self._alerts.append(alert)

    def get_all(self) -> list[Alert]:
        return list(self._alerts)

    def get_by_severity(self, severity: str) -> list[Alert]:
        return [a for a in self._alerts if a.severity == severity]

    def get_by_category(self, category: str) -> list[Alert]:
        return [a for a in self._alerts if a.category == category]

    def get_new_since(self, known_fingerprints: set) -> list[Alert]:
        """Return alerts whose fingerprint is not in the provided set (new detections)."""
        return [a for a in self._alerts if a.fingerprint not in known_fingerprints]

    def all_fingerprints(self) -> set:
        return {a.fingerprint for a in self._alerts}

    def top_alerts(self, n: int = 10) -> list[Alert]:
        """Return the n highest-scoring alerts."""
        return sorted(self._alerts, key=lambda a: a.score, reverse=True)[:n]

    def summary_stats(self) -> dict:
        scores = [a.score for a in self._alerts] if self._alerts else [0]
        return {
            "total": len(self._alerts),
            "by_severity": {
                SEVERITY_HIGH:   len(self.get_by_severity(SEVERITY_HIGH)),
                SEVERITY_MEDIUM: len(self.get_by_severity(SEVERITY_MEDIUM)),
                SEVERITY_LOW:    len(self.get_by_severity(SEVERITY_LOW)),
            },
            "by_category": {
                CATEGORY_PARENT_CHILD:    len(self.get_by_category(CATEGORY_PARENT_CHILD)),
                CATEGORY_SERVICE:         len(self.get_by_category(CATEGORY_SERVICE)),
                CATEGORY_UNAUTHORIZED:    len(self.get_by_category(CATEGORY_UNAUTHORIZED)),
                CATEGORY_TYPOSQUAT:       len(self.get_by_category(CATEGORY_TYPOSQUAT)),
                CATEGORY_BLACKLIST:       len(self.get_by_category(CATEGORY_BLACKLIST)),
                CATEGORY_SUSPICIOUS_PATH: len(self.get_by_category(CATEGORY_SUSPICIOUS_PATH)),
                CATEGORY_HASH_MATCH:      len(self.get_by_category(CATEGORY_HASH_MATCH)),
            },
            "score": {
                "max":     max(scores),
                "average": round(sum(scores) / len(scores), 1),
            },
        }
