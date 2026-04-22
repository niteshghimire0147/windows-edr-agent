"""
alert_engine.py — Alert dataclass, severity scoring, confidence, and collection management.

4-Tier EDR Classification Model
─────────────────────────────────────────────────────────────────────────────
  Tier          Severity Label   Score Range   Meaning
  ──────────    ─────────────    ───────────   ──────────────────────────────
  MALICIOUS     "MALICIOUS"      80 – 100      Confirmed / near-confirmed.
                                               Blacklisted tool, known bad
                                               hash, process injection.
                                               Immediate investigation needed.

  SUSPICIOUS    "SUSPICIOUS"     40 – 70       Behavioral indicator.
                                               Unusual parent-child chain,
                                               binary in Temp/AppData,
                                               typosquat of system process,
                                               process with no resolvable exe.
                                               Warrants analyst review.

  LOW           "LOW"            10 – 30       Unknown / unlisted process
                                               outside standard install dirs.
                                               Not malicious by default.
                                               Review periodically.

  SYSTEM        "SYSTEM"          0 – 10       Known-good OS / whitelisted
                                               process. Informational only.
─────────────────────────────────────────────────────────────────────────────
Scoring formula:
  score = category_base (or severity_base) + category_modifier
  clamped to [0, 100]

Confidence:
  HIGH   — cryptographic or explicit intelligence match (act now)
  MEDIUM — behavioral rule fired (investigate)
  LOW    — single weak signal or inventory observation (review)

MITRE ATT&CK is assigned ONLY when a real behavioral rule fires, never for
inventory listing or unknown processes without behavioral evidence.
"""

import hashlib
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Optional
from utils.helpers import timestamp_now


# ── Severity labels (4-tier EDR model) ───────────────────────────────────────
SEVERITY_MALICIOUS  = "MALICIOUS"    # Confirmed / near-confirmed threat
SEVERITY_SUSPICIOUS = "SUSPICIOUS"   # Behavioral indicator, warrants review
SEVERITY_LOW        = "LOW"          # Unknown / unlisted, informational
SEVERITY_SYSTEM     = "SYSTEM"       # Known-good OS process

# Backward-compatible aliases — all existing module imports keep working
SEVERITY_HIGH     = SEVERITY_MALICIOUS
SEVERITY_MEDIUM   = SEVERITY_SUSPICIOUS
SEVERITY_CRITICAL = SEVERITY_MALICIOUS  # legacy alias

# ── Category labels ───────────────────────────────────────────────────────────
CATEGORY_PARENT_CHILD    = "PARENT_CHILD"
CATEGORY_SERVICE         = "SERVICE"
CATEGORY_UNAUTHORIZED    = "UNAUTHORIZED"     # Confirmed injection (multi-signal)
CATEGORY_TYPOSQUAT       = "TYPOSQUAT"
CATEGORY_BLACKLIST       = "BLACKLIST"
CATEGORY_SUSPICIOUS_PATH = "SUSPICIOUS_PATH"
CATEGORY_HASH_MATCH      = "HASH_MATCH"
CATEGORY_UNKNOWN         = "UNKNOWN"          # Unlisted, not inherently malicious
CATEGORY_SYSTEM          = "SYSTEM"           # Confirmed OS / whitelisted
CATEGORY_INCOMPLETE_DATA = "INCOMPLETE_DATA"  # No resolvable exe — access-denied or suspect


# ── Scoring architecture ──────────────────────────────────────────────────────
#
# Two-layer design:
#
#   Layer 1 — severity tier base (_BASE_SCORES)
#     Provides the starting score for the alert's severity tier.
#     Most categories inherit this.
#
#   Layer 2 — per-category base override (_CATEGORY_BASE_SCORES)
#     Pins the base for categories whose score must be independent of whatever
#     severity the caller passes.  Prevents score drift if severity labels are
#     ever remapped.  Takes priority over Layer 1.
#
#   Final score = (category_base_override OR severity_base) + category_modifier
#   Result is clamped to [0, 100].

# Layer 1 — severity tier base scores
_BASE_SCORES: dict[str, int] = {
    SEVERITY_MALICIOUS:  85,   # + modifier → 80–100
    SEVERITY_SUSPICIOUS: 50,   # + modifier → 40–70
    SEVERITY_LOW:        20,   # + modifier → 10–30
    SEVERITY_SYSTEM:      5,   # + modifier →  0–10
}

# Layer 2 — explicit per-category base overrides
# INCOMPLETE_DATA is the canonical example: it lives in the SUSPICIOUS tier
# (base 50) but the no-path signal is weaker than other SUSPICIOUS detections,
# so we pin its base here to make the math unambiguous:
#   score = 50 (explicit) + (−10) (modifier) = 40  ← always, regardless of severity arg
_CATEGORY_BASE_SCORES: dict[str, int] = {
    CATEGORY_INCOMPLETE_DATA: 50,   # base 50 + modifier(-10) = 40  (explicit, stable)
}

# Category modifiers — push within-tier score up or down based on confidence
_CATEGORY_MODIFIERS: dict[str, int] = {
    CATEGORY_HASH_MATCH:      15,   # 85+15 = 100  cryptographic certainty
    CATEGORY_BLACKLIST:       10,   # 85+10 =  95  named threat intel match
    CATEGORY_UNAUTHORIZED:     0,   # 85+ 0 =  85  confirmed multi-signal injection
    CATEGORY_TYPOSQUAT:       15,   # 50+15 =  65  name masquerading
    CATEGORY_SUSPICIOUS_PATH: 10,   # 50+10 =  60  binary in writable user dir
    CATEGORY_PARENT_CHILD:     5,   # 50+ 5 =  55  suspicious spawn chain
    CATEGORY_SERVICE:          5,   # base+5       severity set by audit check type
    CATEGORY_INCOMPLETE_DATA: -10,  # 50-10 =  40  single ambiguous signal (no exe)
    CATEGORY_UNKNOWN:          0,   # 20+ 0 =  20  unlisted, low signal
    CATEGORY_SYSTEM:           0,   #  5+ 0 =   5  known-good OS process
}


# ── Confidence levels ─────────────────────────────────────────────────────────
#
# Confidence captures HOW CERTAIN the detection is, independent of severity:
#   HIGH   — direct evidence: hash match or explicit blacklist  → act now
#   MEDIUM — behavioral rule fired: spawn chain, path, typosquat → investigate
#   LOW    — single weak signal or inventory observation        → review later
#
# This maps cleanly to SOC triage priority:
#   HIGH   = P1 (immediate response)
#   MEDIUM = P2 (analyst investigation within shift)
#   LOW    = P3 (periodic review)
_CATEGORY_CONFIDENCE: dict[str, str] = {
    CATEGORY_HASH_MATCH:      "HIGH",    # cryptographic — no false positives
    CATEGORY_BLACKLIST:       "HIGH",    # explicit threat intelligence match
    CATEGORY_UNAUTHORIZED:    "HIGH",    # confirmed multi-signal injection evidence
    CATEGORY_TYPOSQUAT:       "MEDIUM",  # behavioral — name masquerading pattern
    CATEGORY_SUSPICIOUS_PATH: "MEDIUM",  # behavioral — execution from writable dir
    CATEGORY_PARENT_CHILD:    "MEDIUM",  # rule-matched spawn-chain anomaly
    CATEGORY_SERVICE:         "MEDIUM",  # rule-matched service configuration abuse
    CATEGORY_INCOMPLETE_DATA: "LOW",     # single ambiguous signal (no exe path)
    CATEGORY_UNKNOWN:         "LOW",     # inventory observation, no behavioral evidence
    CATEGORY_SYSTEM:          "LOW",     # informational — confirmed clean, not a threat
}


def compute_score(severity: str, category: str) -> int:
    """
    Compute a numeric risk score (0–100).

    Scoring formula:
      base     = _CATEGORY_BASE_SCORES[category]  if category has explicit override
                 else _BASE_SCORES[severity]
      modifier = _CATEGORY_MODIFIERS[category]     (0 if not listed)
      score    = clamp(base + modifier, 0, 100)

    Score interpretation:
      80–100  MALICIOUS   → confirmed / near-confirmed threat, act now
      40–70   SUSPICIOUS  → behavioral indicator, investigate
      10–30   LOW         → unlisted process, review periodically
       0–10   SYSTEM      → known-good, informational

    INCOMPLETE_DATA example (explicit override path):
      base     = _CATEGORY_BASE_SCORES["INCOMPLETE_DATA"] = 50  (not from severity)
      modifier = _CATEGORY_MODIFIERS["INCOMPLETE_DATA"]   = -10
      score    = 50 + (-10) = 40  (stable, regardless of severity argument)
    """
    base = (
        _CATEGORY_BASE_SCORES[category]
        if category in _CATEGORY_BASE_SCORES
        else _BASE_SCORES.get(severity, _BASE_SCORES[SEVERITY_LOW])
    )
    modifier = _CATEGORY_MODIFIERS.get(category, 0)
    return min(100, max(0, base + modifier))


def compute_confidence(category: str) -> str:
    """
    Return the confidence label for a detection category.

    Returns one of: "HIGH" | "MEDIUM" | "LOW"

    Maps directly to SOC triage priority:
      HIGH   → P1 — act immediately
      MEDIUM → P2 — investigate within shift
      LOW    → P3 — review periodically
    """
    return _CATEGORY_CONFIDENCE.get(category, "LOW")


# ── Reason codes ──────────────────────────────────────────────────────────────
#
# A short machine-readable identifier for WHY an alert fired.
# Purpose:
#   • Easier to filter/grep in log pipelines ("show me all NO_EXE_PATH")
#   • Unambiguous in interviews/demos without reading the description
#   • Maps 1:1 to a triage playbook step
#
# Convention: SCREAMING_SNAKE_CASE, verb-noun or adjective-noun pattern.
_CATEGORY_REASON_CODES: dict[str, str] = {
    CATEGORY_HASH_MATCH:      "KNOWN_BAD_HASH",           # cryptographic match in threat DB
    CATEGORY_BLACKLIST:       "BLACKLIST_MATCH",           # explicit threat intelligence hit
    CATEGORY_UNAUTHORIZED:    "PROCESS_INJECTION_SUSPECT", # multi-signal hollowing evidence
    CATEGORY_TYPOSQUAT:       "SYSTEM_PROCESS_TYPOSQUAT",  # name mimics a critical OS binary
    CATEGORY_SUSPICIOUS_PATH: "SUSPICIOUS_EXEC_PATH",      # binary running from writable dir
    CATEGORY_PARENT_CHILD:    "PARENT_CHILD_ANOMALY",       # unexpected process spawn chain
    CATEGORY_SERVICE:         "SERVICE_ABUSE",              # suspicious service configuration
    CATEGORY_INCOMPLETE_DATA: "NO_EXE_PATH",               # process has no resolvable binary
    CATEGORY_UNKNOWN:         "UNLISTED_PROCESS",           # not in whitelist or trusted set
    CATEGORY_SYSTEM:          "KNOWN_SYSTEM_PROCESS",       # confirmed OS / whitelisted
}


def compute_reason_code(category: str) -> str:
    """
    Return the structured reason code for a detection category.

    The reason code is machine-readable, stable, and grep-friendly.
    It describes the specific detection trigger, not the alert's severity.

    Example: an alert can be SUSPICIOUS severity with reason SYSTEM_PROCESS_TYPOSQUAT,
    making both the tier (investigate) and the cause (name masquerading) explicit.
    """
    return _CATEGORY_REASON_CODES.get(category, "UNKNOWN_TRIGGER")


def alert_fingerprint(severity: str, category: str, description: str,
                      process_name: Optional[str]) -> str:
    """
    Stable MD5 fingerprint for deduplication across watch-mode scan iterations.
    Keyed on severity+category+description+name — PID is intentionally excluded
    so the same process name running as multiple instances hashes identically.
    """
    key = f"{severity}|{category}|{description}|{process_name or ''}"
    return hashlib.md5(key.encode()).hexdigest()


@dataclass
class Alert:
    severity:     str
    category:     str
    description:  str
    timestamp:    str            = field(default_factory=timestamp_now)
    pid:          Optional[int]  = None
    process_name: Optional[str]  = None
    exe_path:     Optional[str]  = None
    file_hash:    Optional[str]  = None   # SHA-256 of the executable
    signed:       Optional[bool] = None   # Authenticode signature status
    sign_subject: Optional[str]  = None   # Certificate subject
    mitre_id:     Optional[str]  = None   # e.g. "T1059.001"
    mitre_name:   Optional[str]  = None   # e.g. "PowerShell"
    mitre_tactic: Optional[str]  = None   # e.g. "Execution"
    score:        int            = 0      # Numeric risk score 0–100
    confidence:   str            = ""     # "HIGH" | "MEDIUM" | "LOW"
    reason_code:  str            = ""     # e.g. "BLACKLIST_MATCH", "NO_EXE_PATH"
    details:      dict           = field(default_factory=dict)

    def __post_init__(self):
        if self.score == 0:
            self.score = compute_score(self.severity, self.category)
        if not self.confidence:
            self.confidence = compute_confidence(self.category)
        if not self.reason_code:
            self.reason_code = compute_reason_code(self.category)

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
        self._fingerprints: set[str] = set()  # fast dedup index

    def add(self, alert: Alert) -> None:
        """
        Add an alert.  Silently drops exact duplicates (same fingerprint) so
        that the same detection firing on multiple PIDs of the same binary
        does not produce a flood of identical entries.
        """
        fp = alert.fingerprint
        if fp not in self._fingerprints:
            self._alerts.append(alert)
            self._fingerprints.add(fp)

    def get_all(self) -> list[Alert]:
        return list(self._alerts)

    def get_by_severity(self, severity: str) -> list[Alert]:
        return [a for a in self._alerts if a.severity == severity]

    def get_by_category(self, category: str) -> list[Alert]:
        return [a for a in self._alerts if a.category == category]

    def get_new_since(self, known_fingerprints: set) -> list[Alert]:
        return [a for a in self._alerts if a.fingerprint not in known_fingerprints]

    def all_fingerprints(self) -> set:
        return set(self._fingerprints)

    def top_alerts(self, n: int = 10) -> list[Alert]:
        return sorted(self._alerts, key=lambda a: a.score, reverse=True)[:n]

    def get_grouped_unknowns(self) -> list[dict]:
        """
        Return UNKNOWN alerts grouped by process name with occurrence count.

        Each entry: {"alert": Alert, "count": int}
        Sorted by score descending so the most interesting unlisted processes
        surface first.  Used for clean, deduplicated display.
        """
        unknowns = self.get_by_category(CATEGORY_UNKNOWN)
        name_counts: Counter = Counter()
        name_to_alert: dict = {}
        for a in unknowns:
            key = (a.process_name or "").lower()
            name_counts[key] += 1
            if key not in name_to_alert:
                name_to_alert[key] = a

        result = []
        for key, count in name_counts.most_common():
            result.append({"alert": name_to_alert[key], "count": count})

        result.sort(key=lambda e: e["alert"].score, reverse=True)
        return result

    def summary_stats(self) -> dict:
        scores = [a.score for a in self._alerts] if self._alerts else [0]
        return {
            "total": len(self._alerts),
            "by_severity": {
                SEVERITY_MALICIOUS:  len(self.get_by_severity(SEVERITY_MALICIOUS)),
                SEVERITY_SUSPICIOUS: len(self.get_by_severity(SEVERITY_SUSPICIOUS)),
                SEVERITY_LOW:        len(self.get_by_severity(SEVERITY_LOW)),
                SEVERITY_SYSTEM:     len(self.get_by_severity(SEVERITY_SYSTEM)),
            },
            "by_category": {
                CATEGORY_PARENT_CHILD:    len(self.get_by_category(CATEGORY_PARENT_CHILD)),
                CATEGORY_SERVICE:         len(self.get_by_category(CATEGORY_SERVICE)),
                CATEGORY_UNAUTHORIZED:    len(self.get_by_category(CATEGORY_UNAUTHORIZED)),
                CATEGORY_TYPOSQUAT:       len(self.get_by_category(CATEGORY_TYPOSQUAT)),
                CATEGORY_BLACKLIST:       len(self.get_by_category(CATEGORY_BLACKLIST)),
                CATEGORY_SUSPICIOUS_PATH: len(self.get_by_category(CATEGORY_SUSPICIOUS_PATH)),
                CATEGORY_HASH_MATCH:      len(self.get_by_category(CATEGORY_HASH_MATCH)),
                CATEGORY_INCOMPLETE_DATA: len(self.get_by_category(CATEGORY_INCOMPLETE_DATA)),
                CATEGORY_UNKNOWN:         len(self.get_by_category(CATEGORY_UNKNOWN)),
                CATEGORY_SYSTEM:          len(self.get_by_category(CATEGORY_SYSTEM)),
            },
            "score": {
                "max":     max(scores),
                "average": round(sum(scores) / len(scores), 1),
            },
        }
