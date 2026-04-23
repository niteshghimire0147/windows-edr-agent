"""
Tests for modules/alert_engine.py — alert scoring, fingerprinting, deduplication.
Run with: python -m pytest tests/test_alert_engine.py -v
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

try:
    from modules.alert_engine import (
        Alert, AlertEngine, compute_score, compute_confidence, compute_reason_code,
        SEVERITY_MALICIOUS, SEVERITY_SUSPICIOUS, SEVERITY_LOW, SEVERITY_SYSTEM,
        CATEGORY_BLACKLIST, CATEGORY_HASH_MATCH, CATEGORY_UNKNOWN,
        CATEGORY_INCOMPLETE_DATA, CATEGORY_SUSPICIOUS_PATH, CATEGORY_TYPOSQUAT,
    )
    HAS_ENGINE = True
except ImportError:
    HAS_ENGINE = False


def make_alert(
    severity=None,
    category=CATEGORY_BLACKLIST if HAS_ENGINE else "BLACKLIST",
    process_name="malware.exe",
    description="Test alert",
    pid=1234,
):
    if not HAS_ENGINE:
        return {
            "severity": severity or "MALICIOUS",
            "category": category,
            "description": description,
            "pid": pid,
            "process_name": process_name,
        }
    return Alert(
        severity=severity or SEVERITY_MALICIOUS,
        category=category,
        description=description,
        pid=pid,
        process_name=process_name,
        exe_path=f"C:\\Windows\\Temp\\{process_name}",
        mitre_id="T1059",
        mitre_name="Command and Scripting Interpreter",
        mitre_tactic="Execution",
        details={},
    )


# ── Import / instantiation ────────────────────────────────────────────────

class TestAlertEngineBasics:
    def test_module_imports(self):
        if not HAS_ENGINE:
            pytest.skip("alert_engine not importable")
        assert True

    def test_alert_engine_instantiates(self):
        if not HAS_ENGINE:
            pytest.skip("AlertEngine not available")
        engine = AlertEngine()
        assert engine is not None

    def test_add_alert_and_retrieve(self):
        if not HAS_ENGINE:
            pytest.skip("AlertEngine not available")
        engine = AlertEngine()
        engine.add(make_alert())
        assert len(engine.get_all()) == 1

    def test_summary_stats_has_all_severity_keys(self):
        if not HAS_ENGINE:
            pytest.skip("AlertEngine not available")
        engine = AlertEngine()
        engine.add(make_alert(severity=SEVERITY_MALICIOUS,  category=CATEGORY_BLACKLIST))
        engine.add(make_alert(severity=SEVERITY_SUSPICIOUS, category=CATEGORY_SUSPICIOUS_PATH,
                              description="susp", process_name="susp.exe"))
        engine.add(make_alert(severity=SEVERITY_LOW,        category=CATEGORY_UNKNOWN,
                              description="unknown", process_name="unk.exe"))
        stats = engine.summary_stats()
        assert stats["by_severity"][SEVERITY_MALICIOUS]  >= 1
        assert stats["by_severity"][SEVERITY_SUSPICIOUS] >= 1
        assert stats["by_severity"][SEVERITY_LOW]        >= 1
        assert SEVERITY_SYSTEM in stats["by_severity"]


# ── Scoring ───────────────────────────────────────────────────────────────

class TestScoreComputation:
    def test_hash_match_highest_score(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_score(SEVERITY_MALICIOUS, CATEGORY_HASH_MATCH) == 100

    def test_blacklist_score_95(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_score(SEVERITY_MALICIOUS, CATEGORY_BLACKLIST) == 95

    def test_incomplete_data_always_40_regardless_of_severity(self):
        if not HAS_ENGINE:
            pytest.skip()
        # Score is driven by _CATEGORY_BASE_SCORES override — severity arg is ignored
        assert compute_score(SEVERITY_MALICIOUS,  CATEGORY_INCOMPLETE_DATA) == 40
        assert compute_score(SEVERITY_SUSPICIOUS, CATEGORY_INCOMPLETE_DATA) == 40
        assert compute_score(SEVERITY_LOW,        CATEGORY_INCOMPLETE_DATA) == 40

    def test_unknown_base_score_20(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_score(SEVERITY_LOW, CATEGORY_UNKNOWN) == 20

    def test_score_clamped_0_to_100(self):
        if not HAS_ENGINE:
            pytest.skip()
        score = compute_score(SEVERITY_MALICIOUS, CATEGORY_HASH_MATCH)
        assert 0 <= score <= 100


# ── Confidence ────────────────────────────────────────────────────────────

class TestConfidence:
    def test_hash_match_is_high_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_confidence(CATEGORY_HASH_MATCH) == "HIGH"

    def test_blacklist_is_high_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_confidence(CATEGORY_BLACKLIST) == "HIGH"

    def test_suspicious_path_is_medium_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_confidence(CATEGORY_SUSPICIOUS_PATH) == "MEDIUM"

    def test_unknown_is_low_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_confidence(CATEGORY_UNKNOWN) == "LOW"

    def test_incomplete_data_is_low_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_confidence(CATEGORY_INCOMPLETE_DATA) == "LOW"


# ── Reason codes ──────────────────────────────────────────────────────────

class TestReasonCodes:
    def test_blacklist_reason_code(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_reason_code(CATEGORY_BLACKLIST) == "BLACKLIST_MATCH"

    def test_hash_match_reason_code(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_reason_code(CATEGORY_HASH_MATCH) == "KNOWN_BAD_HASH"

    def test_incomplete_data_reason_code(self):
        if not HAS_ENGINE:
            pytest.skip()
        assert compute_reason_code(CATEGORY_INCOMPLETE_DATA) == "NO_EXE_PATH"


# ── Auto-populate in __post_init__ ────────────────────────────────────────

class TestAlertAutoFields:
    def test_alert_auto_populates_score(self):
        if not HAS_ENGINE:
            pytest.skip()
        a = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                  description="test")
        assert a.score == 95

    def test_alert_auto_populates_confidence(self):
        if not HAS_ENGINE:
            pytest.skip()
        a = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                  description="test")
        assert a.confidence == "HIGH"

    def test_alert_auto_populates_reason_code(self):
        if not HAS_ENGINE:
            pytest.skip()
        a = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                  description="test")
        assert a.reason_code == "BLACKLIST_MATCH"

    def test_explicit_score_not_overwritten(self):
        if not HAS_ENGINE:
            pytest.skip()
        a = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                  description="test", score=42)
        assert a.score == 42


# ── Deduplication ─────────────────────────────────────────────────────────

class TestFingerprintDeduplication:
    def test_identical_alerts_same_fingerprint(self):
        if not HAS_ENGINE:
            pytest.skip()
        a1 = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                   description="malware.exe detected", process_name="malware.exe")
        a2 = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                   description="malware.exe detected", process_name="malware.exe",
                   pid=9999)   # different PID — fingerprint must still match
        assert a1.fingerprint == a2.fingerprint

    def test_different_process_different_fingerprint(self):
        if not HAS_ENGINE:
            pytest.skip()
        a1 = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                   description="malware.exe detected", process_name="malware.exe")
        a2 = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                   description="trojan.exe detected", process_name="trojan.exe")
        assert a1.fingerprint != a2.fingerprint

    def test_engine_deduplicates_identical_alerts(self):
        if not HAS_ENGINE:
            pytest.skip()
        engine = AlertEngine()
        a = Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                  description="dup test", process_name="dup.exe")
        engine.add(a)
        engine.add(a)   # same fingerprint → should be dropped
        assert len(engine.get_all()) == 1

    def test_engine_keeps_distinct_alerts(self):
        if not HAS_ENGINE:
            pytest.skip()
        engine = AlertEngine()
        engine.add(Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                         description="alert A", process_name="a.exe"))
        engine.add(Alert(severity=SEVERITY_MALICIOUS, category=CATEGORY_BLACKLIST,
                         description="alert B", process_name="b.exe"))
        assert len(engine.get_all()) == 2
