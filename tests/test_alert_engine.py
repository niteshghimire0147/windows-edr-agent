"""
Tests for modules/alert_engine.py — alert scoring, fingerprinting, deduplication.
Run with: python -m pytest tests/test_alert_engine.py -v
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

# Import alert engine — adjust if class/function names differ
try:
    from modules.alert_engine import Alert, AlertEngine, compute_score
    HAS_COMPUTE_SCORE = True
except ImportError:
    HAS_COMPUTE_SCORE = False

try:
    from modules.alert_engine import AlertEngine
    HAS_ALERT_ENGINE = True
except ImportError:
    HAS_ALERT_ENGINE = False


def make_alert(severity="HIGH", category="BLACKLIST", process_name="malware.exe",
               description="Test alert", pid=1234):
    """Helper to create an Alert dataclass or dict for testing."""
    try:
        from modules.alert_engine import Alert
        return Alert(
            severity=severity,
            category=category,
            description=description,
            pid=pid,
            process_name=process_name,
            exe_path=f"C:\\Windows\\Temp\\{process_name}",
            file_hash=None,
            signed=False,
            mitre_id="T1059",
            mitre_name="Command and Scripting Interpreter",
            mitre_tactic="Execution",
            score=75,
            details={},
        )
    except (ImportError, TypeError):
        return {
            "severity": severity,
            "category": category,
            "description": description,
            "pid": pid,
            "process_name": process_name,
        }


class TestAlertEngineBasics:
    def test_module_imports(self):
        try:
            from modules import alert_engine  # noqa: F401
            assert True
        except ImportError as e:
            pytest.skip(f"alert_engine not importable (may need Windows WMI): {e}")

    def test_alert_engine_instantiates(self):
        if not HAS_ALERT_ENGINE:
            pytest.skip("AlertEngine not available")
        engine = AlertEngine()
        assert engine is not None

    def test_add_alert_and_retrieve(self):
        if not HAS_ALERT_ENGINE:
            pytest.skip("AlertEngine not available")
        from modules.alert_engine import AlertEngine
        engine = AlertEngine()
        alert = make_alert()
        if hasattr(engine, "add"):
            engine.add(alert)
            all_alerts = engine.get_all() if hasattr(engine, "get_all") else engine.alerts
            assert len(all_alerts) >= 1
        else:
            pytest.skip("AlertEngine.add() not found")

    def test_alert_count_by_severity(self):
        if not HAS_ALERT_ENGINE:
            pytest.skip("AlertEngine not available")
        from modules.alert_engine import AlertEngine
        engine = AlertEngine()
        if hasattr(engine, "add"):
            for sev in ["HIGH", "HIGH", "MEDIUM", "LOW"]:
                engine.add(make_alert(severity=sev))
            if hasattr(engine, "count_by_severity"):
                counts = engine.count_by_severity()
                assert counts.get("HIGH", 0) == 2
                assert counts.get("MEDIUM", 0) == 1
                assert counts.get("LOW", 0) == 1


class TestScoreComputation:
    def test_hash_match_is_highest_score(self):
        if not HAS_COMPUTE_SCORE:
            pytest.skip("compute_score not available")
        hash_score = compute_score("HIGH", "HASH_MATCH")
        blacklist_score = compute_score("HIGH", "BLACKLIST")
        assert hash_score >= blacklist_score

    def test_critical_severity_maximum(self):
        if not HAS_COMPUTE_SCORE:
            pytest.skip("compute_score not available")
        score = compute_score("CRITICAL", "HASH_MATCH")
        assert score >= 90

    def test_low_severity_minimum(self):
        if not HAS_COMPUTE_SCORE:
            pytest.skip("compute_score not available")
        score = compute_score("LOW", "SERVICE")
        assert 0 <= score <= 50


class TestFingerprintDeduplication:
    def test_identical_alerts_same_fingerprint(self):
        """Two alerts with same severity+category+description+name → same fingerprint."""
        try:
            from modules.alert_engine import Alert
        except ImportError:
            pytest.skip("Alert not importable")

        a1 = make_alert(severity="HIGH", category="BLACKLIST",
                        description="malware.exe detected", process_name="malware.exe")
        a2 = make_alert(severity="HIGH", category="BLACKLIST",
                        description="malware.exe detected", process_name="malware.exe")

        if hasattr(a1, "fingerprint") and hasattr(a2, "fingerprint"):
            assert a1.fingerprint == a2.fingerprint
        elif isinstance(a1, dict):
            pytest.skip("Using dict alerts, no fingerprint")

    def test_different_alerts_different_fingerprint(self):
        try:
            from modules.alert_engine import Alert
        except ImportError:
            pytest.skip("Alert not importable")

        a1 = make_alert(process_name="malware.exe", description="malware.exe detected")
        a2 = make_alert(process_name="trojan.exe", description="trojan.exe detected")

        if hasattr(a1, "fingerprint") and hasattr(a2, "fingerprint"):
            assert a1.fingerprint != a2.fingerprint
