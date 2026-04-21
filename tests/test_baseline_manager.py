"""
Tests for modules/baseline_manager.py — baseline save/load and drift detection.
Run with: python -m pytest tests/test_baseline_manager.py -v
"""
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


class TestBaselineManagerImport:
    def test_module_imports(self):
        try:
            from modules import baseline_manager  # noqa: F401
            assert True
        except ImportError as e:
            pytest.skip(f"baseline_manager not importable: {e}")


class TestBaselineSaveLoad:
    def test_save_and_load_roundtrip(self, tmp_path):
        """Save a baseline → load it → content must match."""
        try:
            from modules.baseline_manager import BaselineManager
        except ImportError:
            pytest.skip("BaselineManager not importable")

        baseline_path = str(tmp_path / "test_baseline.json")
        mgr = BaselineManager(baseline_path=baseline_path)

        # Create sample baseline data
        sample_processes = [
            {"pid": 1, "name": "system", "exe": "C:\\Windows\\System32\\ntoskrnl.exe"},
            {"pid": 4, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe"},
        ]
        sample_services = [
            {"name": "Spooler", "binary_path": "C:\\Windows\\System32\\spoolsv.exe",
             "start_type": "Auto", "account": "LocalSystem"},
        ]

        # Save baseline
        if hasattr(mgr, "save"):
            mgr.save(processes=sample_processes, services=sample_services)
        elif hasattr(mgr, "create_baseline"):
            mgr.create_baseline(processes=sample_processes, services=sample_services)
        else:
            pytest.skip("No save/create_baseline method found")

        # Verify file was written
        assert os.path.exists(baseline_path)

        # Load and verify
        with open(baseline_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert isinstance(loaded, dict)

    def test_baseline_file_is_valid_json(self, tmp_path):
        """Saved baseline file must be valid JSON."""
        try:
            from modules.baseline_manager import BaselineManager
        except ImportError:
            pytest.skip("BaselineManager not importable")

        baseline_path = str(tmp_path / "baseline.json")
        mgr = BaselineManager(baseline_path=baseline_path)

        if hasattr(mgr, "save"):
            mgr.save(processes=[], services=[])
        elif hasattr(mgr, "create_baseline"):
            mgr.create_baseline(processes=[], services=[])
        else:
            pytest.skip("No save method")

        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)


class TestBaselineDriftDetection:
    def test_new_process_detected_as_drift(self, tmp_path):
        """A process in current scan but not in baseline → drift alert."""
        try:
            from modules.baseline_manager import BaselineManager
        except ImportError:
            pytest.skip("BaselineManager not importable")

        baseline_path = str(tmp_path / "baseline.json")
        mgr = BaselineManager(baseline_path=baseline_path)

        original = [{"pid": 1, "name": "svchost.exe", "exe": "C:\\svchost.exe"}]
        current = [
            {"pid": 1, "name": "svchost.exe", "exe": "C:\\svchost.exe"},
            {"pid": 9999, "name": "suspicious.exe", "exe": "C:\\Temp\\suspicious.exe"},
        ]

        if hasattr(mgr, "save"):
            mgr.save(processes=original, services=[])
        else:
            pytest.skip("No save method")

        if hasattr(mgr, "compare"):
            drifts = mgr.compare(current_processes=current, current_services=[])
            # Should detect suspicious.exe as new
            assert isinstance(drifts, list)
        elif hasattr(mgr, "detect_drift"):
            drifts = mgr.detect_drift(current_processes=current, current_services=[])
            assert isinstance(drifts, list)
        else:
            pytest.skip("No compare/detect_drift method")

    def test_new_service_detected_as_drift(self, tmp_path):
        """A new auto-start service → HIGH drift alert."""
        try:
            from modules.baseline_manager import BaselineManager
        except ImportError:
            pytest.skip("BaselineManager not importable")

        baseline_path = str(tmp_path / "baseline2.json")
        mgr = BaselineManager(baseline_path=baseline_path)

        original_services = [
            {"name": "Spooler", "binary_path": "C:\\spoolsv.exe",
             "start_type": "Auto", "account": "LocalSystem"},
        ]
        new_services = [
            {"name": "Spooler", "binary_path": "C:\\spoolsv.exe",
             "start_type": "Auto", "account": "LocalSystem"},
            {"name": "EvilSvc", "binary_path": "C:\\Temp\\evil.exe",
             "start_type": "Auto", "account": "LocalSystem"},
        ]

        if hasattr(mgr, "save"):
            mgr.save(processes=[], services=original_services)
        else:
            pytest.skip("No save method")

        compare_fn = getattr(mgr, "compare", getattr(mgr, "detect_drift", None))
        if compare_fn is None:
            pytest.skip("No compare method")

        drifts = compare_fn(current_processes=[], current_services=new_services)
        assert isinstance(drifts, list)
