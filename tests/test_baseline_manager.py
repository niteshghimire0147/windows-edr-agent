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

try:
    from modules.baseline_manager import BaselineManager
    HAS_BM = True
except ImportError:
    HAS_BM = False

# ── Sample data matching the actual schema ────────────────────────────────
# Service fields: name, display_name, path, start_mode, state, start_name
# Process fields: pid, name, exe, username, status

_SAMPLE_PROCESSES = [
    {"pid": 4,    "name": "System",      "exe": "",                                  "username": "NT AUTHORITY\\SYSTEM", "status": "running"},
    {"pid": 1024, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe", "username": "NT AUTHORITY\\SYSTEM", "status": "running"},
]

_SAMPLE_SERVICES = [
    {
        "name":         "Spooler",
        "display_name": "Print Spooler",
        "path":         "C:\\Windows\\System32\\spoolsv.exe",
        "start_mode":   "Auto",
        "state":        "Running",
        "start_name":   "LocalSystem",
    },
]


class TestBaselineManagerImport:
    def test_module_imports(self):
        if not HAS_BM:
            pytest.skip("baseline_manager not importable")
        assert True


class TestBaselineSaveLoad:
    def test_save_creates_file(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=_SAMPLE_SERVICES, path=path)
        assert os.path.exists(path)

    def test_saved_file_is_valid_json(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=_SAMPLE_SERVICES, path=path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert "processes" in data
        assert "services" in data
        assert "metadata" in data

    def test_load_returns_none_when_missing(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "nonexistent.json")
        mgr  = BaselineManager(baseline_path=path)
        assert mgr.load(path=path) is None

    def test_roundtrip_preserves_process_count(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=[], path=path)
        data = mgr.load(path=path)
        assert data["metadata"]["process_count"] == len(_SAMPLE_PROCESSES)

    def test_roundtrip_preserves_service_count(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=[], services=_SAMPLE_SERVICES, path=path)
        data = mgr.load(path=path)
        assert data["metadata"]["service_count"] == len(_SAMPLE_SERVICES)


class TestBaselineDriftDetection:
    def test_new_process_detected(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=[], path=path)

        new_proc = {"pid": 9999, "name": "suspicious.exe",
                    "exe": "C:\\Temp\\suspicious.exe", "username": "SYSTEM", "status": "running"}
        current = _SAMPLE_PROCESSES + [new_proc]
        baseline_data = mgr.load(path=path)
        diff = mgr.compare_processes(current, baseline_data)

        new_names = [p["name"] for p in diff["new"]]
        assert "suspicious.exe" in new_names

    def test_missing_process_detected(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=[], path=path)

        # Remove svchost from the current snapshot → it should appear as "missing"
        current = [p for p in _SAMPLE_PROCESSES if p["name"] != "svchost.exe"]
        baseline_data = mgr.load(path=path)
        diff = mgr.compare_processes(current, baseline_data)

        missing_names = [m["name"] for m in diff["missing"]]
        assert "svchost.exe" in missing_names

    def test_new_service_detected(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=[], services=_SAMPLE_SERVICES, path=path)

        evil_svc = {
            "name":       "EvilSvc",
            "display_name": "Evil Service",
            "path":       "C:\\Temp\\evil.exe",
            "start_mode": "Auto",
            "state":      "Running",
            "start_name": "LocalSystem",
        }
        current_svcs = _SAMPLE_SERVICES + [evil_svc]
        baseline_data = mgr.load(path=path)
        diff = mgr.compare_services(current_svcs, baseline_data)

        new_names = [s["name"] for s in diff["new"]]
        assert "EvilSvc" in new_names

    def test_changed_service_path_detected(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=[], services=_SAMPLE_SERVICES, path=path)

        # Tamper the Spooler binary path
        tampered = [{**_SAMPLE_SERVICES[0], "path": "C:\\Temp\\evil_spoolsv.exe"}]
        baseline_data = mgr.load(path=path)
        diff = mgr.compare_services(tampered, baseline_data)

        changed_fields = [c["field"] for c in diff["changed"]]
        assert "path" in changed_fields

    def test_flat_compare_returns_list(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "baseline.json")
        mgr  = BaselineManager(baseline_path=path)
        mgr.save(processes=_SAMPLE_PROCESSES, services=_SAMPLE_SERVICES, path=path)
        result = mgr.compare(current_processes=_SAMPLE_PROCESSES,
                             current_services=_SAMPLE_SERVICES, path=path)
        assert isinstance(result, list)

    def test_no_baseline_compare_returns_empty(self, tmp_path):
        if not HAS_BM:
            pytest.skip()
        path = str(tmp_path / "nonexistent.json")
        mgr  = BaselineManager(baseline_path=path)
        result = mgr.compare(current_processes=[], current_services=[], path=path)
        assert result == []
