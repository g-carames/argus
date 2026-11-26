from importlib.metadata import metadata, version
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("args", [["--help"], ["--version"]])
def test_installed_entrypoint(args):
    completed = subprocess.run([str(Path(sys.executable).with_name("argus")), *args],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    assert (version("argus") if args == ["--version"] else "Local offline repository inventory") in completed.stdout


def test_scan_reports_partial_static_analysis(tmp_path):
    import json
    (tmp_path / "sample.py").write_text("print('synthetic')\n")
    completed = subprocess.run([str(Path(sys.executable).with_name("argus")), "scan", str(tmp_path)],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert report["inventory"]["status"] == "completed"
    assert report["status"] == "partial"
    assert report["coverage"]["files"][0]["status"] == "partial"
    assert len(report["modules"]) == 1
    assert all(c["status"] == "partial" for c in report["coverage"]["categories"] if c["category"] in ("security", "credentials", "ai_specific", "cost_efficiency"))


def test_python_compatibility_metadata():
    assert metadata("argus")["Requires-Python"] == ">=3.12"
