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
    assert (version("argus") if args == ["--version"] else "No scanning capabilities") in completed.stdout


def test_scan_is_not_presented_as_implemented():
    completed = subprocess.run([str(Path(sys.executable).with_name("argus")), "scan", "."],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 2
    assert "unrecognized arguments" in completed.stderr


def test_python_compatibility_metadata():
    assert metadata("argus")["Requires-Python"] == ">=3.12"
