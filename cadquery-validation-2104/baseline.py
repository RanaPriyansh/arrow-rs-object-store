import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


HEAD = "9a6a705fe73ae94300974a3c668719f907b6353f"
SOURCE_HASH = "21b4acc82fc9068881de9368f149e3798c0541980205e2d7a4e7820b732d3fd5"
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-baseline"
START = time.monotonic()


def run(args, **kwargs):
    print("COMMAND", json.dumps([str(arg) for arg in args]), flush=True)
    return subprocess.run(args, check=True, **kwargs)


def identity(stage):
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == HEAD
    assert not subprocess.check_output(["git", "diff", "--name-only"])
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"])
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    assert len(paths) == 219
    assert digest.hexdigest() == SOURCE_HASH
    print("SOURCE_IDENTITY", stage, HEAD, len(paths), digest.hexdigest(), flush=True)


def main():
    assert sys.version_info[:2] == (3, 11)
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir()
    environment = TEMP / "environment"
    run([sys.executable, "-m", "venv", str(environment)])
    python = environment / "bin" / "python"
    report = TEMP / "install-report.json"
    run([str(python), "-m", "pip", "install", "--report", str(report), "-e", ".[dev]"])
    run([str(python), "-m", "pip", "check"])
    run([str(python), "-m", "pip", "freeze", "--all"])
    run([
        str(python), "-c",
        "from pathlib import Path; import cadquery, importlib.metadata as m; "
        "assert Path(cadquery.__file__).resolve().is_relative_to(Path.cwd().resolve()); "
        "assert m.version('cadquery-ocp') in ('8.0.1.1', '8.0.1.1.0'); "
        "print('IMPORT_IDENTITY', cadquery.__file__, m.version('cadquery-ocp'))",
    ])
    identity("before-tests")
    junit = TEMP / "pytest.xml"
    run([str(python), "-m", "pytest", "-v", "--junitxml", str(junit)])
    suites = ET.parse(junit).getroot()
    totals = {
        key: sum(int(suite.attrib.get(key, 0)) for suite in suites.findall("testsuite"))
        for key in ("tests", "failures", "errors", "skipped")
    }
    assert totals["tests"] > totals["skipped"]
    assert totals["failures"] == 0 and totals["errors"] == 0
    print("BASELINE_PYTEST", json.dumps(totals, sort_keys=True), flush=True)
    print("INSTALL_REPORT_SHA256", hashlib.sha256(report.read_bytes()).hexdigest(), flush=True)
    print("JUNIT_SHA256", hashlib.sha256(junit.read_bytes()).hexdigest(), flush=True)


if __name__ == "__main__":
    identity("initial")
    try:
        main()
    finally:
        identity("final")
    print("CADQUERY_BASELINE_COMPLETE", round(time.monotonic() - START, 2), flush=True)
