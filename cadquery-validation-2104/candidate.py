import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


HEAD = "9a6a705fe73ae94300974a3c668719f907b6353f"
BASE_HASH = "21b4acc82fc9068881de9368f149e3798c0541980205e2d7a4e7820b732d3fd5"
SOURCE_HASH = BASE_HASH
CANDIDATE_HASH = '3fffdf628b8e6a84d26a1d2291443cc51e1a3a2c434a4d6a71645bb20e8417bc'
PAYLOAD = Path(__file__).resolve().parent
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-candidate"
START = time.monotonic()


def run(args, **kwargs):
    print("COMMAND", json.dumps([str(arg) for arg in args]), flush=True)
    return subprocess.run(args, check=True, **kwargs)


def identity(stage):
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == HEAD
    changed = subprocess.check_output(["git", "diff", "--name-only"], text=True).splitlines()
    assert changed == ([] if SOURCE_HASH == BASE_HASH else ["tests/test_free_functions.py"])
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"])
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    assert len(paths) == 219
    assert digest.hexdigest() == SOURCE_HASH
    print("SOURCE_IDENTITY", stage, HEAD, len(paths), digest.hexdigest(), flush=True)


def main():
    global SOURCE_HASH
    constraints = PAYLOAD / "constraints.txt"
    patch = PAYLOAD / "candidate.patch"
    assert hashlib.sha256(constraints.read_bytes()).hexdigest() == '6655f2ddd717d5541ac3dc07f43b4a7a5e713e701251fe0ff8cd4e0593dd24d8'
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == '7f71493331594c5cb9df362559166b4471442a7fabc385f09f69c0cb64a26878'
    assert sys.version_info[:2] == (3, 11)
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir()
    environment = TEMP / "environment"
    run([sys.executable, "-m", "venv", str(environment)])
    python = environment / "bin" / "python"
    report = TEMP / "install-report.json"
    run([str(python), "-m", "pip", "install", "--report", str(report), "-c", str(constraints), "-e", ".[dev]"])
    run([str(python), "-m", "pip", "check"])
    run([str(python), "-m", "pip", "freeze", "--all"])
    run([
        str(python), "-c",
        "from pathlib import Path; import cadquery, importlib.metadata as m; "
        "assert Path(cadquery.__file__).resolve().is_relative_to(Path.cwd().resolve()); "
        "assert m.version('cadquery-ocp') in ('8.0.1.1', '8.0.1.1.0'); "
        "print('IMPORT_IDENTITY', cadquery.__file__, m.version('cadquery-ocp'))",
    ])
    run(["git", "apply", "--check", str(patch)])
    run(["git", "apply", str(patch)])
    SOURCE_HASH = CANDIDATE_HASH
    identity("after-patch")
    formatter = TEMP / "formatter"
    run([sys.executable, "-m", "venv", str(formatter)])
    formatter_python = formatter / "bin" / "python"
    formatter_commit = "3395340200a1a3853d0ba52386c62ed4c5772b53"
    run([str(formatter_python), "-m", "pip", "install", "git+https://github.com/CadQuery/black.git@" + formatter_commit])
    run([str(formatter_python), "-m", "pip", "check"])
    run([str(formatter_python), "-c", "import importlib.metadata as m, json; d=json.loads(m.distribution('black').read_text('direct_url.json')); assert d['vcs_info']['commit_id']=='" + formatter_commit + "'; print('FORMATTER_IDENTITY', d)"])
    run([str(formatter_python), "-m", "black", "--check", "tests/test_free_functions.py"])
    identity("after-format-check")
    targeted = TEMP / "targeted.xml"
    run([str(python), "-m", "pytest", "-v", "tests/test_free_functions.py::test_fillet_method_iterable_edges", "tests/test_free_functions.py::test_chamfer_method_iterable_edges", "--junitxml", str(targeted)])
    targeted_suites = ET.parse(targeted).getroot().findall("testsuite")
    assert sum(int(s.attrib["tests"]) for s in targeted_suites) == 6
    assert all(int(s.attrib.get(k, 0)) == 0 for s in targeted_suites for k in ("failures", "errors", "skipped"))
    print("TARGETED_PYTEST", 6, flush=True)
    identity("before-full-suite")
    junit = TEMP / "pytest.xml"
    run([str(python), "-m", "pytest", "-v", "--junitxml", str(junit)])
    suites = ET.parse(junit).getroot()
    totals = {
        key: sum(int(suite.attrib.get(key, 0)) for suite in suites.findall("testsuite"))
        for key in ("tests", "failures", "errors", "skipped")
    }
    assert totals["tests"] == 901 and totals["skipped"] == 3
    assert totals["failures"] == 0 and totals["errors"] == 0
    print("CANDIDATE_PYTEST", json.dumps(totals, sort_keys=True), flush=True)
    print("INSTALL_REPORT_SHA256", hashlib.sha256(report.read_bytes()).hexdigest(), flush=True)
    print("JUNIT_SHA256", hashlib.sha256(junit.read_bytes()).hexdigest(), flush=True)


if __name__ == "__main__":
    identity("initial")
    try:
        main()
    finally:
        identity("final")
    print("CADQUERY_CANDIDATE_COMPLETE", round(time.monotonic() - START, 2), flush=True)
