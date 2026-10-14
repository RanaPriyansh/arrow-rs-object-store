import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


PR_HEAD = "5dfbf5c89932d9c438ba449e29732a6a56680aae"
MASTER_HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
MERGE_HEAD = "2b85056876c75d4380cf821aa4055d44963cccf7"
MERGE_TREE = "ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1"
BASE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6"
SOURCE_HASH = "c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c"
BASELINE_RUN = "38646497682"
BASELINE_ARTIFACT = "11933066912"
PAYLOAD = Path(__file__).resolve().parent
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-candidate"
START = time.monotonic()


def run(args, **kwargs):
    print("COMMAND", json.dumps([str(arg) for arg in args]), flush=True)
    return subprocess.run(args, check=True, **kwargs)


def identity(stage):
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == MERGE_HEAD
    assert not subprocess.check_output(["git", "diff", "--name-only"])
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"])
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    assert len(paths) == 219
    assert digest.hexdigest() == SOURCE_HASH
    print("SOURCE_IDENTITY", stage, MERGE_HEAD, len(paths), digest.hexdigest(), flush=True)


def prepare_merge():
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == PR_HEAD
    run(["git", "fetch", "--no-tags", "https://github.com/CadQuery/cadquery.git", MASTER_HEAD])
    run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "merge", "--no-ff", "--no-commit", "--strategy=ort", MASTER_HEAD])
    message = TEMP / "merge-message.txt"
    message.parent.mkdir(parents=True, exist_ok=True)
    message.write_text("Merge commit '" + MASTER_HEAD + "'\n\n")
    commit_env = os.environ.copy()
    commit_env.update({
        "GIT_AUTHOR_NAME": "RanaPriyansh", "GIT_AUTHOR_EMAIL": "priyanshrana18@gmail.com",
        "GIT_AUTHOR_DATE": "@1792016770 +0530", "GIT_COMMITTER_NAME": "RanaPriyansh",
        "GIT_COMMITTER_EMAIL": "priyanshrana18@gmail.com", "GIT_COMMITTER_DATE": "@1792016770 +0530",
    })
    run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "i18n.commitEncoding=UTF-8", "commit", "--no-verify", "--cleanup=verbatim", "--file", message], env=commit_env)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == MERGE_HEAD
    assert subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip() == MERGE_TREE


def main():
    global SOURCE_HASH
    assert sys.version_info[:2] == (3, 11)
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir()
    environment = TEMP / "environment"
    run([sys.executable, "-m", "venv", str(environment)])
    python = environment / "bin" / "python"
    report = TEMP / "install-report.json"
    prepare_merge()
    identity("after-merge")
    run([str(python), "-m", "pip", "install", "--report", str(report), "--no-deps", "--no-build-isolation", "--editable", "."])
    run([str(python), "-m", "pip", "check"])
    run([str(python), "-m", "pip", "freeze", "--all"])
    run([
        str(python), "-c",
        "from pathlib import Path; import cadquery, importlib.metadata as m; "
        "assert Path(cadquery.__file__).resolve().is_relative_to(Path.cwd().resolve()); "
        "assert m.version('cadquery-ocp') in ('8.0.1.1', '8.0.1.1.0'); "
        "print('IMPORT_IDENTITY', cadquery.__file__, m.version('cadquery-ocp'))",
    ])
    identity("after-editable-install")
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
    try:
        main()
    finally:
        identity("final")
    print("CADQUERY_CANDIDATE_COMPLETE", round(time.monotonic() - START, 2), flush=True)
