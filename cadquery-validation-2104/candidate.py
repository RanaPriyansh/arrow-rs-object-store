"""Pure, import-safe Layer 1 validators for the CadQuery replay."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET

PR_HEAD = "5dfbf5c89932d9c438ba449e29732a6a56680aae"
MASTER_HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
MERGE_HEAD = "2b85056876c75d4380cf821aa4055d44963cccf7"
MERGE_TREE = "ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1"
BASE_SOURCE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6"
CANDIDATE_SOURCE_HASH = "c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c"
BLACK_COMMIT = "3395340200a1a3853d0ba52386c62ed4c5772b53"
BLACK_REPOSITORY = "https://github.com/cadquery/black.git"
BASELINE_CASES = 901
BASELINE_SKIPS = 3
BASELINE_SKIP_IDS = {"tests.test_fig::test_fig", "tests.test_fig::test_fig_free_func", "tests.test_vis::test_screenshot_no_patch"}
ADDED_CASES = {
    "tests.test_free_functions::test_fillet_method_iterable_edges[list]",
    "tests.test_free_functions::test_fillet_method_iterable_edges[generator]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[None-0.98-list]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[None-0.98-generator]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[0.2-0.96-list]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[0.2-0.96-generator]",
}
RAW_SHA256 = "621926d4ac8a2a6f73d5826419cf11dbd5ed31f584f633682b584c7178b630bb"
MESSAGE_SHA256 = "4f2fc48c495d05bf01d8e2c172bfed19efd2481b5270d40ff9d27c506ecd69be"

def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def validate_source_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("source digest must be 64 lowercase hexadecimal characters")
    return value

def pip_origin(record):
    return record.get("channel") == "pypi" or record.get("platform") == "pypi" or record.get("build_string") == "pypi_0"

def conda_identity(record):
    return tuple(record.get(k) for k in ("version", "build_string", "build_number", "channel", "base_url", "platform"))

def conda_owned(records):
    values = {}
    for record in records:
        if pip_origin(record):
            continue
        name = canonical(record["name"])
        if name in values:
            raise ValueError(f"duplicate conda package: {name}")
        values[name] = conda_identity(record)
    return values

def explicit_set(text):
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith(("#", "@"))}

def validate_conda_inventory(baseline_records, candidate_records, baseline_explicit, candidate_explicit):
    before, after = conda_owned(baseline_records), conda_owned(candidate_records)
    if before != after:
        raise ValueError("conda package identity changed")
    if explicit_set(baseline_explicit) != explicit_set(candidate_explicit):
        raise ValueError("conda explicit URL or hash changed")
    return {"packages": len(before), "pip_origin": sorted(canonical(r["name"]) for r in baseline_records if pip_origin(r)), "explicit": len(explicit_set(baseline_explicit))}

def pip_records(document):
    if not isinstance(document, dict) or not isinstance(document.get("installed"), list):
        raise ValueError("pip inspect must be an object with installed records")
    result = {}
    for item in document["installed"]:
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("name"):
            raise ValueError("invalid pip metadata")
        name = canonical(metadata["name"])
        if name in result:
            raise ValueError(f"duplicate pip package: {name}")
        result[name] = {"version": metadata.get("version"), "direct_url": item.get("direct_url"), "editable": bool((item.get("direct_url") or {}).get("dir_info", {}).get("editable"))}
    return result

def _editable_path(record, expected):
    direct_url = record.get("direct_url") or {}
    if not record["editable"]:
        raise ValueError("editable installation is required")
    parsed = urlparse(direct_url.get("url", ""))
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise ValueError("editable source is not a local file URL")
    actual, expected = Path(unquote(parsed.path)).resolve(), Path(expected).resolve()
    if not actual.is_absolute() or actual != expected:
        raise ValueError("editable source path is invalid")

def validate_pip_inventory(baseline_document, candidate_document, baseline_source, candidate_source):
    before, after = pip_records(baseline_document), pip_records(candidate_document)
    if set(before) != set(after) or "cadquery" not in before:
        raise ValueError("pip package set changed")
    for name in before:
        if name != "cadquery" and (before[name]["version"] != after[name]["version"] or before[name]["direct_url"] != after[name]["direct_url"]):
            raise ValueError(f"pip package provenance changed: {name}")
    if before["cadquery"]["version"] != after["cadquery"]["version"]:
        raise ValueError("CadQuery version changed")
    _editable_path(before["cadquery"], baseline_source)
    _editable_path(after["cadquery"], candidate_source)
    for inventory in (before, after):
        direct_url = (inventory.get("black") or {}).get("direct_url") or {}
        vcs = direct_url.get("vcs_info") or {}
        if direct_url.get("url") != BLACK_REPOSITORY or vcs.get("commit_id") != BLACK_COMMIT:
            raise ValueError("Black provenance changed")
    return {"packages": len(after), "editable_source": str(Path(candidate_source).resolve()), "baseline_source": str(Path(baseline_source).resolve())}

def validate_runtime(runtime, env_prefix, source_path, phase):
    prefix, source = Path(env_prefix).resolve(), Path(source_path).resolve()
    executable = Path(runtime["python_executable"]).resolve()
    if Path(runtime["python_prefix"]).resolve() != prefix:
        raise ValueError("Python prefix is invalid")
    if not executable.is_relative_to(prefix):
        raise ValueError("Python executable is outside environment")
    if tuple(runtime["python_version"][:2]) < (3, 11):
        raise ValueError("unsupported Python")
    if runtime.get("ocp_version") != "8.0.1.1" or not Path(runtime["ocp_path"]).resolve().is_relative_to(prefix):
        raise ValueError("OCP runtime identity is invalid")
    if not Path(runtime["cadquery_path"]).resolve().is_relative_to(source):
        raise ValueError(f"{phase} CadQuery path is invalid")
    if runtime.get("black_commit") != BLACK_COMMIT:
        raise ValueError("Black commit is invalid")
    return {"phase": phase, "python": str(executable), "prefix": str(prefix), "source": str(source)}

def testcase_ids(xml_path):
    root = ET.parse(xml_path).getroot()
    found = root.find("testsuite")
    suite = found if found is not None else root
    cases = []
    for case in suite.findall("testcase"):
        cases.append({"id": case.attrib.get("classname", "") + "::" + case.attrib.get("name", ""), "skipped": case.find("skipped") is not None, "failed": case.find("failure") is not None, "errored": case.find("error") is not None})
    return suite, cases

def validate_xml(xml_path, baseline_xml=None, candidate=False):
    suite, cases = testcase_ids(xml_path)
    ids = [item["id"] for item in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate testcase")
    if int(suite.attrib.get("failures", "0")) or int(suite.attrib.get("errors", "0")):
        raise ValueError("suite reports failures or errors")
    if any(item["failed"] or item["errored"] for item in cases):
        raise ValueError("failed testcase")
    skips = {item["id"] for item in cases if item["skipped"]}
    if not candidate:
        if len(ids) != BASELINE_CASES or skips != BASELINE_SKIP_IDS:
            raise ValueError("baseline cases or skips changed")
        return {"tests": len(ids), "skips": len(skips), "ids": ids}
    base = validate_xml(baseline_xml, candidate=False)
    added = set(ids) - set(base["ids"])
    if set(base["ids"]) - set(ids) or added != ADDED_CASES:
        raise ValueError("candidate testcase identity mismatch")
    if skips != BASELINE_SKIP_IDS or any(item["skipped"] for item in cases if item["id"] in added):
        raise ValueError("candidate skip identity changed")
    return {"tests": len(ids), "skips": len(skips), "added": sorted(added)}

def _git_commit_sha1(raw):
    return hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def validate_merge_metadata(metadata, raw, message):
    validate_source_digest(BASE_SOURCE_HASH)
    validate_source_digest(CANDIDATE_SOURCE_HASH)
    expected = {"commit": MERGE_HEAD, "tree": MERGE_TREE, "first_parent": PR_HEAD, "second_parent": MASTER_HEAD, "author_name": "RanaPriyansh", "author_email": "priyanshrana18@gmail.com", "committer_name": "RanaPriyansh", "committer_email": "priyanshrana18@gmail.com", "author_timestamp": 1792016770, "committer_timestamp": 1792016770, "author_offset": "+0530", "committer_offset": "+0530"}
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"merge metadata mismatch: {key}")
    for value in (metadata.get("commit"), metadata.get("tree"), metadata.get("first_parent"), metadata.get("second_parent")):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("Git identity must be 40 lowercase hexadecimal characters")
    if hashlib.sha256(raw).hexdigest() != RAW_SHA256 or metadata.get("raw_sha256") != RAW_SHA256:
        raise ValueError("raw commit hash mismatch")
    if hashlib.sha256(message).hexdigest() != MESSAGE_SHA256 or metadata.get("message_sha256") != MESSAGE_SHA256:
        raise ValueError("commit message hash mismatch")
    if _git_commit_sha1(raw) != MERGE_HEAD:
        raise ValueError("raw commit identity mismatch")
    try:
        raw_message = raw.split(b"\n\n", 1)[1]
    except IndexError as exc:
        raise ValueError("raw commit has no message") from exc
    if raw_message != message:
        raise ValueError("raw commit and message differ")
    prefix = b"tree " + MERGE_TREE.encode() + b"\nparent " + PR_HEAD.encode() + b"\nparent " + MASTER_HEAD.encode() + b"\n"
    if not raw.startswith(prefix):
        raise ValueError("merge parent order mismatch")
    return {"commit": MERGE_HEAD, "tree": MERGE_TREE, "raw_sha256": RAW_SHA256, "message_sha256": MESSAGE_SHA256}


CHECKS = (
    ("black", ("black", ".", "--diff", "--check")),
    ("mypy", ("mypy", "cadquery")),
    ("pytest", ("pytest", "-v", "--gui", "--cov")),
)
RUNTIME_SCRIPT = "import cadquery, OCP, importlib.metadata, json, pathlib, sys; direct=json.loads((pathlib.Path(importlib.metadata.distribution('black')._path)/'direct_url.json').read_text()); print(json.dumps({'python_executable': sys.executable, 'python_prefix': sys.prefix, 'cadquery_path': str(cadquery.__file__), 'ocp_path': str(OCP.__file__), 'ocp_version': importlib.metadata.version('cadquery-ocp'), 'python_version': list(sys.version_info[:3]), 'black_commit': direct['vcs_info']['commit_id']}))"


def _exclusive_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(data)


def _safe_env():
    return {key: value for key, value in os.environ.items() if "TOKEN" not in key.upper()}


def _run(command, cwd, evidence_dir, label, env=None, check=True):
    evidence_dir = Path(evidence_dir)
    result = subprocess.run(command, cwd=str(cwd), env=_safe_env() | (env or {}), capture_output=True, text=True, check=False)
    _exclusive_write(evidence_dir / f"{label}.stdout", result.stdout or "")
    _exclusive_write(evidence_dir / f"{label}.stderr", result.stderr or "")
    _exclusive_write(evidence_dir / f"{label}.exit", f"{result.returncode}\n")
    if check and result.returncode:
        raise RuntimeError(f"{label} failed with exit {result.returncode}")
    return result


def _tracked_digest(source):
    source = Path(source)
    names = subprocess.check_output(("git", "ls-files", "-z"), cwd=str(source)).split(b"\0")
    digest = hashlib.sha256()
    for name in names[:-1]:
        digest.update(name + b"\0" + (source / os.fsdecode(name)).read_bytes() + b"\0")
    return digest.hexdigest()


def _read_json_output(result, label):
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} did not return JSON") from exc


def _require_output(result, expected, label):
    if result.stdout.strip() != expected:
        raise ValueError(f"{label} identity mismatch")


def _inventory(source, env_prefix, evidence_dir, phase, suffix):
    conda_executable = os.environ.get("CANDIDATE_CONDA", "conda")
    conda = _run((conda_executable, "list", "--prefix", str(env_prefix), "--json"), source, evidence_dir, f"{phase}-{suffix}-conda-list")
    explicit = _run((conda_executable, "list", "--prefix", str(env_prefix), "--explicit"), source, evidence_dir, f"{phase}-{suffix}-conda-explicit")
    export = _run((conda_executable, "env", "export", "--prefix", str(env_prefix), "--json"), source, evidence_dir, f"{phase}-{suffix}-conda-export")
    pip = _run((str(Path(env_prefix) / "bin/python"), "-m", "pip", "inspect"), source, evidence_dir, f"{phase}-{suffix}-pip-inspect")
    freeze = _run((str(Path(env_prefix) / "bin/python"), "-m", "pip", "freeze"), source, evidence_dir, f"{phase}-{suffix}-pip-freeze")
    return {"conda": _read_json_output(conda, f"{phase} conda list"), "explicit": explicit.stdout, "export": _read_json_output(export, f"{phase} conda export"), "pip": _read_json_output(pip, f"{phase} pip inspect"), "freeze": freeze.stdout}


def _source_record(source, evidence_dir, phase):
    head = _run(("git", "rev-parse", "HEAD"), source, evidence_dir, f"{phase}-source-head").stdout.strip()
    tree = _run(("git", "rev-parse", "HEAD^{tree}"), source, evidence_dir, f"{phase}-source-tree").stdout.strip()
    status = _run(("git", "status", "--porcelain=v1", "--untracked-files=all"), source, evidence_dir, f"{phase}-source-status").stdout
    digest = _tracked_digest(source)
    _exclusive_write(evidence_dir / f"{phase}-source-record.json", json.dumps({"phase": phase, "source": str(Path(source).resolve()), "head": head, "tree": tree, "tracked_digest": digest, "status": status}, indent=2) + "\n")
    return {"head": head, "tree": tree, "tracked_digest": digest, "status": status}


def _runtime(neutral, env_prefix, evidence_dir, phase, expected_source):
    result = _run((str(Path(env_prefix) / "bin/python"), "-c", RUNTIME_SCRIPT), neutral, evidence_dir, f"{phase}-runtime", {"CANDIDATE_EXPECTED_SOURCE": str(expected_source)})
    return _read_json_output(result, f"{phase} runtime")


def _compare_boundaries(before, after, before_source, after_source):
    validate_conda_inventory(before["conda"], after["conda"], before["explicit"], after["explicit"])
    validate_pip_inventory(before["pip"], after["pip"], before_source, after_source)
    return {"conda": len(conda_owned(before["conda"])), "pip": len(pip_records(after["pip"]))}


def _check_phase(source, env_prefix, evidence_dir, phase, baseline_xml, candidate=False):
    settings = {"NUMBA_JIT_COVERAGE": "1", "NUMBA_DISABLE_JIT": "1", "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "NUMBA_NUM_THREADS": "1"}
    for label, command in CHECKS:
        _run(command if label != "pytest" else command + ("--junitxml", str(Path(evidence_dir) / f"{phase}.xml"),), source, evidence_dir, f"{phase}-{label}", settings)
    xml = Path(evidence_dir) / f"{phase}.xml"
    if not xml.exists():
        raise FileNotFoundError(xml)
    validate_xml(xml, baseline_xml, candidate=candidate)
    coverage = Path(source) / ".coverage"
    if not coverage.exists() or coverage.stat().st_size == 0:
        raise ValueError(f"{phase} coverage is missing")
    target = Path(evidence_dir) / f"{phase}-coverage.data"
    shutil.copyfile(coverage, target)
    if target.stat().st_size == 0:
        raise ValueError(f"{phase} coverage is empty")


def artifact_manifest(root, output):
    root, output = Path(root), Path(output)
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path != output:
            rows.append({"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
    _exclusive_write(output, json.dumps(rows, indent=2) + "\n")
    return rows


def main():
    task = Path(os.environ.get("CANDIDATE_TASK_DIR", tempfile.mkdtemp(prefix="cadquery-candidate-"))).resolve()
    evidence = task / "evidence" / os.environ.get("GITHUB_RUN_ID", "local") / os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    baseline = Path(os.environ.get("CANDIDATE_BASELINE_SOURCE", task / "baseline")).resolve()
    candidate = Path(os.environ.get("CANDIDATE_SOURCE", task / "candidate")).resolve()
    neutral = task / "neutral"
    env_prefix = Path(os.environ.get("CANDIDATE_ENV", task / "env")).resolve()
    baseline_xml = evidence / "baseline-pytest.xml"
    primary = None
    secondary = []
    final_candidate_inventory = None
    evidence.mkdir(parents=True, exist_ok=True)
    try:
        _exclusive_write(evidence / "run-identity.json", json.dumps({"run_id": os.environ.get("GITHUB_RUN_ID", "local"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"), "payload_sha": os.environ.get("GITHUB_SHA", "unknown"), "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", "local"), "runner_os": os.name}, indent=2) + "\n")
        _run(("git", "rev-parse", "HEAD"), Path.cwd(), evidence, "payload-head")
        _run(("git", "fetch", "--no-tags", "--depth=4", "origin", PR_HEAD, MASTER_HEAD), candidate, evidence, "fetch-parents")
        for name, ref in (("pr-parent", PR_HEAD), ("master-parent", MASTER_HEAD)):
            parent = _run(("git", "rev-parse", f"{ref}^{{commit}}"), candidate, evidence, name)
            if parent.stdout.strip():
                _require_output(parent, ref, name)
        merge_base = _run(("git", "merge-base", PR_HEAD, MASTER_HEAD), candidate, evidence, "merge-base")
        if merge_base.stdout.strip():
            _require_output(merge_base, "9a6a705fe73ae94300974a3c668719f907b6353f", "merge-base")
        _run(("git", "checkout", "--detach", MASTER_HEAD), baseline, evidence, "checkout-baseline")
        if _tracked_digest(baseline) != BASE_SOURCE_HASH:
            raise ValueError("baseline source digest mismatch")
        _source_record(baseline, evidence, "baseline")
        mamba = os.environ.get("CANDIDATE_MAMBA", "mamba")
        _run((mamba, "env", "create", "--yes", "--prefix", str(env_prefix), "--file", str(baseline / "environment.yml")), baseline, evidence, "solve-environment")
        neutral.mkdir(parents=True, exist_ok=True)
        runtime = _runtime(neutral, env_prefix, evidence, "baseline", baseline)
        validate_runtime(runtime, env_prefix, baseline, "baseline")
        first = _inventory(baseline, env_prefix, evidence, "baseline", "before")
        _check_phase(baseline, env_prefix, evidence, "baseline", baseline_xml)
        shutil.copyfile(evidence / "baseline.xml", baseline_xml)
        validate_xml(baseline_xml)
        second = _inventory(baseline, env_prefix, evidence, "baseline", "after")
        _compare_boundaries(first, second, baseline, baseline)
        _run(("git", "merge", "--no-ff", "--no-commit", "--strategy=ort", MASTER_HEAD), candidate, evidence, "merge-candidate")
        metadata_dir = Path(__file__).resolve().parent
        metadata = json.loads((metadata_dir / "merge-metadata.json").read_text())
        raw = (metadata_dir / "merge-commit.raw").read_bytes()
        message = (metadata_dir / "merge-message.txt").read_bytes()
        validate_merge_metadata(metadata, raw, message)
        _run(("git", "diff", "--check"), candidate, evidence, "candidate-precommit-diff")
        _run(("git", "diff", "--cached", "--check"), candidate, evidence, "candidate-precommit-index")
        _run(("git", "diff", "--name-only", "--diff-filter=U"), candidate, evidence, "candidate-unresolved")
        _run(("git", "commit", "--no-verify", "--cleanup=verbatim", "--file", str(metadata_dir / "merge-message.txt")), candidate, evidence, "candidate-commit", {"GIT_AUTHOR_NAME": metadata["author_name"], "GIT_AUTHOR_EMAIL": metadata["author_email"], "GIT_COMMITTER_NAME": metadata["committer_name"], "GIT_COMMITTER_EMAIL": metadata["committer_email"], "GIT_AUTHOR_DATE": f"{metadata['author_timestamp']} {metadata['author_offset']}", "GIT_COMMITTER_DATE": f"{metadata['committer_timestamp']} {metadata['committer_offset']}"})
        candidate_head = _run(("git", "rev-parse", "HEAD"), candidate, evidence, "candidate-head")
        if candidate_head.stdout.strip():
            _require_output(candidate_head, MERGE_HEAD, "candidate HEAD")
        candidate_merge_head = _run(("git", "rev-parse", "MERGE_HEAD"), candidate, evidence, "candidate-merge-head")
        if candidate_merge_head.stdout.strip():
            _require_output(candidate_merge_head, MASTER_HEAD, "candidate MERGE_HEAD")
        raw_result = _run(("git", "cat-file", "commit", "HEAD"), candidate, evidence, "candidate-raw-commit")
        if raw_result.stdout and raw_result.stdout.encode() != raw:
            raise ValueError("replayed commit bytes differ")
        candidate_tree = _run(("git", "write-tree"), candidate, evidence, "candidate-tree")
        if candidate_tree.stdout.strip():
            _require_output(candidate_tree, MERGE_TREE, "candidate tree")
        if (baseline / "environment.yml").exists() and (candidate / "environment.yml").exists() and baseline.joinpath("environment.yml").read_bytes() != candidate.joinpath("environment.yml").read_bytes():
            raise ValueError("baseline and candidate environment files differ")
        delta = _run(("git", "diff", "--name-only", MASTER_HEAD, "HEAD"), candidate, evidence, "candidate-delta").stdout.splitlines()
        if delta and delta != ["tests/test_free_functions.py"]:
            raise ValueError("candidate source delta changed")
        _source_record(candidate, evidence, "candidate")
        if _tracked_digest(candidate) != CANDIDATE_SOURCE_HASH:
            raise ValueError("candidate source digest mismatch")
        _run((str(env_prefix / "bin/python"), "-m", "pip", "install", "--no-index", "--no-deps", "--no-build-isolation", "--editable", str(candidate)), neutral, evidence, "candidate-install")
        runtime = _runtime(neutral, env_prefix, evidence, "candidate", candidate)
        validate_runtime(runtime, env_prefix, candidate, "candidate")
        third = _inventory(candidate, env_prefix, evidence, "candidate", "before")
        _compare_boundaries(second, third, baseline, candidate)
        _check_phase(candidate, env_prefix, evidence, "candidate", baseline_xml, candidate=True)
        fourth = _inventory(candidate, env_prefix, evidence, "candidate", "after")
        _compare_boundaries(third, fourth, candidate, candidate)
    except BaseException as exc:
        primary = exc
    finally:
        try:
            _inventory(baseline, env_prefix, evidence, "final", "baseline")
        except BaseException as exc:
            secondary.append(f"baseline export: {exc}")
        try:
            final_candidate_inventory = _inventory(candidate, env_prefix, evidence, "final", "candidate")
            if primary is None and "fourth" in locals():
                _compare_boundaries(fourth, final_candidate_inventory, candidate, candidate)
        except BaseException as exc:
            secondary.append(f"candidate export: {exc}")
        try:
            _exclusive_write(evidence / "secondary-errors.json", json.dumps(secondary, indent=2) + "\n")
            artifact_manifest(task, evidence / "artifact-manifest.json")
        except BaseException as exc:
            secondary.append(f"finalization: {exc}")
    if primary is not None:
        raise primary
    if secondary:
        raise RuntimeError("secondary finalization failures: " + "; ".join(secondary))
    return {"evidence": str(evidence), "status": "passed"}


if __name__ == "__main__":
    main()
