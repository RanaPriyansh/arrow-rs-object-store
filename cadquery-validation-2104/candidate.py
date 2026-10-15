"""Pure, import-safe Layer 1 validators for the CadQuery replay."""
import hashlib
import re
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
