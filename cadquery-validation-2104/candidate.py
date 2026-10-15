"""Pure Layer 1 validators for the CadQuery candidate replay.

The execution driver is intentionally deferred until independent review accepts these validators.
"""
import hashlib
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET

PR_HEAD = "5dfbf5c89932d9c438ba449e29732a6a56680aae"
MASTER_HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
MERGE_HEAD = "2b85056876c75d4380cf821aa4055d44963cccf7"
MERGE_TREE = "ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1"
BASE_SOURCE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6"
CANDIDATE_SOURCE_HASH = "c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c"
BLACK_COMMIT = "3395340200a1a3853d0ba52386c62ed4c5772b53"
BASELINE_CASES = 901
BASELINE_SKIPS = 3
ADDED_CASES = {
    "tests.test_free_functions::test_fillet_method_iterable_edges[list]",
    "tests.test_free_functions::test_fillet_method_iterable_edges[generator]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[list-None-0.98]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[generator-None-0.98]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[list-0.2-0.96]",
    "tests.test_free_functions::test_chamfer_method_iterable_edges[generator-0.2-0.96]",
}


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def pip_origin(record):
    return record.get("channel") == "pypi" or record.get("subdir") == "pypi" or record.get("build") == "pypi_0"


def conda_identity(record):
    return (canonical(record["name"]), record.get("version"), record.get("build"), record.get("build_number"), record.get("channel"), record.get("subdir"))


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
        raise ValueError({"missing": sorted(set(before) - set(after)), "extra": sorted(set(after) - set(before)), "changed": sorted(k for k in set(before) & set(after) if before[k] != after[k])})
    if explicit_set(baseline_explicit) != explicit_set(candidate_explicit):
        raise ValueError("conda explicit URL or hash changed")
    return {"packages": len(before), "pip_origin": sorted(canonical(r["name"]) for r in baseline_records if pip_origin(r)), "explicit": len(explicit_set(baseline_explicit))}


def pip_records(document):
    installed = document.get("installed", document if isinstance(document, list) else [])
    result = {}
    for item in installed:
        metadata = item.get("metadata", item)
        name = canonical(metadata["name"])
        if name in result:
            raise ValueError(f"duplicate pip package: {name}")
        result[name] = {"version": metadata.get("version"), "direct_url": item.get("direct_url"), "editable": bool(item.get("direct_url", {}).get("dir_info", {}).get("editable"))}
    return result


def validate_pip_inventory(baseline_document, candidate_document, baseline_source, candidate_source):
    before, after = pip_records(baseline_document), pip_records(candidate_document)
    if "cadquery" not in before or "cadquery" not in after:
        raise ValueError("CadQuery is missing")
    for name in set(before) | set(after):
        if name == "cadquery":
            continue
        if name not in before or name not in after or before[name]["version"] != after[name]["version"]:
            raise ValueError(f"pip package changed: {name}")
    if after["cadquery"]["version"] != before["cadquery"]["version"]:
        raise ValueError("CadQuery version changed")
    editable = after["cadquery"]["direct_url"] or {}
    if not editable.get("dir_info", {}).get("editable") or Path(editable.get("url", "")).resolve() != Path(candidate_source).resolve():
        raise ValueError("candidate CadQuery editable path is invalid")
    black = before.get("black", {})
    commit = (black.get("direct_url") or {}).get("vcs_info", {}).get("commit_id")
    if commit != BLACK_COMMIT:
        raise ValueError("Black provenance changed")
    return {"packages": len(after), "editable_source": str(Path(candidate_source).resolve()), "baseline_source": str(Path(baseline_source).resolve())}


def validate_runtime(runtime, env_prefix, source_path, phase):
    prefix = Path(env_prefix).resolve(); source = Path(source_path).resolve()
    if Path(runtime["python_executable"]).resolve().parent.parent != prefix:
        raise ValueError("Python executable is outside environment")
    if tuple(runtime["python_version"][:2]) < (3, 11):
        raise ValueError("unsupported Python")
    if runtime.get("ocp_version") != "8.0.1.1" or not Path(runtime["ocp_path"]).resolve().is_relative_to(prefix):
        raise ValueError("OCP runtime identity is invalid")
    if not Path(runtime["cadquery_path"]).resolve().is_relative_to(source):
        raise ValueError(f"{phase} CadQuery path is invalid")
    if runtime.get("black_commit") != BLACK_COMMIT:
        raise ValueError("Black commit is invalid")
    return {"phase": phase, "python": str(Path(runtime["python_executable"]).resolve()), "source": str(source)}


def testcase_ids(xml_path):
    root = ET.parse(xml_path).getroot(); suite = root.find("testsuite") or root
    cases = []
    for case in suite.findall("testcase"):
        cases.append({"id": case.attrib.get("classname", "") + "::" + case.attrib.get("name", ""), "skipped": case.find("skipped") is not None, "failed": case.find("failure") is not None, "errored": case.find("error") is not None})
    return suite, cases


def validate_xml(xml_path, baseline_xml=None, candidate=False):
    suite, cases = testcase_ids(xml_path); ids = [x["id"] for x in cases]
    if len(ids) != len(set(ids)) or any(x["failed"] or x["errored"] for x in cases): raise ValueError("duplicate or failed testcase")
    if not candidate:
        if len(ids) != BASELINE_CASES or sum(x["skipped"] for x in cases) != BASELINE_SKIPS: raise ValueError("baseline count or skips changed")
        return {"tests": len(ids), "skips": sum(x["skipped"] for x in cases), "ids": ids}
    base = validate_xml(baseline_xml, candidate=False); added = set(ids) - set(base["ids"])
    if set(base["ids"]) - set(ids) or added != ADDED_CASES: raise ValueError("candidate testcase identity mismatch")
    if any(x["skipped"] for x in cases if x["id"] in added): raise ValueError("new testcase skipped")
    return {"tests": len(ids), "skips": sum(x["skipped"] for x in cases), "added": sorted(added)}


def validate_merge_metadata(metadata, raw, message):
    expected = {"commit": MERGE_HEAD, "tree": MERGE_TREE, "first_parent": PR_HEAD, "second_parent": MASTER_HEAD, "author_name": "RanaPriyansh", "author_email": "priyanshrana18@gmail.com", "committer_name": "RanaPriyansh", "committer_email": "priyanshrana18@gmail.com", "author_timestamp": 1792016770, "committer_timestamp": 1792016770}
    for key, value in expected.items():
        if metadata.get(key) != value: raise ValueError(f"merge metadata mismatch: {key}")
    if hashlib.sha256(raw).hexdigest() != metadata["raw_sha256"] or hashlib.sha256(message).hexdigest() != metadata["message_sha256"]: raise ValueError("merge metadata hash mismatch")
    if not raw.startswith(b"tree " + MERGE_TREE.encode() + b"\nparent " + PR_HEAD.encode() + b"\nparent " + MASTER_HEAD.encode() + b"\n"): raise ValueError("merge parent order mismatch")
    return {"commit": metadata["commit"], "tree": metadata["tree"], "raw_sha256": metadata["raw_sha256"], "message_sha256": metadata["message_sha256"]}
