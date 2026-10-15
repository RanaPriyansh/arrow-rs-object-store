import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET

HEAD = "2b85056876c75d4380cf821aa4055d44963cccf7"
PR_HEAD = "5dfbf5c89932d9c438ba449e29732a6a56680aae"
MASTER_HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
BASE_SOURCE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6"
SOURCE_HASH = "c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c"
BLACK_REPOSITORY = "https://github.com/cadquery/black.git"
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-baseline"
ARTIFACTS = TEMP / "artifacts"
START = time.monotonic()


def command(args):
    args = [str(arg) for arg in args]
    print("COMMAND", json.dumps(args), flush=True)
    return args


def capture(name, args, env, cwd=ROOT):
    args = command(args)
    stdout = ARTIFACTS / f"{name}.stdout"
    stderr = ARTIFACTS / f"{name}.stderr"
    with stdout.open("x") as out, stderr.open("x") as err:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=err)
    (ARTIFACTS / f"{name}.exit").write_text(f"{result.returncode}\n")
    print("RESULT", name, result.returncode, flush=True)
    return result.returncode


def copy_if_present(source, destination):
    source = Path(source)
    if source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def source_identity(stage, expected_head=HEAD, expected_hash=SOURCE_HASH):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == expected_head
    assert not subprocess.check_output(["git", "diff", "--name-only"])
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"])
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    assert len(paths) == 219
    assert digest.hexdigest() == expected_hash
    (ARTIFACTS / f"source-identity-{stage}.json").write_text(json.dumps({
        "stage": stage,
        "head": expected_head,
        "tracked_files": len(paths),
        "tracked_digest": digest.hexdigest(),
    }, indent=2, sort_keys=True) + "\n")
    print("SOURCE_IDENTITY", stage, expected_head, len(paths), digest.hexdigest(), flush=True)


def conda_records(environment):
    return [json.loads(path.read_text()) for path in sorted((environment / "conda-meta").glob("*.json"))]


def validate_import_identity(mamba, environment, env):
    code = "import cadquery, importlib.metadata as m, OCP; print(cadquery.__file__); print(OCP.__file__); print(m.version('cadquery'))"
    result = subprocess.run(command([mamba, "run", "--prefix", environment, "python", "-c", code]), cwd=ROOT, env=env, capture_output=True, text=True)
    (ARTIFACTS / "import-identity.stdout").write_text(result.stdout)
    (ARTIFACTS / "import-identity.stderr").write_text(result.stderr)
    (ARTIFACTS / "import-identity.exit").write_text(f"{result.returncode}\n")
    if result.returncode:
        return result.returncode
    cadquery_path, ocp_path, _ = result.stdout.strip().splitlines()
    assert Path(cadquery_path).resolve().is_relative_to(ROOT)
    assert Path(ocp_path).resolve().is_relative_to(Path(environment).resolve())
    (ARTIFACTS / "imported-source-paths.json").write_text(json.dumps({"cadquery": cadquery_path, "OCP": ocp_path}, indent=2) + "\n")
    return 0


def validate_conda_identity(environment):
    records = conda_records(environment)
    ocp = [record for record in records if record.get("name") == "ocp"]
    assert len(ocp) == 1 and ocp[0]["version"] == "8.0.1.1"
    payload = {key: ocp[0].get(key) for key in ("name", "version", "build", "build_number", "channel")}
    (ARTIFACTS / "ocp-conda-identity.json").write_text(json.dumps(payload, indent=2) + "\n")


def black_identity(mamba, environment, env):
    code = "import importlib.metadata as m; print(m.distribution('black')._path / 'direct_url.json')"
    result = subprocess.run(command([mamba, "run", "--prefix", environment, "python", "-c", code]), cwd=ROOT, env=env, capture_output=True, text=True)
    (ARTIFACTS / "black-direct-url-command.stdout").write_text(result.stdout)
    (ARTIFACTS / "black-direct-url-command.stderr").write_text(result.stderr)
    (ARTIFACTS / "black-direct-url-command.exit").write_text(f"{result.returncode}\n")
    assert result.returncode == 0
    direct_url = Path(result.stdout.strip())
    assert direct_url.name == "direct_url.json" and direct_url.is_file()
    data = json.loads(direct_url.read_text())
    assert data.get("url") == BLACK_REPOSITORY
    vcs = data.get("vcs_info", {})
    assert vcs.get("vcs") == "git" and vcs.get("requested_revision") == "cq"
    assert re.fullmatch(r"[0-9a-f]{40}", vcs.get("commit_id", ""))
    shutil.copy2(direct_url, ARTIFACTS / "black-direct-url.json")
    (ARTIFACTS / "black-identity.json").write_text(json.dumps(data, indent=2) + "\n")


def package_exports(conda, mamba, environment, env, prefix=""):
    exports = [
        ("conda-explicit", [conda, "list", "--prefix", environment, "--explicit", "--md5"]),
        ("conda-list", [conda, "list", "--prefix", environment, "--json"]),
        ("environment-resolved", [conda, "env", "export", "--prefix", environment, "--json"]),
        ("pip-freeze", [mamba, "run", "--prefix", environment, "python", "-m", "pip", "freeze", "--all"]),
        ("pip-inspect", [mamba, "run", "--prefix", environment, "python", "-m", "pip", "inspect"]),
    ]
    failures = [capture(f"{prefix}export-{name}", args, env) for name, args in exports]
    assert not any(failures)
    conda_json = json.loads((ARTIFACTS / f"{prefix}export-conda-list.stdout").read_text())
    json.loads((ARTIFACTS / f"{prefix}export-environment-resolved.stdout").read_text())
    inspect_json = json.loads((ARTIFACTS / f"{prefix}export-pip-inspect.stdout").read_text())
    conda_names = {
        record["name"].lower().replace("_", "-")
        for record in conda_json
        if record.get("channel") not in ("pypi", "") and record.get("subdir") != "pypi"
    }
    pip_only = []
    for item in inspect_json.get("installed", []):
        name = item["metadata"]["name"].lower().replace("_", "-")
        if name == "cadquery" or name in conda_names:
            continue
        direct_url = item.get("direct_url", {})
        vcs = direct_url.get("vcs_info", {})
        if vcs.get("vcs") == "git":
            pip_only.append(f"{name} @ git+{direct_url['url']}@{vcs['commit_id']}")
        else:
            pip_only.append(f"{name}=={item['metadata']['version']}")
    (ARTIFACTS / f"{prefix}pip-only-requirements.txt").write_text("\n".join(sorted(pip_only)) + "\n")
    return

def artifact_manifest():
    manifest = {}
    for path in sorted(ARTIFACTS.rglob("*")):
        if path.is_file() and path.name != "artifact-manifest.json":
            manifest[str(path.relative_to(ARTIFACTS))] = hashlib.sha256(path.read_bytes()).hexdigest()
    (ARTIFACTS / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def runtime_identity(mamba, environment, env):
    commands = {
        "conda_python": [mamba, "run", "--prefix", environment, "python", "--version"],
        "mypy": [mamba, "run", "--prefix", environment, "mypy", "--version"],
        "black": [mamba, "run", "--prefix", environment, "black", "--version"],
    }
    versions = {}
    for name, args in commands.items():
        result = subprocess.run(command(args), cwd=ROOT, env=env, capture_output=True, text=True)
        assert result.returncode == 0
        versions[name] = (result.stdout + result.stderr).strip()
    identities = json.loads((ARTIFACTS / "run-identities.json").read_text())
    identities.update(versions)
    if "python" in identities:
        identities["launcher_python"] = identities.pop("python")
    (ARTIFACTS / "run-identities.json").write_text(json.dumps(identities, indent=2, sort_keys=True) + "\n")


def merge_candidate():
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == MASTER_HEAD
    subprocess.run(["git", "fetch", "--no-tags", "--depth=4", "https://github.com/CadQuery/cadquery.git", PR_HEAD, MASTER_HEAD], check=True)
    assert subprocess.check_output(["git", "merge-base", PR_HEAD, MASTER_HEAD], text=True).strip() == "9a6a705fe73ae94300974a3c668719f907b6353f"
    subprocess.run(["git", "checkout", "--detach", PR_HEAD], check=True)
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "merge", "--no-ff", "--no-commit", "--strategy=ort", MASTER_HEAD], check=True)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == PR_HEAD
    assert subprocess.check_output(["git", "rev-parse", "MERGE_HEAD"], text=True).strip() == MASTER_HEAD
    message = ROOT / "../validation/cadquery-validation-2104/merge-message.txt"
    commit_env = os.environ.copy()
    commit_env.update({"GIT_AUTHOR_NAME":"RanaPriyansh", "GIT_AUTHOR_EMAIL":"priyanshrana18@gmail.com", "GIT_AUTHOR_DATE":"@1792016770 +0530", "GIT_COMMITTER_NAME":"RanaPriyansh", "GIT_COMMITTER_EMAIL":"priyanshrana18@gmail.com", "GIT_COMMITTER_DATE":"@1792016770 +0530"})
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "i18n.commitEncoding=UTF-8", "commit", "--no-verify", "--cleanup=verbatim", "--file", message], check=True, env=commit_env)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == HEAD
    assert subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip() == "ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1"
    raw = subprocess.check_output(["git", "cat-file", "commit", "HEAD"])
    assert raw == (ROOT / "../validation/cadquery-validation-2104/merge-commit.raw").read_bytes()


def package_map(path):
    data = json.loads(Path(path).read_text())
    return {re.sub(r"[-_.]+", "-", x["metadata"]["name"].lower()): x["metadata"]["version"] for x in data["installed"]}


def compare_inventories(before, after, source_path):
    b, a = package_map(before), package_map(after)
    for name in ("cadquery",): b.pop(name, None)
    a.pop("cadquery", None)
    result = {"missing": sorted(set(b)-set(a)), "extra": sorted(set(a)-set(b)), "changed": sorted(k for k in set(a)&set(b) if a[k] != b[k])}
    (ARTIFACTS / "inventory-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    assert not any(result.values())


def validate_candidate_xml(path, baseline_ids):
    root = ET.parse(path).getroot(); suite = root.find("testsuite")
    assert suite is not None and int(suite.attrib["failures"]) == 0 and int(suite.attrib["errors"]) == 0
    ids = [case.attrib.get("classname", "") + "::" + case.attrib.get("name", "") for case in suite.findall("testcase")]
    assert len(ids) == len(set(ids)) and set(baseline_ids).issubset(ids)
    added = [x for x in ids if x not in baseline_ids]
    assert len(added) == 6 and all("iterable_edges" in x for x in added)
    return {"tests": len(ids), "skipped": int(suite.attrib.get("skipped", 0)), "added": added}


def main():
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir(parents=True, exist_ok=True); ARTIFACTS.mkdir(parents=True, exist_ok=True)
    mamba = TEMP / "miniforge" / "bin" / "mamba"; conda = TEMP / "miniforge" / "bin" / "conda"; environment = TEMP / "environment"
    env = os.environ.copy(); env.update({"MAMBA_ROOT_PREFIX":str(TEMP/"mamba-root"), "CONDA_PKGS_DIRS":str(TEMP/"conda-pkgs"), "NUMBA_JIT_COVERAGE":"1", "NUMBA_DISABLE_JIT":"1"}); env.update({k:"1" for k in ("OMP_NUM_THREADS","OPENBLAS_NUM_THREADS","MKL_NUM_THREADS","NUMBA_NUM_THREADS")})
    shutil.copy2(ROOT / "environment.yml", ARTIFACTS / "environment.yml")
    source_identity("baseline", MASTER_HEAD, BASE_SOURCE_HASH)
    assert capture("environment-solve", [mamba,"env","create","--yes","--prefix",environment,"--file",ROOT/"environment.yml"], env) == 0
    validate_conda_identity(environment); runtime_identity(mamba, environment, env)
    assert validate_import_identity(mamba, environment, env) == 0; black_identity(mamba, environment, env)
    baseline_failures=[capture("baseline-black",[mamba,"run","--prefix",environment,"black",".","--diff","--check"],env),capture("baseline-mypy",[mamba,"run","--prefix",environment,"mypy","cadquery"],env),capture("baseline-pytest",[mamba,"run","--prefix",environment,"pytest","-v","--gui","--cov","--junitxml",ARTIFACTS/"baseline.xml"],env)]
    package_exports(conda,mamba,environment,env,"baseline-"); assert not any(baseline_failures)
    baseline_root=ET.parse(ARTIFACTS/"baseline.xml").getroot().find("testsuite"); baseline_ids=[c.attrib.get("classname","")+"::"+c.attrib.get("name","") for c in baseline_root.findall("testcase")]
    merge_candidate(); source_identity("candidate", HEAD, SOURCE_HASH)
    assert capture("candidate-editable",[mamba,"run","--prefix",environment,"python","-m","pip","install","--no-index","--no-deps","--no-build-isolation","--editable","."],env)==0
    assert capture("candidate-pip",[mamba,"run","--prefix",environment,"python","-m","pip","inspect"],env)==0
    failures=[capture("candidate-black",[mamba,"run","--prefix",environment,"black",".","--diff","--check"],env),capture("candidate-mypy",[mamba,"run","--prefix",environment,"mypy","cadquery"],env),capture("candidate-pytest",[mamba,"run","--prefix",environment,"pytest","-v","--gui","--cov","--junitxml",ARTIFACTS/"candidate.xml"],env)]
    validate_candidate_xml(ARTIFACTS/"candidate.xml", baseline_ids); copy_if_present(ROOT/".coverage",ARTIFACTS/"coverage.data"); package_exports(conda,mamba,environment,env,"candidate-")
    if any(failures): raise SystemExit(1)


if __name__ == "__main__":
    main()
