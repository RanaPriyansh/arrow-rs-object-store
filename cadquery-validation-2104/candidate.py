import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

PR_HEAD = "5dfbf5c89932d9c438ba449e29732a6a56680aae"
MASTER_HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
MERGE_HEAD = "2b85056876c75d4380cf821aa4055d44963cccf7"
MERGE_TREE = "ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1"
SOURCE_HASH = "c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c"
BASELINE_RUN = "38646497682"
BASELINE_ARTIFACT = "11933066912"
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-candidate"
ARTIFACTS = TEMP / "artifacts"
MAMBA = TEMP / "miniforge" / "bin" / "mamba"
ENV = TEMP / "environment"


def cmd(args, **kwargs):
    print("COMMAND", json.dumps([str(x) for x in args]), flush=True)
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def capture(name, args, env):
    out, err = ARTIFACTS / f"{name}.stdout", ARTIFACTS / f"{name}.stderr"
    with out.open("w") as stdout, err.open("w") as stderr:
        result = subprocess.run([str(x) for x in args], cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
    (ARTIFACTS / f"{name}.exit").write_text(f"{result.returncode}\n")
    return result.returncode


def digest_tree():
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    return len(paths), digest.hexdigest()


def source_identity(stage):
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == MERGE_HEAD
    assert subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip() == MERGE_TREE
    assert not subprocess.check_output(["git", "diff", "--name-only"])
    count, digest = digest_tree()
    assert count == 219 and digest == SOURCE_HASH
    (ARTIFACTS / f"source-identity-{stage}.json").write_text(json.dumps({"stage": stage, "head": MERGE_HEAD, "tree": MERGE_TREE, "tracked_files": count, "tracked_digest": digest}, indent=2) + "\n")


def download_baseline():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    token = os.environ["GITHUB_TOKEN"]
    url = f"https://api.github.com/repos/RanaPriyansh/arrow-rs-object-store/actions/artifacts/{BASELINE_ARTIFACT}/zip"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    archive = TEMP / "baseline-artifact.zip"
    with urllib.request.urlopen(request) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    extracted = TEMP / "baseline"
    extracted.mkdir()
    with zipfile.ZipFile(archive) as source:
        source.extractall(extracted)
    manifest = json.loads((extracted / "artifact-manifest.json").read_text())
    for relative, expected in manifest.items():
        actual = hashlib.sha256((extracted / relative).read_bytes()).hexdigest()
        assert actual == expected, relative
    shutil.copytree(extracted, ARTIFACTS / "baseline", dirs_exist_ok=True)
    (ARTIFACTS / "baseline-binding.json").write_text(json.dumps({"run": BASELINE_RUN, "artifact": BASELINE_ARTIFACT, "manifest_entries": len(manifest)}, indent=2) + "\n")
    return extracted


def reconstruct_merge():
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == PR_HEAD
    cmd(["git", "fetch", "--no-tags", "https://github.com/CadQuery/cadquery.git", MASTER_HEAD])
    cmd(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "merge", "--no-ff", "--no-commit", "--strategy=ort", MASTER_HEAD])
    message = TEMP / "merge-message.txt"
    message.write_text("Merge commit '" + MASTER_HEAD + "'\n\n")
    commit_env = os.environ.copy()
    commit_env.update({"GIT_AUTHOR_NAME": "RanaPriyansh", "GIT_AUTHOR_EMAIL": "priyanshrana18@gmail.com", "GIT_AUTHOR_DATE": "@1792016770 +0530", "GIT_COMMITTER_NAME": "RanaPriyansh", "GIT_COMMITTER_EMAIL": "priyanshrana18@gmail.com", "GIT_COMMITTER_DATE": "@1792016770 +0530"})
    cmd(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "i18n.commitEncoding=UTF-8", "commit", "--no-verify", "--cleanup=verbatim", "--file", message], env=commit_env)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == MERGE_HEAD
    assert subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip() == MERGE_TREE
    (ARTIFACTS / "merge-commit.raw").write_bytes(subprocess.check_output(["git", "cat-file", "commit", "HEAD"]))


def main():
    TEMP.mkdir(parents=True, exist_ok=True); ARTIFACTS.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy(); env.update({"MAMBA_ROOT_PREFIX": str(TEMP / "mamba-root"), "CONDA_PKGS_DIRS": str(TEMP / "conda-pkgs"), "NUMBA_JIT_COVERAGE": "1", "NUMBA_DISABLE_JIT": "1", "GITHUB_TOKEN": os.environ["GITHUB_TOKEN"]})
    baseline = download_baseline()
    reconstruct_merge(); source_identity("merged")
    assert capture("conda-create", [MAMBA, "create", "--yes", "--prefix", ENV, "--file", baseline / "export-conda-explicit.stdout"], env) == 0
    assert capture("pip-replay", [MAMBA, "run", "--prefix", ENV, "python", "-m", "pip", "install", "--no-index", "--find-links", baseline / "wheels", "--no-deps", "--require-hashes", "--requirement", baseline / "pip-only-hashed-requirements.txt"], env) == 0
    assert capture("candidate-editable", [MAMBA, "run", "--prefix", ENV, "python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "--editable", "."], env) == 0
    for name, args in (("conda-list", [MAMBA, "list", "--prefix", ENV, "--json"]), ("pip-inspect", [MAMBA, "run", "--prefix", ENV, "python", "-m", "pip", "inspect"]), ("python-version", [MAMBA, "run", "--prefix", ENV, "python", "--version"])):
        assert capture(name, args, env) == 0
    checks = (("black", [MAMBA, "run", "--prefix", ENV, "black", ".", "--diff", "--check"]), ("mypy", [MAMBA, "run", "--prefix", ENV, "mypy", "cadquery"]), ("pytest", [MAMBA, "run", "--prefix", ENV, "pytest", "-v", "--gui", "--cov", "--junitxml", ARTIFACTS / "pytest.xml"]))
    failures = [capture(name, args, env) for name, args in checks]
    (ARTIFACTS / "environment-resolved.json").write_text(subprocess.check_output([MAMBA, "env", "export", "--prefix", ENV, "--json"], env=env, text=True))
    if any(failures): raise SystemExit(1)


try:
    main()
finally:
    source_identity("final")
