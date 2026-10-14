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

HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
SOURCE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6"
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


def source_identity(stage):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == HEAD
    assert not subprocess.check_output(["git", "diff", "--name-only"])
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"])
    paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        digest.update(raw + b"\0" + (ROOT / os.fsdecode(raw)).read_bytes() + b"\0")
    assert len(paths) == 219
    assert digest.hexdigest() == SOURCE_HASH
    (ARTIFACTS / f"source-identity-{stage}.json").write_text(json.dumps({
        "stage": stage,
        "head": HEAD,
        "tracked_files": len(paths),
        "tracked_digest": digest.hexdigest(),
    }, indent=2, sort_keys=True) + "\n")
    print("SOURCE_IDENTITY", stage, HEAD, len(paths), digest.hexdigest(), flush=True)


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


def package_exports(conda, mamba, environment, env):
    exports = [
        ("conda-explicit", [conda, "list", "--prefix", environment, "--explicit", "--md5"]),
        ("conda-list", [conda, "list", "--prefix", environment, "--json"]),
        ("environment-resolved", [conda, "env", "export", "--prefix", environment, "--json"]),
        ("pip-freeze", [mamba, "run", "--prefix", environment, "python", "-m", "pip", "freeze", "--all"]),
        ("pip-inspect", [mamba, "run", "--prefix", environment, "python", "-m", "pip", "inspect"]),
    ]
    failures = [capture(f"export-{name}", args, env) for name, args in exports]
    assert not any(failures)
    conda_json = json.loads((ARTIFACTS / "export-conda-list.stdout").read_text())
    json.loads((ARTIFACTS / "export-environment-resolved.stdout").read_text())
    inspect_json = json.loads((ARTIFACTS / "export-pip-inspect.stdout").read_text())
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
    (ARTIFACTS / "pip-only-requirements.txt").write_text("\n".join(sorted(pip_only)) + "\n")
    wheelhouse = ARTIFACTS / "wheels"
    wheelhouse.mkdir()
    assert capture("pip-wheel-build", [mamba, "run", "--prefix", environment, "python", "-m", "pip", "wheel", "--wheel-dir", wheelhouse, "--no-deps", "--requirement", ARTIFACTS / "pip-only-requirements.txt"], env) == 0
    expected = {}
    for item in inspect_json.get("installed", []):
        name = item["metadata"]["name"].lower().replace("_", "-")
        if name == "cadquery" or name in conda_names:
            continue
        expected[name] = item["metadata"]["version"]
    actual = {}
    for wheel in sorted(wheelhouse.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            metadata = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            fields = dict(line.split(": ", 1) for line in archive.read(metadata).decode().splitlines() if ": " in line)
        key = fields["Name"].lower().replace("_", "-")
        assert key not in actual
        actual[key] = fields["Version"]
    assert actual == expected
    black_requirement = next(line for line in pip_only if line.startswith("black @ "))
    assert black_requirement.startswith("black @ git+https://github.com/cadquery/black.git@")
    hashed = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            metadata = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            fields = dict(line.split(": ", 1) for line in archive.read(metadata).decode().splitlines() if ": " in line)
        hashed.append(f"{fields['Name']}=={fields['Version']} --hash=sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}")
    (ARTIFACTS / "pip-only-hashed-requirements.txt").write_text("\n".join(sorted(hashed)) + "\n")


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


def main():
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    mamba = TEMP / "miniforge" / "bin" / "mamba"
    conda = TEMP / "miniforge" / "bin" / "conda"
    environment = TEMP / "environment"
    env = os.environ.copy()
    env.update({"MAMBA_ROOT_PREFIX": str(TEMP / "mamba-root"), "CONDA_PKGS_DIRS": str(TEMP / "conda-pkgs")})
    env.update({"NUMBA_JIT_COVERAGE": "1", "NUMBA_DISABLE_JIT": "1"})
    env.update({key: "1" for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMBA_NUM_THREADS")})
    miniforge_download = TEMP.parent / "cadquery-baseline-miniforge"
    copy_if_present(miniforge_download / "Miniforge.sh", ARTIFACTS / "Miniforge.sh")
    copy_if_present(miniforge_download / "Miniforge.sha256", ARTIFACTS / "Miniforge.sha256")
    shutil.copy2(ROOT / "environment.yml", ARTIFACTS / "environment.yml")
    (ARTIFACTS / "run-identities.json").write_text(json.dumps({
        "payload_sha": os.environ.get("GITHUB_SHA"),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "launcher_python": sys.version,
    }, indent=2, sort_keys=True) + "\n")
    solve = capture("environment-solve", [mamba, "env", "create", "--yes", "--prefix", environment, "--file", ROOT / "environment.yml"], env)
    if solve:
        artifact_manifest()
        raise SystemExit(solve)
    validate_conda_identity(environment)
    runtime_identity(mamba, environment, env)
    import_failure = validate_import_identity(mamba, environment, env)
    if import_failure:
        package_exports(conda, mamba, environment, env)
        raise SystemExit(import_failure)
    failures = []
    black_identity(mamba, environment, env)
    failures += [
        capture("black", [mamba, "run", "--prefix", environment, "black", ".", "--diff", "--check"], env),
        capture("mypy", [mamba, "run", "--prefix", environment, "mypy", "cadquery"], env),
        capture("pytest", [mamba, "run", "--prefix", environment, "pytest", "-v", "--gui", "--cov", "--junitxml", ARTIFACTS / "pytest.xml"], env),
    ]
    copy_if_present(ROOT / ".coverage", ARTIFACTS / "coverage.data")
    package_exports(conda, mamba, environment, env)
    if any(failures):
        raise SystemExit(1)


if __name__ == "__main__":
    source_identity("initial")
    try:
        main()
    finally:
        source_identity("final")
        artifact_manifest()
    print("CADQUERY_BASELINE_COMPLETE", round(time.monotonic() - START, 2), flush=True)
