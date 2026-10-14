import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import shutil


HEAD = "5f5bc62b255f62e3512105740025361b6c31eddd"
SOURCE_HASH = "054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c"
ROOT = Path.cwd().resolve()
TEMP = Path(os.environ["RUNNER_TEMP"]).resolve() / "cadquery-baseline"
ARTIFACTS = TEMP / "artifacts"
START = time.monotonic()


def run(args, **kwargs):
    print("COMMAND", json.dumps([str(arg) for arg in args]), flush=True)
    return subprocess.run(args, check=False, **kwargs)


def run_logged(name, args, env):
    log = ARTIFACTS / f"{name}.log"
    exit_file = ARTIFACTS / f"{name}.exit"
    with log.open("x") as stream:
        stream.write("COMMAND " + json.dumps([str(arg) for arg in args]) + "\n")
        result = subprocess.run(args, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    exit_file.write_text(f"{result.returncode}\n")
    print("CHECK", name, result.returncode, flush=True)
    return result.returncode


def copy_if_present(source, destination):
    source = Path(source)
    if source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def export_environment(mamba, environment, env):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    commands = [
        ("conda-explicit.txt", [mamba, "list", "--prefix", str(environment), "--explicit"]),
        ("conda-list.json", [mamba, "list", "--prefix", str(environment), "--json"]),
        ("environment-resolved.json", [mamba, "env", "export", "--prefix", str(environment), "--json"]),
        ("pip-freeze.txt", [mamba, "run", "--prefix", str(environment), "python", "-m", "pip", "freeze", "--all"]),
        ("pip-inspect.json", [mamba, "run", "--prefix", str(environment), "python", "-m", "pip", "inspect"]),
    ]
    for filename, command in commands:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        (ARTIFACTS / filename).write_text(result.stdout + result.stderr)
        (ARTIFACTS / f"{filename}.exit").write_text(f"{result.returncode}\n")
    black_url = subprocess.run(
        [mamba, "run", "--prefix", str(environment), "python", "-c", "import importlib.metadata as m; print(m.distribution('black')._path / 'direct_url.json')"],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    (ARTIFACTS / "black-direct-url-command.log").write_text(black_url.stdout + black_url.stderr)
    if black_url.returncode == 0:
        copy_if_present(black_url.stdout.strip(), ARTIFACTS / "black-direct-url.json")
    (ARTIFACTS / "source-environment.yml.sha256").write_text(
        hashlib.sha256((ROOT / "environment.yml").read_bytes()).hexdigest() + "  environment.yml\n"
    )
    manifest = {}
    for path in sorted(ARTIFACTS.iterdir()):
        if path.name == "artifact-manifest.json":
            continue
        if path.is_file():
            manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (ARTIFACTS / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


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
    for key in ("CONDA_PREFIX", "CONDA_PY", "READTHEDOCS", "APPVEYOR"):
        assert key not in os.environ, key
    TEMP.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    mamba_root = TEMP / "miniforge"
    mamba = mamba_root / "bin" / "mamba"
    environment = TEMP / "environment"
    env = os.environ.copy()
    env.update({"MAMBA_ROOT_PREFIX": str(TEMP / "mamba-root"), "CONDA_PKGS_DIRS": str(TEMP / "conda-pkgs")})
    env.update({"NUMBA_JIT_COVERAGE": "1", "NUMBA_DISABLE_JIT": "1"})
    env.update({key: "1" for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMBA_NUM_THREADS")})
    miniforge_download = TEMP.parent / "cadquery-baseline-miniforge"
    copy_if_present(miniforge_download / "Miniforge.sh", ARTIFACTS / "Miniforge.sh")
    copy_if_present(miniforge_download / "Miniforge.sha256", ARTIFACTS / "Miniforge.sha256")
    solve = [str(mamba), "env", "create", "--yes", "--prefix", str(environment), "--file", str(ROOT / "environment.yml")]
    solve_result = run(solve, cwd=ROOT, env=env)
    (ARTIFACTS / "environment-solve.exit").write_text(f"{solve_result.returncode}\n")
    if solve_result.returncode != 0:
        raise SystemExit(solve_result.returncode)
    python = [str(mamba), "run", "--prefix", str(environment), "python"]
    identity("before-tests")
    import_check = python + ["-c", "from pathlib import Path; import cadquery, importlib.metadata as m; assert Path(cadquery.__file__).resolve().is_relative_to(Path.cwd().resolve()); assert m.version('cadquery-ocp') == '8.0.1.1'; print('IMPORT_IDENTITY', cadquery.__file__, m.version('cadquery-ocp'))"]
    failures = [run_logged("import", import_check, env)]
    failures.append(run_logged("black", [str(mamba), "run", "--prefix", str(environment), "black", ".", "--diff", "--check"], env))
    failures.append(run_logged("mypy", [str(mamba), "run", "--prefix", str(environment), "mypy", "cadquery"], env))
    junit = ARTIFACTS / "pytest.xml"
    failures.append(run_logged("pytest", [str(mamba), "run", "--prefix", str(environment), "pytest", "-v", "--gui", "--cov", "--junitxml", str(junit)], env))
    export_environment(str(mamba), environment, env)
    identity("after-tests")
    if any(failures):
        raise SystemExit(1)


if __name__ == "__main__":
    identity("initial")
    try:
        main()
    finally:
        if ROOT.exists():
            identity("final")
    print("CADQUERY_BASELINE_COMPLETE", round(time.monotonic() - START, 2), flush=True)
