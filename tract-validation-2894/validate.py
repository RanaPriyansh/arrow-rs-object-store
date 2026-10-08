import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import urllib.request


BASE = "4cc53e7f69df21ea0004076c16db5c033486e504"
LOCK = "e1320365bd95176505a770bfd188ab571ac23f1aa699c003afe2bdb104b407d5"
PAYLOAD = pathlib.Path(__file__).resolve().parent
SOURCE = pathlib.Path.cwd()
CONTROL = "frame::mmm::blocked_walk_tests::dispatch_controls"
REGRESSION = CONTROL + "_and_one_thread_pool_regression"
CARGO = ["rustup", "run", "1.91.0", "cargo"]
LOGS = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "tract-validation-02"


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def run(name, args, expected=0, env=None):
    print("COMMAND", name, shlex.join(args), flush=True)
    LOGS.mkdir(exist_ok=True)
    with (LOGS / (name + ".log")).open("w") as output:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, env=env)
        for line in process.stdout:
            output.write(line)
            print(line, end="", flush=True)
        code = process.wait()
    text = (LOGS / (name + ".log")).read_text()
    print("COMMAND_EXIT", name, code, flush=True)
    require(code == expected, (name, "unexpected exit", code, expected))
    return text


def source_identity(expected, allowed_untracked):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(head == BASE, ("Unexpected HEAD", head))
    names = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")[:-1]
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0" + pathlib.Path(name).read_bytes() + b"\0")
    require(len(names) == 2222 and digest.hexdigest() == expected,
            ("Unexpected tracked source", len(names), digest.hexdigest(), expected))
    require(hashlib.sha256(pathlib.Path("Cargo.lock").read_bytes()).hexdigest() == LOCK,
            "Tracked Cargo.lock changed")
    others = subprocess.check_output(
        ["git", "ls-files", "--others", "-z"]
    ).decode().split("\0")[:-1]
    require(set(others) == set(allowed_untracked), ("Unexpected untracked files", others))
    print("SOURCE_IDENTITY", head, len(names), digest.hexdigest(), LOCK, others, flush=True)


def cargo(name, command, options, expected=0, env=None):
    return run(name, CARGO + [command] + options + ["--locked", "--offline", "--jobs", "1"],
               expected, env)


def messages(text):
    entries = []
    for line in text.splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def clippy(name, options, targets, stable=False):
    if stable:
        text = run(name, ["cargo", "clippy"] + options +
                   ["--locked", "--offline", "--jobs", "1", "--message-format=json"])
    else:
        text = cargo(name, "clippy", options + ["--message-format=json"])
    entries = messages(text)
    diagnostics = [e for e in entries if e.get("reason") == "compiler-message"
                   and e["message"]["level"] in ("warning", "error")]
    artifacts = [e for e in entries if e.get("reason") == "compiler-artifact"]
    require(any(e.get("reason") == "build-finished" and e["success"] for e in entries),
            (name, "Missing successful build-finished record"))
    require(artifacts and set(targets) <= {e["target"]["name"] for e in artifacts},
            (name, "Missing required compiler artifacts", targets))
    require(not diagnostics and not re.search(r"^(?:warning|error):", text, re.M),
            (name, "Compiler diagnostics", diagnostics))
    print("CLIPPY_CLEAN", name, len(artifacts), flush=True)
    return entries


def binding_contract(text):
    text = re.sub(r"#\s*\[\s*doc\s*=\s*\"(?:\\.|[^\"\\])*\"\s*\]", "", text)
    text = re.sub(r"^\s*///[^\n]*", "", text, flags=re.M)
    normalize = lambda value: re.sub(r",(?=\))", "", re.sub(r"\s+", "", value))
    functions = re.findall(
        r'(?:unsafe\s+)?extern\s*"C"\s*\{\s*(pub fn (tract_\w+).*?;)\s*\}', text, re.S
    )
    structs = re.findall(
        r"#\s*\[\s*repr\s*\(\s*C\s*\)\s*\]\s*"
        r"(?:#\s*\[\s*derive[^\]]*\]\s*)?(pub struct (Tract\w+)\s*\{[^}]*\})", text, re.S
    )
    constants = re.findall(
        r"(pub const ((?:DatumType_TRACT_DATUM_TYPE_|TRACT_RESULT_TRACT_RESULT_)\w+)[^;]*;)", text
    )
    aliases = re.findall(r"(pub type (DatumType|TRACT_RESULT)\s*=[^;]*;)", text)
    result = {"functions": {name: normalize(decl) for decl, name in functions},
              "structs": {name: normalize(decl) for decl, name in structs},
              "constants": {name: normalize(decl) for decl, name in constants},
              "aliases": {name: normalize(decl) for decl, name in aliases}}
    require([len(result[key]) for key in result] == [88, 11, 20, 2],
            ("Incomplete C binding contract", {key: len(value) for key, value in result.items()}))
    return result


def verify_bindings(entries):
    dirs = {e["out_dir"] for e in entries if e.get("reason") == "build-script-executed"
            and "tract-proxy-sys" in e["package_id"]}
    require(len(dirs) == 1, ("Unexpected bindgen output directories", dirs))
    path = pathlib.Path(next(iter(dirs))) / "bindings.rs"
    text = path.read_text()
    actual = binding_contract(text)
    expected = json.loads((PAYLOAD / "baseline-c-bindings.json").read_text())
    require(actual == expected, "C functions, enum aliases, constants, or opaque layouts changed")
    header = pathlib.Path("api/proxy/sys/tract.h").read_text()
    require(set(re.findall(r"\b(tract_\w+)\s*\(", header)) == set(actual["functions"]),
            "Generated C function set differs from the tracked header")
    require(set(re.findall(r"pub\s+fn\s+(\w+)\s*\(", text)) == set(actual["functions"]),
            "Unexpected generated functions remain")
    print("GENERATED_BINDINGS_BEGIN", path, hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    print(text, flush=True)
    print("GENERATED_BINDINGS_END", flush=True)
    print("C_BINDINGS_CONTRACT_PASS", 88, 11, 20, 2, flush=True)


def test_summary(text, passed=None, failed=0):
    summaries = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    require(summaries, "No executed test summary")
    totals = [sum(int(row[i]) for row in summaries) for i in range(3)]
    require(totals[1] == failed and (passed is None or totals[0] == passed),
            ("Unexpected test totals", totals, passed, failed))
    require(totals[0] + totals[1] > 0, "Empty test selector")
    print("EXECUTED_TEST_TOTALS", totals, flush=True)
    return totals


def linalg_tests(name, options, selector=None, expected=0):
    args = CARGO + ["test", "-p", "tract-linalg", "--lib", "--locked", "--offline", "-j1"] + options
    if selector:
        args += [selector]
    return run(name, args + ["--", "--exact", "--nocapture", "--test-threads=1"]
               if selector else args + ["--", "--test-threads=1"], expected)


def main():
    for key in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTDOC", "CARGO_BUILD_TARGET"]:
        os.environ.pop(key, None)
    identities = json.loads((PAYLOAD / "source-identities.json").read_text())
    current = identities["baseline"]
    model_files = []
    try:
        source_identity(current, model_files)
        for name, expected in identities["payload_sha256"].items():
            require(hashlib.sha256((PAYLOAD / name).read_bytes()).hexdigest() == expected,
                    ("Validation payload changed", name))
        for name in ["mobilenetv2-7.onnx", "mobilenet_v2_1.0.onnx.nnef.tgz"]:
            path = pathlib.Path("api/proxy") / name
            require(not path.exists(), ("Unexpected existing model", path))
            url = "https://s3.amazonaws.com/tract-ci-builds/tests/" + name
            with urllib.request.urlopen(url, timeout=120) as response:
                require(response.status == 200, ("Model response", url, response.status))
                data = response.read(32 * 1024 * 1024 + 1)
            require(0 < len(data) <= 32 * 1024 * 1024, ("Unexpected model size", url, len(data)))
            path.write_bytes(data)
            model_files.append(str(path))
            print("PUBLIC_MODEL", url, len(data), hashlib.sha256(data).hexdigest(), flush=True)
        run("apply-prerequisite", ["git", "apply", str(PAYLOAD / "prerequisite.patch")])
        current = identities["prerequisite"]
        source_identity(current, model_files)
        run("prerequisite-format", ["cargo", "fmt", "--all", "--", "--check"])
        run("stable-rustc-version", ["rustc", "-Vv"])
        run("stable-clippy-version", ["cargo", "clippy", "--version"])
        clippy("prerequisite-stable-workspace-clippy", ["--workspace"],
               ["tract_core", "tract_linalg", "tract_proxy_sys", "tract_metal", "tract"], stable=True)
        entries = clippy("prerequisite-workspace-clippy", ["--workspace"],
                         ["tract_core", "tract_linalg", "tract_proxy_sys", "tract_metal", "tract"])
        verify_bindings(entries)
        ffi = cargo("prerequisite-ffi-build", "build", ["-p", "tract-ffi", "--message-format=json"])
        libraries = [pathlib.Path(name) for e in messages(ffi) if e.get("reason") == "compiler-artifact"
                     and e["target"]["name"] == "tract" and "cdylib" in e["target"]["kind"]
                     for name in e["filenames"] if name.endswith(".dylib")]
        require(len(libraries) == 1 and libraries[0].is_file() and libraries[0].stat().st_size > 0,
                ("Missing nonempty built FFI dylib", libraries))
        dylib_dir = str(libraries[0].parent.resolve())
        proxy_env = dict(os.environ, TRACT_DYLIB_SEARCH_PATH=dylib_dir,
                         LD_LIBRARY_PATH=dylib_dir, DYLD_LIBRARY_PATH=dylib_dir)
        proxy_args = CARGO + ["test", "-p", "tract-proxy", "--locked", "--offline", "-j1"]
        listed = run("proxy-discovery", proxy_args + ["--", "--list"], env=proxy_env)
        require(len(re.findall(r"^[\w:]+: test$", listed, re.M)) == 33,
                "Expected one proxy unit test and 32 shared integration tests")
        proxy = run("prerequisite-proxy-tests", proxy_args + ["--", "--test-threads=1"], env=proxy_env)
        test_summary(proxy, passed=33)
        require("test tests::clone_tensor_no_double_free ... ok" in proxy, "Missing clone/drop control")
        source_identity(current, model_files)

        run("apply-baseline-tests", ["git", "apply", str(PAYLOAD / "baseline-tests.patch")])
        current = identities["test_only_baseline"]
        source_identity(current, model_files)
        listed = run("baseline-discovery", CARGO + ["test", "-p", "tract-linalg", "--lib",
                     "--features", "multithread-mm", "--locked", "--offline", "-j1",
                     "frame::mmm::blocked_walk_tests::", "--", "--list"])
        for name in [CONTROL, REGRESSION]:
            require(listed.count(name + ": test") == 1, ("Missing exact baseline test", name))
        test_summary(linalg_tests("baseline-controls", ["--features", "multithread-mm"], CONTROL), passed=1)
        failed = linalg_tests("baseline-regression", ["--features", "multithread-mm"], REGRESSION, 101)
        test_summary(failed, passed=0, failed=1)
        require("assertion `left == right` failed" in failed
                and re.search(r"left: (?!1\s*$)\d+\s*\n\s*right: 1", failed, re.M),
                "Baseline did not fail the callback-count assertion")
        source_identity(current, model_files)

        run("remove-baseline-tests", ["git", "apply", "--reverse", str(PAYLOAD / "baseline-tests.patch")])
        current = identities["prerequisite"]
        source_identity(current, model_files)
        run("apply-dispatcher", ["git", "apply", str(PAYLOAD / "dispatcher.patch")])
        current = identities["candidate"]
        source_identity(current, model_files)
        run("candidate-format", ["cargo", "fmt", "--all", "--", "--check"])
        run("candidate-shell", ["sh", "-n", "harness/nnef-test-cases/parallel-matmul/runme.sh"])
        clippy("candidate-stable-workspace-clippy", ["--workspace"],
               ["tract_core", "tract_linalg", "tract"], stable=True)
        clippy("candidate-workspace-clippy", ["--workspace"], ["tract_core", "tract_linalg", "tract"])
        clippy("candidate-feature-clippy", ["-p", "tract-linalg", "--all-targets", "--features", "multithread-mm"],
               ["tract_linalg"])
        for name in [CONTROL, REGRESSION]:
            test_summary(linalg_tests("candidate-" + name.rsplit("::", 1)[1],
                                     ["--features", "multithread-mm"], name), passed=1)
        feature = test_summary(linalg_tests("candidate-feature-library", ["--features", "multithread-mm"]))
        default = test_summary(linalg_tests("candidate-default-library", []))
        require(feature[0] > 1000 and default[0] > 1000, "Incomplete linalg library execution")
        listed = run("default-discovery", CARGO + ["test", "-p", "tract-linalg", "--lib", "--locked",
                     "--offline", "-j1", "frame::mmm::blocked_walk_tests::", "--", "--list"])
        require(CONTROL + ": test" not in listed and REGRESSION + ": test" not in listed,
                "Feature-only tests unexpectedly exist without the feature")
        cli = cargo("candidate-cli-build", "build", ["-p", "tract-cli", "--bin", "tract",
                     "--features", "multithread-mm", "--message-format=json"])
        binaries = [e["executable"] for e in messages(cli) if e.get("reason") == "compiler-artifact"
                    and e["target"]["name"] == "tract" and "bin" in e["target"]["kind"] and e["executable"]]
        require(len(binaries) == 1 and pathlib.Path(binaries[0]).is_file(), ("Missing built CLI", binaries))
        run("model-preflight", [binaries[0], "--threads", "1", "harness/nnef-test-cases/parallel-matmul", "dump", "-q"])
        model = run("candidate-model-harness", ["sh", "harness/nnef-test-cases/parallel-matmul/runme.sh"],
                    env=dict(os.environ, TRACT_RUN=binaries[0], CARGO_OPTS=""))
        for count in [1, 2, 3, 8]:
            require(re.search(r"^\+ .* --threads " + str(count) + r" \. -O run .*--approx exact", model, re.M),
                    ("Missing exact model comparison", count))
        require("WARNING:" not in model and "NOT run" not in model, "Threaded model checks did not run")
        require(not pathlib.Path("harness/nnef-test-cases/parallel-matmul/ref.npz").exists(), "Model output remains")
        run("candidate-whitespace", ["git", "diff", "--check"])
    finally:
        source_identity(current, model_files)
        print("FINAL_SOURCE_IDENTITY_RECORDED", current, flush=True)
    print("TRACT_VALIDATION_COMPLETE", current, flush=True)


if __name__ == "__main__":
    main()
