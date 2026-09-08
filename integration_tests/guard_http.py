"""Real native Guard HTTP/Git integration, using a local reader principal.

Requires the independently installed pinned Guard package. No production
credentials, RuntimePort double, admission, executor call or merge is used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading

import organism_guard
from organism_guard.client import APIError, GuardClient
from organism_guard.configuration import Configuration, Principal, Repository
from organism_guard.http_api import GuardHTTPServer
from organism_guard.service import GuardService

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard_observe", ROOT / "tools/guard_observe.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    pin = json.loads((ROOT / "integration/organism-guard.json").read_text())
    installed = Path(organism_guard.__file__).resolve().parent
    files = {str(f.relative_to(installed)): hashlib.sha256(f.read_bytes()).hexdigest()
             for f in sorted(installed.rglob("*.py"))}
    tree_digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if tree_digest != pin["python_tree_sha256"]:
        raise ValueError("Installed Guard sources differ from the pinned integration reference")
    expected = subprocess.check_output(["git", "-C", str(args.repository), "rev-parse", "HEAD"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="uriprocess-guard-http-") as temporary:
        root = Path(temporary)
        fixture = root / "fixture"
        subprocess.run(["git", "init", "-q", str(fixture)], check=True)
        subprocess.run(["git", "-C", str(fixture), "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture"], check=True)
        fixture_head = subprocess.check_output(["git", "-C", str(fixture), "rev-parse", "HEAD"], text=True).strip()
        reader = Principal("reader", frozenset({"reader"}), frozenset({"uriprocess", "fixture"}))
        # Native Configuration requires an executor identity. It gets no
        # repositories, bearer credential or execution opt-in in this test.
        inert = Principal("disabled-executor", frozenset({"executor"}), frozenset())
        token = secrets.token_urlsafe(40)
        config = Configuration(root / "control", {
            "uriprocess": Repository("uriprocess", args.repository.resolve()),
            "fixture": Repository("fixture", fixture)}, {reader.id: reader, inert.id: inert}, inert.id,
            {hashlib.sha256(token.encode()).hexdigest(): reader.id}, allow_local_test_execution=False)
        server = GuardHTTPServer(("127.0.0.1", 0), GuardService(config))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            client = GuardClient(url, token)
            report = observer.observe(client, "uriprocess", expected, pin["contract_sha256"])
            checks = ["real-repository-exact-head"]
            cli_output = root / "cli-observation.json"
            argv = [sys.executable, str(ROOT / "tools/guard_observe.py"), "--base-url", url,
                    "--repository-id", "uriprocess", "--expected-head", expected,
                    "--expected-contract-sha256", pin["contract_sha256"], "--out", str(cli_output)]
            environment = {"URIPROCESS_GUARD_TOKEN": token, "PYTHONPATH": str(installed.parent)}
            subprocess.run(argv, env=environment, check=True, capture_output=True)
            cli_report = json.loads(cli_output.read_text())
            assert cli_report["head"] == expected and cli_report["execution_authority"] is False
            checks.append("real-cli-http-success")
            previous = cli_output.read_bytes()
            repeated = subprocess.run(argv, env=environment, capture_output=True, text=True)
            assert repeated.returncode == 2
            assert json.loads(repeated.stderr)["code"] == "OUTPUT_ALREADY_EXISTS"
            assert cli_output.read_bytes() == previous
            checks.append("cli-refuses-overwrite")
            for label, invoke, error, expected_error in [
                ("wrong-contract", lambda: observer.observe(client, "uriprocess", expected, "0" * 64), observer.ObservationRejected, "GUARD_CONTRACT_MISMATCH"),
                ("stale-head", lambda: observer.observe(client, "fixture", "0" * 40, pin["contract_sha256"]), observer.ObservationRejected, "REPOSITORY_REVISION_CHANGED"),
                ("invalid-bearer", lambda: GuardClient(url, "invalid-token").call("git.status", {"repository_id": "fixture"}), APIError, 401),
                ("reader-cannot-admit", lambda: client.call("admission.decide", {}), APIError, 403),
            ]:
                try:
                    invoke()
                except error as exc:
                    assert (exc.status if isinstance(exc, APIError) else str(exc)) == expected_error
                    checks.append(label)
                else:
                    raise AssertionError(f"Native boundary did not reject {label}")
            (fixture / "dirty").write_text("untracked fixture\n")
            try:
                observer.observe(client, "fixture", fixture_head, pin["contract_sha256"])
            except observer.ObservationRejected:
                checks.append("dirty-repository")
            else:
                raise AssertionError("Dirty fixture accepted")
            report["integration"] = {"transport": "real-loopback-http", "guard_source_revision": pin["source_revision"],
                "checks": checks, "production_guard": False, "merge_executed": False}
            with args.out.open("x") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
            print(json.dumps({"status": "passed", "checks": len(checks), "guard_version": report["guard_version"]}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
