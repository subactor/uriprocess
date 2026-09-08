"""Full local native Guard export of the two real uriprocess packages.

The three principals are test identities in a disposable server, not production
approval. Original source is read from an explicit immutable Git revision.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import threading

from organism_guard.configuration import Configuration, Principal, Repository
import organism_guard
import uripack_refactor.executor
from organism_guard.client import GuardClient, APIError
from organism_guard.contracts import contract_digest
from organism_guard.service import GuardService
from organism_guard.http_api import GuardHTTPServer

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard_export", ROOT / "tools/guard_export.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


def run(argv, cwd, **kwargs):
    return subprocess.run(argv, cwd=cwd, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repository", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    pin = json.loads((ROOT / 'integration/organism-guard-export.json').read_text())
    guard_root = Path(organism_guard.__file__).resolve().parent
    files = {str(p.relative_to(guard_root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(guard_root.rglob('*.py'))}
    actual_tree = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert actual_tree == pin['python_tree_sha256'] and contract_digest() == pin['contract_sha256']
    uripack_file = Path(uripack_refactor.executor.__file__).resolve()
    assert hashlib.sha256(uripack_file.read_bytes()).hexdigest() == pin['uripack_executor_sha256']
    args.output.mkdir(parents=True, exist_ok=False)
    archive = subprocess.check_output(["git", "-C", str(args.source_repository), "archive", args.source_revision])
    results = []
    with tempfile.TemporaryDirectory(prefix="uriprocess-full-guard-") as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
            tf.extractall(repo, filter="data")
        policy = (ROOT / "integration/fastlane-project.proposed.json").read_bytes()
        (repo / ".guard").mkdir()
        (repo / ".guard/fastlane.json").write_bytes(policy)
        run(["git", "init", "-q", "-b", "main"], repo)
        run(["git", "add", "."], repo)
        run(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Local export test",
             "-c", "user.email=fixture@example.invalid", "commit", "-qm", "explicit local test profile"], repo)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        principals = {name: Principal(name, frozenset(roles), frozenset({"uriprocess"})) for name, roles in {
            "author": ["reader", "planner"], "reviewer": ["reader", "approver", "higher_authority"],
            "executor": ["reader", "executor"]}.items()}
        tokens = {name: secrets.token_urlsafe(40) for name in principals}
        config = Configuration(root / "control", {"uriprocess": Repository("uriprocess", repo, {
            "TICKET-4": "https://github.com/subactor/uriprocess/issues/4"})}, principals, "executor",
            {hashlib.sha256(token.encode()).hexdigest(): name for name, token in tokens.items()},
            allow_local_test_execution=False, plan_ttl=600)
        server = GuardHTTPServer(("127.0.0.1", 0), GuardService(config))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            author, reviewer, executor = [GuardClient(url, tokens[name]) for name in ("author", "reviewer", "executor")]
            contract = contract_digest()
            for unit in ("ticket-currency", "ticket-readiness"):
                plan_file = root / (unit + '-plan.json')
                def cli(action, token, output, *extra):
                    return run([sys.executable, str(ROOT / 'tools/guard_export.py'), action,
                        '--base-url', url, '--contract-sha256', contract, '--repository-id', 'uriprocess',
                        '--revision', revision, '--unit', unit, '--out', str(output), *extra], root,
                        env={'PATH': os.defpath, 'URIPROCESS_GUARD_TOKEN': token,
                             'PYTHONPATH': str(guard_root.parent) + os.pathsep + str(uripack_file.parent.parent)},
                        capture_output=True, text=True)
                cli('plan', tokens['author'], plan_file, '--ticket-id', 'TICKET-4')
                plan = json.loads(plan_file.read_text())
                decision = {k: plan[k] for k in ("plan_id", "plan_hash", "queue_revision")}
                decision.update(decision="accept", reason_code="POLICY_ACCEPTED")
                try:
                    author.call("admission.decide", decision)
                except APIError as error:
                    assert error.status == 403
                else:
                    raise AssertionError("Author admitted its own export")
                grant = reviewer.call("admission.decide", decision)
                target = args.output / unit
                try:
                    consumer.execute(author, contract, grant['execution_envelope'], 'uriprocess', revision, unit, target)
                except APIError as error:
                    assert error.status == 403
                else:
                    raise AssertionError('Planner used the executor envelope')
                occupied = root / (unit + '-occupied')
                occupied.mkdir()
                try:
                    consumer.execute(executor, contract, grant['execution_envelope'], 'uriprocess', revision, unit, occupied)
                except consumer.ExportRejected as error:
                    assert str(error) == 'TARGET_UNAVAILABLE'
                else:
                    raise AssertionError('Existing target accepted')
                assert executor.call('plan.get', {'plan_id': plan['plan_id']})['state'] == 'authorized'
                envelope_file = root / (unit + '-envelope.json')
                envelope_file.write_text(json.dumps(grant['execution_envelope']))
                outcome = args.output / (unit + '-result.json')
                cli('execute', tokens['executor'], outcome, '--envelope', str(envelope_file), '--target', str(target))
                result = json.loads(outcome.read_text())
                receipt = executor.call('receipt.get', {'plan_id': plan['plan_id']})['receipt']
                bundle = executor.call('artifact.get', {'artifact_ref': receipt['output_ref']})['value']
                corrupt = json.loads(json.dumps(bundle))
                first = next(iter(corrupt['contents_base64']))
                corrupt['contents_base64'][first] = 'Y29ycnVwdA=='
                try:
                    consumer.verify_bundle(corrupt, revision, unit)
                except consumer.ExportRejected as error:
                    assert str(error) == 'EXPORT_CONTENT_MISMATCH'
                else:
                    raise AssertionError('Corrupt bundle accepted')
                package = target / "poa" / unit / "subactor.com/v1"
                original = repo / "poa" / unit / "subactor.com/v1"
                run(["node", "--test", str(package / "tests" / (unit + ".test.mjs"))], root)
                request = json.dumps({"ticket": {"id": "PLF-ą😀", "status": "done"}})
                expected = run(["node", "bin.mjs"], original, input=request, text=True, capture_output=True).stdout
                actual = run(["node", "bin.mjs"], package, input=request, text=True, capture_output=True).stdout
                assert actual == expected
                image = "uriprocess-guard-export-" + unit
                run(["docker", "build", "--network=none", "-t", image, "."], package)
                container = run(["docker", "run", "--rm", "-i", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", image], root,
                    input=request, text=True, capture_output=True).stdout
                assert container == expected
                distribution = args.output / (unit + "-dist")
                distribution.mkdir()
                packed = run(["npm", "pack", "--ignore-scripts", "--json", "--pack-destination", str(distribution)],
                             package, text=True, capture_output=True)
                tarball = distribution / json.loads(packed.stdout)[0]["filename"]
                install = root / (unit + "-installed")
                run(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund",
                     "--prefix", str(install), str(tarball)], root)
                name = json.loads((package / "package.json").read_text())["name"]
                installed = run(["node", str(install / "node_modules" / name / "bin.mjs")], root,
                                input=request, text=True, capture_output=True).stdout
                assert installed == expected
                # A second fetch reads immutable evidence, never invokes execution.
                fetched = consumer.fetch(executor, contract, plan["plan_id"], plan["plan_hash"],
                                         "uriprocess", revision, unit, root / (unit + "-readback"))
                assert fetched["receipt_sha256"] == result["receipt_sha256"]
                results.append({"unit": unit, **result, "docker": "passed", "npm_install": "passed",
                                "upstream_tests": "passed", "native_http": "passed",
                                "denied_planner_execution": True, "existing_target_preserved": True,
                                "corrupt_bundle_rejected": True})
            report = {"status": "passed", "source_revision": args.source_revision,
                      "test_repository_revision": revision, "policy_sha256": hashlib.sha256(policy).hexdigest(),
                      "guard_contract_sha256": contract, "results": results,
                      "production_guard": False, "production_cutover": False, "test_principals": True}
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    print(json.dumps({"status": "passed", "packages": len(results), "production_guard": False}))


if __name__ == "__main__":
    main()
