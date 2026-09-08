import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("generate", ROOT / "tools/generate.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class GeneratorTests(unittest.TestCase):
    def test_uri_identity_and_collision_boundaries(self):
        self.assertEqual(str(generator.uri_path("poa://subactor.com/process/ticket-currency/v1")),
                         "poa/ticket-currency/subactor.com/v1")
        for uri in ["poa://host/process/../v1", "poa://host/process/name/v0", "poa://host/process/name/v1?x",
                    "poa://user@host/process/name/v1", "poa://host/process/%2e%2e/v1", "file:///tmp/x"]:
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                generator.uri_path(uri)
        self.assertNotEqual(generator.uri_path("poa://one/process/name/v1"),
                            generator.uri_path("poa://two/process/name/v1"))

    def test_unsafe_selected_paths(self):
        for path in ["../secret", "/etc/passwd", "src/../../x", "src//x", "src\\x", "."]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                generator.relative(path)

    def test_pinned_git_content_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
            git("init", "-q")
            (repo / "source.mjs").write_text("original\n")
            (repo / "link").symlink_to("source.mjs")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
            revision = git("rev-parse", "HEAD")
            (repo / "source.mjs").write_text("dirty\n")
            self.assertEqual(generator.read_object(repo, revision, "source.mjs"), b"original\n")
            with self.assertRaises(ValueError):
                generator.read_object(repo, revision, "link")

    def test_invalid_pins_rejected_before_output(self):
        config = json.loads((ROOT / "selections/runtime-v1.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            for field, value in [("source_revision", "main"), ("base_image", "node:latest")]:
                invalid = {**config, field: value}
                output = Path(temporary) / "out"
                with self.assertRaises(ValueError):
                    generator.generate(invalid, ROOT, output)
                self.assertFalse(output.exists())

    def test_cli_rejects_authority_injection_and_invalid_input(self):
        for process in json.loads((ROOT / "catalog.json").read_text())["processes"]:
            base = ROOT / process["path"]
            for request in ['{}', '{', '{"ticket":{},"context":{"actorCoversRequirements":true}}',
                            '{"ticket":{},"context":{"actors":{}}}']:
                result = subprocess.run(["node", "bin.mjs"], cwd=base, input=request, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_readiness_cli_requires_real_actor_validator(self):
        uri = "planfile://subactor/tickets/command/reconcile-lifecycle"
        ticket = {"id": "PLF-900", "status": "open",
                  "execution": {"state": "ready", "assigned_to": "operator"},
                  "inputs": {"process_manifest": {"schema": "subactor.process-envelope.v2", "definitions": {
                      "aql": [{"actor": "operator"}], "oql": [{"id": "work"}],
                      "eql": [{"id": "result", "verified_by": ["work"]}],
                      "uri": [{"id": "work", "uri": uri, "actor": "bot:operator"}]}}}}
        request = {"ticket": ticket, "context": {"actors": [{"id": "operator", "kind": "bot"}], "routes": [uri]}}
        result = subprocess.run(["node", "bin.mjs"], cwd=ROOT / "poa/ticket-readiness/subactor.com/v1",
                                input=json.dumps(request), text=True, capture_output=True, check=True)
        decision = json.loads(result.stdout)
        self.assertEqual(decision["action"], "blocked")
        self.assertEqual(decision["reason"], "actor_contract_validator_required")


if __name__ == "__main__":
    unittest.main()
