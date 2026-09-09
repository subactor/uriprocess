"""Offline, pinned inputs shared by source and installed-wheel conformance."""
from __future__ import annotations

import atexit
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import tempfile

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
pins = json.loads((FIXTURES / "pins.json").read_text())
assert pins["schema"] == "subactor.twin-map-test-inputs/v1"
for item in pins["files"]:
    path = FIXTURES / item["path"]
    assert path.resolve().is_relative_to(FIXTURES.resolve()) and not path.is_symlink()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], item["path"]

_temporary = tempfile.TemporaryDirectory(prefix="twin-map-conformance-")
atexit.register(_temporary.cleanup)
workspace = Path(_temporary.name)
reference = workspace / "plesk"
shutil.copytree(FIXTURES / "plesk", reference)
shutil.copytree(FIXTURES / "core", reference / "node_modules" / "@uri-twin" / "core")

repository = "https://github.com/uri-twin/uri-twin-plesk.git"
relative_path = "baseline/plesk-surface.v1.json"
ref = "main"
document = json.loads((reference / relative_path).read_text())
attestation = json.loads((reference / "baseline/plesk-surface.v1.attestation.json").read_text())
digest = "sha256:" + hashlib.sha256(
    json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
cache_dir = workspace / "cache"
cache_dir.mkdir()
key = hashlib.sha256(f"{repository}\0{ref}\0{relative_path}".encode()).hexdigest()[:24]
(cache_dir / f"plesk-{key}.json").write_text(json.dumps({
    "source": repository,
    "revision": next(item["revision"] for item in pins["files"]
                     if item["path"] == "plesk/" + relative_path),
    "digest": digest, "document": document,
    "attestation": attestation, "catalog": None,
}))
# The package initializer imports core too. Prepare the cache before importing
# any package module. Production load_baseline authenticates the real release
# signature with its unchanged signer allowlist when it reads this envelope.
# Restore the environment afterwards: loader tests exercise their own Git repos.
with pytest.MonkeyPatch.context() as initialization:
    initialization.setenv("URI_TWIN_CACHE_DIR", str(cache_dir))
    initialization.setenv("URI_TWIN_OFFLINE", "1")
    initialization.setenv("URI_TWIN_PLESK_REPOSITORY", repository)
    initialization.setenv("URI_TWIN_PLESK_REF", ref)
    initialization.setenv("URI_TWIN_PLESK_PATH", relative_path)
    core = importlib.import_module("urirun_connector_subactor_twin_map.core")
assert core.BASELINE_SNAPSHOT.digest == digest
assert core.BASELINE_SNAPSHOT.loaded_from == "cache"
assert core.BASELINE_SNAPSHOT.attestation


@pytest.fixture
def js_reference():
    assert shutil.which("node"), "Node is required for cross-runtime conformance"
    return reference


@pytest.fixture
def connector_workspace():
    return FIXTURES / "providers"
