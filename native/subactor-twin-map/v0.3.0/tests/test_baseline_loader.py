from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from urirun_connector_subactor_twin_map import baseline_loader
from urirun_connector_subactor_twin_map.baseline_loader import (
    CatalogResolution,
    load_baseline,
    resolve_catalog_baseline,
    verify_baseline_attestation,
)


def baseline(version="test"):
    return {
        "schema": "uri-twin.baseline/v1",
        "twin_family": "plesk",
        "version": version,
        "capabilities": [{
            "id": "plesk.site.docroot",
            "effect": "query",
            "transport": "xml-api",
            "requires_credentials": [],
            "provided_by": [{"connector": "urirun-connector-plesk", "uri": "plesk://host/site/query/docroot"}],
        }],
    }


def catalog(repository="https://github.com/uri-twin/uri-twin-plesk.git"):
    return {
        "schema": "uri-twin.catalog/v1",
        "version": 1,
        "organization": "uri-twin",
        "repositories": [{
            "id": "uri-twin-plesk",
            "family": "plesk",
            "repository": repository,
            "default_ref": "main",
            "baseline": {"path": "baseline/plesk-surface.v1.json", "schema": "uri-twin.baseline/v1"},
            "supported_schemas": ["uri-twin.baseline/v1"],
        }],
    }


def signed_attestation(document, repository="https://github.com/uri-twin/uri-twin-plesk.git"):
    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = f"sha256:{hashlib.sha256(public_der).hexdigest()}"
    signer_id = "test-release-signer"
    statement = {
        "schema": "uri-twin.attestation/v1",
        "version": 1,
        "issued_at": "2026-07-29T00:00:00.000Z",
        "subject": {
            "repository": repository,
            "path": "baseline/plesk-surface.v1.json",
            "schema": document["schema"],
            "version": str(document["version"]),
            "digest": baseline_loader._digest(document),
        },
        "signer": {"id": signer_id, "algorithm": "ed25519", "public_key_sha256": fingerprint},
    }
    signature = private_key.sign(json.dumps(statement, sort_keys=True, separators=(",", ":")).encode())
    attestation = {**statement, "signature": base64.b64encode(signature).decode()}
    allowed = {signer_id: {
        "algorithm": "ed25519",
        "public_key_spki_base64": base64.b64encode(public_der).decode(),
        "public_key_sha256": fingerprint,
    }}
    return attestation, allowed


def git_repository(path: Path, document: dict) -> str:
    path.mkdir()
    (path / "baseline").mkdir()
    (path / "baseline" / "plesk-surface.v1.json").write_text(json.dumps(document), encoding="utf-8")
    subprocess.run(["git", "init", "--initial-branch=main", str(path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.name=Twin Test", "-c", "user.email=twin@example.invalid", "commit", "-m", "baseline"],
        check=True,
        capture_output=True,
    )
    return path.as_uri()


def test_git_is_the_primary_source_and_records_exact_revision(tmp_path):
    repository = git_repository(tmp_path / "source", baseline("git-2"))
    snapshot = load_baseline(
        fallback=baseline("embedded-1"), repository=repository, cache_dir=tmp_path / "cache", timeout=5, offline=False,
    )

    assert snapshot.loaded_from == "git"
    assert snapshot.stale is False
    assert snapshot.document["version"] == "git-2"
    assert len(snapshot.revision) == 40
    assert snapshot.digest.startswith("sha256:")


def test_catalog_resolves_reviewed_plesk_baseline_with_auditable_provenance():
    resolution = resolve_catalog_baseline(catalog(), revision="abc123")

    assert resolution.repository == "https://github.com/uri-twin/uri-twin-plesk.git"
    assert resolution.ref == "main"
    assert resolution.relative_path == "baseline/plesk-surface.v1.json"
    assert resolution.revision == "abc123"
    assert resolution.digest.startswith("sha256:")


def test_default_source_uses_catalog_but_explicit_source_bypasses_it(tmp_path, monkeypatch):
    repository = git_repository(tmp_path / "source", baseline("git-catalog"))
    resolution = CatalogResolution(
        repository=repository,
        ref="main",
        relative_path="baseline/plesk-surface.v1.json",
        source="https://github.com/uri-twin/uri-twin-catalog.git",
        revision="catalog-revision",
        digest="sha256:catalog",
        loaded_from="git",
        stale=False,
    )
    calls = []
    monkeypatch.setattr(baseline_loader, "_load_catalog_resolution", lambda **kwargs: calls.append(kwargs) or resolution)

    snapshot = load_baseline(fallback=baseline("embedded"), cache_dir=tmp_path / "cache", timeout=5)
    explicit = load_baseline(
        fallback=baseline("embedded"),
        repository=repository,
        cache_dir=tmp_path / "explicit-cache",
        timeout=5,
    )

    assert snapshot.document["version"] == "git-catalog"
    assert snapshot.provenance()["catalog"]["revision"] == "catalog-revision"
    assert len(calls) == 1
    assert "catalog" not in explicit.provenance()


@pytest.mark.parametrize("document", [
    catalog("https://github.com/not-uri-twin/uri-twin-plesk.git"),
    catalog("file:///tmp/uri-twin-plesk"),
    {**catalog(), "repositories": []},
])
def test_catalog_cannot_widen_repository_authority(document):
    with pytest.raises(ValueError):
        resolve_catalog_baseline(document)


def test_attestation_verifies_offline_against_an_allowed_signer():
    document = baseline("signed-v1")
    attestation, allowed = signed_attestation(document)

    verified = verify_baseline_attestation(
        document,
        attestation,
        repository="https://github.com/uri-twin/uri-twin-plesk.git",
        relative_path="baseline/plesk-surface.v1.json",
        allowed_signers=allowed,
    )

    assert verified["signer"]["id"] == "test-release-signer"


def test_attestation_rejects_changed_content_and_an_unallowed_signer():
    document = baseline("signed-v1")
    attestation, allowed = signed_attestation(document)
    changed = baseline("changed-without-signature")

    with pytest.raises(ValueError, match="twin_attestation_version_invalid"):
        verify_baseline_attestation(
            changed,
            attestation,
            repository="https://github.com/uri-twin/uri-twin-plesk.git",
            relative_path="baseline/plesk-surface.v1.json",
            allowed_signers=allowed,
        )
    with pytest.raises(ValueError, match="twin_attestation_signer_not_allowed"):
        verify_baseline_attestation(
            document,
            attestation,
            repository="https://github.com/uri-twin/uri-twin-plesk.git",
            relative_path="baseline/plesk-surface.v1.json",
            allowed_signers={},
        )


def test_offline_load_uses_last_known_good_git_snapshot(tmp_path):
    repository_path = tmp_path / "source"
    repository = git_repository(repository_path, baseline("git-2"))
    first = load_baseline(
        fallback=baseline(), repository=repository, cache_dir=tmp_path / "cache", timeout=5, offline=False,
    )

    shutil.rmtree(repository_path)
    second = load_baseline(
        fallback=baseline("embedded-1"), repository=repository, cache_dir=tmp_path / "cache", offline=True,
    )

    assert second.loaded_from == "cache"
    assert second.stale is True
    assert second.revision == first.revision
    assert second.document["version"] == "git-2"


def test_embedded_baseline_is_last_resort(tmp_path):
    snapshot = load_baseline(
        fallback=baseline("embedded-1"),
        repository=(tmp_path / "missing").as_uri(),
        cache_dir=tmp_path / "cache",
        offline=True,
    )

    assert snapshot.loaded_from == "embedded"
    assert snapshot.stale is True
    assert snapshot.document["version"] == "embedded-1"


@pytest.mark.parametrize("repository", [
    "https://user:password@github.com/uri-twin/uri-twin-plesk.git",
    "https://github.com/uri-twin/uri-twin-plesk.git?token=nope",
    "git@github.com:uri-twin/uri-twin-plesk.git",
])
def test_repository_source_rejects_embedded_credentials_and_unsafe_schemes(tmp_path, repository):
    with pytest.raises(ValueError):
        load_baseline(fallback=baseline(), repository=repository, cache_dir=tmp_path, offline=True)


def test_invalid_git_document_does_not_replace_the_embedded_baseline(tmp_path):
    repository = git_repository(tmp_path / "source", {"schema": "wrong", "capabilities": []})
    snapshot = load_baseline(
        fallback=baseline("embedded-1"), repository=repository, cache_dir=tmp_path / "cache", timeout=5, offline=False,
    )

    assert snapshot.loaded_from == "embedded"
    assert snapshot.document["version"] == "embedded-1"
