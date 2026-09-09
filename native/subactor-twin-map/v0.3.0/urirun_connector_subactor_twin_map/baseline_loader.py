"""Load a reviewed URI-twin baseline from Git with safe offline fallback.

Git is the canonical default. A successful clone is validated and cached as a
last-known-good snapshot. Network or Git failure falls back to that cache and
then to package data, so loading a connector never widens authority merely
because its catalog source is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BASELINE_SCHEMA = "uri-twin.baseline/v1"
CATALOG_SCHEMA = "uri-twin.catalog/v1"
DEFAULT_REPOSITORY = "https://github.com/uri-twin/uri-twin-plesk.git"
DEFAULT_REF = "main"
DEFAULT_PATH = "baseline/plesk-surface.v1.json"
DEFAULT_CATALOG_REPOSITORY = "https://github.com/uri-twin/uri-twin-catalog.git"
DEFAULT_CATALOG_REF = "main"
DEFAULT_CATALOG_PATH = "catalog.v1.json"
DEFAULT_TWIN_FAMILY = "plesk"
ATTESTATION_SCHEMA = "uri-twin.attestation/v1"
ALLOWED_SIGNERS = {
    "uri-twin-release-2026-01": {
        "algorithm": "ed25519",
        "public_key_spki_base64": "MCowBQYDK2VwAyEAdaOeJFWWK+ZTG5IpP20CtAfFIqrjdW3jBBPJ/YQ9jzM=",
        "public_key_sha256": "sha256:8289bd2651989cead1bc8fd6a609bee91699cad07ecc55feca8a1ec8e49d04be",
    },
}
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SECRETISH = re.compile(r"(password|secret|token|api[_-]?key|authorization)", re.I)


@dataclass(frozen=True)
class BaselineSnapshot:
    document: dict[str, Any]
    source: str
    revision: str
    digest: str
    loaded_from: str
    stale: bool
    catalog: dict[str, Any] | None = None
    attestation: dict[str, Any] | None = None

    def provenance(self) -> dict[str, Any]:
        result = {
            "source": self.source,
            "revision": self.revision,
            "digest": self.digest,
            "loaded_from": self.loaded_from,
            "stale": self.stale,
        }
        if self.catalog is not None:
            result["catalog"] = self.catalog
        if self.attestation is not None:
            result["attestation"] = {
                "schema": self.attestation["schema"],
                "signer": self.attestation["signer"]["id"],
                "issued_at": self.attestation["issued_at"],
                "subject_digest": self.attestation["subject"]["digest"],
                "verified": True,
            }
        return result


@dataclass(frozen=True)
class CatalogResolution:
    repository: str
    ref: str
    relative_path: str
    source: str
    revision: str
    digest: str
    loaded_from: str
    stale: bool

    def provenance(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "revision": self.revision,
            "digest": self.digest,
            "loaded_from": self.loaded_from,
            "stale": self.stale,
        }


def _digest(document: dict[str, Any]) -> str:
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def _attestation_path(relative_path: str) -> str:
    path = Path(relative_path)
    return path.with_name(f"{path.stem}.attestation.json").as_posix()


def _requires_attestation(repository: str) -> bool:
    parsed = urlsplit(repository)
    return parsed.scheme == "https" and parsed.hostname == "github.com" and parsed.path.startswith("/uri-twin/")


def verify_baseline_attestation(
    document: dict[str, Any],
    attestation: Any,
    *,
    repository: str,
    relative_path: str,
    allowed_signers: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    if not isinstance(attestation, dict) or attestation.get("schema") != ATTESTATION_SCHEMA or attestation.get("version") != 1:
        raise ValueError("twin_attestation_schema_invalid")
    subject = attestation.get("subject")
    signer_claim = attestation.get("signer")
    if not isinstance(subject, dict) or not isinstance(signer_claim, dict):
        raise ValueError("twin_attestation_claim_invalid")
    if subject.get("repository") != repository or subject.get("path") != relative_path:
        raise ValueError("twin_attestation_subject_invalid")
    if subject.get("schema") != document.get("schema") or str(subject.get("version")) != str(document.get("version")):
        raise ValueError("twin_attestation_version_invalid")
    if subject.get("digest") != _digest(document):
        raise ValueError("twin_attestation_digest_invalid")
    signer_id = str(signer_claim.get("id") or "")
    signers = ALLOWED_SIGNERS if allowed_signers is None else allowed_signers
    signer = signers.get(signer_id)
    if signer is None or signer.get("algorithm") != "ed25519":
        raise ValueError("twin_attestation_signer_not_allowed")
    if signer_claim.get("algorithm") != signer["algorithm"] or signer_claim.get("public_key_sha256") != signer["public_key_sha256"]:
        raise ValueError("twin_attestation_signer_invalid")
    try:
        public_der = base64.b64decode(signer["public_key_spki_base64"], validate=True)
        fingerprint = f"sha256:{hashlib.sha256(public_der).hexdigest()}"
        if fingerprint != signer["public_key_sha256"]:
            raise ValueError("twin_attestation_signer_key_invalid")
        public_key = serialization.load_der_public_key(public_der)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("twin_attestation_signer_key_invalid")
        statement = {key: value for key, value in attestation.items() if key != "signature"}
        body = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = base64.b64decode(str(attestation.get("signature") or ""), validate=True)
        public_key.verify(signature, body)
    except (InvalidSignature, TypeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("twin_attestation_"):
            raise
        raise ValueError("twin_attestation_signature_invalid") from error
    return attestation


def _validated(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != BASELINE_SCHEMA:
        raise ValueError("twin_baseline_schema_invalid")
    if not str(document.get("version") or ""):
        raise ValueError("twin_baseline_version_missing")
    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ValueError("twin_baseline_capabilities_missing")
    ids: set[str] = set()
    for capability in capabilities:
        capability_id = str(capability.get("id") or "") if isinstance(capability, dict) else ""
        if not capability_id or capability_id in ids:
            raise ValueError("twin_baseline_capability_id_invalid")
        ids.add(capability_id)
        providers = capability.get("provided_by") or []
        if not providers:
            raise ValueError("twin_baseline_provider_missing")
        for provider in providers:
            uri = str(provider.get("uri") or "")
            if not uri or _SECRETISH.search(uri):
                raise ValueError("twin_baseline_provider_uri_invalid")
    return document


def _safe_repository(value: str) -> str:
    repository = str(value or "").strip()
    if not repository:
        raise ValueError("twin_git_repository_missing")
    if Path(repository).is_absolute():
        return repository
    parsed = urlsplit(repository)
    if parsed.scheme == "file":
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("twin_git_repository_credential_forbidden")
        return repository
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("twin_git_repository_scheme_invalid")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("twin_git_repository_credential_forbidden")
    return repository


def _safe_catalog_entry_repository(value: str) -> str:
    repository = _safe_repository(value)
    parsed = urlsplit(repository)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ValueError("twin_catalog_repository_scope_invalid")
    path = parsed.path.rstrip("/")
    if not path.startswith("/uri-twin/") or path.count("/") != 2:
        raise ValueError("twin_catalog_repository_scope_invalid")
    return repository


def _safe_ref(value: str) -> str:
    ref = str(value or "").strip()
    if not _REF.fullmatch(ref) or ".." in ref or "//" in ref:
        raise ValueError("twin_git_ref_invalid")
    return ref


def _safe_relative_path(value: str) -> str:
    path = Path(str(value or ""))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("twin_git_path_invalid")
    return path.as_posix()


def _cache_path(cache_dir: Path, repository: str, ref: str, relative_path: str) -> Path:
    key = hashlib.sha256(f"{repository}\0{ref}\0{relative_path}".encode("utf-8")).hexdigest()[:24]
    return cache_dir / f"plesk-{key}.json"


def _catalog_cache_path(cache_dir: Path, repository: str, ref: str, relative_path: str, family: str) -> Path:
    key = hashlib.sha256(f"{repository}\0{ref}\0{relative_path}\0{family}".encode("utf-8")).hexdigest()[:24]
    return cache_dir / f"catalog-{key}.json"


def resolve_catalog_baseline(
    document: Any,
    *,
    family: str = DEFAULT_TWIN_FAMILY,
    source: str = DEFAULT_CATALOG_REPOSITORY,
    revision: str = "unknown",
    loaded_from: str = "git",
    stale: bool = False,
) -> CatalogResolution:
    if not isinstance(document, dict) or document.get("schema") != CATALOG_SCHEMA:
        raise ValueError("twin_catalog_schema_invalid")
    repositories = document.get("repositories")
    if not isinstance(repositories, list):
        raise ValueError("twin_catalog_repositories_invalid")
    matches = [entry for entry in repositories if isinstance(entry, dict) and entry.get("family") == family]
    if len(matches) != 1:
        raise ValueError("twin_catalog_family_invalid")
    entry = matches[0]
    baseline = entry.get("baseline")
    schemas = entry.get("supported_schemas")
    if not isinstance(baseline, dict) or baseline.get("schema") != BASELINE_SCHEMA:
        raise ValueError("twin_catalog_baseline_invalid")
    if not isinstance(schemas, list) or BASELINE_SCHEMA not in schemas:
        raise ValueError("twin_catalog_baseline_schema_unlisted")
    return CatalogResolution(
        repository=_safe_catalog_entry_repository(str(entry.get("repository") or "")),
        ref=_safe_ref(str(entry.get("default_ref") or "")),
        relative_path=_safe_relative_path(str(baseline.get("path") or "")),
        source=source,
        revision=revision,
        digest=_digest(document),
        loaded_from=loaded_from,
        stale=stale,
    )


def _read_cache(
    path: Path,
    *,
    repository: str,
    relative_path: str,
    require_attestation: bool,
) -> BaselineSnapshot | None:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        document = _validated(envelope["document"])
        digest = _digest(document)
        if digest != envelope.get("digest"):
            return None
        catalog = envelope.get("catalog")
        if catalog is not None:
            if not isinstance(catalog, dict):
                return None
            catalog = {**catalog, "stale": True}
        attestation = envelope.get("attestation")
        if require_attestation:
            attestation = verify_baseline_attestation(
                document,
                attestation,
                repository=repository,
                relative_path=relative_path,
            )
        return BaselineSnapshot(
            document=document,
            source=str(envelope["source"]),
            revision=str(envelope["revision"]),
            digest=digest,
            loaded_from="cache",
            stale=True,
            catalog=catalog,
            attestation=attestation,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _write_cache(path: Path, snapshot: BaselineSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({
        "source": snapshot.source,
        "revision": snapshot.revision,
        "digest": snapshot.digest,
        "document": snapshot.document,
        "catalog": snapshot.catalog,
        "attestation": snapshot.attestation,
    }, sort_keys=True, separators=(",", ":"))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.write(descriptor, body.encode("utf-8"))
        os.close(descriptor)
        descriptor = -1
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _clone_snapshot(
    repository: str,
    ref: str,
    relative_path: str,
    timeout: float,
    catalog: dict[str, Any] | None = None,
    require_attestation: bool = False,
) -> BaselineSnapshot:
    with tempfile.TemporaryDirectory(prefix="uri-twin-plesk-") as directory:
        checkout = Path(directory) / "checkout"
        environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        completed = subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--single-branch", "--branch", ref, "--", repository, str(checkout)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            raise RuntimeError("twin_git_clone_failed")
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
            env=environment,
        ).stdout.strip()
        document = _validated(json.loads((checkout / relative_path).read_text(encoding="utf-8")))
        attestation = None
        if require_attestation:
            attestation = verify_baseline_attestation(
                document,
                json.loads((checkout / _attestation_path(relative_path)).read_text(encoding="utf-8")),
                repository=repository,
                relative_path=relative_path,
            )
        return BaselineSnapshot(
            document=document,
            source=repository,
            revision=revision,
            digest=_digest(document),
            loaded_from="git",
            stale=False,
            catalog=catalog,
            attestation=attestation,
        )


def _clone_catalog(
    repository: str,
    ref: str,
    relative_path: str,
    family: str,
    timeout: float,
) -> tuple[CatalogResolution, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="uri-twin-catalog-") as directory:
        checkout = Path(directory) / "checkout"
        environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        completed = subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--single-branch", "--branch", ref, "--", repository, str(checkout)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            raise RuntimeError("twin_catalog_git_clone_failed")
        revision = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
            env=environment,
        ).stdout.strip()
        document = json.loads((checkout / relative_path).read_text(encoding="utf-8"))
        return resolve_catalog_baseline(
            document,
            family=family,
            source=repository,
            revision=revision,
            loaded_from="git",
            stale=False,
        ), document


def _write_catalog_cache(path: Path, resolution: CatalogResolution, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({
        "source": resolution.source,
        "revision": resolution.revision,
        "digest": resolution.digest,
        "document": document,
    }, sort_keys=True, separators=(",", ":"))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.write(descriptor, body.encode("utf-8"))
        os.close(descriptor)
        descriptor = -1
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_catalog_cache(path: Path, family: str) -> CatalogResolution | None:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        resolution = resolve_catalog_baseline(
            envelope["document"],
            family=family,
            source=str(envelope["source"]),
            revision=str(envelope["revision"]),
            loaded_from="cache",
            stale=True,
        )
        if resolution.digest != envelope.get("digest"):
            return None
        return resolution
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _load_catalog_resolution(
    *,
    cache_dir: Path,
    timeout: float,
    offline: bool,
) -> CatalogResolution | None:
    repository = _safe_repository(os.environ.get("URI_TWIN_CATALOG_REPOSITORY", DEFAULT_CATALOG_REPOSITORY))
    ref = _safe_ref(os.environ.get("URI_TWIN_CATALOG_REF", DEFAULT_CATALOG_REF))
    relative_path = _safe_relative_path(os.environ.get("URI_TWIN_CATALOG_PATH", DEFAULT_CATALOG_PATH))
    family = str(os.environ.get("URI_TWIN_FAMILY", DEFAULT_TWIN_FAMILY)).strip()
    if not family:
        raise ValueError("twin_catalog_family_missing")
    cache = _catalog_cache_path(cache_dir, repository, ref, relative_path, family)
    if not offline:
        try:
            resolution, document = _clone_catalog(repository, ref, relative_path, family, timeout)
            _write_catalog_cache(cache, resolution, document)
            return resolution
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass
    return _read_catalog_cache(cache, family)


def load_baseline(
    *,
    fallback: dict[str, Any],
    repository: str | None = None,
    ref: str | None = None,
    relative_path: str | None = None,
    cache_dir: Path | None = None,
    timeout: float = 15,
    offline: bool | None = None,
) -> BaselineSnapshot:
    cache_dir = cache_dir or Path(os.environ.get("URI_TWIN_CACHE_DIR", Path.home() / ".cache" / "urirun" / "uri-twin"))
    is_offline = offline if offline is not None else os.environ.get("URI_TWIN_OFFLINE", "").lower() in {"1", "true", "yes"}
    explicit_source = any((
        repository is not None,
        ref is not None,
        relative_path is not None,
        os.environ.get("URI_TWIN_PLESK_REPOSITORY") is not None,
        os.environ.get("URI_TWIN_PLESK_REF") is not None,
        os.environ.get("URI_TWIN_PLESK_PATH") is not None,
    ))
    catalog = None if explicit_source else _load_catalog_resolution(
        cache_dir=cache_dir,
        timeout=timeout,
        offline=is_offline,
    )
    repository = _safe_repository(repository or os.environ.get("URI_TWIN_PLESK_REPOSITORY", catalog.repository if catalog else DEFAULT_REPOSITORY))
    ref = _safe_ref(ref or os.environ.get("URI_TWIN_PLESK_REF", catalog.ref if catalog else DEFAULT_REF))
    relative_path = _safe_relative_path(relative_path or os.environ.get("URI_TWIN_PLESK_PATH", catalog.relative_path if catalog else DEFAULT_PATH))
    cache = _cache_path(cache_dir, repository, ref, relative_path)
    catalog_provenance = catalog.provenance() if catalog else None
    require_attestation = _requires_attestation(repository)

    if not is_offline:
        try:
            snapshot = _clone_snapshot(
                repository,
                ref,
                relative_path,
                timeout,
                catalog_provenance,
                require_attestation,
            )
            _write_cache(cache, snapshot)
            return snapshot
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass

    cached = _read_cache(
        cache,
        repository=repository,
        relative_path=relative_path,
        require_attestation=require_attestation,
    )
    if cached is not None:
        return cached
    document = _validated(fallback)
    return BaselineSnapshot(
        document=document,
        source="package://urirun-connector-subactor-twin-map/baseline/plesk-surface.v1.json",
        revision=f"embedded-v{document['version']}",
        digest=_digest(document),
        loaded_from="embedded",
        stale=True,
        catalog=catalog_provenance,
    )
