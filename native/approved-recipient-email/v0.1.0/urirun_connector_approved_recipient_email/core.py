"""Exact, fail-closed adapter for ticket-approved outbound email."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import tempfile
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "approved-recipient-email"
ROUTE = "email://approved-recipients/message/command/send"
SCHEMA = "subactor.approved-recipient-email/v1"
ACTOR = "bot:communications-bot"
PLAN_SCHEMA = "subactor.approved-recipient-email-plan/v1"
GRANT_RISK_CLASSES = {"read_only", "reversible", "boundary", "governance"}
GRANT_CLOCK_SKEW_SECONDS = 60
MAX_RECIPIENTS = 100
conn = urirun.connector(CONNECTOR_ID, scheme="email")


def _fail(error: str, **details: Any) -> dict[str, Any]:
    return urirun.fail(error, connector=CONNECTOR_ID, schema=SCHEMA, **details)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name.lower()}_not_configured")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _recipients(value: str | list[str] | tuple[str, ...] | None) -> list[str]:
    candidates = value.split(",") if isinstance(value, str) else list(value or ())
    normalized: list[str] = []
    for candidate in candidates:
        address = str(candidate or "").strip()
        if not address or "\r" in address or "\n" in address:
            raise ValueError("approved_recipient_invalid")
        parsed = parseaddr(address)[1]
        if parsed != address or address.count("@") != 1 or any(char.isspace() for char in address):
            raise ValueError("approved_recipient_invalid")
        if address.lower() not in {item.lower() for item in normalized}:
            normalized.append(address)
    if not normalized:
        raise ValueError("approved_recipients_required")
    if len(normalized) > MAX_RECIPIENTS:
        raise ValueError("approved_recipients_limit_exceeded")
    return normalized


def _build_plan(
    source_ticket_id: str,
    recipients: str | list[str] | tuple[str, ...] | None,
    subject: str,
    body: str,
) -> tuple[dict[str, Any], str, str]:
    ticket_id = str(source_ticket_id or "").strip().upper()
    if not re.fullmatch(r"PLF-[0-9]+", ticket_id):
        raise ValueError("source_ticket_id_invalid")
    clean_subject = str(subject or "").strip()
    clean_body = str(body or "")
    if not clean_subject or len(clean_subject) > 300 or "\r" in clean_subject or "\n" in clean_subject:
        raise ValueError("subject_invalid")
    if not clean_body or len(clean_body.encode("utf-8")) > 100_000:
        raise ValueError("body_invalid")
    message = {
        "recipients": _recipients(recipients),
        "subject": clean_subject,
        "body": clean_body,
    }
    artifact_sha256 = _sha256(message)
    plan = {
        "schema": PLAN_SCHEMA,
        "route": ROUTE,
        "actor": ACTOR,
        "source_ticket_id": ticket_id,
        "transport_ref": "deployment://smtp/external",
        "message": message,
        "artifact_sha256": artifact_sha256,
    }
    return plan, _sha256(plan), artifact_sha256


def _vault_password() -> str:
    base = _required_env("SMTP_VAULT_URL").rstrip("/")
    entry_id = _required_env("SMTP_VAULT_ENTRY_ID")
    origin = _required_env("SMTP_VAULT_ORIGIN")
    token = os.environ.get("BROWSER_AGENT_SERVICE_TOKEN", "").strip() or os.environ.get(
        "BRIDGE_INTROSPECTION_SECRET", ""
    ).strip()
    if not token:
        raise ValueError("smtp_vault_token_not_configured")
    request = Request(
        f"{base}/internal/vault/{quote(entry_id, safe='')}/lease",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "urirun-connector-approved-recipient-email/0.1",
        },
        data=json.dumps({"origin": origin, "field": "password"}).encode("utf-8"),
        method="POST",
    )
    try:
        with urlopen(request, timeout=8.0) as response:
            document = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"smtp_vault_secret_unavailable:{exc.code}") from None
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"smtp_vault_unavailable:{type(exc).__name__}") from None
    secret = str(document.get("secret") or "")
    if not secret:
        raise RuntimeError("smtp_vault_secret_unavailable")
    return secret


def _smtp_settings() -> dict[str, Any]:
    if not _truthy("EMAIL_ENABLED") or os.environ.get("EMAIL_MODE", "").strip() != "smtp":
        raise ValueError("email_smtp_not_enabled")
    if not _truthy("SMTP_EXTERNAL_ENABLED") or not _truthy("SMTP_EXTERNAL_REQUIRED"):
        raise ValueError("external_smtp_not_required")
    host = _required_env("SMTP_EXTERNAL_HOST")
    servername = os.environ.get("SMTP_EXTERNAL_SERVERNAME", "").strip() or host
    if servername != host:
        raise ValueError("smtp_servername_override_unsupported")
    try:
        port = int(_required_env("SMTP_EXTERNAL_PORT"))
        timeout = max(0.1, int(_required_env("SMTP_TIMEOUT_MS")) / 1000)
    except (TypeError, ValueError):
        raise ValueError("smtp_numeric_configuration_invalid") from None
    if not 1 <= port <= 65535:
        raise ValueError("smtp_port_invalid")
    username = _required_env("SMTP_EXTERNAL_USER")
    sender = _required_env("SMTP_EXTERNAL_FROM")
    _recipients([username])
    _recipients([sender])
    if not _truthy("SMTP_EXTERNAL_SECURE") or not _truthy("SMTP_TLS_REJECT_UNAUTHORIZED"):
        raise ValueError("external_smtp_verified_tls_required")
    return {
        "host": host,
        "port": port,
        "username": username,
        "password": _vault_password(),
        "sender": sender,
        "ehlo": _required_env("SMTP_EHLO_NAME"),
        "timeout": timeout,
    }


def _open_smtp(settings: dict[str, Any]) -> smtplib.SMTP:
    smtp = smtplib.SMTP_SSL(
        settings["host"],
        settings["port"],
        local_hostname=settings["ehlo"],
        timeout=settings["timeout"],
        context=ssl.create_default_context(),
    )
    smtp.ehlo()
    smtp.login(settings["username"], settings["password"])
    return smtp


def _preflight(settings: dict[str, Any]) -> None:
    smtp = _open_smtp(settings)
    try:
        status, _message = smtp.noop()
        if status != 250:
            raise RuntimeError("smtp_preflight_failed")
    finally:
        smtp.quit()


def _decode_json(part: str) -> dict[str, Any] | None:
    try:
        padding = "=" * (-len(part) % 4)
        value = json.loads(base64.urlsafe_b64decode(part + padding).decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _verify_grant(token: str, plan_hash: str, artifact_sha256: str) -> tuple[dict[str, str] | None, str | None]:
    secrets = [
        os.environ.get("APPLY_GRANT_HMAC_SECRET", "").strip()
        or os.environ.get("TOKEN_PEPPER", "").strip(),
        os.environ.get("APPLY_GRANT_HMAC_SECRET_NEXT", "").strip(),
    ]
    secrets = [secret for secret in secrets if secret]
    if not secrets:
        return None, "apply_grant_secret_missing"
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        return None, "apply_grant_required" if not str(token or "").strip() else "apply_grant_signature_invalid"
    header = _decode_json(parts[0])
    claims_value = _decode_json(parts[1])
    if header != {"alg": "HS256", "typ": "apply-grant"} or claims_value is None:
        return None, "apply_grant_signature_invalid"
    try:
        padding = "=" * (-len(parts[2]) % 4)
        supplied = base64.urlsafe_b64decode(parts[2] + padding)
    except ValueError:
        return None, "apply_grant_signature_invalid"
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError:
        return None, "apply_grant_signature_invalid"
    if not any(hmac.compare_digest(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest(), supplied) for secret in secrets):
        return None, "apply_grant_signature_invalid"
    claims = {key: str(value) for key, value in claims_value.items()}
    try:
        expiry_value = datetime.fromisoformat(claims.get("expires_at", "").replace("Z", "+00:00"))
        if expiry_value.tzinfo is None:
            return None, "apply_grant_signature_invalid"
        expires_at = expiry_value.timestamp()
    except ValueError:
        return None, "apply_grant_signature_invalid"
    if time.time() > expires_at + GRANT_CLOCK_SKEW_SECONDS:
        return None, "apply_grant_expired"
    expected = {
        "plan_hash": plan_hash,
        "target": ROUTE,
        "actor": ACTOR,
        "artifact_sha256": artifact_sha256,
    }
    errors = {
        "plan_hash": "apply_grant_plan_hash_mismatch",
        "target": "apply_grant_target_mismatch",
        "actor": "apply_grant_actor_mismatch",
        "artifact_sha256": "apply_grant_artifact_mismatch",
    }
    for key, value in expected.items():
        if claims.get(key, "").lower() != value.lower():
            return None, errors[key]
    if not claims.get("intent_pack") or not claims.get("jti") or claims.get("risk_class") not in GRANT_RISK_CLASSES:
        return None, "apply_grant_signature_invalid"
    return claims, None


def _consume_grant(claims: dict[str, str]) -> str | None:
    store_value = os.environ.get("APPLY_GRANT_JTI_STORE", "").strip()
    if not store_value:
        return "apply_grant_replay_store_required"
    store_path = Path(store_value)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store_path.with_suffix(f"{store_path.suffix}.lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            try:
                document = json.loads(store_path.read_text(encoding="utf-8"))
                if not isinstance(document, dict) or not isinstance(document.get("entries"), dict):
                    return "apply_grant_replay_store_invalid"
                entries = dict(document.get("entries") or {})
            except FileNotFoundError:
                entries = {}
            except (OSError, ValueError, json.JSONDecodeError):
                return "apply_grant_replay_store_invalid"
            now = time.time() * 1000
            entries = {key: value for key, value in entries.items() if isinstance(value, (int, float)) and value > now}
            jti = claims["jti"]
            if jti in entries:
                return "apply_grant_replay"
            expiry = datetime.fromisoformat(claims["expires_at"].replace("Z", "+00:00")).timestamp() * 1000
            entries[jti] = expiry + GRANT_CLOCK_SKEW_SECONDS * 1000
            fd, temporary = tempfile.mkstemp(prefix=f"{store_path.name}.", suffix=".tmp", dir=store_path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump({"schema": "apply-grant-jti-replay-1", "entries": entries}, stream, indent=2)
                    stream.write("\n")
                os.chmod(temporary, 0o600)
                os.replace(temporary, store_path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    return None


def _deliver(settings: dict[str, Any], message: dict[str, Any]) -> list[dict[str, str]]:
    smtp = _open_smtp(settings)
    receipts: list[dict[str, str]] = []
    try:
        for recipient in message["recipients"]:
            email = EmailMessage()
            email["From"] = settings["sender"]
            email["To"] = recipient
            email["Subject"] = message["subject"]
            email.set_content(message["body"])
            smtp.send_message(email, from_addr=settings["sender"], to_addrs=[recipient])
            receipts.append({"recipient": recipient, "status": "accepted"})
    finally:
        smtp.quit()
    return receipts


@conn.handler(
    ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Plan or send one grant-bound message to approved recipients"},
)
def send(
    source_ticket_id: str = "",
    to: str | list[str] | tuple[str, ...] | None = None,
    recipients: str | list[str] | tuple[str, ...] | None = None,
    subject: str = "",
    body: str = "",
    require_external: bool = True,
    apply: bool = False,
    plan_hash: str = "",
    apply_grant: str = "",
) -> dict[str, Any]:
    """Preflight by default; delivery requires the exact plan and signed one-time grant."""
    if not isinstance(apply, bool):
        return _fail("apply_flag_invalid")
    if require_external is not True:
        return _fail("external_smtp_required")
    if to not in (None, "") and recipients not in (None, ""):
        return _fail("approved_recipient_alias_conflict")
    try:
        plan, expected_hash, artifact_sha256 = _build_plan(
            source_ticket_id,
            recipients if recipients not in (None, "") else to,
            subject,
            body,
        )
    except ValueError as exc:
        return _fail(str(exc))

    common = {
        "route": ROUTE,
        "actor": ACTOR,
        "source_ticket_id": plan["source_ticket_id"],
        "plan": plan,
        "plan_hash": expected_hash,
        "artifact_sha256": artifact_sha256,
        "adapter_implemented": True,
        "exact_route_registered": True,
        "uri_coverage_verified": True,
        "source_readiness_preflight_green": False,
    }
    claims = None
    if apply:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", str(plan_hash or "")) or not hmac.compare_digest(
            str(plan_hash).lower(), expected_hash
        ):
            return _fail("plan_hash_mismatch", **common)
        claims, grant_error = _verify_grant(apply_grant, expected_hash, artifact_sha256)
        if grant_error:
            return _fail(grant_error, **common)
    try:
        settings = _smtp_settings()
        _preflight(settings)
    except (ValueError, RuntimeError, OSError, smtplib.SMTPException) as exc:
        return _fail(str(exc) if isinstance(exc, (ValueError, RuntimeError)) else "smtp_preflight_failed", **common)
    common["source_readiness_preflight_green"] = True
    if not apply:
        return urirun.ok(
            connector=CONNECTOR_ID,
            schema=SCHEMA,
            dry_run=True,
            production_apply=False,
            authority_granted=False,
            **common,
        )
    replay_error = _consume_grant(claims or {})
    if replay_error:
        return _fail(replay_error, **common)
    try:
        receipts = _deliver(settings, plan["message"])
    except (OSError, smtplib.SMTPException):
        return _fail("smtp_delivery_failed", **common)
    return urirun.ok(
        connector=CONNECTOR_ID,
        schema=SCHEMA,
        dry_run=False,
        production_apply=True,
        authority_granted=True,
        receipts=receipts,
        **common,
    )


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
