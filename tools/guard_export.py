"""Consume a native admitted Guard unit export. There is no approval command.

Guard owns plans, grants, execution and recovery. uripack owns filesystem
materialization primitives. This client never substitutes either authority.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

PROCESS = "poa://organism-guard/process/fastlane-unit-export/v1"


class ExportRejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ExportRejected(code)


def discover(client, contract):
    require(re.fullmatch(r"[0-9a-f]{64}", contract) is not None, "CONTRACT_PIN_REQUIRED")
    value = client.call("system.discover", {})
    require(value.get("ok") is True and value.get("name") == "organism-guard"
            and value.get("contract_sha256") == contract, "GUARD_CONTRACT_MISMATCH")


def checked_artifact(client, reference, digest):
    from organism_guard.wire import sha
    result = client.call("artifact.get", {"artifact_ref": reference})
    require(result.get("ok") is True and result.get("artifact_ref") == reference
            and result.get("sha256") == digest and sha(result.get("value")) == digest,
            "ARTIFACT_BINDING_MISMATCH")
    return result["value"]


def bound_plan(client, plan_id, expected_hash, repository_id, revision, unit):
    from organism_guard.wire import sha
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "SOURCE_PIN_REQUIRED")
    response = client.call("plan.get", {"plan_id": plan_id})
    require(response.get("ok") is True, "PLAN_UNAVAILABLE")
    plan = response["plan"]
    require(plan["plan_id"] == plan_id and plan["plan_hash"] == expected_hash
            and sha({k: v for k, v in plan.items() if k != "plan_hash"}) == expected_hash,
            "PLAN_HASH_MISMATCH")
    require(plan["process_ref"] == PROCESS and plan["operation"] == "fastlane-unit-export"
            and plan["repository_id"] == repository_id and plan["observation"]["main"] == revision,
            "PLAN_SCOPE_MISMATCH")
    value = checked_artifact(client, plan["input_ref"], plan["input_sha256"])
    require(value == {"repository_id": repository_id, "ticket_id": plan["ticket_id"],
                      "revision": revision, "unit": unit}, "EXPORT_INPUT_MISMATCH")
    return plan


def prepare(client, contract, repository_id, ticket_id, revision, unit):
    discover(client, contract)
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "SOURCE_PIN_REQUIRED")
    value = {"repository_id": repository_id, "ticket_id": ticket_id, "revision": revision, "unit": unit}
    artifact = client.call("artifact.put", {"process_ref": PROCESS, "input": value})
    require(artifact.get("ok") is True, "INPUT_REJECTED")
    response = client.call("process.plan", {"request": {"schema": "poa.request/v1", "operation": "plan",
        "process_ref": PROCESS, "input_ref": artifact["input_ref"], "input_sha256": artifact["input_sha256"]}})
    require(response.get("ok") is True, "PLAN_REJECTED")
    plan = response["plan"]
    return bound_plan(client, plan["plan_id"], plan["plan_hash"], repository_id, revision, unit)


def verify_bundle(bundle, revision, unit):
    from organism_guard.wire import sha
    require(bundle.get("ok") is True and bundle.get("schema") == "organism.guard.unit-export-result/v1"
            and bundle.get("source_revision") == revision and bundle.get("unit") == unit,
            "EXPORT_RESULT_MISMATCH")
    record = bundle["export"]
    require(sha(record) == bundle["export_sha256"] and record["source_revision"] == revision
            and record["unit"] == unit, "PROVENANCE_MISMATCH")
    encoded = bundle["contents_base64"]
    require(set(encoded) == set(record["files"]) == set(bundle["file_modes"]), "EXPORT_FILE_SET_MISMATCH")
    require(len(encoded) <= 1000, "EXPORT_BUDGET")
    files = {}
    for name, value in encoded.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and all(p not in ("", ".", "..", ".git", ".uriprocess")
                for p in name.split("/")) and "\\" not in name and name != "unit-export.json",
                "EXPORT_PATH_INVALID")
        require(bundle["file_modes"][name] in (0o644, 0o755), "EXPORT_MODE_INVALID")
        data = base64.b64decode(value, validate=True)
        require(hashlib.sha256(data).hexdigest() == record["files"][name], "EXPORT_CONTENT_MISMATCH")
        files[name] = data
    require(sum(map(len, files.values())) <= 65536, "EXPORT_BUDGET")
    return files


def fetch(client, contract, plan_id, plan_hash, repository_id, revision, unit, target):
    from organism_guard.wire import sha
    from uripack_refactor.executor import _write, _publish_no_replace
    discover(client, contract)
    plan = bound_plan(client, plan_id, plan_hash, repository_id, revision, unit)
    response = client.call("receipt.get", {"plan_id": plan_id})
    require(response.get("ok") is True, "VERIFIED_RECEIPT_REQUIRED")
    receipt = response["receipt"]
    require(receipt.get("status") == "verified" and receipt.get("plan_hash") == plan_hash
            and all(receipt.get(k) == plan[k] for k in ("plan_id", "queue_revision", "repository_id", "ticket_id"))
            and receipt.get("executor") == plan["executor"]
            and receipt.get("process_uri") == plan["step"]["process_uri"]
            and sha({k: v for k, v in receipt.items() if k != "receipt_sha256"}) == receipt["receipt_sha256"],
            "RECEIPT_BINDING_MISMATCH")
    bundle = checked_artifact(client, receipt["output_ref"], receipt["output_sha256"])
    files = verify_bundle(bundle, revision, unit)
    target = Path(target).absolute()
    require(not target.exists() and not target.is_symlink(), "TARGET_EXISTS")
    require(target.parent.is_dir(), "TARGET_PARENT_MISSING")
    with tempfile.TemporaryDirectory(prefix=".uriprocess-download-", dir=target.parent) as temporary:
        staged = Path(temporary) / "bundle"
        staged.mkdir(mode=0o700)
        for name, data in files.items():
            _write(staged, name, data, bundle["file_modes"][name])
        _write(staged, "unit-export.json", (json.dumps(bundle["export"], indent=2) + "\n").encode(), 0o644)
        _write(staged, ".uriprocess/export-receipt.json", (json.dumps(receipt, indent=2) + "\n").encode(), 0o600)
        for name, data in files.items():
            require((staged / name).read_bytes() == data, "LOCAL_READBACK_FAILED")
        _publish_no_replace(staged, target)
    return {"status": "materialized", "plan_id": plan_id, "receipt_sha256": receipt["receipt_sha256"],
            "files": len(files), "production_cutover": False}


def execute(client, contract, envelope, repository_id, revision, unit, target):
    require(set(envelope) == {"plan_id", "plan_hash", "queue_revision", "grant_ref"}, "NATIVE_ENVELOPE_REQUIRED")
    target = Path(target).absolute()
    require(not target.exists() and not target.is_symlink() and target.parent.is_dir(), "TARGET_UNAVAILABLE")
    discover(client, contract)
    plan = bound_plan(client, envelope["plan_id"], envelope["plan_hash"], repository_id, revision, unit)
    require(envelope["queue_revision"] == plan["queue_revision"], "QUEUE_REVISION_MISMATCH")
    # No automatic retry. Unknown outcomes belong to native independent recovery.
    result = client.call("execution.start", envelope)
    require(result.get("ok") is True, "EXECUTION_NOT_VERIFIED")
    return fetch(client, contract, plan["plan_id"], plan["plan_hash"], repository_id, revision, unit, target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["plan", "execute", "fetch"])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token-env", default="URIPROCESS_GUARD_TOKEN")
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--ticket-id")
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--plan-id")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--target", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        from organism_guard.client import GuardClient
        from organism_guard.wire import strict_loads
        require(not args.out.exists(), "OUTPUT_EXISTS")
        token = os.environ.get(args.token_env)
        require(bool(token), "GUARD_TOKEN_MISSING")
        client = GuardClient(args.base_url, token)
        common = (client, args.contract_sha256)
        scope = (args.repository_id, args.revision, args.unit)
        if args.action == "plan":
            require(bool(args.ticket_id), "TICKET_REQUIRED")
            result = prepare(*common, args.repository_id, args.ticket_id, args.revision, args.unit)
        else:
            require(args.target is not None, "TARGET_REQUIRED")
            require(not args.out.resolve().is_relative_to(args.target.resolve()), "EVIDENCE_OUTSIDE_TARGET_REQUIRED")
            if args.action == "execute":
                require(args.envelope is not None, "NATIVE_ENVELOPE_REQUIRED")
                result = execute(*common, strict_loads(args.envelope.read_bytes()), *scope, args.target)
            else:
                require(bool(args.plan_id and args.plan_sha256), "PLAN_BINDING_REQUIRED")
                result = fetch(*common, args.plan_id, args.plan_sha256, *scope, args.target)
        with args.out.open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, ExportRejected) else "GUARD_EXPORT_FAILED"
        print(json.dumps({"status": "blocked", "code": code, "automatic_retry": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
