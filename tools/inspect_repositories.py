"""Read-only recovery observations for an explicit, pinned URIpack batch.

Local hashes establish consistency only. This tool neither calls Guard nor
replays effects, removes writer state or authenticates completion decisions.
"""
import argparse
import json
import os
from pathlib import Path

from verify_repositories import verify_repositories


def _inventory(root):
    """Bound direct-child observation; never descend into locks or staging."""
    from uripack_refactor.common import checked_root

    result = {}
    with os.scandir(checked_root(root)) as entries:
        for entry in entries:
            if len(result) >= 4096:
                raise ValueError("Repository directory exceeds inspection limit")
            observed = entry.stat(follow_symlinks=False)
            result[entry.name] = (observed.st_dev, observed.st_ino, observed.st_mode,
                                  observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
    return result


def _receipt_consistent(receipt, plan):
    """Check the pinned executor's local receipt shape, never its authority."""
    from uripack_refactor.common import digest
    from uripack_refactor.journal import verify_chain
    from uripack_refactor.planner import artifact_digest

    if not isinstance(receipt, dict):
        return False
    if (receipt.get("schema") != "uripack.extraction-receipt/v1"
            or receipt.get("receipt_sha256") != digest({k: v for k, v in receipt.items() if k != "receipt_sha256"})
            or receipt.get("plan_sha256") != plan["plan_sha256"]
            or receipt.get("artifact_sha256") != artifact_digest(plan)
            or receipt.get("source_sha256") != plan["source_sha256"]
            or type(receipt.get("source_files_copied")) is not int
            or receipt["source_files_copied"] != sum(op["kind"] == "copy" for op in plan["operations"])
            or not isinstance(receipt.get("guard"), str) or not receipt["guard"]
            or any(receipt.get(flag) is not False for flag in
                   ("source_modified_by_uripack", "production_cutover", "git_effects", "registry_publication"))):
        return False
    status, checks, events = (receipt.get(key) for key in ("status", "checks", "events"))
    if status not in ("EXTRACTED", "MATERIALIZED_PENDING_COMPLETION"):
        return False
    if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
        return False
    tool_ids = [check.get("tool_id") for check in checks]
    if (not all(isinstance(tool, str) and tool for tool in tool_ids)
            or tool_ids != sorted(set(tool_ids)) or not set(plan["checks"]).issubset(tool_ids)):
        return False
    for check in checks:
        refs = check.get("evidence_refs")
        if (check.get("schema") != "uripack.check-result/v1" or check.get("status") != "passed"
                or check.get("subject_sha256") != plan["plan_sha256"]
                or check.get("artifact_sha256") != artifact_digest(plan)
                or not isinstance(refs, list) or not refs
                or not all(isinstance(ref, str) and ref for ref in refs)):
            return False
    expected_events = [("extraction.admitted", "ACCEPTED"), ("extraction.staged", "SUCCEEDED")]
    expected_events += [("extraction.checked", "SUCCEEDED")] * len(checks)
    if status == "EXTRACTED":
        expected_events.append(("extraction.completed", "SUCCEEDED"))
    if (not isinstance(events, list) or not all(isinstance(event, dict) for event in events)
            or [(event.get("event_type"), event.get("outcome")) for event in events] != expected_events
            or not verify_chain(events)):
        return False
    if (events[1].get("evidence_ref") != "sha256:" + artifact_digest(plan)
            or any(event.get("evidence_ref") != check["evidence_refs"][0]
                   for event, check in zip(events[2:], checks))):
        return False
    return all(event.get("schema") == "uripack.local-event/v1"
               and event.get("plan_sha256") == plan["plan_sha256"]
               and event.get("authoritative") is False
               and isinstance(event.get("evidence_ref"), str) and event["evidence_ref"]
               for event in events)


def _target_observation(plan):
    from uripack_refactor.common import UripackError, checked_root, parse_document, read_regular, sha256
    from uripack_refactor.executor import STATE_PATH, verify_artifact

    try:
        target = checked_root(plan["target_root"])
        raw, _ = read_regular(target, STATE_PATH)
        receipt = parse_document(raw)
        if not _receipt_consistent(receipt, plan):
            return {"status": "inconsistent", "code": "BATCH_RECEIPT_INCONSISTENT"}
        verification = verify_artifact(plan)
        if read_regular(target, STATE_PATH)[0] != raw:
            return {"status": "inconsistent", "code": "BATCH_OBSERVATION_CHANGED"}
        return {"status": "extracted_local" if receipt["status"] == "EXTRACTED" else "pending_completion",
                "receipt_sha256": sha256(raw), "artifact_verification": verification}
    except (UripackError, OSError) as exc:
        return {"status": "inconsistent", "code": getattr(exc, "code", "BATCH_TARGET_UNREADABLE")}


def inspect_repositories(config, package_source, sources, workspace):
    from uripack_refactor.common import checked_root, digest, load_document
    from uripack_refactor.planner import validate_plan

    workspace = checked_root(workspace)
    verification = verify_repositories(config, package_source, sources, workspace)
    index = load_document(workspace / "repository-plans.json")
    if digest(index) != verification["index_sha256"]:
        raise ValueError("Batch index changed after verification")
    plans = []
    for record in index["repositories"]:
        plan = load_document(workspace / record["plan_path"])
        if plan["plan_sha256"] != record["plan_sha256"]:
            raise ValueError("Batch plan changed after verification")
        validate_plan(plan)
        plans.append(plan)

    targets = checked_root(workspace / "repositories")
    before = _inventory(targets)
    known_names, observations = set(), []
    for record, plan in zip(index["repositories"], plans):
        name = Path(plan["target_root"]).name
        lock = "." + name + ".uripack-writer.lock"
        stages = {entry for entry in before if entry.startswith("." + name + ".uripack-stage-")}
        known_names.update({name, lock, *stages})
        observed = _target_observation(plan) if name in before else {"status": "not_materialized"}
        observations.append({"repository": record["repository"], "plan_sha256": record["plan_sha256"],
                             "artifact_sha256": record["artifact_sha256"], **observed,
                             "writer_lock_present": lock in before, "staging_entries": len(stages)})
    changed = before != _inventory(targets)
    unexpected = len(set(before) - known_names)
    attention = changed or bool(unexpected) or any(
        row["status"] in {"pending_completion", "inconsistent"}
        or row["writer_lock_present"] or row["staging_entries"] for row in observations)
    return {"schema": "uriprocess.repository-inspection/v1",
            "status": "requires_reconciliation" if attention else "observed",
            "verification": verification, "repositories": observations,
            "unexpected_entries": unexpected, "directory_changed_during_observation": changed,
            "observation_atomic": False, "independent_recovery_required": bool(attention),
            "guard_receipts_authenticated": False, "execution_authority": False,
            "automatic_retry": False, "remote_publication": False, "production_cutover": False}


def main(argv=None):
    from uripack_refactor.common import UripackError, load_document

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--source", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args(argv)
    sources = {}
    for item in args.source:
        name, separator, path = item.partition("=")
        if not separator or not path or name in sources:
            parser.error("--source requires a unique ID=PATH")
        sources[name] = Path(path)
    try:
        result = inspect_repositories(load_document(args.selection), args.package_source, sources, args.workspace)
    except (UripackError, ValueError, OSError):
        result = {"schema": "uriprocess.repository-inspection/v1", "status": "blocked",
                  "code": "BATCH_INSPECTION_PREFLIGHT_FAILED", "execution_authority": False,
                  "automatic_retry": False, "guard_receipts_authenticated": False,
                  "observation_atomic": False, "remote_publication": False, "production_cutover": False}
    print(json.dumps(result))
    return 0 if result["status"] == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
