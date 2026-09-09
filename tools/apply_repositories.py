"""Apply an explicit verified batch through operator-protected URIpack bridges.

This is an execution primitive for already selected plans, not Strategy
selection or Git publication. No test Guard or approval shortcut is exposed.
Unknown outcomes halt the batch; existing targets require independent recovery.
"""
import argparse
import json
from pathlib import Path

from generate import encode
from verify_repositories import verify_repositories


class ApplicationRejected(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ApplicationOutcomeUnknown(RuntimeError):
    """An execution attempt could not persist its bounded failure receipt."""


def apply_repositories(config, package_source, sources, workspace, guard_configs, output):
    from uripack_refactor.common import checked_root, digest, load_document, read_regular, sha256, UripackError
    from uripack_refactor.executor import _write, apply_plan
    from uripack_refactor.guard import GuardBridge
    from uripack_refactor.planner import validate_plan

    workspace = checked_root(workspace)
    output = checked_root(output, exists=False)
    checked_root(output.parent)
    if output.exists():
        raise ApplicationRejected("BATCH_EVIDENCE_EXISTS", "Application evidence directory must be new")
    roots = [workspace, checked_root(package_source), *(checked_root(p) for p in sources.values())]
    if any(root == output or root in output.parents or output in root.parents for root in roots):
        raise ApplicationRejected("BATCH_EVIDENCE_SCOPE", "Application evidence and source/batch roots must be disjoint")
    verification = verify_repositories(config, package_source, sources, workspace)
    index = load_document(workspace / "repository-plans.json")
    if digest(index) != verification["index_sha256"]:
        raise ApplicationRejected("BATCH_INDEX_DRIFT", "Batch index changed after verification")
    if set(guard_configs) != {r["repository"] for r in verification["repositories"]}:
        raise ApplicationRejected("BATCH_GUARD_MAPPING_INCOMPLETE", "An explicit protected bridge is required for every repository")
    prepared = []
    for record in index["repositories"]:
        plan = load_document(workspace / record["plan_path"])
        if plan["plan_sha256"] != record["plan_sha256"]:
            raise ApplicationRejected("BATCH_PLAN_DRIFT", "Plan changed after batch verification")
        validate_plan(plan)
        target = checked_root(plan["target_root"], exists=False)
        if target.exists():
            raise ApplicationRejected("BATCH_TARGET_RECONCILIATION_REQUIRED", "Existing extraction target requires independent recovery; no automatic replay")
        bridge_path = checked_root(guard_configs[record["repository"]], exists=False)
        if any(root == bridge_path or root in bridge_path.parents for root in [*roots, output]):
            raise ApplicationRejected("BATCH_GUARD_SCOPE", "Protected bridge configuration must be outside source, batch and evidence roots")
        # Construct every real bridge before the first effect. Its constructor
        # validates the operator configuration, executable pins and required checks.
        bridge = GuardBridge(bridge_path, plan["source_root"], target)
        for filename in bridge.config["pinned_files"]:
            path = Path(filename).resolve()
            if any(root == path or root in path.parents for root in [*roots, output]):
                raise ApplicationRejected("BATCH_GUARD_SCOPE", "Protected bridge implementation must be outside every batch source")
        prepared.append((record, plan, bridge))
    output.mkdir(mode=0o700)
    _write(output, "started.json", encode({"schema": "uriprocess.batch-application-start/v1",
           "verification": verification, "automatic_retry": False,
           "repositories": [{"repository": r["repository"], "guard_identity": guard.identity,
                             "plan_sha256": plan["plan_sha256"]} for r, plan, guard in prepared]}), 0o600)
    completed = []
    active = None
    try:
        for ordinal, (record, plan, guard) in enumerate(prepared, 1):
            active = record["repository"]
            _write(output, f"attempt-{ordinal:02d}.json", encode({"repository": active,
                   "plan_sha256": plan["plan_sha256"], "status": "started", "automatic_retry": False}), 0o600)
            result = apply_plan(plan, guard)
            if result["status"] != "EXTRACTED" or result.get("already_materialized") is not False:
                raise ApplicationRejected("BATCH_TARGET_RECONCILIATION_REQUIRED", "A fresh protected extraction is required")
            raw, _ = read_regular(Path(plan["target_root"]), ".uripack/receipt.json")
            receipt = {"repository": active, "plan_sha256": plan["plan_sha256"],
                       "artifact_sha256": result["artifact_sha256"], "receipt_sha256": sha256(raw),
                       "status": "extracted", "guard_identity": guard.identity}
            _write(output, f"completed-{ordinal:02d}.json", encode(receipt), 0o600)
            completed.append(receipt)
        active = None
        readback = verify_repositories(config, package_source, sources, workspace, extracted=True)
        result = {"schema": "uriprocess.batch-application/v1", "status": "extracted",
                  "repositories": completed, "readback": readback,
                  "automatic_retry": False, "remote_publication": False, "production_cutover": False}
        _write(output, "batch-extraction.json", encode(result), 0o600)
        return result
    except Exception as error:
        # Raw bridge output and exception text are never placed in receipts.
        # A started marker without completion also survives abrupt process loss.
        result = {"schema": "uriprocess.batch-application/v1", "status": "halted",
                  "failed_repository": active, "completed": completed,
                  "code": error.code if isinstance(error, (UripackError, ApplicationRejected)) else "BATCH_APPLICATION_FAILED",
                  "independent_recovery_required": True, "automatic_retry": False,
                  "remote_publication": False, "production_cutover": False}
        try:
            _write(output, "halted.json", encode(result), 0o600)
        except (OSError, UripackError):
            raise ApplicationOutcomeUnknown("BATCH_EVIDENCE_UNAVAILABLE") from None
        return result


def main(argv=None):
    from uripack_refactor.common import load_document, UripackError

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--source", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--guard-config", action="append", default=[], metavar="REPOSITORY=PATH")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    def mappings(items):
        result = {}
        for item in items:
            name, separator, path = item.partition("=")
            if not separator or not path or name in result:
                parser.error("Explicit, unique NAME=PATH arguments required")
            result[name] = Path(path)
        return result

    try:
        result = apply_repositories(load_document(args.selection), args.package_source, mappings(args.source),
                                    args.workspace, mappings(args.guard_config), args.output)
    except ApplicationOutcomeUnknown:
        print(json.dumps({"status": "halted", "stage": "execution", "effects_may_have_occurred": True,
                          "code": "BATCH_EVIDENCE_UNAVAILABLE", "independent_recovery_required": True,
                          "automatic_retry": False, "remote_publication": False, "production_cutover": False}))
        return 2
    except (ValueError, OSError, UripackError) as error:
        print(json.dumps({"status": "blocked", "stage": "preflight", "execution_started": False,
                          "code": error.code if isinstance(error, (ApplicationRejected, UripackError)) else "BATCH_PREFLIGHT_FAILED",
                          "automatic_retry": False, "remote_publication": False, "production_cutover": False}))
        return 2
    print(json.dumps({"status": result["status"], "automatic_retry": False,
                      "remote_publication": False, "production_cutover": False}))
    return 0 if result["status"] == "extracted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
