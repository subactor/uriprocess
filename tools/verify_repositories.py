"""Verify a complete repository batch against explicit, pinned source selections.

Reconstruct expected packages and URIpack plans from upstream Git objects in a
temporary directory. Never trust the batch's own index or local source hashes
as upstream evidence. This is a read-only check, not Guard or publication
authority. Optional artifact verification does not authenticate Guard receipts.
"""
import argparse
import json
from pathlib import Path
import tempfile

from generate import encode
from prepare_repositories import prepare_repositories


def verify_repositories(config, package_source, sources, workspace, *, extracted=False):
    from uripack_refactor.common import checked_root, digest, load_document
    from uripack_refactor.executor import verify_artifact
    from uripack_refactor.planner import validate_plan

    workspace = checked_root(workspace)
    if digest(load_document(workspace / "repository-selection.json")) != digest(config):
        raise ValueError("Batch selection differs from the explicitly expected selection")
    actual_index = load_document(workspace / "repository-plans.json")
    plans = []
    with tempfile.TemporaryDirectory(prefix="uriprocess-repository-verification-") as temporary:
        reference = Path(temporary) / "reference"
        expected_index = prepare_repositories(config, package_source, sources, reference)
        plan_names = {Path(record["plan_path"]).name for record in expected_index["repositories"]}
        plan_directory = checked_root(workspace / "plans")
        if {path.name for path in plan_directory.iterdir()} != plan_names:
            raise ValueError("Batch plan files differ from the complete pinned selection")
        for record in expected_index["repositories"]:
            expected = load_document(reference / record["plan_path"])
            # Only workspace coordinates differ. Every operation, URI, source
            # byte/mode, destination binding and compiler result must match.
            for field in ("source_root", "target_root"):
                expected[field] = str(workspace / Path(expected[field]).relative_to(reference))
            expected["plan_sha256"] = digest({k: v for k, v in expected.items() if k != "plan_sha256"})
            record["plan_sha256"] = expected["plan_sha256"]
            actual = load_document(workspace / record["plan_path"])
            if digest(actual) != digest(expected):
                raise ValueError("Repository plan differs from pinned upstream reconstruction")
            # Reobserve the actual candidate after validating its paths and
            # complete plan against independently reconstructed expectations.
            validate_plan(actual)
            plans.append(actual)
        if digest(actual_index) != digest(expected_index):
            raise ValueError("Repository index differs from pinned upstream reconstruction")

    artifacts = []
    if extracted:
        targets = checked_root(workspace / "repositories")
        if {path.name for path in targets.iterdir()} != {Path(plan["target_root"]).name for plan in plans}:
            raise ValueError("Complete extraction of every selected repository required")
        artifacts = [verify_artifact(plan) for plan in plans]
    return {"schema": "uriprocess.repository-verification/v1", "status": "passed",
            "selection_sha256": digest(config), "index_sha256": digest(actual_index),
            "package_revision": config["package_revision"],
            "repositories": [{"repository": record["repository"], "plan_sha256": record["plan_sha256"],
                              "artifact_sha256": record["artifact_sha256"],
                              "source_revision": record["source_revision"]}
                             for record in expected_index["repositories"]],
            "public_uri_count": len(expected_index["uri_owners"]),
            "pinned_upstream_comparison": "passed", "artifacts_checked": extracted,
            "artifacts": artifacts, "guard_receipts_authenticated": False,
            "behavioral_equivalence_claimed": False, "execution_authority": False,
            "remote_publication": False, "production_cutover": False}


def main(argv=None):
    from uripack_refactor.common import checked_root, load_document
    from uripack_refactor.executor import _write

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--source", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--extracted", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    sources = {}
    for item in args.source:
        name, separator, path = item.partition("=")
        if not separator or not path or name in sources:
            parser.error("--source requires a unique ID=PATH")
        sources[name] = Path(path)
    output = checked_root(args.out, exists=False)
    checked_root(output.parent)
    if output.exists():
        raise ValueError("Verification receipt must be new")
    for root in [args.workspace, args.package_source, *sources.values()]:
        root = checked_root(root)
        if output == root or root in output.parents:
            raise ValueError("Verification receipt must be outside the batch and source repositories")
    result = verify_repositories(load_document(args.selection), args.package_source, sources,
                                 args.workspace, extracted=args.extracted)
    # No receipt exists on verification failure; URIpack's exclusive writer
    # also rejects a destination that appears after the initial check.
    _write(output.parent, output.name, encode(result), 0o600)
    print(json.dumps({"status": result["status"], "repositories": len(result["repositories"]),
                      "public_uris": result["public_uri_count"], "artifacts_checked": result["artifacts_checked"],
                      "execution_authority": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
