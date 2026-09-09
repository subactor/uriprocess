"""Prepare immutable process candidates and a real uripack extraction plan.

Install uripack-refactor explicitly; no sibling discovery or Guard fallback.
The workspace must be new and outside the source repository. Applying the plan
is a separate invocation of uripack apply with a protected GuardBridge config.
"""
import argparse
import json
from pathlib import Path

from generate import encode, generate


def prepare(config, source, workspace, *, selection_root=None):
    from uripack_refactor.planner import build_plan

    batch = config.get("schema") == "uriprocess.native-batch-selection/v1"
    workspace = Path(workspace).resolve()
    if batch:
        from generate_native_catalog import generate_catalog, selected_groups
        if selection_root is None:
            raise ValueError("Native batch requires an explicit selection root")
        selected_groups(config, selection_root, source)
        roots = [Path(value).resolve() for value in source.values()]
    else:
        source = Path(source).resolve()
        roots = [source]
    if any(root == workspace or root in workspace.parents or workspace in root.parents for root in roots):
        raise ValueError("Workspace and source must be disjoint")
    workspace.mkdir(parents=True, exist_ok=False)
    candidate = workspace / "candidate"
    if batch:
        generate_catalog(config, selection_root, source, candidate)
        processes = json.loads((candidate / "native-catalog.json").read_text())["packages"]
    elif config.get("schema") == "uriprocess.native-selection/v1":
        from generate_native import generate_native
        generate_native(config, source, candidate)
        processes = json.loads((candidate / "native-catalog.json").read_text())["packages"]
    else:
        generate(config, source, candidate)
        processes = json.loads((candidate / "catalog.json").read_text())["processes"]
    # Each candidate owns a closed file set. The shared readiness implementation
    # remains an intentional pinned projection in both independently usable units.
    request = {"schema": "uripack.refactor-request/v1", "operation": "plan",
               "namespace": "subactor", "units": []}
    for process in processes:
        path = Path(process["path"])
        request["units"].append({"id": "-".join(path.parts),
                                 "include": [process["path"]],
                                 "public_uris": process["public_uris"] if "public_uris" in process else [process["process_ref"]]})
    plan = build_plan(request, candidate, workspace / "extracted")
    (workspace / "request.json").write_bytes(encode(request))
    (workspace / "plan.json").write_bytes(encode(plan))
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    mapping = parser.add_mutually_exclusive_group(required=True)
    mapping.add_argument("--source", type=Path)
    mapping.add_argument("--source-map", action="append", metavar="NAME=PATH")
    parser.add_argument("--selection-root", type=Path)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    from generate_native_catalog import source_mapping
    source = source_mapping(args.source_map) if args.source_map else args.source
    plan = prepare(json.loads(args.selection.read_text()), source, args.workspace, selection_root=args.selection_root)
    print(json.dumps({"plan_sha256": plan["plan_sha256"], "target": plan["target_root"],
                      "status": "planned", "execution_authority": False}))
