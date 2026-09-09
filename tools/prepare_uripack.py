"""Prepare immutable process candidates and a real uripack extraction plan.

Install uripack-refactor explicitly; no sibling discovery or Guard fallback.
The workspace must be new and outside the source repository. Applying the plan
is a separate invocation of uripack apply with a protected GuardBridge config.
"""
import argparse
import json
from pathlib import Path

from generate import encode, generate


def prepare(config, source, workspace):
    from uripack_refactor.planner import build_plan

    source, workspace = Path(source).resolve(), Path(workspace).resolve()
    if source == workspace or source in workspace.parents or workspace in source.parents:
        raise ValueError("Workspace and source must be disjoint")
    workspace.mkdir(parents=True, exist_ok=False)
    candidate = workspace / "candidate"
    if config.get("schema") == "uriprocess.native-selection/v1":
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
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    plan = prepare(json.loads(args.selection.read_text()), args.source, args.workspace)
    print(json.dumps({"plan_sha256": plan["plan_sha256"], "target": plan["target_root"],
                      "status": "planned", "execution_authority": False}))
