"""Prepare independent URIpack plans for explicitly named destination repositories.

Reads selections from pinned Git objects and original source repositories.
Only candidates and plans are written. Guard admission, extraction, repository
publication and consumer cutover remain separate operations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from generate import encode, generate, read_object, relative
from generate_native import generate_native


def selection_groups(config):
    if (set(config) != {"schema", "version", "package_repository", "package_revision", "groups"}
            or config["schema"] != "uriprocess.repository-selection/v1"
            or type(config["version"]) is not int or config["version"] < 1
            or not re.fullmatch(r"[0-9a-f]{40}", config["package_revision"])
            or config["package_repository"] != "https://github.com/subactor/uriprocess"
            or not isinstance(config["groups"], list) or not config["groups"]):
        raise ValueError("Explicit pinned repository selection required")
    sources, destinations = set(), set()
    for group in config["groups"]:
        if (set(group) != {"source_id", "selection", "repositories"}
                or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", group["source_id"])
                or group["source_id"] in sources
                or not isinstance(group["repositories"], dict) or not group["repositories"]):
            raise ValueError("Unique source groups and explicit repository mappings required")
        sources.add(group["source_id"])
        relative(group["selection"])
        for package, repository in group["repositories"].items():
            relative(package)
            if (not re.fullmatch(r"uriprocess/[a-z][a-z0-9-]{0,95}", repository)
                    or repository in destinations):
                raise ValueError("Unique uriprocess repository destinations required")
            destinations.add(repository)
    return sources


def prepare_repositories(config, package_source, sources, workspace):
    from uripack_refactor.common import checked_root, digest, parse_json
    from uripack_refactor.planner import artifact_digest, build_plan

    required = selection_groups(config)
    if set(sources) != required:
        raise ValueError("Supply exactly the explicitly selected source repositories")
    package_source = checked_root(package_source)
    sources = {name: checked_root(path) for name, path in sources.items()}
    workspace = checked_root(workspace, exists=False)
    for source in [package_source, *sources.values()]:
        if source == workspace or source in workspace.parents or workspace in source.parents:
            raise ValueError("Workspace and source repositories must be disjoint")
    # Read all selection objects before writing. Dirty checkout selections and
    # mutable branches never select upstream code.
    selections = {}
    for group in config["groups"]:
        data = read_object(package_source, config["package_revision"], group["selection"])
        selection = parse_json(data)
        if selection.get("schema") not in {"uriprocess.selection/v1", "uriprocess.native-selection/v1"}:
            raise ValueError("Unsupported process selection")
        selections[group["source_id"]] = (selection, hashlib.sha256(data).hexdigest())
    workspace.mkdir(parents=True, exist_ok=False)
    (workspace / "plans").mkdir()
    (workspace / "repositories").mkdir()
    records, uri_owners = [], {}
    for group in config["groups"]:
        source_id = group["source_id"]
        selection, selection_hash = selections[source_id]
        candidate = workspace / "candidates" / source_id
        if selection["schema"] == "uriprocess.native-selection/v1":
            generate_native(selection, sources[source_id], candidate)
            packages = json.loads((candidate / "native-catalog.json").read_text())["packages"]
        else:
            generate(selection, sources[source_id], candidate)
            packages = json.loads((candidate / "catalog.json").read_text())["processes"]
        if set(group["repositories"]) != {package["path"] for package in packages}:
            raise ValueError("Repository mapping must cover exactly the pinned selection")
        for package in packages:
            repository = group["repositories"][package["path"]]
            name = repository.split("/")[1]
            uris = package.get("public_uris", [package.get("process_ref")])
            if any(uri in uri_owners for uri in uris):
                raise ValueError("Public URI has multiple destination repositories")
            uri_owners.update({uri: repository for uri in uris})
            # Include the destination binding in the copied source, so changing
            # a target repository changes the actual URIpack plan digest.
            binding_path = f"repository-targets/{name}.json"
            binding = {"schema": "uriprocess.repository-target/v1", "repository": repository,
                       "package_path": package["path"], "public_uris": uris,
                       "package_repository": config["package_repository"],
                       "package_revision": config["package_revision"],
                       "selection_path": group["selection"], "selection_sha256": selection_hash,
                       "source_repository": selection["source_repository"],
                       "source_revision": selection["source_revision"],
                       "repository_selection_sha256": digest(config),
                       "remote_binding_verified": False, "production_cutover": False}
            binding_file = candidate / binding_path
            binding_file.parent.mkdir(exist_ok=True)
            binding_file.write_bytes(encode(binding))
            request = {"schema": "uripack.refactor-request/v1", "operation": "plan",
                       "namespace": "uriprocess", "units": [{"id": name,
                       "include": [package["path"], binding_path], "public_uris": uris}]}
            plan = build_plan(request, candidate, workspace / "repositories" / name)
            plan_path = f"plans/{name}.json"
            (workspace / plan_path).write_bytes(encode(plan))
            records.append({**binding, "plan_path": plan_path, "plan_sha256": plan["plan_sha256"],
                            "artifact_sha256": artifact_digest(plan),
                            "package_root": f"packs/{name}/tree/{package['path']}"})
    index = {"schema": "uriprocess.repository-plans/v1", "status": "planned",
             "selection_sha256": digest(config), "repositories": records,
             "uri_owners": dict(sorted(uri_owners.items())),
             "execution_authority": False, "remote_publication": False, "production_cutover": False}
    (workspace / "repository-selection.json").write_bytes(encode(config))
    # Written last: a failed preparation never leaves a complete batch index.
    (workspace / "repository-plans.json").write_bytes(encode(index))
    return index


def main():
    from uripack_refactor.common import load_document

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--package-source", type=Path, required=True)
    parser.add_argument("--source", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    sources = {}
    for item in args.source:
        name, separator, path = item.partition("=")
        if not separator or not path or name in sources:
            parser.error("--source requires a unique ID=PATH")
        sources[name] = Path(path)
    result = prepare_repositories(load_document(args.selection), args.package_source, sources, args.workspace)
    print(json.dumps({"status": result["status"], "repositories": len(result["repositories"]),
                      "public_uris": len(result["uri_owners"]), "execution_authority": False}))


if __name__ == "__main__":
    main()
