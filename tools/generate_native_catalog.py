"""Combine pinned native selections using explicit source repository mappings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

from generate import encode, relative
from generate_native import generate_native


def selected_groups(config, selection_root, sources):
    if (set(config) != {"schema", "version", "groups"}
            or config["schema"] != "uriprocess.native-batch-selection/v1"
            or type(config["version"]) is not int or config["version"] not in {1, 2}
            or not isinstance(config["groups"], list) or not config["groups"]):
        raise ValueError("Unsupported native batch selection")
    root = Path(selection_root).resolve()
    groups, ids, repositories = [], set(), set()
    for group in config["groups"]:
        if not isinstance(group, dict) or set(group) != {"source_id", "selection", "selection_sha256"}:
            raise ValueError("Unsupported native batch group")
        identifier = group["source_id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", identifier) or identifier in ids:
            raise ValueError("Duplicate or invalid native source identity")
        ids.add(identifier)
        path = root / relative(group["selection"])
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ValueError("Native selection must be a regular file")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != group["selection_sha256"]:
            raise ValueError("Native selection digest mismatch")
        selection = json.loads(data)
        if selection.get("schema") != "uriprocess.native-selection/v1":
            raise ValueError("A native source selection is required")
        # Version 2 permits another immutable revision of an existing source.
        # Keep earlier package provenance intact during incremental extraction.
        repository = selection["source_repository"]
        if config["version"] == 2:
            repository = (repository, selection["source_revision"])
        if repository in repositories:
            raise ValueError("Duplicate native source repository")
        repositories.add(repository)
        groups.append((identifier, selection))
    if not isinstance(sources, dict) or set(sources) != ids:
        raise ValueError("Explicit native source mapping must cover exactly the selected groups")
    return groups


def generate_catalog(config, selection_root, sources, output):
    groups = selected_groups(config, selection_root, sources)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    packages, paths, uris, identifiers = [], set(), set(), set()
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        temporary = Path(temporary)
        result = temporary / "result"
        result.mkdir()
        for index, (source_id, selection) in enumerate(groups):
            candidate = temporary / f"source-{index}"
            generate_native(selection, sources[source_id], candidate)
            for package in json.loads((candidate / "native-catalog.json").read_text())["packages"]:
                routes = set(package["public_uris"])
                if package["path"] in paths or package["id"] in identifiers or routes & uris:
                    raise ValueError("Native package or URI ownership collision across repositories")
                paths.add(package["path"])
                identifiers.add(package["id"])
                uris.update(routes)
                target = result / package["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(candidate / package["path"]), target)
                packages.append(package)
        (result / "native-catalog.json").write_bytes(encode({"schema": "uriprocess.native-catalog/v1", "packages": packages}))
        shutil.move(str(result), output)


def source_mapping(values):
    result = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path or name in result:
            raise ValueError("Source mapping requires unique NAME=PATH entries")
        result[name] = Path(path)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-root", type=Path, required=True)
    parser.add_argument("--source", action="append", required=True, metavar="NAME=PATH")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate_catalog(json.loads(args.selection.read_text()), args.selection_root, source_mapping(args.source), args.output)
