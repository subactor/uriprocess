"""Export complete pinned POA packages for a source-only consumer.

This offline projection does not execute package code, install dependencies,
change consumer imports, apply a URIpack plan or authorize deployment.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from check_standard import _json, _read, _relative, load_standard
from generate import encode, uri_path


REPOSITORY = "https://github.com/subactor/uriprocess"


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args])


def regular_blob(source, revision, name):
    _relative(name)
    records = git(source, "ls-tree", "-z", revision, "--", name).split(b"\0")
    if len(records) != 2 or not records[0]:
        raise ValueError("Expected one tracked package file")
    metadata, actual = records[0].split(b"\t", 1)
    mode, kind, _ = metadata.split()
    if actual.decode() != name or kind != b"blob" or mode not in (b"100644", b"100755"):
        raise ValueError("Regular Git package file required")
    return git(source, "show", f"{revision}:{name}"), int(mode, 8) & 0o777


def projected_files(source, revision, catalog_sha256, process_refs):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Immutable URIprocess commit required")
    if git(source, "rev-parse", f"{revision}^{{commit}}").decode().strip() != revision:
        raise ValueError("URIprocess pin must identify a commit")
    catalog_bytes, _ = regular_blob(source, revision, "catalog.json")
    if (not re.fullmatch(r"[0-9a-f]{64}", catalog_sha256)
            or hashlib.sha256(catalog_bytes).hexdigest() != catalog_sha256):
        raise ValueError("Catalog differs from independent digest pin")
    catalog = _json(catalog_bytes)
    if (not isinstance(catalog, dict) or set(catalog) != {"schema", "processes"}
            or catalog["schema"] != "uriprocess.catalog/v1"
            or not isinstance(catalog["processes"], list)):
        raise ValueError("Unsupported POA catalog")
    if not process_refs or len(process_refs) != len(set(process_refs)):
        raise ValueError("Select distinct original process URIs explicitly")
    selections, seen_uris, seen_paths = [], set(), set()
    for record in catalog["processes"]:
        if not isinstance(record, dict) or set(record) != {"process_ref", "path", "files"}:
            raise ValueError("Invalid POA catalog record")
        uri, path = record["process_ref"], record["path"]
        if str(uri_path(uri)) != path or uri in seen_uris or path in seen_paths:
            raise ValueError("Invalid or duplicate POA identity")
        seen_uris.add(uri)
        seen_paths.add(path)
        if uri in process_refs:
            selections.append(record)
    if set(process_refs) != {r["process_ref"] for r in selections}:
        raise ValueError("Selected URI is absent from catalog")

    files, packages = {}, []
    with tempfile.TemporaryDirectory(prefix="poa-consumer-check-") as temporary:
        frozen = Path(temporary)
        with load_standard() as (standard, standard_receipt):
            for record in selections:
                path = record["path"]
                if not isinstance(record["files"], dict) or not record["files"]:
                    raise ValueError("Complete package inventory required")
                expected = {path + "/" + name for name in record["files"]}
                tracked = {n.decode() for n in git(source, "ls-tree", "-r", "--name-only", "-z",
                                                  revision, "--", path + "/").split(b"\0") if n}
                if expected != tracked:
                    raise ValueError("Package inventory differs from Git tree")
                modes = {}
                for name, digest in record["files"].items():
                    _relative(name)
                    target = path + "/" + name
                    data, mode = regular_blob(source, revision, target)
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise ValueError("Package content differs from catalog")
                    files[target] = (data, mode)
                    modes[name] = mode
                    local = frozen / target
                    local.parent.mkdir(parents=True, exist_ok=True)
                    local.write_bytes(data)
                    local.chmod(mode)
                result = standard.check_package(frozen / path)
                if (result["profile"] != "poa-node-v1"
                        or result["public_uris"] != [record["process_ref"]]):
                    raise ValueError("Package does not preserve selected POA identity")
                packages.append({**record, "modes": modes})
    lock = {"schema": "uriprocess.consumer-lock/v1", "repository": REPOSITORY,
            "source_revision": revision, "catalog_sha256": catalog_sha256,
            "packages": packages, "standard_receipt": standard_receipt,
            "execution_authority": False, "production_binding_verified": False}
    files["consumer-lock.json"] = (encode(lock), 0o644)
    return files


def check_projection(output, files):
    with load_standard() as (standard, _):
        if standard.inventory(Path(output)) != set(files):
            raise ValueError("Consumer projection inventory changed")
        for name, (data, mode) in files.items():
            observed, observed_mode = standard.read_file(output, name)
            if (observed, observed_mode) != (data, mode):
                raise ValueError("Consumer projection bytes or Git mode changed")


def export_consumer(source, revision, catalog_sha256, process_refs, output):
    files = projected_files(source, revision, catalog_sha256, process_refs)
    output = Path(os.path.abspath(output))
    # Refuse symlink ancestors and require the caller to choose an existing
    # parent. Reserve the destination exclusively; a partial export is retained
    # after interruption and is never silently overwritten on retry.
    if any(parent.is_symlink() for parent in output.parents):
        raise ValueError("Consumer output parent must not be a symlink")
    output.mkdir(mode=0o700)
    for name, (data, mode) in files.items():
        if name == "consumer-lock.json":
            continue
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(mode)
    # The lock is the completion marker, written only after all package files.
    data, mode = files["consumer-lock.json"]
    with (output / "consumer-lock.json").open("xb") as stream:
        stream.write(data)
    (output / "consumer-lock.json").chmod(mode)
    check_projection(output, files)
    return _json(_read(output, "consumer-lock.json"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--process-ref", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Verify an existing projection without writing")
    args = parser.parse_args(argv)
    if args.check:
        check_projection(args.output, projected_files(args.source, args.revision,
                                                      args.catalog_sha256, args.process_ref))
    else:
        export_consumer(args.source, args.revision, args.catalog_sha256, args.process_ref, args.output)
    print("Verified complete pinned POA consumer projection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
