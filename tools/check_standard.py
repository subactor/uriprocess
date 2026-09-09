"""Verify the pinned Wellmanifest bundle and check explicit package catalogs."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_FILES = {"VERSION", "policy.json", "schemas/package.schema.json", "operations/conformance.py"}
MAX_BYTES = 8 * 1024 * 1024


def _relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name or "\\" in name
            or any(part in (".", "..") for part in name.split("/"))
            or any(ord(c) < 32 for c in name)):
        raise ValueError("Unsafe standard or package path")
    return path.parts


def _read(root, name):
    root = Path(os.path.abspath(root))
    parts = (*root.parts[1:], *_relative(name))
    fd = file_fd = None
    try:
        fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        observed = os.fstat(file_fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > MAX_BYTES:
            raise ValueError("Bounded regular standard or package file required")
        with os.fdopen(file_fd, "rb") as source:
            file_fd = None
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Standard or package file exceeds size limit")
        return data
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if fd is not None:
            os.close(fd)


def _json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("Non-finite JSON value")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


@contextmanager
def load_standard(adopter_root=ROOT):
    lock = _json(_read(adopter_root, ".governance/uriprocess.lock.json"))
    required = {"schema", "repository", "standard", "version", "source_revision", "bundle_sha256"}
    if (not isinstance(lock, dict) or set(lock) != required
            or lock["schema"] != "wellmanifest.uriprocess/adoption/v1"
            or lock["repository"] != "subactor/uriprocess" or lock["standard"] != "wellmanifest/uriprocess"
            or not re.fullmatch(r"[0-9a-f]{40}", str(lock["source_revision"]))
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(lock["version"]))):
        raise ValueError("Explicit immutable URIprocess standard pin required")
    bundle_root = Path(adopter_root) / ".governance/uriprocess"
    bundle_bytes = _read(bundle_root, "bundle.json")
    if hashlib.sha256(bundle_bytes).hexdigest() != lock["bundle_sha256"]:
        raise ValueError("URIprocess standard bundle digest differs from the adoption pin")
    bundle = _json(bundle_bytes)
    if (not isinstance(bundle, dict) or set(bundle) != {"schema", "standard", "version", "files"}
            or bundle["schema"] != "wellmanifest.uriprocess/bundle/v1"
            or bundle["standard"] != lock["standard"] or bundle["version"] != lock["version"]
            or not isinstance(bundle["files"], dict) or set(bundle["files"]) != BUNDLE_FILES):
        raise ValueError("Incomplete or unsupported URIprocess standard bundle")
    contents = {}
    for name, expected in bundle["files"].items():
        data = _read(bundle_root, name)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("URIprocess standard file differs from the pinned bundle")
        contents[name] = data
    if contents["VERSION"].decode().strip() != lock["version"]:
        raise ValueError("URIprocess standard version differs from its pin")
    # Execute only the verified bytes. Data files are frozen beside them so a
    # changed projection cannot replace the schema after integrity checking.
    with tempfile.TemporaryDirectory(prefix="uriprocess-standard-") as temporary:
        frozen = Path(temporary)
        for name, data in contents.items():
            path = frozen / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        source = frozen / "operations/conformance.py"
        module = types.ModuleType("wellmanifest_uriprocess_conformance")
        module.__file__ = str(source)
        exec(compile(contents["operations/conformance.py"], str(source), "exec"), module.__dict__)
        yield module, {"standard": lock["standard"], "version": lock["version"],
                       "source_revision": lock["source_revision"], "bundle_sha256": lock["bundle_sha256"],
                       "bundle_verified": True, "source_revision_authenticated": False,
                       "execution_authority": False}


def check_catalogs(package_root=ROOT, *, adopter_root=ROOT):
    package_root = Path(os.path.abspath(package_root))
    results, owners = [], set()
    with load_standard(adopter_root) as (standard, receipt):
        for filename, schema, field in (("catalog.json", "uriprocess.catalog/v1", "processes"),
                                        ("native-catalog.json", "uriprocess.native-catalog/v1", "packages")):
            if not os.path.lexists(package_root / filename):
                continue
            catalog = _json(_read(package_root, filename))
            if (not isinstance(catalog, dict) or catalog.get("schema") != schema
                    or not isinstance(catalog.get(field), list) or not catalog[field]):
                raise ValueError("Explicit nonempty package catalog required")
            for record in catalog[field]:
                base = package_root.joinpath(*_relative(record["path"]))
                result = standard.check_package(base)
                expected_uris = [record["process_ref"]] if field == "processes" else record["public_uris"]
                if result["public_uris"] != expected_uris or owners.intersection(expected_uris):
                    raise ValueError("Package URI identities or ownership differ from the catalog")
                owners.update(expected_uris)
                if len(record["files"]) != result["files_checked"]:
                    raise ValueError("Package catalog file coverage differs from the standard")
                for name, expected in record["files"].items():
                    if hashlib.sha256(_read(base, name)).hexdigest() != expected:
                        raise ValueError("Package bytes differ from the catalog")
                results.append({"path": record["path"], **result})
    if not results:
        raise ValueError("At least one explicit package catalog required")
    return {"schema": "uriprocess.standard-verification/v1", "status": "passed",
            "standard_receipt": receipt, "packages": results, "public_uri_count": len(owners),
            "execution_authority": False, "production_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        result = check_catalogs(args.root)
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({"status": "invalid", "code": "URIPROCESS_STANDARD_REJECTED",
                          "execution_authority": False}))
        return 2
    print(json.dumps({"status": result["status"], "standard_receipt": result["standard_receipt"],
                      "packages": len(result["packages"]), "public_uris": result["public_uri_count"],
                      "execution_authority": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
