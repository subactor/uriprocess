"""Read-only package conformance, without upstream or execution authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tomllib
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

STANDARD_ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 4096


class ConformanceError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise ConformanceError(code)


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value
            and not any(ord(c) < 32 for c in value), "URP-PATH-001")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and not any(part in (".", "..") for part in value.split("/")), "URP-PATH-001")
    return path.parts


def read_file(root, name):
    """Read through directory descriptors; never follow a path component."""
    parts = Path(os.path.abspath(root)).parts
    relative_parts = relative(name)
    fd = file_fd = None
    try:
        fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in (*parts[1:], *relative_parts[:-1]):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(relative_parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        observed = os.fstat(file_fd)
        require(stat.S_ISREG(observed.st_mode), "URP-PATH-001")
        require(observed.st_size <= MAX_BYTES, "URP-DATA-001")
        remaining, chunks = MAX_BYTES + 1, []
        while remaining:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        require(len(value) <= MAX_BYTES, "URP-DATA-001")
        return value, 0o755 if observed.st_mode & stat.S_IXUSR else 0o644
    except OSError as exc:
        raise ConformanceError("URP-PATH-001") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if fd is not None:
            os.close(fd)


def document(root, name):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "URP-DATA-001")
            result[key] = value
        return result

    def constant(_):
        raise ConformanceError("URP-DATA-001")

    try:
        return json.loads(read_file(root, name)[0], object_pairs_hook=pairs, parse_constant=constant)
    except ConformanceError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ConformanceError("URP-DATA-001") from exc


def inventory(root):
    files, pending, count = set(), [Path(root)], 0
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    count += 1
                    require(count <= MAX_ENTRIES, "URP-PATH-001")
                    observed = entry.stat(follow_symlinks=False)
                    require(stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode), "URP-PATH-001")
                    path = Path(entry.path)
                    name = path.relative_to(root).as_posix()
                    relative(name)
                    if stat.S_ISDIR(observed.st_mode):
                        pending.append(path)
                    else:
                        files.add(name)
        except OSError as exc:
            raise ConformanceError("URP-PATH-001") from exc
    return files


def validate_uri(uri):
    try:
        value = urlsplit(uri)
        require(bool(value.scheme and value.hostname and value.path)
                and value.username is None and value.password is None
                and not value.query and not value.fragment, "URP-IDENTITY-001")
    except ValueError as exc:
        raise ConformanceError("URP-IDENTITY-001") from exc


def validate_schema(schema, definition, value):
    validator = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/" + definition})
    require(next(validator.iter_errors(value), None) is None, "URP-SCHEMA-001")


def check_package(root):
    root = Path(os.path.abspath(root))
    policy = document(STANDARD_ROOT, "policy.json")
    schema = document(STANDARD_ROOT, "schemas/package.schema.json")
    manifest = document(root, "uriprocess.json")
    require(isinstance(manifest, dict), "URP-SCHEMA-001")
    profiles = [name for name, profile in policy["profiles"].items()
                if profile["manifest_schema"] == manifest.get("schema")]
    require(len(profiles) == 1, "URP-SCHEMA-001")
    profile = profiles[0]
    validate_schema(schema, profile, manifest)
    provenance = document(root, manifest["source"])
    validate_schema(schema, "provenance", provenance)
    validate_uri(provenance["repository"])
    copied, source_paths = set(), set()
    for record in provenance["files"]:
        relative(record["source"])
        relative(record["destination"])
        require(record["source"] not in source_paths and record["destination"] not in copied, "URP-INTEGRITY-001")
        source_paths.add(record["source"])
        copied.add(record["destination"])
        data, mode = read_file(root, record["destination"])
        require(hashlib.sha256(data).hexdigest() == record["sha256"], "URP-INTEGRITY-001")
        require(profile != "python-native-v1" or "mode" in record, "URP-SCHEMA-001")
        require(mode == record.get("mode", 0o644), "URP-INTEGRITY-001")
    generated = set(policy["profiles"][profile]["generated_files"])
    require(not generated.intersection(copied), "URP-INTEGRITY-001")
    actual_files = inventory(root)
    require(actual_files == copied | generated, "URP-INTEGRITY-001")

    if profile == "poa-node-v1":
        require(manifest["contract"] in copied and manifest["entry"] in copied, "URP-INTEGRITY-001")
        require(any(name.startswith("tests/") and name.endswith(".test.mjs") for name in copied), "URP-TESTS-001")
        contract = document(root, manifest["contract"])
        require(isinstance(contract, dict) and contract.get("schema") == "poa.process/v1"
                and contract.get("process_ref") == manifest["process_ref"], "URP-IDENTITY-001")
        distribution = document(root, "package.json")
        require(isinstance(distribution, dict) and distribution.get("type") == "module"
                and distribution.get("exports") in ("./" + manifest["entry"],
                                                      {".": "./" + manifest["entry"]}), "URP-IDENTITY-001")
        docker_lines = read_file(root, "Dockerfile")[0].splitlines()
        require(docker_lines and docker_lines[0] == ("FROM " + manifest["base_image"]).encode(), "URP-IDENTITY-001")
        require(read_file(root, "bin.mjs")[1] == 0o755, "URP-INTEGRITY-001")
        uris = [manifest["process_ref"]]
    else:
        require(manifest["native_manifest"] in copied and "pyproject.toml" in copied, "URP-INTEGRITY-001")
        require(any(name.startswith("tests/test_") and name.endswith(".py") for name in copied), "URP-TESTS-001")
        native = document(root, manifest["native_manifest"])
        try:
            project = tomllib.loads(read_file(root, "pyproject.toml")[0].decode())["project"]
            require(isinstance(native, dict) and native.get("routes") == manifest["public_uris"]
                    and project["name"] == manifest["native_distribution"]
                    and project["version"] == manifest["native_version"]
                    and project["entry-points"]["urirun.bindings"] == manifest["entry_points"]
                    and project.get("dependencies", []) == manifest["dependencies"], "URP-IDENTITY-001")
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ConformanceError("URP-IDENTITY-001") from exc
        uris = manifest["public_uris"]
    for uri in uris:
        validate_uri(uri)
    return {"schema": "wellmanifest.uriprocess/conformance/v1", "status": "passed",
            "standard": policy["standard"], "version": policy["version"], "profile": profile,
            "public_uris": uris, "files_checked": len(actual_files), "source_revision": provenance["revision"],
            "upstream_git_verified": False, "behavior_verified": False, "guard_authenticated": False,
            "execution_authority": False, "publication_authority": False, "production_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = check_package(args.package)
    except ConformanceError as exc:
        print(json.dumps({"status": "invalid", "code": exc.code, "execution_authority": False}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
