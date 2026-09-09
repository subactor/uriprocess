"""Package explicit native Python connectors without changing their contracts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

from generate import encode, read_object, relative


def generate_native(config, source, output):
    if config.get("schema") != "uriprocess.native-selection/v1":
        raise ValueError("Unsupported native selection")
    revision = config["source_revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Immutable source revision required")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    catalog, owned_uris = [], set()
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        root = Path(temporary) / "result"
        root.mkdir()
        for selection in config["packages"]:
            prefix = str(relative(selection["package_root"])) + "/"
            files, provenance = {}, []
            for selected in selection["files"]:
                relative(selected)
                if not selected.startswith(prefix):
                    raise ValueError("Selected file is outside its native package")
                name = selected[len(prefix):]
                if name in files or name in {"provenance.json", "uriprocess.json"}:
                    raise ValueError("Duplicate or reserved native destination")
                data = read_object(source, revision, selected)
                mode = int(subprocess.check_output(["git", "-C", str(source), "ls-tree", revision,
                                                    "--", selected], text=True).split()[0], 8) & 0o777
                files[name] = data
                provenance.append({"source": selected, "destination": name, "mode": mode,
                                   "sha256": hashlib.sha256(data).hexdigest()})
            metadata = tomllib.loads(files["pyproject.toml"].decode())
            manifest_path = str(relative(selection["manifest"]))
            manifest = json.loads(files[manifest_path])
            identifier, version = manifest["id"], metadata["project"]["version"]
            if (not re.fullmatch(r"[a-z][a-z0-9-]*", identifier)
                    or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)):
                raise ValueError("Unsafe native package identity")
            routes = manifest["routes"]
            if not routes or len(routes) != len(set(routes)) or set(routes) != set(selection["public_uris"]):
                raise ValueError("Selected URI set must equal the native manifest routes")
            if owned_uris.intersection(routes):
                raise ValueError("Native URI ownership collision")
            owned_uris.update(routes)
            if not any(name.startswith("tests/test_") and name.endswith(".py") for name in files):
                raise ValueError("Native upstream tests must be selected")
            bindings = metadata["project"]["entry-points"]["urirun.bindings"]
            if not bindings:
                raise ValueError("Native urirun entry points required")
            destination = f"native/{identifier}/v{version}"
            base = root / destination
            base.mkdir(parents=True, exist_ok=False)
            files["provenance.json"] = encode({"schema": "uriprocess.provenance/v1",
                "repository": config["source_repository"], "revision": revision, "files": provenance})
            files["uriprocess.json"] = encode({"schema": "uriprocess.native-package/v1",
                "kind": "python-connector", "public_uris": routes, "native_manifest": manifest_path,
                "native_distribution": metadata["project"]["name"], "native_version": version,
                "entry_points": bindings, "dependencies": metadata["project"].get("dependencies", []),
                "source": "provenance.json", "production_binding_verified": False})
            modes = {item["destination"]: item["mode"] for item in provenance}
            for name, data in files.items():
                path = base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(modes.get(name, 0o644))
            catalog.append({"id": identifier, "path": destination, "public_uris": routes,
                            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}})
        if not catalog:
            raise ValueError("Native selection must not be empty")
        (root / "native-catalog.json").write_bytes(encode({"schema": "uriprocess.native-catalog/v1", "packages": catalog}))
        shutil.move(str(root), str(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate_native(json.loads(args.selection.read_text()), args.source, args.output)
