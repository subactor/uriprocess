"""Copy explicitly reviewed process selections from immutable Git objects.

This is an offline source packager, not an uripack apply/Guard replacement.
It does not execute discovered code, register capabilities or move consumers.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import shutil


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def uri_path(uri):
    match = re.fullmatch(r"(poa)://([a-z0-9]+(?:[.-][a-z0-9]+)*)/process/([a-z][a-z0-9-]*)/(v[1-9][0-9]*)", uri)
    if not match:
        raise ValueError("Unsupported or unsafe process URI")
    scheme, authority, command, version = match.groups()
    return PurePosixPath(scheme, command, authority, version)


def relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(p in ("", ".", "..") for p in value.split("/")) or "\\" in value:
        raise ValueError("Unsafe selection path")
    return path


def read_object(source, revision, path):
    relative(path)
    mode = subprocess.check_output(["git", "-C", str(source), "ls-tree", revision, "--", path], text=True)
    if not mode.startswith(("100644 blob ", "100755 blob ")):
        raise ValueError("Selection must be a regular tracked file")
    return subprocess.check_output(["git", "-C", str(source), "show", f"{revision}:{path}"])


def cli(entry, export):
    if not re.fullmatch(r"[a-z][A-Za-z0-9]*", export):
        raise ValueError("Invalid exported function")
    return f'''import {{ {export} as decide }} from {json.dumps('./' + entry)};
let input = '';
try {{
  for await (const chunk of process.stdin) {{
    input += chunk;
    if (Buffer.byteLength(input) > 1048576) throw new Error('request too large');
  }}
  const request = JSON.parse(input);
  if (!request || Array.isArray(request) || typeof request !== 'object'
      || Object.keys(request).some(k => !['ticket', 'context'].includes(k))
      || !request.ticket || typeof request.ticket !== 'object' || Array.isArray(request.ticket))
    throw new Error('invalid request');
  const context = request.context ?? {{}};
  if (typeof context !== 'object' || Array.isArray(context)
      || Object.keys(context).some(k => !['tickets', 'actors', 'routes'].includes(k))
      || Object.values(context).some(v => !Array.isArray(v))) throw new Error('invalid context');
  process.stdout.write(JSON.stringify(decide(request.ticket, context)) + '\\n');
}} catch {{
  process.stderr.write('{{"error":"invalid_process_request"}}\\n');
  process.exitCode = 2;
}}
'''.encode()


def generate(config, source, output):
    revision = config["source_revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("An immutable source revision is required")
    image = config["base_image"]
    if not re.fullmatch(r"[a-z0-9./:-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("A digest-pinned image is required")
    if output.exists():
        raise ValueError("Output must not exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        root = Path(temporary) / "result"
        root.mkdir()
        catalog = []
        for selection in config["processes"]:
            contract_bytes = read_object(source, revision, selection["contract"])
            contract = json.loads(contract_bytes)
            if contract.get("schema") != "poa.process/v1":
                raise ValueError("Unsupported POA contract")
            uri = contract["process_ref"]
            path = uri_path(uri)
            base = root / path
            base.mkdir(parents=True, exist_ok=False)
            files = {"process.poa.json": contract_bytes}
            provenance = [{"source": selection["contract"], "destination": "process.poa.json",
                           "sha256": hashlib.sha256(contract_bytes).hexdigest()}]
            for selected in selection["files"]:
                relative(selected)
                data = read_object(source, revision, selected)
                files[selected] = data
                provenance.append({"source": selected, "destination": selected,
                                   "sha256": hashlib.sha256(data).hexdigest()})
            entry = str(relative(selection["entry"]))
            if entry not in files:
                raise ValueError("Entry must be selected")
            name = f"@subactor/uriprocess-{path.parts[1]}-{path.parts[2]}-{path.parts[3]}"
            package = {"name": name, "version": "0.1.0", "type": "module", "license": "UNLICENSED",
                       "description": contract["title"], "exports": "./" + entry,
                       "bin": {"uriprocess-" + path.parts[1]: "bin.mjs"},
                       "files": ["src", "bin.mjs", "process.poa.json", "provenance.json", "uriprocess.json"],
                       "scripts": {"test": "node --test tests/*.test.mjs"},
                       "engines": {"node": ">=22"}}
            files["bin.mjs"] = b"#!/usr/bin/env node\n" + cli(entry, selection["export"])
            files["package.json"] = encode(package)
            files["package-lock.json"] = encode({"name": name, "version": "0.1.0", "lockfileVersion": 3,
                "requires": True, "packages": {"": {k: package[k] for k in ("name", "version", "license", "bin", "engines")}}})
            files["Dockerfile"] = (f"FROM {image}\nWORKDIR /app\nCOPY package.json package-lock.json ./\n"
                "RUN npm ci --omit=dev --ignore-scripts --offline\nCOPY src ./src\n"
                "COPY bin.mjs process.poa.json provenance.json uriprocess.json ./\n"
                "USER 65532:65532\nENTRYPOINT [\"node\", \"bin.mjs\"]\n").encode()
            files[".dockerignore"] = b"**\n!package.json\n!package-lock.json\n!src/\n!src/**\n!bin.mjs\n!process.poa.json\n!provenance.json\n!uriprocess.json\n"
            files["provenance.json"] = encode({"schema": "uriprocess.provenance/v1",
                "repository": config["source_repository"], "revision": revision, "files": provenance})
            files["uriprocess.json"] = encode({"schema": "uriprocess.package/v1", "process_ref": uri,
                "contract": "process.poa.json", "language": "javascript", "entry": entry,
                "export": selection["export"], "transport": "stdin-json", "request_fields": ["ticket", "context"],
                "base_image": image, "role": "decision-library", "executes_declared_capabilities": False,
                "authority": "decision-only; no execution grant", "source": "provenance.json"})
            for name_, data in files.items():
                target = base / name_
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            (base / "bin.mjs").chmod(0o755)
            catalog.append({"process_ref": uri, "path": str(path), "files": {
                name_: hashlib.sha256(data).hexdigest() for name_, data in sorted(files.items())}})
        (root / "catalog.json").write_bytes(encode({"schema": "uriprocess.catalog/v1", "processes": catalog}))
        shutil.move(str(root), str(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(json.loads(args.selection.read_text()), args.source, args.output)
