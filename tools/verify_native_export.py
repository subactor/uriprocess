"""Run the real native Guard reference flow from immutable Git sources.

All identities and admission decisions belong to a disposable local test server.
This command neither connects to production nor grants operational authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from generate import encode, read_object, relative

CONSUMER_REVISION = "3f107a5825babf1b48c99f287f19fd2128ee5e47"
PACKAGE_REVISION = "f76773988ccdccd81725ce93017c66615b84a8fb"
ROOT = Path(__file__).resolve().parents[1]


def snapshot(repository, revision, paths, target):
    """Read explicit tracked trees; dirty/untracked checkout files never execute."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Immutable Git revision required")
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise ValueError("Snapshot target must be new")
    for path in paths:
        relative(path)
    entries = subprocess.check_output(["git", "-C", str(repository), "ls-tree", "-rz",
                                       revision, "--", *paths]).split(b"\0")
    selected = []
    for entry in filter(None, entries):
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        path = str(relative(name.decode()))
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("Snapshot requires regular tracked files")
        selected.append((path, mode, object_id))
    for prefix in paths:
        if not any(path == prefix or path.startswith(prefix + "/") for path, _, _ in selected):
            raise ValueError("Pinned snapshot path is missing")
    target.mkdir(parents=True)
    for path, mode, object_id in selected:
        data = subprocess.check_output(["git", "-C", str(repository), "cat-file", "blob", object_id])
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(int(mode, 8) & 0o777)


def verify_downloads(repository, output, report):
    """Bind native readback to source Git, independently of returned hashes."""
    catalog = json.loads(read_object(repository, PACKAGE_REVISION, "catalog.json"))
    expected_units = {Path(item["path"]).parts[1] for item in catalog["processes"]}
    results = report.get("results", [])
    if (report.get("status") != "passed" or report.get("source_revision") != PACKAGE_REVISION
            or report.get("production_guard") is not False or report.get("production_cutover") is not False
            or report.get("test_principals") is not True
            or len(results) != len(expected_units)
            or {item.get("unit") for item in results} != expected_units):
        raise ValueError("Native test report scope mismatch")
    for process in catalog["processes"]:
        unit = Path(process["path"]).parts[1]
        result = next(item for item in results if item["unit"] == unit)
        if result.get("status") != "materialized" or any(result.get(key) != "passed" for key in (
                "docker", "npm_install", "upstream_tests", "native_http")):
            raise ValueError("Native test acceptance incomplete")
        package = output / unit / process["path"]
        actual = {str(path.relative_to(package)) for path in package.rglob("*") if path.is_file()}
        if actual != set(process["files"]):
            raise ValueError("Downloaded package file set mismatch")
        for name in process["files"]:
            path = package / name
            if path.is_symlink() or path.read_bytes() != read_object(repository, PACKAGE_REVISION, process["path"] + "/" + name):
                raise ValueError("Downloaded package differs from source Git")


def verify(uripack_repository, guard_repository, output, consumer_repository=ROOT):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be new")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="uriprocess-pinned-native-") as temporary:
        temporary = Path(temporary)
        consumer = temporary / "consumer"
        snapshot(consumer_repository, CONSUMER_REVISION, ["tools/guard_export.py",
                 "integration_tests/full_guard_export.py", "integration/organism-guard-export.json",
                 "integration/fastlane-project.proposed.json"], consumer)
        pin = json.loads((consumer / "integration/organism-guard-export.json").read_text())
        guard, uripack = temporary / "guard", temporary / "uripack"
        snapshot(guard_repository, pin["source_revision"], ["organism_guard"], guard)
        snapshot(uripack_repository, pin["uripack_revision"], ["src/uripack_refactor"], uripack)
        # Exclude inherited credentials, PYTHONOPTIMIZE, PYTHONPATH and startup
        # customization. Native test principals are created by the pinned test.
        env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8",
               "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": str(guard) + os.pathsep + str(uripack / "src")}
        with (output / "native.log").open("xb") as log:
            subprocess.run([sys.executable, str(consumer / "integration_tests/full_guard_export.py"),
                            "--source-repository", str(Path(consumer_repository).resolve()),
                            "--source-revision", PACKAGE_REVISION, "--output", str(output / "exports")],
                           cwd=temporary, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        report_path = output / "exports/report.json"
        report = json.loads(report_path.read_text())
        verify_downloads(consumer_repository, output / "exports", report)
        receipt = {"schema": "uriprocess.native-verification/v1", "status": "passed",
                   "consumer_revision": CONSUMER_REVISION, "package_revision": PACKAGE_REVISION,
                   "guard_revision": pin["source_revision"], "uripack_revision": pin["uripack_revision"],
                   "native_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                   "log_sha256": hashlib.sha256((output / "native.log").read_bytes()).hexdigest(),
                   "packages": len(report["results"]), "upstream_git_comparison": "passed",
                   "production_guard": False, "production_cutover": False, "test_principals": True}
        (output / "verification.json").write_bytes(encode(receipt))
        return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uripack-repository", type=Path, required=True)
    parser.add_argument("--guard-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.uripack_repository, args.guard_repository, args.output)))
