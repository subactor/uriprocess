"""Verify native source identity, upstream tests, wheels and installed bindings.

Requires existing test/runtime/build dependencies. No dependency downloads or
production connector invocations are performed by this checker.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET

from generate import encode, read_object

ROOT = Path(__file__).resolve().parents[1]


def git_file_mode(path):
    # Git and uripack preserve the owner executable bit, not checkout umask/ACL
    # write permissions. A group-writable checkout still represents mode 100644.
    return 0o755 if Path(path).stat().st_mode & 0o100 else 0o644


def complete_test_cases(report):
    """Require observed passing cases, not just pytest's exit code or counters."""
    try:
        document = ET.parse(report).getroot()
    except (ET.ParseError, OSError) as error:
        raise ValueError("Native test report unavailable or invalid") from error
    cases = list(document.iter("testcase"))
    if (document.tag not in {"testsuite", "testsuites"} or not cases
            or any(case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error"))):
        raise ValueError("Native test evidence is incomplete: missing, skipped or failed cases")
    if any(not case.get("name") for case in cases):
        raise ValueError("Native test evidence has an unnamed case")
    # Keep duplicates and parameter IDs: equal totals do not prove that the
    # installed wheel exercised the same upstream behavior.
    return sorted((case.get("classname", ""), case.get("name")) for case in cases)


def complete_test_count(report):
    return len(complete_test_cases(report))


def matching_test_cases(source_report, installed_report):
    source_cases = complete_test_cases(source_report)
    if complete_test_cases(installed_report) != source_cases:
        raise ValueError("Installed native test identities differ from source")
    return len(source_cases)


def check(root, source, output, builder):
    from packaging.requirements import Requirement

    root, output = Path(root).resolve(), Path(output).absolute()
    sources = ({repository: Path(path).resolve() for repository, path in source.items()}
               if isinstance(source, dict) else None)
    if sources is None:
        source = Path(source).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("Verification output must be new")
    catalog = json.loads((root / "native-catalog.json").read_text())
    output.mkdir(parents=True)
    results = []
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PIP_NO_INDEX": "1"}
    with (output / "verification.log").open("xb") as log:
        def run(argv, cwd, pythonpath=None, extra_env=None):
            command_env = {**env, **({"PYTHONPATH": str(pythonpath)} if pythonpath else {}), **(extra_env or {})}
            return subprocess.run(argv, cwd=cwd, env=command_env, check=True, stdout=log, stderr=subprocess.STDOUT)

        for package in catalog["packages"]:
            base = root / package["path"]
            actual = {str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()}
            if actual != set(package["files"]):
                raise ValueError("Native package file set mismatch")
            for name, digest in package["files"].items():
                path = base / name
                if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError("Native package integrity mismatch")
            provenance = json.loads((base / "provenance.json").read_text())
            if sources is not None:
                key = provenance["repository"] + "@" + provenance["revision"]
                if key not in sources:
                    key = provenance["repository"]
                if key not in sources:
                    raise ValueError("Explicit source repository mapping is incomplete")
                source = sources[key]
            destinations = [item["destination"] for item in provenance["files"]]
            if (len(destinations) != len(set(destinations))
                    or set(destinations) != actual - {"provenance.json", "uriprocess.json"}):
                raise ValueError("Native provenance is incomplete")
            for item in provenance["files"]:
                path = base / item["destination"]
                if path.read_bytes() != read_object(source, provenance["revision"], item["source"]):
                    raise ValueError("Native package differs from pinned source")
                source_mode = int(subprocess.check_output(["git", "-C", str(source), "ls-tree",
                    provenance["revision"], "--", item["source"]], text=True).split()[0], 8) & 0o777
                if git_file_mode(path) != source_mode or item["mode"] != source_mode:
                    raise ValueError("Native file mode mismatch")
            metadata = json.loads((base / "uriprocess.json").read_text())
            project = tomllib.loads((base / "pyproject.toml").read_text())["project"]
            if (metadata["native_distribution"] != project["name"]
                    or metadata["native_version"] != project["version"]
                    or metadata["dependencies"] != project.get("dependencies", [])
                    or metadata["entry_points"] != project["entry-points"]["urirun.bindings"]):
                raise ValueError("Native package metadata changed")
            dependencies = {}
            for spec in metadata["dependencies"]:
                requirement = Requirement(spec)
                if requirement.marker and not requirement.marker.evaluate():
                    continue
                version = importlib.metadata.version(requirement.name)
                if not requirement.specifier.contains(version):
                    raise ValueError("Installed dependency does not satisfy native metadata")
                dependencies[requirement.name] = version
            with tempfile.TemporaryDirectory(prefix="uriprocess-native-check-") as temporary:
                temporary = Path(temporary)
                copied, installed = temporary / "source", temporary / "installed"
                shutil.copytree(base, copied)
                tests = sorted((copied / "tests").glob("test_*.py"))
                if not tests:
                    raise ValueError("Native upstream tests missing")
                distribution = output / package["id"]
                distribution.mkdir()
                source_report = distribution / "source-tests.xml"
                run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(source_report), *map(str, tests)],
                    temporary, copied)
                source_test_count = complete_test_count(source_report)
                run([builder, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(distribution), str(copied)], temporary)
                wheels = list(distribution.glob("*.whl"))
                if len(wheels) != 1:
                    raise ValueError("Exactly one native wheel expected")
                run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--no-compile",
                     "--target", str(installed), str(wheels[0])], temporary)
                # Tests live away from both source and installed modules, so
                # imports must use the installed wheel, not the source checkout.
                test_root = temporary / "tests"
                shutil.copytree(copied / "tests", test_root)
                installed_report = distribution / "installed-tests.xml"
                run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(installed_report), str(test_root)], temporary, installed)
                matching_test_cases(source_report, installed_report)
                probe = '''import importlib, importlib.metadata, json, pathlib, sys
target, name, expected = pathlib.Path(sys.argv[1]).resolve(), sys.argv[2], set(json.loads(sys.argv[3]))
dist = importlib.metadata.distribution(name)
entries = [ep for ep in dist.entry_points if ep.group == 'urirun.bindings']
assert entries, 'Installed native entry point missing'
routes = set()
for ep in entries:
    module = importlib.import_module(ep.module)
    assert pathlib.Path(module.__file__).resolve().is_relative_to(target), 'Source import leaked into installed check'
    routes.update(ep.load()()['bindings'])
assert routes == expected, 'Installed URI bindings differ from native manifest'
'''
                run([sys.executable, "-c", probe, str(installed), metadata["native_distribution"],
                     json.dumps(package["public_uris"])], temporary, installed,
                    # Loading bindings may initialize twin-map. Keep discovery
                    # offline with a disposable cache; signed conformance is
                    # exercised by the complete original tests above.
                    {"URI_TWIN_OFFLINE": "1", "URI_TWIN_CACHE_DIR": str(temporary / "probe-cache")})
                results.append({"id": package["id"], "source_revision": provenance["revision"],
                    "source_repository": provenance["repository"],
                    "public_uris": package["public_uris"], "wheel": str(wheels[0].relative_to(output)),
                    "wheel_sha256": hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
                    "dependencies": dependencies, "source_tests": "passed", "installed_tests": "passed",
                    "upstream_test_count": source_test_count,
                    "test_identity_comparison": "passed",
                    "test_reports": {label: {"path": str(report.relative_to(output)),
                        "sha256": hashlib.sha256(report.read_bytes()).hexdigest()}
                        for label, report in (("source", source_report), ("installed", installed_report))},
                    "installed_bindings": "passed", "upstream_git_comparison": "passed"})
    receipt = {"schema": "uriprocess.native-package-verification/v1", "status": "passed", "packages": results,
               "dependency_installation": "preinstalled-runtime; offline-wheel-install-without-dependency-resolution",
               "production_calls": False, "production_cutover": False}
    (output / "verification.json").write_bytes(encode(receipt))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source", type=Path)
    source.add_argument("--source-map", action="append", metavar="REPOSITORY=PATH")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--builder-python", default=sys.executable)
    args = parser.parse_args()
    from generate_native_catalog import source_mapping
    source = source_mapping(args.source_map) if args.source_map else args.source
    print(json.dumps(check(args.root, source, args.output, args.builder_python)))
