"""Validate catalog integrity, upstream tests and isolated distributables."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv, cwd, **kwargs):
    return subprocess.run(argv, cwd=cwd, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--pack", action="store_true")
    args = parser.parse_args()
    catalog = json.loads((ROOT / "catalog.json").read_text())
    for process in catalog["processes"]:
        base = ROOT / process["path"]
        expected_files = set(process["files"])
        actual_files = {str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()}
        if actual_files != expected_files:
            raise ValueError("Package file set differs from catalog")
        for path, expected in process["files"].items():
            if hashlib.sha256((base / path).read_bytes()).hexdigest() != expected:
                raise ValueError(f"Integrity mismatch: {path}")
        provenance = json.loads((base / "provenance.json").read_text())
        for source in provenance["files"]:
            if hashlib.sha256((base / source["destination"]).read_bytes()).hexdigest() != source["sha256"]:
                raise ValueError("Source copy changed")
        run(["node", "--test", *map(str, sorted((base / "tests").glob("*.test.mjs")))], base)
        cases = [{"ticket": {"id": "PLF-1", "status": "done"}},
                 {"ticket": {"id": "PLF-ą😀", "status": "open", "labels": []}}]
        expected = [run(["node", "bin.mjs"], base, input=json.dumps(case), text=True,
                        capture_output=True).stdout for case in cases]
        if args.docker:
            name = "uriprocess-test-" + base.parts[-3]
            run(["docker", "build", "--network=none", "-t", name, "."], base)
            for case, answer in zip(cases, expected):
                actual = run(["docker", "run", "--rm", "-i", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32",
                    "--memory=128m", name], base, input=json.dumps(case), text=True, capture_output=True)
                assert actual.stdout == answer, "Container/native behavior differs"
            uid = run(["docker", "run", "--rm", "--network=none", "--read-only", "--entrypoint=node",
                name, "-e", "console.log(process.getuid())"], base, text=True, capture_output=True)
            assert uid.stdout.strip() == "65532"
        if args.pack:
            output = ROOT / "dist"
            output.mkdir(exist_ok=True)
            result = run(["npm", "pack", "--ignore-scripts", "--json", "--pack-destination", str(output)],
                         base, text=True, capture_output=True)
            archive = output / json.loads(result.stdout)[0]["filename"]
            with tempfile.TemporaryDirectory(prefix="uriprocess-install-") as temporary:
                run(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund",
                     "--prefix", temporary, str(archive)], ROOT)
                package = json.loads((base / "package.json").read_text())
                binary = Path(temporary) / "node_modules" / package["name"] / "bin.mjs"
                for case, answer in zip(cases, expected):
                    actual = run(["node", str(binary)], temporary, input=json.dumps(case),
                                 text=True, capture_output=True)
                    assert actual.stdout == answer, "Installed package/native behavior differs"
            print("Package verified:", archive.name)
        print("Verified:", process["process_ref"], flush=True)


if __name__ == "__main__":
    main()
