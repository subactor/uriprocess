"""Read-only native Organism Guard observation; never an execution grant.

Install the operator-selected organism_guard package separately. This consumer
uses its existing HTTP client and never implements a second Guard transport.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys


class ObservationRejected(ValueError):
    pass


def observe(client, repository_id, expected_head, expected_contract):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", repository_id):
        raise ObservationRejected("INVALID_REPOSITORY_ID")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ObservationRejected("IMMUTABLE_HEAD_REQUIRED")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_contract):
        raise ObservationRejected("CONTRACT_PIN_REQUIRED")
    discovery = client.call("system.discover", {})
    if (not isinstance(discovery, dict) or discovery.get("ok") is not True
            or discovery.get("name") != "organism-guard"
            or discovery.get("contract_sha256") != expected_contract):
        raise ObservationRejected("GUARD_CONTRACT_MISMATCH")
    for _ in range(2):
        status = client.call("git.status", {"repository_id": repository_id})
        if not isinstance(status, dict) or status.get("ok") is not True:
            raise ObservationRejected("GUARD_STATUS_INVALID")
        if status.get("head") != expected_head:
            raise ObservationRejected("REPOSITORY_REVISION_CHANGED")
        if status.get("dirty") is not False or status.get("unmerged") != []:
            raise ObservationRejected("REPOSITORY_NOT_CLEAN")
    version = discovery.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ObservationRejected("GUARD_VERSION_INVALID")
    return {"schema": "uriprocess.guard-observation/v1", "status": "observed",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "repository_id": repository_id, "head": expected_head,
            "guard_version": version, "guard_contract_sha256": expected_contract,
            "operations": ["system.discover", "git.status", "git.status"],
            "clean": True, "scope": "git-state-only", "execution_authority": False,
            "architecture_verified": False, "publication_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token-env", default="URIPROCESS_GUARD_TOKEN")
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-contract-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ObservationRejected("OUTPUT_ALREADY_EXISTS")
        token = os.environ.get(args.token_env)
        if not token:
            raise ObservationRejected("GUARD_TOKEN_MISSING")
        from organism_guard.client import GuardClient
        result = observe(GuardClient(args.base_url, token), args.repository_id,
                         args.expected_head, args.expected_contract_sha256)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        return 0
    except ObservationRejected as error:
        code = str(error)
    except ImportError:
        code = "GUARD_SDK_NOT_INSTALLED"
    except Exception:
        # Native transport exceptions and malformed responses may carry untrusted
        # strings. Do not print their bodies, URLs, tokens or repository paths.
        code = "GUARD_OBSERVATION_FAILED"
    print(json.dumps({"status": "blocked", "code": code, "execution_authority": False}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
