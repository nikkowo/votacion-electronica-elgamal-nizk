"""Independent verifier: requires only the public dossier, never the private state."""
import argparse
import json
import sys
from crypto_vote import validate_params, verify_ballot, verify_tally


def verify_dossier(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if set(doc) != {"version", "params", "ballots", "result"} or doc["version"] != 1:
        raise ValueError("invalid dossier format")
    params, ballots = doc["params"], doc["ballots"]
    validate_params(params)
    if not isinstance(ballots, list) or not 1 <= len(ballots) <= 20:
        raise ValueError("invalid ballot count")
    for i, ballot in enumerate(ballots):
        if not verify_ballot(params, ballot):
            raise ValueError(f"invalid ballot at index {i}")
    if not verify_tally(params, ballots, doc["result"]):
        raise ValueError("invalid tally or decryption proof")
    return len(ballots), doc["result"]["yes"], doc["result"]["no"]


def main():
    p = argparse.ArgumentParser(description="Verify a public election dossier offline")
    p.add_argument("dossier")
    args = p.parse_args()
    try:
        count, yes, no = verify_dossier(args.dossier)
        print(f"VALID: {count} ballots; yes={yes}; no={no}")
        return 0
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("INVALID:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
