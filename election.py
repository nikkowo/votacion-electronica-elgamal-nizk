"""Local election authority, voter client, and ballot box CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import uuid
from contextlib import contextmanager

from crypto_vote import (G, canonical_json, make_ballot, point_hex, public_params,
                         scalar, tally, validate_params, verify_ballot)


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def atomic_json(path, obj, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".vote-", suffix=".tmp", dir=path.parent)
    try:
        if private and os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(canonical_json(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(path):
    lock_path = str(path) + ".lock"
    with open(lock_path, "a+b") as f:
        f.seek(0)
        if not f.read(1):
            f.write(b"0")
            f.flush()
        f.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            f.seek(0)
            if os.name == "nt":
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def token_digest(election_id, token):
    if not isinstance(token, str) or len(token) != 64:
        raise ValueError("token must be 32 bytes in lowercase hex")
    try:
        raw = bytes.fromhex(token)
    except ValueError as exc:
        raise ValueError("invalid token") from exc
    if token != raw.hex():
        raise ValueError("noncanonical token")
    return hashlib.sha256(b"class-vote/token/v1" + bytes.fromhex(election_id) + raw).hexdigest()


def create(db, question, voters, public_out, tokens_out):
    if not 1 <= voters <= 20:
        raise ValueError("voters must be between 1 and 20")
    if not question.strip():
        raise ValueError("question is required")
    db = Path(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        raise ValueError("election database already exists")
    election_id = uuid.uuid4().hex
    secret = scalar()
    params = public_params(election_id, question, G * secret)
    tokens = [secrets.token_hex(32) for _ in range(voters)]
    state = {"version": 1, "params": params, "secret": f"{secret:064x}",
             "status": "open", "tokens": {token_digest(election_id, t): False for t in tokens},
             "ballots": []}
    with locked(db):
        if db.exists():
            raise ValueError("election database already exists")
        atomic_json(db, state, private=True)
    atomic_json(public_out, params)
    atomic_json(tokens_out, {"version": 1, "election_id": election_id, "tokens": tokens}, private=True)
    return election_id


def prepare(public_file, token, choice, output):
    params = read_json(public_file)
    validate_params(params)
    token_digest(params["election_id"], token)
    ballot = make_ballot(params, choice)
    atomic_json(output, {"token": token, "ballot": ballot})


def submit(db, submission_file):
    submission = read_json(submission_file)
    if set(submission) != {"token", "ballot"}:
        raise ValueError("malformed submission")
    db = Path(db)
    with locked(db):
        state = read_json(db)
        if state["status"] != "open":
            raise ValueError("election is closed")
        digest = token_digest(state["params"]["election_id"], submission["token"])
        if digest not in state["tokens"]:
            raise ValueError("unknown token")
        if state["tokens"][digest]:
            raise ValueError("token already used")
        ballot = submission["ballot"]
        if not verify_ballot(state["params"], ballot):
            raise ValueError("invalid ciphertext or proof")
        if ballot in state["ballots"]:
            raise ValueError("ballot already submitted")
        if len(state["ballots"]) >= 20:
            raise ValueError("voter limit reached")
        state["tokens"][digest] = True
        state["ballots"].append(ballot)
        atomic_json(db, state, private=True)
        return len(state["ballots"])


def status(db):
    state = read_json(db)
    return {"status": state["status"], "accepted": len(state["ballots"]),
            "issued_tokens": len(state["tokens"]),
            "used_tokens": sum(state["tokens"].values())}


def close(db, output):
    db = Path(db)
    with locked(db):
        state = read_json(db)
        if state["status"] != "open":
            raise ValueError("election already closed")
        if not state["ballots"]:
            raise ValueError("at least one vote is needed to close")
        params = state["params"]
        ballots = state["ballots"]
        if any(not verify_ballot(params, ballot) for ballot in ballots):
            raise ValueError("stored ballot failed verification")
        result = tally(params, ballots, int(state["secret"], 16))
        dossier = {"version": 1, "params": params, "ballots": ballots, "result": result}
        atomic_json(output, dossier)
        state["status"] = "closed"
        atomic_json(db, state, private=True)
        return result


def main():
    p = argparse.ArgumentParser(description="Verifiable classroom election")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    c.add_argument("--db", required=True)
    c.add_argument("--question", required=True)
    c.add_argument("--voters", type=int, required=True)
    c.add_argument("--public", required=True)
    c.add_argument("--tokens", required=True)
    v = sub.add_parser("vote")
    v.add_argument("--public", required=True)
    v.add_argument("--token", required=True)
    v.add_argument("--choice", type=int, choices=(0, 1), required=True)
    v.add_argument("--out", required=True)
    s = sub.add_parser("submit")
    s.add_argument("--db", required=True)
    s.add_argument("--submission", required=True)
    t = sub.add_parser("status")
    t.add_argument("--db", required=True)
    f = sub.add_parser("close")
    f.add_argument("--db", required=True)
    f.add_argument("--out", required=True)
    args = p.parse_args()
    try:
        if args.command == "create":
            print("Election created:", create(args.db, args.question, args.voters, args.public, args.tokens))
        elif args.command == "vote":
            prepare(args.public, args.token, args.choice, args.out)
            print("Encrypted ballot written:", args.out)
        elif args.command == "submit":
            print("Ballot accepted, total:", submit(args.db, args.submission))
        elif args.command == "status":
            print(json.dumps(status(args.db), indent=2))
        elif args.command == "close":
            result = close(args.db, args.out)
            print("Election closed. Yes:", result["yes"], "No:", result["no"])
    except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
