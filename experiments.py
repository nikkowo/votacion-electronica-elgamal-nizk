"""Repeatable measurements for 1, 5, 10, and 20 ballots."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import time

from crypto_vote import G, canonical_json, make_ballot, public_params, scalar, tally, verify_ballot, verify_tally


def timed(fn):
    start = time.perf_counter_ns()
    value = fn()
    return value, (time.perf_counter_ns() - start) / 1_000_000


def run(repetitions=3):
    rows = []
    for n in (1, 5, 10, 20):
        create_ms, verify_ms, audit_ms, sizes = [], [], [], []
        for rep in range(repetitions):
            secret = scalar()
            params = public_params(f"{n:08x}{rep:08x}" + "0" * 16, "Approve?", G * secret)
            ballots = []
            for i in range(n):
                ballot, ms = timed(lambda: make_ballot(params, i % 2))
                ballots.append(ballot)
                create_ms.append(ms)
                ok, ms = timed(lambda: verify_ballot(params, ballot))
                assert ok
                verify_ms.append(ms)
                sizes.append(len(canonical_json(ballot).encode("utf-8")))
            result = tally(params, ballots, secret)
            ok, ms = timed(lambda: verify_tally(params, ballots, result))
            assert ok
            audit_ms.append(ms)
        rows.append({"votes": n, "repetitions": repetitions,
                     "ballot_bytes_mean": round(statistics.mean(sizes), 2),
                     "create_ms_mean": round(statistics.mean(create_ms), 3),
                     "verify_ms_mean": round(statistics.mean(verify_ms), 3),
                     "audit_ms_mean": round(statistics.mean(audit_ms), 3)})
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--out", default="results/measurements.csv")
    args = p.parse_args()
    if not 1 <= args.repetitions <= 100:
        p.error("repetitions must be between 1 and 100")
    rows = run(args.repetitions)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
