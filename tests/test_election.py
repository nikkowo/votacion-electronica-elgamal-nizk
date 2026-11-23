import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from crypto_vote import G, canonical_json, make_ballot, point_hex, public_params, scalar, tally, verify_ballot, verify_tally
from election import atomic_json, close, create, prepare, read_json, status, submit
from verify import verify_dossier


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.secret = scalar()
        self.params = public_params("a" * 32, "Choose?", G * self.secret)

    def test_known_distributions(self):
        for votes in ([0] * 20, [1] * 20, [1] * 12 + [0] * 8):
            ballots = [make_ballot(self.params, bit) for bit in votes]
            result = tally(self.params, ballots, self.secret)
            self.assertEqual(result["yes"], sum(votes))
            self.assertTrue(verify_tally(self.params, ballots, result))

    def test_tampering_and_nonbinary(self):
        ballot = make_ballot(self.params, 1)
        altered = copy.deepcopy(ballot)
        altered["proof"]["s0"] = "00" * 32
        self.assertFalse(verify_ballot(self.params, altered))
        altered = copy.deepcopy(ballot)
        altered["ciphertext"]["c2"] = "04" + "00" * 64
        self.assertFalse(verify_ballot(self.params, altered))
        altered = copy.deepcopy(ballot)
        r = scalar()
        altered["ciphertext"]["c1"] = point_hex(G * r)
        altered["ciphertext"]["c2"] = point_hex(G * 2 + (G * self.secret) * r)
        self.assertFalse(verify_ballot(self.params, altered))
        with self.assertRaises(ValueError):
            make_ballot(self.params, 2)
        altered = copy.deepcopy(ballot)
        altered["election_id"] = "b" * 32
        self.assertFalse(verify_ballot(self.params, altered))

    def test_tally_manipulation(self):
        ballots = [make_ballot(self.params, 0), make_ballot(self.params, 1)]
        result = tally(self.params, ballots, self.secret)
        altered = copy.deepcopy(result)
        altered["yes"] = 2
        altered["no"] = 0
        self.assertFalse(verify_tally(self.params, ballots, altered))
        altered = copy.deepcopy(result)
        altered["decryption_proof"]["s"] = "00" * 32
        self.assertFalse(verify_tally(self.params, ballots, altered))


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "private.json"
        self.public = self.root / "public.json"
        self.tokens = self.root / "tokens.json"
        self.dossier = self.root / "dossier.json"
        create(self.db, "Approve?", 2, self.public, self.tokens)
        self.token_list = read_json(self.tokens)["tokens"]

    def tearDown(self):
        self.tmp.cleanup()

    def submission(self, i, vote):
        path = self.root / f"submission-{i}.json"
        prepare(self.public, self.token_list[i], vote, path)
        return path

    def test_full_flow_and_independent_verification(self):
        submit(self.db, self.submission(0, 1))
        submit(self.db, self.submission(1, 0))
        self.assertEqual(status(self.db)["accepted"], 2)
        result = close(self.db, self.dossier)
        self.assertEqual((result["yes"], result["no"]), (1, 1))
        self.assertEqual(verify_dossier(self.dossier), (2, 1, 1))
        self.db.unlink()  # Prove verification has no private-state dependency.
        self.assertEqual(verify_dossier(self.dossier), (2, 1, 1))

    def test_replay_unknown_and_closed(self):
        path = self.submission(0, 1)
        submit(self.db, path)
        with self.assertRaisesRegex(ValueError, "already used"):
            submit(self.db, path)
        invalid = read_json(self.submission(1, 0))
        invalid["token"] = "ab" * 32
        atomic_json(self.root / "bad.json", invalid)
        with self.assertRaisesRegex(ValueError, "unknown token"):
            submit(self.db, self.root / "bad.json")
        close(self.db, self.dossier)
        with self.assertRaisesRegex(ValueError, "closed"):
            submit(self.db, self.submission(1, 0))

    def test_same_ballot_with_different_token_is_rejected(self):
        path = self.submission(0, 1)
        submit(self.db, path)
        duplicate = read_json(path)
        duplicate["token"] = self.token_list[1]
        second = self.root / "duplicate.json"
        atomic_json(second, duplicate)
        with self.assertRaisesRegex(ValueError, "ballot already submitted"):
            submit(self.db, second)
        self.assertEqual(status(self.db)["used_tokens"], 1)

    def test_invalid_proof_does_not_consume_token(self):
        path = self.submission(0, 1)
        invalid = read_json(path)
        invalid["ballot"]["proof"]["c0"] = "00" * 32
        atomic_json(path, invalid)
        with self.assertRaisesRegex(ValueError, "invalid ciphertext"):
            submit(self.db, path)
        self.assertEqual(status(self.db)["used_tokens"], 0)
        path = self.submission(0, 1)
        submit(self.db, path)

    def test_atomic_replace_failure_keeps_previous_file(self):
        before = self.db.read_bytes()
        with patch("election.os.replace", side_effect=OSError("injected failure")):
            with self.assertRaises(OSError):
                atomic_json(self.db, {"broken": True})
        self.assertEqual(self.db.read_bytes(), before)

    def test_dossier_tamper(self):
        submit(self.db, self.submission(0, 1))
        close(self.db, self.dossier)
        doc = read_json(self.dossier)
        doc["result"]["yes"] = 0
        atomic_json(self.dossier, doc)
        with self.assertRaises(ValueError):
            verify_dossier(self.dossier)

    def test_concurrent_replay_accepts_exactly_once(self):
        path = self.submission(0, 1)
        script = Path(__file__).resolve().parents[1] / "election.py"
        command = [sys.executable, str(script), "submit", "--db", str(self.db),
                   "--submission", str(path)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: subprocess.run(command, capture_output=True), range(2)))
        self.assertEqual(sorted(r.returncode for r in results), [0, 1])
        self.assertEqual(status(self.db)["accepted"], 1)


if __name__ == "__main__":
    unittest.main()
