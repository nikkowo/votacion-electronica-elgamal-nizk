"""P-256 exponential ElGamal and Fiat-Shamir OR proof for binary ballots."""
import hashlib
import json
import secrets

from Crypto.PublicKey import ECC

CURVE = "P-256"
G = ECC._curves[CURVE].G
Q = int(ECC._curves[CURVE].order)
POINT_BYTES = 65
DOMAIN_VOTE = b"class-vote/v1/or-proof/P-256/sha256"
DOMAIN_TALLY = b"class-vote/v1/tally-proof/P-256/sha256"


def scalar():
    return secrets.randbelow(Q - 1) + 1


def scalar_hex(n):
    if not isinstance(n, int) or not 0 <= n < Q:
        raise ValueError("invalid scalar")
    return n.to_bytes(32, "big").hex()


def parse_scalar(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("invalid scalar encoding")
    try:
        n = int(value, 16)
    except ValueError as exc:
        raise ValueError("invalid scalar encoding") from exc
    if value != scalar_hex(n):
        raise ValueError("noncanonical scalar")
    return n


def point_hex(point):
    if point.is_point_at_infinity():
        raise ValueError("point at infinity")
    return (b"\x04" + int(point.x).to_bytes(32, "big") + int(point.y).to_bytes(32, "big")).hex()


def parse_point(value):
    if not isinstance(value, str) or len(value) != POINT_BYTES * 2 or not value.startswith("04"):
        raise ValueError("invalid point encoding")
    try:
        raw = bytes.fromhex(value)
        point = ECC.EccPoint(int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"), curve=CURVE)
    except (ValueError, TypeError) as exc:
        raise ValueError("point outside P-256") from exc
    if point_hex(point) != value:
        raise ValueError("noncanonical point")
    return point


def hash_challenge(domain, election_id, points):
    h = hashlib.sha256(domain)
    eid = election_id.encode("ascii")
    h.update(len(eid).to_bytes(2, "big"))
    h.update(eid)
    for point in points:
        h.update(bytes.fromhex(point_hex(point)))
    return int.from_bytes(h.digest(), "big") % Q


def public_params(election_id, question, public_key):
    return {"version": 1, "election_id": election_id, "question": question,
            "group": CURVE, "algorithm": "exponential-ElGamal-P256-OR-FS-SHA256",
            "generator": point_hex(G), "public_key": point_hex(public_key), "max_voters": 20}


def make_ballot(params, choice):
    if choice not in (0, 1):
        raise ValueError("choice must be 0 or 1")
    validate_params(params)
    H = parse_point(params["public_key"])
    r = scalar()
    C1 = G * r
    C2 = H * r + G * choice
    simulated = 1 - choice
    c = [0, 0]
    s = [0, 0]
    A = [None, None]
    B = [None, None]
    c[simulated], s[simulated] = scalar(), scalar()
    Y_sim = C2 + -(G * simulated)
    A[simulated] = G * s[simulated] + -(C1 * c[simulated])
    B[simulated] = H * s[simulated] + -(Y_sim * c[simulated])
    k = scalar()
    A[choice], B[choice] = G * k, H * k
    challenge = hash_challenge(DOMAIN_VOTE, params["election_id"],
                               [G, H, C1, C2, A[0], B[0], A[1], B[1]])
    c[choice] = (challenge - c[simulated]) % Q
    s[choice] = (k + c[choice] * r) % Q
    ballot = {"version": 1, "election_id": params["election_id"],
              "ciphertext": {"c1": point_hex(C1), "c2": point_hex(C2)},
              "proof": {"c0": scalar_hex(c[0]), "c1": scalar_hex(c[1]),
                        "s0": scalar_hex(s[0]), "s1": scalar_hex(s[1])}}
    assert verify_ballot(params, ballot)
    return ballot


def validate_params(params):
    if not isinstance(params, dict) or params.get("version") != 1 or params.get("group") != CURVE:
        raise ValueError("unsupported election parameters")
    if params.get("algorithm") != "exponential-ElGamal-P256-OR-FS-SHA256" or params.get("generator") != point_hex(G):
        raise ValueError("unsupported cryptographic parameters")
    if not isinstance(params.get("election_id"), str) or len(params["election_id"]) != 32:
        raise ValueError("invalid election id")
    if not isinstance(params.get("question"), str) or not params["question"]:
        raise ValueError("invalid question")
    if params.get("max_voters") != 20:
        raise ValueError("invalid voter limit")
    parse_point(params["public_key"])


def verify_ballot(params, ballot):
    try:
        validate_params(params)
        if set(ballot) != {"version", "election_id", "ciphertext", "proof"}:
            return False
        if ballot["version"] != 1 or ballot["election_id"] != params["election_id"]:
            return False
        ct, proof = ballot["ciphertext"], ballot["proof"]
        if set(ct) != {"c1", "c2"} or set(proof) != {"c0", "c1", "s0", "s1"}:
            return False
        H = parse_point(params["public_key"])
        C1, C2 = parse_point(ct["c1"]), parse_point(ct["c2"])
        c = [parse_scalar(proof["c0"]), parse_scalar(proof["c1"])]
        s = [parse_scalar(proof["s0"]), parse_scalar(proof["s1"])]
        A, B = [], []
        for bit in (0, 1):
            Y = C2 + -(G * bit)
            A.append(G * s[bit] + -(C1 * c[bit]))
            B.append(H * s[bit] + -(Y * c[bit]))
        challenge = hash_challenge(DOMAIN_VOTE, params["election_id"],
                                   [G, H, C1, C2, A[0], B[0], A[1], B[1]])
        return (c[0] + c[1]) % Q == challenge
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return False


def aggregate(ballots):
    A, B = G * 0, G * 0
    for ballot in ballots:
        A += parse_point(ballot["ciphertext"]["c1"])
        B += parse_point(ballot["ciphertext"]["c2"])
    return A, B


def tally(params, ballots, secret):
    A, B = aggregate(ballots)
    D = A * secret
    M_point = B + -D
    count = next((i for i in range(len(ballots) + 1) if G * i == M_point), None)
    if count is None:
        raise ValueError("aggregate outside vote range")
    # Equality-of-discrete-logs proof makes the tally independently checkable.
    k = scalar()
    K, L = G * k, A * k
    H = parse_point(params["public_key"])
    e = hash_challenge(DOMAIN_TALLY, params["election_id"], [G, H, A, D, K, L])
    s = (k + e * secret) % Q
    return {"yes": count, "no": len(ballots) - count,
            "aggregate": {"a": point_hex(A), "b": point_hex(B), "factor": point_hex(D)},
            "decryption_proof": {"k": point_hex(K), "l": point_hex(L), "s": scalar_hex(s)}}


def verify_tally(params, ballots, result):
    try:
        if not ballots or any(not verify_ballot(params, b) for b in ballots):
            return False
        if not isinstance(result["yes"], int) or isinstance(result["yes"], bool) or not 0 <= result["yes"] <= len(ballots):
            return False
        if result["no"] != len(ballots) - result["yes"]:
            return False
        A, B = aggregate(ballots)
        if result["aggregate"]["a"] != point_hex(A) or result["aggregate"]["b"] != point_hex(B):
            return False
        D = parse_point(result["aggregate"]["factor"])
        if B + -D != G * result["yes"]:
            return False
        H = parse_point(params["public_key"])
        K = parse_point(result["decryption_proof"]["k"])
        L = parse_point(result["decryption_proof"]["l"])
        s = parse_scalar(result["decryption_proof"]["s"])
        e = hash_challenge(DOMAIN_TALLY, params["election_id"], [G, H, A, D, K, L])
        return G * s == K + H * e and A * s == L + D * e
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return False


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
