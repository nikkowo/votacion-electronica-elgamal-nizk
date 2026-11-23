"""One-command reproducible classroom election demonstration."""
import shutil
from pathlib import Path

from election import close, create, prepare, read_json, submit
from verify import verify_dossier


def main():
    root = Path("demo_data")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    private, public, tokens, dossier = (root / name for name in
                                        ("private.json", "public.json", "tokens.json", "dossier.json"))
    create(private, "¿Aprueba la propuesta?", 5, public, tokens)
    issued = read_json(tokens)["tokens"]
    for i, (token, bit) in enumerate(zip(issued, [1, 0, 1, 1, 0])):
        submission = root / f"submission-{i + 1}.json"
        prepare(public, token, bit, submission)
        submit(private, submission)
    try:
        submit(private, root / "submission-1.json")
    except ValueError as exc:
        assert "already used" in str(exc)
        print("Replay rejected:", exc)
    else:
        raise AssertionError("replay was accepted")
    result = close(private, dossier)
    assert (result["yes"], result["no"]) == (3, 2)
    count, yes, no = verify_dossier(dossier)
    print(f"Public verification: {count} ballots, yes={yes}, no={no}")
    print("Public dossier:", dossier)


if __name__ == "__main__":
    main()
