"""Generate fixed, synthetic teaching examples for both binary choices.

The fixed witness values here are deliberately public and MUST NOT be used
for a real election. The application itself uses secrets.randbelow.
"""
import hashlib
from pathlib import Path
from unittest.mock import patch

from crypto_vote import (DOMAIN_VOTE, G, Q, canonical_json, make_ballot,
                         parse_point, parse_scalar, point_hex, public_params,
                         verify_ballot)


def show_example(params, choice, witness, simulated_c, simulated_s, real_k):
    with patch("crypto_vote.scalar", side_effect=[witness, simulated_c, simulated_s, real_k]):
        ballot = make_ballot(params, choice)
    H = parse_point(params["public_key"])
    C1 = parse_point(ballot["ciphertext"]["c1"])
    C2 = parse_point(ballot["ciphertext"]["c2"])
    c = [parse_scalar(ballot["proof"][f"c{i}"]) for i in (0, 1)]
    s = [parse_scalar(ballot["proof"][f"s{i}"]) for i in (0, 1)]
    A, B = [], []
    for bit in (0, 1):
        Y = C2 + -(G * bit)
        A.append(G * s[bit] + -(C1 * c[bit]))
        B.append(H * s[bit] + -(Y * c[bit]))
    eid = params["election_id"].encode("ascii")
    transcript = DOMAIN_VOTE + len(eid).to_bytes(2, "big") + eid
    transcript += b"".join(bytes.fromhex(point_hex(p)) for p in
                           [G, H, C1, C2, A[0], B[0], A[1], B[1]])
    digest = hashlib.sha256(transcript).hexdigest()
    challenge = int(digest, 16) % Q
    assert C1 == G * witness
    assert C2 == H * witness + G * choice
    assert (c[0] + c[1]) % Q == challenge
    assert verify_ballot(params, ballot)
    return ballot, dict(x="0000000000000000000000000000000000000000000000000000000000000017",
                        r=f"{witness:064x}", G=point_hex(G), H=point_hex(H),
                        C1=point_hex(C1), C2=point_hex(C2),
                        A0=point_hex(A[0]), B0=point_hex(B[0]),
                        A1=point_hex(A[1]), B1=point_hex(B[1]),
                        c0=f"{c[0]:064x}", c1=f"{c[1]:064x}",
                        s0=f"{s[0]:064x}", s1=f"{s[1]:064x}",
                        digest=digest, challenge=f"{challenge:064x}")


def main():
    directory = Path(__file__).resolve().parent / "examples"
    directory.mkdir(exist_ok=True)
    params = public_params("e1" * 16, "¿Aprueba la propuesta?", G * 23)
    (directory / "parametros_ejemplo.json").write_text(canonical_json(params) + "\n", encoding="utf-8")
    sections = [
        "# Dos ejemplos completos de voto binario\n",
        "Valores sintéticos y deterministas solo para explicar el protocolo. No usar estos escalares en una elección real.\n",
        "Grupo P-256, clave privada educativa `x=17` hexadecimal (23 decimal), H=xG. El identificador de elección es `e1` repetido 16 veces. Todos los valores siguientes son hexadecimales canónicos en minúscula.\n",
    ]
    for choice, values in [(0, (0x12345, 0x23456, 0x34567, 0x45678)),
                           (1, (0x56789, 0x6789A, 0x789AB, 0x89ABC))]:
        ballot, trace = show_example(params, choice, *values)
        (directory / f"voto_{choice}.json").write_text(canonical_json(ballot) + "\n", encoding="utf-8")
        sections += [f"\n## Voto {choice}\n",
                     f"El cliente usa `m={choice}` y `r={trace['r']}`. Comprueba `C1=rG` y `C2=rH+{choice}G`. La rama {choice} es real; la otra es simulada.\n",
                     "| Campo | Valor completo |\n|---|---|\n"]
        for name in ("G", "H", "C1", "C2", "A0", "B0", "A1", "B1", "c0", "c1", "s0", "s1"):
            sections.append(f"| {name} | `{trace[name]}` |\n")
        sections += ["\nVerificación: `A0=s0G−c0C1`, `B0=s0H−c0C2`, `A1=s1G−c1C1`, "
                     "`B1=s1H−c1(C2−G)`. Estos cálculos reconstruyen los compromisos completos de la tabla.\n",
                     "El transcript SHA-256 concatena: dominio `class-vote/v1/or-proof/P-256/sha256`, "
                     "longitud de `election_id` (2 bytes), identificador ASCII, G, H, C1, C2, A0, B0, A1 y B1 "
                     "(puntos SEC1 de 65 bytes) en ese orden.\n",
                     f"- SHA-256 del transcript: `{trace['digest']}`.\n",
                     f"- Desafío reducido módulo q: `{trace['challenge']}`.\n",
                     f"- `(c0+c1) mod q == desafío`: **sí**. `verify_ballot(...)`: **True**.\n",
                     f"- Ballot serializado: [`voto_{choice}.json`](voto_{choice}.json).\n"]
    sections += ["\n## Rechazos esperados\n",
                 "Cambiar un byte de C2 o de cualquiera de los cuatro escalares rompe la igualdad "
                 "del desafío. Un ciphertext construido con `m=2` carece de testigo válido para ambas "
                 "ramas; la suite automatizada comprueba que se rechaza.\n"]
    (directory / "ejemplos_0_y_1.md").write_text("".join(sections), encoding="utf-8")
    print("Generated:", directory / "ejemplos_0_y_1.md")


if __name__ == "__main__":
    main()
