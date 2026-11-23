# Dos ejemplos completos de voto binario
Valores sintéticos y deterministas solo para explicar el protocolo. No usar estos escalares en una elección real.
Grupo P-256, clave privada educativa `x=17` hexadecimal (23 decimal), H=xG. El identificador de elección es `e1` repetido 16 veces. Todos los valores siguientes son hexadecimales canónicos en minúscula.

## Voto 0
El cliente usa `m=0` y `r=0000000000000000000000000000000000000000000000000000000000012345`. Comprueba `C1=rG` y `C2=rH+0G`. La rama 0 es real; la otra es simulada.
| Campo | Valor completo |
|---|---|
| G | `046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5` |
| H | `040e91c7239c2640d7d28a3e39d4583fa63c0bc0a5df64a4fe672e573045ca78965df65c3b550dba221a22733bb8e0bd6d7e68833575e7a5ae138046543140ad55` |
| C1 | `0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4` |
| C2 | `04dd4206a74e47dc9fc7e4bc585af7622d5d4ddb713ac221f8d8183b54e40feec560f909f531021f1ee0c0ac9c1feb1fcd5aa4c764eb8db79d3317839a5b2d03a6` |
| A0 | `04fdbf041bb94dfa94b7273c72c1083998737da8ac14659d5b74374917e581e5ffc64bd23a676f4bbfc39db1e276bfeae680f49a45b1948a95608fb3ff4f3cf879` |
| B0 | `042a1c7ca5034bb5ae912056516b2110f88b217854acef24e8d3c50d262a60f715055707413c61e272b735e6524a150199ab3792e39906a5f5d2dc4b07271b847d` |
| A1 | `043b2c61a88d007c71b4d2156471da92e26b62799b42d591b4aeb84371af2a3ce4bd708e71404a1237dd2422ca7e470e4dbb1e1a4a2bf89d4309c5de4ee19dc76e` |
| B1 | `04ca8e3f9b4bbbf442295f7d830f92905050814cf12c49e2e523d0a5a230c497ab6a3894556a6ecd0a3e1fc492c283db4d07fceba09211fa84c4f60c6b1f56431b` |
| c0 | `0f887782fd6f5142df28489459b0fda90d64e3a11004224d20c7099c4e5bd7c0` |
| c1 | `0000000000000000000000000000000000000000000000000000000000023456` |
| s0 | `4fa22e0fd85fd904f05c31f05d0b8d6c091b7ad92eb59588fe47166f5ced49cc` |
| s1 | `0000000000000000000000000000000000000000000000000000000000034567` |

Verificación: `A0=s0G−c0C1`, `B0=s0H−c0C2`, `A1=s1G−c1C1`, `B1=s1H−c1(C2−G)`. Estos cálculos reconstruyen los compromisos completos de la tabla.
El transcript SHA-256 concatena: dominio `class-vote/v1/or-proof/P-256/sha256`, longitud de `election_id` (2 bytes), identificador ASCII, G, H, C1, C2, A0, B0, A1 y B1 (puntos SEC1 de 65 bytes) en ese orden.
- SHA-256 del transcript: `0f887782fd6f5142df28489459b0fda90d64e3a11004224d20c7099c4e5e0c16`.
- Desafío reducido módulo q: `0f887782fd6f5142df28489459b0fda90d64e3a11004224d20c7099c4e5e0c16`.
- `(c0+c1) mod q == desafío`: **sí**. `verify_ballot(...)`: **True**.
- Ballot serializado: [`voto_0.json`](voto_0.json).

## Voto 1
El cliente usa `m=1` y `r=0000000000000000000000000000000000000000000000000000000000056789`. Comprueba `C1=rG` y `C2=rH+1G`. La rama 1 es real; la otra es simulada.
| Campo | Valor completo |
|---|---|
| G | `046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5` |
| H | `040e91c7239c2640d7d28a3e39d4583fa63c0bc0a5df64a4fe672e573045ca78965df65c3b550dba221a22733bb8e0bd6d7e68833575e7a5ae138046543140ad55` |
| C1 | `042a001ddf5c087ab4cefd15d68cb0030b293d9863f783aa0ba9e0f830240777ed4c3d8e2c38908ccff0ee222853c224de8efa4092fd7dd2b1dc46f1f512c3e1b8` |
| C2 | `04b77e295c830606c299783daca1114ff6d688a4be018ff4ca85acf2c8a6c2a789c612b4c62964a3787b84fc98b0896d1c7e76ed091dd0488fc4cfe39f04d37820` |
| A0 | `0452b9ac1d292cbd6f7d08a601d82ada6c94f14d813ba70989a2d63bd6c224dd2df6babad8ef277e4143a3412d47a106c49b8f31785b42b64732f2a0b53fc231ce` |
| B0 | `04b6927aae7b79ff93adbcd971736bef1cab49bf189ee4f8c42567beed3f4c475216826b5432e786639c12a7a011dbcff7280c7d7da1457525e72fcb7914e7ea17` |
| A1 | `04f88093efbf6177689c98bc4f5be593fd0aa865a6294518add8db7f447179907164e45c0dc240d4e3a0eb537c9dc7a28b9f58060f82da7b14e857032f1561b263` |
| B1 | `044057d8546bc142d6a030f1a40db963aacee494dc55a7772b87546a94e1b91f3cfa00e588ba439c31f7f5756b96b926c7972bd5cd5b535aabf5c0c6d7e099bf00` |
| c0 | `000000000000000000000000000000000000000000000000000000000006789a` |
| c1 | `5fc98618d2a90269c5d57657aeaed985a0a161377c2f3cc7279f369178f30355` |
| s0 | `00000000000000000000000000000000000000000000000000000000000789ab` |
| s1 | `f64ae303c879b0b31190059f14b3d6f9671ea775af9e6c175cb0158cc41beecd` |

Verificación: `A0=s0G−c0C1`, `B0=s0H−c0C2`, `A1=s1G−c1C1`, `B1=s1H−c1(C2−G)`. Estos cálculos reconstruyen los compromisos completos de la tabla.
El transcript SHA-256 concatena: dominio `class-vote/v1/or-proof/P-256/sha256`, longitud de `election_id` (2 bytes), identificador ASCII, G, H, C1, C2, A0, B0, A1 y B1 (puntos SEC1 de 65 bytes) en ese orden.
- SHA-256 del transcript: `5fc98618d2a90269c5d57657aeaed985a0a161377c2f3cc7279f369178f97bef`.
- Desafío reducido módulo q: `5fc98618d2a90269c5d57657aeaed985a0a161377c2f3cc7279f369178f97bef`.
- `(c0+c1) mod q == desafío`: **sí**. `verify_ballot(...)`: **True**.
- Ballot serializado: [`voto_1.json`](voto_1.json).

## Rechazos esperados
Cambiar un byte de C2 o de cualquiera de los cuatro escalares rompe la igualdad del desafío. Un ciphertext construido con `m=2` carece de testigo válido para ambas ramas; la suite automatizada comprueba que se rechaza.
