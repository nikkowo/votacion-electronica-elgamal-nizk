# Correspondencia con el enunciado y la rúbrica

| Exigencia | Evidencia |
|---|---|
| Una pregunta binaria, hasta 20 votantes, una autoridad | `election.py create`; límite validado |
| Interfaz de administración | CLI: `create`, `status`, `close` |
| Cliente de votación | CLI: `vote`, cifrado y prueba local |
| Urna y tokens de un solo uso | CLI: `submit`, hashes de tokens, bloqueo y actualización atómica |
| ElGamal exponencial en grupo primo | `crypto_vote.py`, P-256 de PyCryptodome |
| Prueba OR NIZK con Fiat–Shamir | `make_ballot`, `verify_ballot` |
| Conteo homomórfico y descifrado solo del agregado | `aggregate`, `tally` |
| Expediente público y verificador independiente | `close`, `verify.py`, `examples/dossier.json` |
| Formato versionado y codificación inequívoca | JSON versión 1, SEC1 y escalares de 32 bytes; `README.md` |
| Pruebas positivas, negativas y manipulación | `tests/test_election.py`; 10 pruebas |
| Experimentos 1, 5, 10 y 20 votos | `experiments.py`, `results/measurements.csv` |
| Reproducción desde cero | `requirements.txt`, `README.md`, `demo.py`, CI |
| Informe final de 8–12 páginas | `docs/Informe_final_votacion_electronica.pdf`, 9 páginas |

## Criterios de evaluación

- **Producto funcional (30 %):** comandos `create`, `vote`, `submit`, `status`, `close`; `demo.py`.
- **Diseño y precisión técnica (25 %):** secciones 2–5 y 8 del informe; formatos y supuestos en `README.md`.
- **Criptografía aplicada (20 %):** `crypto_vote.py`, validación de puntos, dominios de hash, prueba OR y prueba del agregado.
- **Pruebas y experimentos (15 %):** `tests/`, `results/` y `experiments.py`.
- **Informe y reproducibilidad (10 %):** `docs/`, `README.md`, dependencias fijadas y CI.

El proyecto usa una CLI local en lugar de la arquitectura web propuesta en el Entregable 1. La sección 8 del informe explica esta y las demás desviaciones.
