# Voto Aula — Entregable 2

Prototipo local para una elección de aula con una pregunta binaria y hasta 20
votantes. Usa ElGamal exponencial en P-256, una prueba OR no interactiva por
Fiat–Shamir, tokens aleatorios de un solo uso, conteo homomórfico y un
verificador público independiente. **No es apto para elecciones reales.**

El informe final está en [`docs/Informe_final_votacion_electronica.pdf`](docs/Informe_final_votacion_electronica.pdf)
y la correspondencia con los requisitos en [`RUBRICA.md`](RUBRICA.md).
Los [ejemplos completos de voto 0 y 1](examples/ejemplos_0_y_1.md) responden
a las observaciones del docente sobre el primer entregable; se regeneran con
`python examples_generate.py`.

## Requisitos e instalación

- Python 3.11 o superior.
- `pycryptodome==3.23.0` (versión fijada en `requirements.txt`).
- Windows, Linux o macOS. No requiere servidor ni base de datos externa.

Desde esta carpeta:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Si el entorno ya tiene PyCryptodome 3.23.0, se puede ejecutar directamente.

## Demostración en un comando

```bash
python demo.py
```

El script crea una elección de 5 personas con votos `[1, 0, 1, 1, 0]`, intenta
reutilizar un token y comprueba que se rechace, cierra la elección y verifica
el expediente sin consultar el archivo privado. Los archivos de esta ejecución
quedan en `demo_data/` (se recrean en cada ejecución).

## Guion manual de demostración

```bash
python election.py create --db demo_data/private.json --question "¿Aprueba la propuesta?" --voters 2 --public demo_data/public.json --tokens demo_data/tokens.json
```

`tokens.json` contiene dos tokens de 64 caracteres hexadecimales. Cada
participante recibe **solo su propio token**. Para cada token, el cliente
ejecuta el cifrado local:

```bash
python election.py vote --public demo_data/public.json --token TOKEN --choice 1 --out demo_data/vote1.json
python election.py submit --db demo_data/private.json --submission demo_data/vote1.json
python election.py status --db demo_data/private.json
python election.py close --db demo_data/private.json --out demo_data/dossier.json
python verify.py demo_data/dossier.json
```

Cambie `TOKEN` por un token real. Para mostrar un rechazo, reenvíe el mismo
`vote1.json`: `submit` terminará con código 1 e indicará que el token ya se usó.
La votación puede prepararse con `--choice 0` o `--choice 1`. Si se cierra la
elección, los envíos posteriores se rechazan.

## Experimentos

```bash
python experiments.py --repetitions 5 --out results/measurements.csv
```

El CSV incluido registra tamaño del ballot en bytes UTF-8, tiempos de creación
y verificación por voto, y auditoría completa de elecciones con 1, 5, 10 y 20
votos. Los tiempos pueden variar según hardware y carga; repetir el script
permite compararlos en el equipo evaluador. Los datos son sintéticos.

## Estructura

- `crypto_vote.py`: primitivas, pruebas OR, agregación y prueba del resultado.
- `election.py`: interfaz CLI, estado privado, tokens y ciclo de vida.
- `verify.py`: auditoría pública sin importar ni leer el estado de `election.py`.
- `tests/`: pruebas funcionales, negativas y de persistencia.
- `experiments.py`, `results/`: mediciones y datos.
- `demo.py`: recorrido completo reproducible.

## Formatos y controles

Los archivos JSON incluyen `version: 1`. Los puntos P-256 se codifican como
SEC1 sin comprimir, 65 bytes en hexadecimal minúsculo; los escalares son
32 bytes en hexadecimal minúsculo. La biblioteca valida que los puntos estén
en la curva. El transcript de voto incluye dominio, identificador de elección,
generador, clave pública, ciphertext y cuatro compromisos reconstruidos en
orden fijo. Los dos desafíos y dos respuestas viajan en el ballot. El token no
se publica en el expediente: la urna guarda su hash vinculado a la elección.
Una transacción local con bloqueo y sustitución atómica del archivo de estado
consume el token y registra el ballot juntos.

El expediente incluye parámetros, ballots, total y una prueba de igualdad de
logaritmos discretos del factor de descifrado agregado. Este complemento
permite verificar el resultado sin la clave privada; el enunciado no lo exigía.

## Límites

La clave privada reside en el archivo de estado local de la autoridad, cuya
protección depende de los permisos del sistema operativo. Una autoridad con
acceso a ella podría descifrar votos individuales; el programa solo descifra
el agregado. Con un único voto, el total revela ese voto. Los metadatos de
red, los horarios y la asignación de tokens pueden revelar participación.
No hay anonimato de red, resistencia a coerción, autenticación remota de la
administración ni despliegue público. Mantener el archivo privado y la lista
de tokens fuera de Git y no distribuirlos junto al expediente.

## Fuentes

- Enunciado del curso, *Banco de Proyectos I+D en Criptografía Aplicada*, pp. 2–6.
- Boneh y Shoup, *A Graduate Course in Applied Cryptography*, v0.6, secciones
  11.5, 19.7 y 20.3.1–20.3.3.
- Adida (2008), *Helios: Web-based Open-Audit Voting*.
- Fiat y Shamir (1986), *How to Prove Yourself*.
