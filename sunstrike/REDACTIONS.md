# Redactions in the public copy (2026-11-14)

The files published here are byte-identical to the sealed study files except for the edits listed below. They are header lines naming an internal working-protocol version, plus a role label next to the operator's name. Nothing that affects behaviour was changed. Because any byte change changes a sha256, the hash constants that check the labs were updated to match, so the published code still verifies itself.

| Edit | Files |
|---|---|
| internal protocol-version label → `PVTE family` (header comment / docstring) | `v0.7.5/sunstrike_lab.py`, `v0.7.5/sunstrike_lab_pre_r11_fixes.py`, `v0.7.5/sunstrike_probes_r7_v071.py`, `_r8.py`, `_r9.py`, `_r10.py` |
| role label after the operator's name removed (docstring) | `v0.7.5/sunstrike_lab.py`, `v0.7.5/sunstrike_lab_pre_r11_fixes.py` |
| expected-lab-hash constants: sealed → public values | `v0.7.5/sunstrike_probes_r2.py`–`_r11.py`, `m3/m3_cenarios.py`, `pacote_reproducao/reproduzir_sunstrike.py` |

| Lab | Sealed sha256 (cited throughout the report and run outputs) | Public sha256 (this folder) |
|---|---|---|
| v0.7.5 `sunstrike_lab.py` | `5162964f2df283fd6ed0a1a4d53f8b3650f491b4892e24abb198494b7abcb441` | `cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d788ae2fb723320b091cb86f8` |
| v0.7.4 `sunstrike_lab_pre_r11_fixes.py` | `1643887c517f94cf9e1e30b3a03a5ccb4be928dc3e1397eecc45638c61f18837` | `c039ab6174e309ddfd4158f6a865abda22471518a6f2119358a772b1069c62c1` |

The run outputs (`v0.7.5/*.txt`, `m3/referencia/`, `m3/supervisor/`) are historical records and show the sealed hashes; they were not edited. Comments and docstrings that quote a sealed hash in abbreviated form (e.g. `5162964f…`) were also left as written.

Check after redaction: the reproduction package was re-run on these public files (supervisor, Linux, Python 3.13.18, 2026-11-14 16:21 UTC) → 15/15 PASS, every number identical to the sealed runs.
