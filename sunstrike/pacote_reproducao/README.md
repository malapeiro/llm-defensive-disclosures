# Sunstrike — reproduction package (code frozen at v0.7.5)

Re-runs everything behind the case's numbers from the `v0.7.5/` folder and compares each result with its expected value.

    python3 -I pacote_reproducao/reproduzir_sunstrike.py v0.7.5

- Checks the hashes first, using the public (redacted) values: lab v0.7.5 `cf9fbe3e…86f8` and the preserved lab v0.7.4 (`sunstrike_lab_pre_r11_fixes.py`, `c039ab61…62c1`). The sealed hashes cited in the report are `5162964f…b441` and `1643887c…8837`; see `../REDACTIONS.md`.
- Copies everything into a new folder `repro_run_<UTC>/`; the source is never modified.
- 15 steps: selftest, demo, measure, R11 against v0.7.4 ("before"), R2–R11 against v0.7.5, and the supervisor probe for the declared numbers (parking at 45.1 %, curtailment at 26 %, AUD-03, HMAC).
- Output: PASS/FAIL per step, with full outputs in `repro_run_*/outputs/`. Exit code 0 means every step matched.
- Standard library only, loopback only. Takes about 5 minutes.

Reference runs:
- Supervisor (Claude), Linux, Python 3.13.18 — 2026-11-14 15:08 UTC — 15/15 PASS.
- Operator, macOS, Python 3.15.2 — 2026-11-14 15:16 UTC — 15/15 PASS.
- Supervisor, Linux, Python 3.13.18 — 2026-11-14 16:21 UTC — 15/15 PASS on the redacted public copy.

Code comments, probe output and some evidence files are in Portuguese (the working language of the study); the report and READMEs are in English.
