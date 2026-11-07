# Sigma T1003.001 Hardening Study

Execution-verified case study on **LLM self-validation blindness and parser-semantic differentials** in detection engineering. Unlike synthetic-telemetry labs, every rule version in this directory (`v0 → v1 → v2 → v3`) is evaluated against an **external ground truth**: official SigmaHQ rule [`proc_access_win_lsass_memdump.yml`](rules/proc_access_win_lsass_memdump_v0.yml) (`5ef9853e-4d0e-4a70-846f-a9ca37d876da`, MITRE ATT&CK `T1003.001` — OS Credential Dumping: LSASS Memory), compiled by the production **`pySigma 2.0.2` (`pysigma-backend-sqlite 2.1.1`)** engine and executed against **725 real `.evtx` files (`37,841` Windows events)** from [`EVTX-ATTACK-SAMPLES`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) and [`SigmaHQ regression_data`](https://github.com/SigmaHQ/sigma/tree/master/regression_data/rules/windows).

The full technical report — including the cross-study introduction connecting this work to [`hydrostrike`](../hydrostrike/hydrostrike_report.md), the round-by-round trajectory, the `7 → 7 → 2` selection-level activation matrix, and the explicit Section 7 **"Limitations and epistemic boundaries"** — is in [`sigma_t1003_report.md`](sigma_t1003_report.md).

## Key Finding in 30 Seconds

Asked in Round 2 (`v1 → v2`) to close two false positives (`0x1410` process listing and WMI `python.exe` consumer) without losing 7 `TP`s or 4 `FN`s, the builder LLM (GLM 5.3) added a `CallTrace|contains` allowlist of untrusted folders to [`proc_access_win_lsass_memdump_v2.yml`](rules/proc_access_win_lsass_memdump_v2.yml), ending with `- '\\'` (intended to match UNC paths `\\server\share`).
- The rule passed **`sigma check` (`0 errors`)**.
- The rule passed **the builder's own self-test harness (`19/19 PASS`, claiming both false positives were closed)** because the builder evaluated the YAML in raw Python (`'\\\\' in call_trace`).
- **In the real `pySigma` compiler (`sigma.types.SigmaString`), `SigmaString("\\\\").s == ['\\']` collapses `- '\\'` to a single literal backslash `\`.** In `pysigma-backend-sqlite 2.1.1` ([`compiled_sql/v2_compiled.sql`](compiled_sql/v2_compiled.sql)), this compiles to:
  ```sql
  OR CallTrace LIKE '%\\%' ESCAPE '\'
  ```
  — a **100% tautology across all Windows paths** that short-circuited all six preceding `CallTrace` folder restrictions and silently reopened **both** false positives (`selection_lowaccess_untrusted_path` file count stayed stuck at `7 → 7` from `v1` to `v2`, before dropping to `2` in `v3` once `- '\\'` was removed after the builder was shown the compiled SQL).

## What is in this directory

- [`sigma_t1003_report.md`](sigma_t1003_report.md) — full technical report.
- [`evaluate_sigma.py`](evaluate_sigma.py) — deterministic `pySigma` + `SQLite` evaluation harness with programmatic 15-file oracle exhaustiveness verification (`verify_oracle_exhaustiveness`) and individual `selection_*` / `filter_*` block evaluation.
- [`rules/`](rules/) — the four Sigma rule versions (`v0` official baseline, `v1`, `v2`, `v3`).
- [`compiled_sql/`](compiled_sql/) — exact SQL queries compiled by `pySigma 2.0.2` (`sqliteBackend 2.1.1` + `sysmon 3.0.0` + `windows 3.0.0`), including the smoking-gun [`v2_compiled.sql`](compiled_sql/v2_compiled.sql).
- [`results/`](results/) — full JSON evaluation outputs (`v0_eval.json` – `v3_eval.json`) containing rule-level and block-level activation matrices across the 725-file corpus.

## How to run

```bash
# Evaluate all four versions (v0 -> v1 -> v2 -> v3) and regenerate compiled_sql/ and results/
python3 evaluate_sigma.py --all-versions \
    --db ./evtx_corpus.db \
    --evtx-attack-dir ./EVTX-ATTACK-SAMPLES \
    --sigma-reg-dir ./sigma/regression_data/rules/windows

# Evaluate a single Sigma rule YAML
python3 evaluate_sigma.py --rule rules/proc_access_win_lsass_memdump_v3.yml
```

## Limitations summary (see Section 7 of the report)

1. **Narrow demonstrated scope:** 1 rule (`proc_access_win_lsass_memdump`), 1 technique (`T1003.001`), 1 backend (`pySigma` → `SQLite`), and 725 `.evtx` files (15 touching `lsass.exe` via Sysmon EventID 10). Demonstrates one concrete instance of self-test blindness, not a universal law.
2. **Parser-level cause, backend-scoped proof:** `SigmaString("\\\\").s == ['\\']` occurs in `pySigma`'s core string parser (affecting all `pySigma` backends), but the end-to-end reopening of the two false positives was executed and proven only on `pysigma-backend-sqlite 2.1.1`.
3. **Un-exercised `SourceUser` filter:** `SourceUser` is `NULL` in 13/15 `lsass`-touching files (captures predate `SourceUser` in Sysmon EID 10), so `filter_main_system_user` is largely un-exercised.
4. **Under-powered false-positive corpus:** Negative files are other attack samples, not enterprise administrative/EDR/AV telemetry. `0/710` outside the `lsass` set does not prove production false-positive readiness.
5. **Technique-scoping vs. benign FP:** `CommandLineEventConsumer` (`python27` WMI persistence) is a clean false positive for credential dumping; `discovery_meterpreter_ps_cmd_process_listing` (`T1057`) is malicious process enumeration misattributed to credential dumping (`T1003.001`).
6. **Constructive conclusion:** Shown the real `pySigma` SQL in Round 3, the builder diagnosed its own escaping defect, switched from its ad-hoc evaluator to `sqliteBackend`, caught its own silent edit failure, and converged to `0 FP` in `v3`.

## Licenses

- Code and rule evaluations (`evaluate_sigma.py`, `compiled_sql/`, `results/`): Apache-2.0 — see [`LICENSE`](LICENSE) (upstream SigmaHQ rule `v0` and derivatives `v1–v3` carry SigmaHQ's DRL 1.1 license).
- Report and documentation (`sigma_t1003_report.md`, this file): CC BY-NC-SA 4.0 — see [`LICENSE-docs`](LICENSE-docs).
