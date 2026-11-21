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

## Upstream follow-up (status as of 2026-11-16)

The escaping finding was reported upstream as a validator suggestion, not as a bug: the collapse of `'\\'` to one literal backslash is intended Sigma behavior.

- **[SigmaHQ/pySigma#615](https://github.com/SigmaHQ/pySigma/issues/615)** — issue opened 2026-11-09 proposing a validator for `contains` values that reduce to a lone backslash. Open.
- **[SigmaHQ/pySigma#617](https://github.com/SigmaHQ/pySigma/pull/617)** — pull request by another contributor implementing a `TautologicalValueValidator`. After review discussion the single-separator check was limited to `contains`; empty values are flagged for `contains`, `startswith` and `endswith`. Open, awaiting maintainer review.
- **[SigmaHQ/sigma#6596](https://github.com/SigmaHQ/sigma/issues/6596) / [#6597](https://github.com/SigmaHQ/sigma/pull/6597)** — issue and proposed fix for an official rule in which that validator found an empty `contains` value turning a filter into a catch-all. Open.
- Short write-up of the case: [I asked an LLM to harden a real SigmaHQ rule. Its self-test said 19/19 PASS. The real compiler said otherwise.](https://dev.to/malapeiro/i-asked-an-llm-to-harden-a-real-sigmahq-rule-its-self-test-said-1919-pass-the-real-compiler-said-3gga)

What can and cannot be claimed: nothing above is merged. The validator and the rule fix are third-party work; this study's contribution is the finding, the report and the review comments on #617. The minimal repro (`'\\'` under `contains` compiling to `LIKE '%\\%' ESCAPE '\'`) was re-run on pySigma 2.0.3 and 2.1.0 with the same result; the full corpus evaluation in this directory was run on 2.0.2 only.

## What is in this directory

- [`sigma_t1003_report.md`](sigma_t1003_report.md) — full technical report.
- [`evaluate_sigma.py`](evaluate_sigma.py) — deterministic `pySigma` + `SQLite` evaluation harness with programmatic 15-file oracle exhaustiveness verification (`verify_oracle_exhaustiveness`) and individual `selection_*` / `filter_*` block evaluation.
- [`rules/`](rules/) — the four Sigma rule versions (`v0` official baseline, `v1`, `v2`, `v3`).
- [`compiled_sql/`](compiled_sql/) — exact SQL queries compiled by `pySigma 2.0.2` (`sqliteBackend 2.1.1` + `sysmon 3.0.0` + `windows 3.0.0`), including the smoking-gun [`v2_compiled.sql`](compiled_sql/v2_compiled.sql).
- [`results/`](results/) — full JSON evaluation outputs (`v0_eval.json` – `v3_eval.json`) containing rule-level and block-level activation matrices across the 725-file corpus.
- [`minpair/`](minpair/) — cross-backend minimal event pair follow-up (2026-11-21): the v2 always-true branch and the v3 fix re-tested end-to-end on a second real engine (Elasticsearch/Lucene), with pre-registration, run artifacts and hashes.

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
2. **Parser-level cause, backend-scoped proof:** `SigmaString("\\\\").s == ['\\']` occurs in `pySigma`'s core string parser (affecting all `pySigma` backends), but the end-to-end reopening of the two false positives was executed and proven only on `pysigma-backend-sqlite 2.1.1`. *(Update 2026-11-21: the end-to-end reopening has since been executed and confirmed on a second real backend — Elasticsearch 7.17.4 / Lucene 8.11.1 — via a minimal event pair with pre-registered predictions; see [`minpair/`](minpair/) and the update section below. Still two of many backends: no Splunk, KQL/EQL or Elastic 8.x.)*
3. **Un-exercised `SourceUser` filter:** `SourceUser` is `NULL` in 13/15 `lsass`-touching files (captures predate `SourceUser` in Sysmon EID 10), so `filter_main_system_user` is largely un-exercised.
4. **Under-powered false-positive corpus:** Negative files are other attack samples, not enterprise administrative/EDR/AV telemetry. `0/710` outside the `lsass` set does not prove production false-positive readiness.
5. **Technique-scoping vs. benign FP:** `CommandLineEventConsumer` (`python27` WMI persistence) is a clean false positive for credential dumping; `discovery_meterpreter_ps_cmd_process_listing` (`T1057`) is malicious process enumeration misattributed to credential dumping (`T1003.001`).
6. **Constructive conclusion:** Shown the real `pySigma` SQL in Round 3, the builder diagnosed its own escaping defect, switched from its ad-hoc evaluator to `sqliteBackend`, caught its own silent edit failure, and converged to `0 FP` in `v3`.

## Update 2026-11-21 — cross-backend minimal pair (Elasticsearch)

A fair reviewer question (DEV Community, 16 Nov 2026): the v2 false positive is interesting, but is it a SQLite quirk? To answer it, a **minimal event pair** of 4 synthetic events — identical in every field except the path form of `CallTrace` — was run through the same `v2`/`v3` rules **end-to-end on a second, real query engine** (Elasticsearch 7.17.4 / Lucene 8.11.1, compiled live with `pySigma-backend-elasticsearch 2.1.1`), with a pre-registration written before any run and engine + stack versions recorded per result. Evidence, deviations and chain of custody: [`minpair/`](minpair/).

| Rule → event | E1 benign local path | E2 UNC path | E3 forward-slash control | E4 true positive (Downloads) |
|---|---|---|---|---|
| v2 on SQLite (study stack; 3.46.1 baseline + 3.54.1 re-run) | MATCH | MATCH | no match | MATCH |
| v2 on Elasticsearch/Lucene | MATCH | MATCH | no match | MATCH |
| v3 on SQLite | no match | no match | no match | MATCH |
| v3 on Elasticsearch | no match | no match | no match | MATCH |

The v2 always-true branch — the bare `'\\'` Sigma value collapsing to one backslash in pySigma's core parser — compiled to `*\\*` in Lucene ("contains one backslash"), so the same false positive (E1, a benign local path that MUST NOT alert) reopens end-to-end on the second engine, while the no-backslash control (E3) stays clean and the v3 fix (remove the bare value) closes it on both engines without losing the explicit-pattern true positive (E4). The pre-registered falsifiable alternative — Lucene escaping preventing the tautology — was refuted: no cross-backend divergence was observed. Scoping declared: pySigma 1.5.1 on the Elastic side (pip constraint, dated pre-registration amendment), core collapse verified identical at runtime in both compilers (2.0.2 and 1.5.1); synthetic events only, no production FP-rate claim.

## Licenses

- Code and rule evaluations (`evaluate_sigma.py`, `compiled_sql/`, `results/`): Apache-2.0 — see [`LICENSE`](LICENSE) (upstream SigmaHQ rule `v0` and derivatives `v1–v3` carry SigmaHQ's DRL 1.1 license).
- Report and documentation (`sigma_t1003_report.md`, this file): CC BY-NC-SA 4.0 — see [`LICENSE-docs`](LICENSE-docs).
