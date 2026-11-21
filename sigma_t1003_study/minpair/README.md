# minpair/ — Cross-backend minimal event pair (Elasticsearch), 2026-11-21

This folder answers a fair reviewer question about the sigma_t1003_study article: the SQLite false positive is interesting, but is it a SQLite quirk? This run tests the same v2/v3 rules **end-to-end on a second, real query engine** (Elasticsearch/Lucene), with engine and versions recorded per result.

Status: **execution-verified on two real engines**. Run date: 2026-11-21. Verification: independent (by Vibe, from the run artifacts in this folder), after independent baseline execution.

## What was tested

A minimal pair of 4 **synthetic** events (`minpair_events.json`), identical in every field except the path form of `CallTrace`:

| Event | CallTrace form | Role |
|---|---|---|
| E1_local_backslash | `C:\Program Files\Vendor\agent.dll+0x1234` | benign local path; MUST NOT alert on a correct rule — v2's tautology branch makes it alert (the false-positive mechanism) |
| E2_unc | `\\filesrv\metrics\agent.dll+0x1234` | same module content in UNC form; the intended target of the v2 bare value |
| E3_forward_slash | `C:/Program Files/Vendor/agent.dll+0x1234` | same module content with no backslash at all; control that isolates the backslash as the trigger |
| E4_downloads_true_positive | `C:\Users\dev\Downloads\agent.exe+0x1234` | user-writable path covered by an explicit pattern; MUST alert on both v2 and v3 |

## Result matrix (observed on both engines)

| Rule | E1 (benign local) | E2 (UNC) | E3 (control) | E4 (true positive) |
|---|---|---|---|---|
| v2 (SQLite 3.46.1 baseline + 3.54.1 Mac) | MATCH | MATCH | no | MATCH |
| v2 (Elasticsearch 7.17.4 / Lucene 8.11.1) | MATCH | MATCH | no | MATCH |
| v3 (SQLite, both) | no | no | no | MATCH |
| v3 (Elasticsearch) | no | no | no | MATCH |

The v2 always-true branch — a bare `'\\'` Sigma value collapsing to one backslash in pySigma's core parser — reopens the **same false positive end-to-end on a second, real query engine** (confirmed in both the query compiler output and the live index): Lucene compiles the bare value to `*\\*` ("contains one backslash"), which E1 satisfies and E3 (no backslash) does not. The v3 fix (remove the bare value) closes the false positive on both engines without losing the explicit-pattern true positive (E4). Pre-registered falsifiable alternative P4 (Lucene escaping prevents the tautology) was **REFUTED**: no cross-backend divergence was observed.

## Files

| File | Role |
|---|---|
| `PRE_REGISTRATION.md` | Pre-registered predictions PS1–PS3, P1–P4 + verdict rules, registered before any run; dated Amendment E-01 (two venvs / two compilers) appended before the Elasticsearch run (sha256 `371a2be8…`) |
| `minpair_events.json` | The 4 synthetic events (labeled as such; no real telemetry) |
| `RUNBOOK.md` | Operator's runbook as executed (in Portuguese, run language; kept verbatim) — two venvs, engine install, ingest, search, cleanup |
| `sqlite_baseline.py` / `results_sqlite_baseline.json` | Independent baseline: study's own compiled SQL executed verbatim on an in-memory SQLite database (stdlib only, sqlite3 3.46.1) — PS1–PS3 8/8 CONFIRMED |
| `minpair_sqlite_run.py` (v1.2, post-run revision) / `results_sqlite_mac.json` | SQLite side, study stack (pySigma 2.0.2), study compile recipe verbatim; compiled SQL identical to `../compiled_sql/` modulo the reference file's trailing newline (hash triple recorded); matrix MATCH. **Executed version: v1.1** (sha256 `a22612c2…`, hashed by the operator at run time, before the results; recorded in the verification dossier). v1.2 delta: identity-label taxonomy (see the `Fixes` docstring). See deviation 9. |
| `minpair_es_compile.py` (v1.2, post-run revision) / `results_es_compile.json` | Elastic side: Lucene compilation (no-pipeline variant consumed by the index; pipelined variant recorded), core-collapse check in pySigma 1.5.1, field cross-check. **Executed version: v1.1** (sha256 `43cc079e…`, same run-time hashing and record). v1.2 delta: bulk NDJSON generator interleave fix (see the `Fixes` docstring). See deviation 9. |
| `es_query_v2.json` / `es_query_v3.json` (+ `_pipelined`) | The exact request bodies run against the index |
| `es_mapping.json`, `es_bulk.ndjson`, `es_bulk_fixed.ndjson`, `es_bulk_response.txt`, `es_create_index.txt`, `es_count.txt` | Index setup and ingest (see Deviations: the buggy `es_bulk.ndjson` is kept as history; the run ingested with `es_bulk_fixed.ndjson`) |
| `es_results_raw.txt` | Raw search responses: v2 → E4, E1, E2 (3 hits, E3 absent); v3 → E4 only |
| `es_version.txt` | Engine version record (Elasticsearch 7.17.4 / Lucene 8.11.1, tar build 2022-05-18) |
| `freeze_sqlite_full.txt` / `freeze_es_full.txt` | Full `pip freeze` of both venvs |
| `hashes_run_2026-11-21.txt` | sha256 of 13 run artifacts, generated on the operator's Mac |

## Engines and stacks (recorded at run time)

| Side | Engine | Stack |
|---|---|---|
| SQLite | sqlite3 3.54.1 (host) | pySigma 2.0.2 · backend-sqlite 2.1.1 · pipeline-sysmon 3.0.0 · pipeline-windows 3.0.0 (study's stack) |
| Elastic | Elasticsearch 7.17.4 (tar, 2022-05-18) · Lucene 8.11.1 · Python 3.13.18 | pySigma 1.5.1 · backend-elasticsearch 2.1.1 · pipeline-sysmon 2.0.0 · pipeline-windows 2.0.1 (pip constraint: the backend requires pysigma<2.0.0 — dated Amendment E-01) |
| Collapse anchor | `SigmaString("\\\\").s == ['\\']` verified at runtime in BOTH compilers (2.0.2 and 1.5.1) | |

## Deviations and incidents (complete)

1. **es_bulk.ndjson generator bug**: the script emitted ONE bulk action line for all 4 documents; ES bulk requires one action line before EACH document. Caught mid-run; the ingest used `es_bulk_fixed.ndjson` (sha256 `9c32b775…`); the buggy artifact (`c8cab5c3…`) is kept and hashed as history. Generator fixed in minpair_es_compile.py v1.2.
2. **Elasticsearch 7.17.4 (2022) via brew tap** rather than a current 8.x line — accepted, evidence scoped per engine version.
3. `byte_identical_to_study_sql` label in the v1.1 output of results_sqlite_mac.json is superseded by the trailing-newline taxonomy (minpair_sqlite_run.py v1.2) — content identical, exact byte equality not claimed.
4. **Broken import in the v1.0 scripts** (written by the verifier model, Mistral Vibe; fixed before any valid result existed): `from sigma.rule import SigmaString` raises ImportError in both pySigma versions; correct location is `from sigma.types import SigmaString` (sha256 of v1.1 fixes: `a22612c2…` / `43cc079e…`; errata dated in the docstrings). Ruled an implementation bug, not a design change: PRE_REGISTRATION.md was NOT amended (hash unchanged, P1–P4 intact), per the same dated-errata discipline as E-01. Final scripts are v1.2.
5. **freeze_es_full.txt generated after the run**, from the same, unaltered Elastic venv (sha256 `9f3bd775…`, appended to hashes_run_2026-11-21.txt). No environment changes between run and freeze.
6. **OpenJDK 17 (brew) ran the Elasticsearch cluster**: the bundled JDK is Intel-only on this machine ("Bad CPU type"); the cluster ran with `-E xpack.ml.enabled=false`. This should not affect Lucene query semantics; recorded for reproducibility. *(Added 2026-11-21, after an independent second-opinion review.)*
7. **Pipeline asymmetry between sides**: the query executed against the index was the no-pipeline variant (`es_query_v2.json` / `es_query_v3.json`, no `Channel`/`EventID` clauses); the SQLite side ran the study's full pipelined SQL (`Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=10`). The `CallTrace` predicate under test is identical on both sides; the pipelined Lucene variants were compiled and recorded (`es_query_v*_pipelined.json`, `lucene_query_with_pipeline`) but not executed against the index. *(Added 2026-11-21.)*
8. **sqlite3 host version drift**: the operator's Mac ran sqlite3 3.54.1, the independent baseline 3.46.1; identical matrix on both (also disclosed in the result matrix and stack tables above). *(Added 2026-11-21.)*
9. **The executed script versions were overwritten in place** *(Added 2026-11-21, upon the executed-version question raised by an independent second-opinion review)*: the runs were produced by v1.1 of both scripts (sha256 `a22612c2…` / `43cc079e…`, hashed by the operator at run time, before the results — `byte_identical_to_study_sql` in results_sqlite_mac.json is v1.1 output); the post-run revisions that became v1.2 (identity-label taxonomy; bulk-generator interleave) were saved on top of the same filenames, so v1.1 survives by hash only. If a copy matching either hash is recovered, it will be published in a separate commit. Custody policy from now on: a new version gets a new file, never an in-place overwrite.

## What cannot be claimed (limits)

- One rule, one technique (T1003.001), two of many backends: demonstrated on SQLite and Elasticsearch/Lucene 8.11.1 ONLY (no Splunk, no KQL/EQL, no Elastic 8.x). Evidence scoped per backend+version.
- 4 synthetic events, labeled as such: no clean enterprise telemetry, no production FP-rate claim; 0 FP on this pair says nothing about production FP rates.
- The pip stack split (pySigma 2.0.2 vs 1.5.1, different pipeline versions) is a declared scoping condition (Amendment E-01); the mechanism under test (the core collapse) was verified identical at runtime in both compilers.
- Engine is a 2022 build (7.17.4); the Lucene term behavior is verified for Lucene 8.11.1.
- All synthetic events deliberately constructed for this pair; attacker-optimization, evasion and telemetry-noise behavior out of scope.

## Chain of custody

- Execution: local, by the operator; a second model guided the run step by step (commands dictated, outputs pasted back; no direct file access). Vibe verified independently from the custody artifacts. *(Provenance line added 2026-11-21.)*
- Version policy (from 2026-11-21): custody files are never modified in place; a new version is a new file. *(The v1.1 executed scripts predate this policy and were overwritten in place — see deviation 9.)*
- `hashes_run_2026-11-21.txt` (13 artifacts) generated on the operator's Mac; the Elasticsearch venv's full freeze was captured after the run, same venv, no changes (Deviation 5).
- Pre-registration (amended, `371a2be8…`) hashed in the telemetry of both run outputs; the pre-amendment hash (`f1e80010…`) is recorded in `results_sqlite_baseline.json` telemetry, which stays unamended.
- Supplementary sha256 (computed at packaging time, files with no operator-registered hash): `sqlite_baseline.py` `6f2d1980…`, `results_sqlite_baseline.json` `0e59df22…`, `es_create_index.txt` `9620fb61…`, `es_query_v2_pipelined.json` `7a57d472…`, `es_query_v3_pipelined.json` `15fb3d34…`, `hashes_run_2026-11-21.txt` `819ce4b0…`.
- Cross-check: all run artifacts were read directly from the operator's custody folder and reconciled against the pre-registration, the RUNBOOK, and the study's published compiled SQL.
