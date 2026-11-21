# PRE-REGISTRATION — sigma_t1003_study minimal event pair, cross-backend
Date: 2026-11-21 (registered by Vibe, this session, BEFORE any run of this pair)

## Purpose
Answer the DEV Community reviewer's point on the sigma_t1003_study article: demonstrate (or refute) that the v2 rule's always-true branch (`CallTrace LIKE '%\\%' ESCAPE '\'`, from the bare `'\\'` Sigma value collapsing to one backslash in pySigma's core parser) reopens the same false positive END-TO-END on a second, real query engine — not only on SQLite. Minimal pair: 4 synthetic events identical except the path form of CallTrace (see minpair_events.json).

Engines, both real: SQLite (baseline, study's own compiled SQL) and Elasticsearch (Lucene query_string, compiled live on the operator's Mac; engine local to the Mac, loopback only). pySigma is NOT installed in the preparing environment (sandbox forbids pip); compilation happens on the operator's Mac, versions recorded at run time.

## Pre-registered predictions

### SQLite baseline (executed here with the study's own v2_compiled.sql / v3_compiled.sql)
- PS1: v2 matches E1_local_backslash (false positive via the `LIKE '%\\%' ESCAPE '\'` branch).
- PS2: v2 matches E2_unc and E4_downloads; v2 does NOT match E3_forward_slash (no backslash -> tautology branch inert -> mechanism isolated).
- PS3: v3 matches only E4_downloads. v3 does NOT match E1 (fix confirmed), NOT E2 (declared trade-off in the v3 rule description), NOT E3.

### Elasticsearch / Lucene (second backend, executed on the operator's Mac)
- P1: pySigma-backend-elasticsearch compiles the bare `'\\'` value to a wildcard pattern that requires at most one literal backslash (e.g. `*\\*` in query_string escaping), i.e. the collapse is inherited through pySigma core (already verified in runtime: SigmaString('\\').s == ['\\']) and the backend does not re-widen it into a two-backslash requirement.
- P2: end-to-end on Elastic, v2 matches E1_local_backslash — same false positive reopens. v2 does not match E3.
- P3: v3 matches only E4 on Elastic.
- P4 (falsifiable alternative, would be a NEW finding if it happens): Elastic/Lucene escaping makes the bare-value branch require `\\` or behave otherwise -> v2 does NOT match E1 on Elastic. Then the cross-backend divergence is real and becomes the headline: same rule, same parser, different producer languages, different detection outcome.

## Verdict rules (registered before runs)
- MATCH = engine returns the event row (SQL) / hit (ES, query at face value over the 4-doc index).
- Any surprise not covered by P1–P4 -> recorded as-is, no re-run without errata; discrepancies between prediction and result reported, never smoothed.
- Backend + plugin + engine versions recorded at run time; evidence scoped per backend version.

---

## EMENDA E-01 (datada) — divisão em dois venvs / dois compiladores — 2026-11-21

Registered BEFORE any Elasticsearch run (no ES execution has occurred at the date of this amendment).

**Cause (empirical, operator's Mac, 2026-11-21):** pip resolution impossibility — every version of `pysigma-backend-elasticsearch` (0.1.0 through 2.1.1) constrains `pysigma<2.0.0`, so the study's SQLite stack (pySigma 2.0.2) cannot coexist with the Elasticsearch backend in one environment.

**Split registered:**
- **SQLite side** (`freeze_sqlite.txt`): pySigma 2.0.2 / pysigma-backend-sqlite 2.1.1 / pysigma-pipeline-sysmon 3.0.0 / pysigma-pipeline-windows 3.0.0 — identical to the study's stack (`evaluate_sigma.py` header); compile recipe reproduced verbatim (`sysmon_pipeline() + windows_logsource_pipeline()`); byte-identity of the compiled SQL vs `v2_compiled.sql`/`v3_compiled.sql` is asserted by the script.
- **Elastic side** (`freeze_es.txt`): pySigma 1.5.1 / pysigma-backend-elasticsearch 2.1.1 / pysigma-pipeline-sysmon 2.0.0 / pysigma-pipeline-windows 2.0.1 — latest combination pip resolves under `pysigma<2.0.0`; **compiler version differs from the study's; declared**.

**Runtime anchors recorded at split (operator's Mac):** `SigmaString("\\").s == ['\\']` verified in BOTH compilers (2.0.2 and 1.5.1). The collapse — the mechanism under test — is identical across the two versions; the version split changes the pipeline/compilation surface, not the parsed pattern. Cross-version difference is therefore declared as a scoping condition, not treated as a confounder of P1–P4, which remain UNCHANGED (per operator instruction): predictions now read as "on the declared stacks above".

**Environment errata registered in the same amendment:**
1. RUNBOOK Errata 1: original Passo 1 omitted `pysigma-pipeline-sysmon` / `pysigma-pipeline-windows`; without them the SQLite-side compile is not byte-identical to the study. Fixed RUNBOOK + scripts require them.
2. Environment Errata 2: Python 3.15 does not compile `google-re2` (transitive dependency of the pysigma stack); all venvs use Python 3.13.18 — recorded, affects both sides equally.
3. `minpair_mac_run.py` (single-venv design) is SUPERSEDED and removed; replaced by `minpair_sqlite_run.py` (SQLite venv) and `minpair_es_compile.py` (Elastic venv).

**Chain of custody of this file:** the sha256 of this file before the amendment was `f1e80010f8c00d11111b3921069ef7974e872a34a6ed210e3c9708ce561c72e1` (recorded in `results_sqlite_baseline.json` telemetry, which stays unamended); the amended file's hash is recomputed and recorded by both run scripts at run time.
