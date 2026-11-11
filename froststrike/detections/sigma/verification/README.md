# Sigma rules — execution check against the lab audit log

Status: the two audit-log Sigma rules of this lab are **execution-verified** against the
lab's own audit log, compiled by pySigma and run in SQLite. The webserver-category rule
(`web_offhours_ot_config.yaml`) is only compiled: the lab does not emit a webserver log, so it stays
**textual compliance**. The KQL queries are not covered here.

This is a check of the rules against the synthetic FROSTBOX audit schema. It says nothing
about a production SIEM, its field mapping or its pipeline.

## Method

1. **Fixtures.** `fixtures/h1.jsonl`, `h2.jsonl` and `negative.jsonl` are the audit logs
   written by `froststrike_lab.py demo`. `fixtures/branches.jsonl` comes from a short loopback
   session against a fresh server: twelve setpoint writes (both directions out of band, in band, and the four band edges and their
nearest outside values), one failed service-code attempt and one failed login.
   `fixtures/manifest.txt` pins the lab file and the four fixtures by sha256; the replay
   fails closed when they no longer match.
2. **Engine.** Each rule is compiled with `pysigma-backend-sqlite` and the SQL is run on an
   in-memory SQLite table holding one fixture. The compiled SQL is in `compiled_sql/`.
3. **Expectation.** The match counts per rule and fixture, and per selection, were written
   in `verify_sigma.py` before the first run.
4. **Oracle.** The matched rows are also compared, row by row, with a predicate written in
   plain Python from the rule's description. It was written by the same hand as the
   expectations, so it is a second reading of the rule, not an independent ground truth.
5. **Mutation.** `verify_sigma.py --mutation` breaks one selection at a time (the value of its
   first field) and confirms that the check then fails.

## Recorded run

Linux x86_64, Python 3.13.18, pySigma 2.1.0, pysigma-backend-sqlite 2.1.1, SQLite 3.53.1,
2026-11-11, repository at commit `d4c9ef8`. Fixtures captured in the same environment
(21, 21, 3 and 15 events). Not run on the macOS environment of the Suricata check.

| Rule | h1 | h2 | negative | branches |
|---|---|---|---|---|
| `frostbox_service_auth.yaml` | 0 | 1 | 0 | 0 |
| `frostbox_setpoint_band.yaml` | 6 | 6 | 0 | 6 |

Per selection of `frostbox_setpoint_band.yaml`, over all fixtures: `freezer_too_high` 7,
`freezer_too_low` 2, `chilled_too_high` 7, `chilled_too_low` 2. The demo only pushes
setpoints up (+50 C), so the two `too_low` selections are exercised by the branches fixture
alone. That fixture also holds the band edges: -15, -30, 6 and 0 do not match; -14.9, -30.1,
6.1 and -0.1 do. A failed service-code attempt and a failed login are in it as well and match
nothing.

All counts equal the expectation, the oracle agrees row by row, and every mutation of an
exercised selection is caught. All expectations were met on the first run of the rules.

## Limits

- **Synthetic schema.** The rules are run against the field names the lab emits. A real
  forwarder renames and retypes fields; map them and re-run.
- **One backend.** pySigma's SQLite backend only. String matches compile to `LIKE`, which is
  case-insensitive in SQLite; other backends may differ.
- **Small fixtures.** Tens of events per fixture, from one attack chain, one benign session
  and one branch session. No volume, no noise, no time-window logic.
- **Webserver rule and KQL.** Not executed (see Status).

## Reproduce

```bash
pip install pysigma pysigma-backend-sqlite
python3 verify_sigma.py             # replay the committed fixtures
python3 verify_sigma.py --mutation
python3 verify_sigma.py --capture   # regenerate the fixtures from the lab (stdlib, loopback)
```

## Who did what

Claude wrote the harness, the expectations, the oracle and the branch session, captured the
fixtures and ran the check. The author reviewed the result. Qwen's first review suggested
promoting the Sigma rules with the pySigma harness already used in `sigma_t1003_study/`.
A first version of the harness built one table per fixture and failed with a missing column
on a fixture that lacked a field; it now uses one schema for all fixtures. That was a harness
defect, not a rule finding.
