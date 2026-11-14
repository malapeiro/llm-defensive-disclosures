# Sunstrike — external detection (Suricata + Sigma)

Rules written against the frozen lab v0.7.5; nothing in the lab was changed. Predictions were fixed in `M3_PREVISOES.md` before any run. The official result is the supervisor's run 1 (`supervisor/M3_RUN1_OFICIAL.md`); later runs are complementary.

| Path | What it is |
|---|---|
| `sunstrike_m3.rules` | Suricata rules as delivered (run 1: 11 of 20 failed to load) |
| `sunstrike_m3_v0.1.1.rules` | syntax erratum E-M3-1 (`-> any (` → `-> any any (` on 11 lines); loads on Suricata 7.0.3 and 8.0.8 |
| `sigma/` | 18 Sigma rules over the lab's JSONL audit log (180/180 cells, 0 on the negative scenario) |
| `m3_cenarios.py`, `m3_captura.sh` | scenario generator (10 scenarios) and capture script |
| `referencia/` | reference pcaps, generator logs, evidence and `SHA256SUMS.txt` |
| `supervisor/` | the supervisor's evaluators and run reports |
| `README_M3.md`, `M3_PREVISOES.md` | builder's README and pre-registered predictions (Portuguese) |

**ATT&CK tags inside the rule files are the builder's provisional tags and several are wrong.** The verified mapping is the table in `../sunstrike_report.md` §3, which supersedes them. The rule files were left byte-identical to the versions that were run and hashed.
