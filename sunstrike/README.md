# Sunstrike

Remote-command abuse against a synthetic fleet of hybrid solar inverters with batteries, and the resilience of households during a night blackout — built, attacked and verified with LLMs. Full report: [`sunstrike_report.md`](sunstrike_report.md).

**Verification level:** execution-verified (lab v0.7.5 sealed `5162964f…`, public copy `cf9fbe3e…` — see [`REDACTIONS.md`](REDACTIONS.md); detector with 26 rules, guard proxy, probe batteries R2–R11, reproduction package 15/15 on Linux and macOS, audit-log Sigma rules 180/180, Suricata rules on 7.0.3 and 8.0.8 after a dated syntax erratum). KQL: not produced.

## Contents

| Path | What it is |
|---|---|
| `sunstrike_report.md` | the case study |
| `v0.7.5/sunstrike_lab.py` | final lab (single file, standard library, loopback only) |
| `v0.7.5/sunstrike_lab_pre_r11_fixes.py` | the preserved v0.7.4 lab, the "before" target of probe R11 (see `REDACTIONS.md`) |
| `v0.7.5/sunstrike_probes_r*.py` | probe batteries with pre-registered predictions |
| `pacote_reproducao/` | one-command reproduction of every number (15 steps) |
| `m3/` | Suricata and Sigma rules, scenario generator, predictions, reference pcaps and verification (see `m3/README.md`) |
| `v0.7.5/*.txt` | outputs of the official probe runs, demo and measure |
| `REDACTIONS.md` | the only differences between these files and the sealed study files |
| `LICENSE`, `LICENSE-docs` | Apache-2.0 for code, CC BY-NC-SA 4.0 for documents |

## Run

```sh
python3 -I v0.7.5/sunstrike_lab.py selftest
python3 -I v0.7.5/sunstrike_lab.py demo
python3 -I pacote_reproducao/reproduzir_sunstrike.py v0.7.5
```

Loopback only; the lab refuses any non-loopback target (`ScopeError`). Synthetic devices only — nothing here reproduces a real vendor's cloud, protocol or firmware.
