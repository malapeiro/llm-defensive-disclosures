# Hydrostrike — HYDROBOX Lab

Defensive security research on European municipal water treatment and pumping
station (*Stacje Uzdatniania Wody* / ETA) HMI/SCADA sabotage campaigns
documented by Poland's ABW and CERT Polska (Tolkmicko, Małdyty, Szczytno,
Jabłonna Lacka, Sierakowo) and ANSSI / CERT-FR / ENISA advisories on exposed
industrial controllers. This directory reconstructs the publicly documented
sabotage class against a **synthetic water station controller (`HYDROBOX`)**
on loopback (`127.0.0.1`), and subjects both its streaming detector and
write-protecting guard proxy to four rounds of multi-model adversarial
probing (`v1.0 → v1.3.1`).

The full technical report — threat model, multi-auditor validation loop
(GLM 5.3 builder under PVTE-X + Gemini adversarial auditor + Claude
independent verifier), measured lab results, and the explicit Section 7
**"What cannot be claimed"** disclosures — is in
[`hydrostrike_report.md`](hydrostrike_report.md).

## Notice

Notice. This repository is independent defensive research based exclusively on
public sources (ABW, CERT Polska/CSIRT NASK, ANSSI, CERT-FR, ENISA). The
emulation code does not reproduce any vendor endpoint, industrial protocol,
firmware path, password algorithm, or CVE exploit chain; it operates only
against the synthetic controller defined in this repository, on loopback
(`127.0.0.1`; the attack module refuses any non-loopback target with
`ScopeError`). It cannot be used against real equipment and adds no capability
to anyone seeking to do so. The purpose is detection engineering and hardening,
not offense.

## What is in this directory

- [`hydrostrike_lab.py`](hydrostrike_lab.py) — the lab (`v1.3.1`, `1,745 lines`
  on disk, SHA-256 `d55c324f2876256746c7289865e3c3a6cc0824a2e57df0d536e77c351a6f3072`;
  GLM sandbox `1,770 lines`, SHA-256 `7287caef46de7a2d4713d9837de24da746a04e91e59f6cc127cd041292539089`):
  a synthetic water treatment/pumping controller (`HYDROBOX`), a loopback-only
  adversary-emulation module (`H1` default credentials, `H2` predictable daily
  service code), a streaming detection engine (`Detector`), a write-protecting
  guard proxy (`GuardHandler`) sharing a single request canonicalizer
  (`canonicalize_request`) and atomic controller-side hydraulic interlocks, and
  `rule_liveness_check()` (`15/15` rules in `RULE_ATTACK_MAP` reachable in
  `Detector.scan`). 100% Python 3 standard library.
- [`hydrostrike_report.md`](hydrostrike_report.md) — the full technical report.
- [`audit_probes_v1.py`](audit_probes_v1.py),
  [`audit_probes_v2.py`](audit_probes_v2.py),
  [`audit_probes_v3.py`](audit_probes_v3.py) — the adversarial probe
  batteries (Probes `P1–P13B` + independent verification `Additions A–D`)
  executed across `v1.0 → v1.3.1`.
- [`detections/`](detections/README.md) — reference Sigma, Suricata, and
  Microsoft Sentinel KQL rules (Suricata **execution-verified**; Sigma and KQL
  **textual compliance**).

## How to run

```bash
python3 hydrostrike_lab.py demo                    # full autonomous demo: H1, H2, NEG (with valve isolation), GUARD (7/7 checks)
python3 hydrostrike_lab.py serve                   # controller on 127.0.0.1:8600 (atomic interlocks ON)
python3 hydrostrike_lab.py attack --variant h1     # adversary emulation (refuses non-loopback targets)
python3 hydrostrike_lab.py guard                   # prevention proxy on 127.0.0.1:8605 -> upstream 8600
python3 audit_probes_v1.py                         # Round 1 adversarial probes (P1–P5)
python3 audit_probes_v2.py                         # Round 2 adversarial probes (P6, P7A, P7B, P8)
python3 audit_probes_v3.py                         # Round 3 + v1.3.1 probes (P9–P12B, Additions A–D, P13A/13B)
```

## Execution-verified vs textual compliance

The Python controller, streaming detection engine, guard proxy, and the three
adversarial probe scripts **were executed** in isolated sandboxes (`v1.3.1` full
regression: `H1/H2` 17 CRIT / 9 WARN, `NEG` 0 alerts including legitimate
pump-stop valve isolation, `GUARD` 9 blocks / 0 controller alerts, `15/15` rules
in `RULE_ATTACK_MAP` verified reachable by `rule_liveness_check()`, plus all
probes `P1–P13B` and `Additions A–D` passing).

The Suricata rules in `detections/suricata/` **were executed** against Suricata
8.0.8 by replaying pcaps of the lab (17/17 alerts on the attack chain, 0 in the
negative case). That run exposed a trailing-byte evasion of two signatures,
fixed in rev 2, and a wider request-line tokenisation gap, fixed in the next
revisions with one new signature (a 446-request matrix, checked per request,
found one more gap in it); see [`detections/suricata/verification/`](detections/suricata/verification/README.md).

The Sigma and KQL rules in [`detections/`](detections/README.md) are **textual
compliance**: they are written against the lab audit schema and public log
conventions, but were **not** executed against Sigma or Microsoft Sentinel engines. Validate them against your own pipeline before
production use.

## What cannot be claimed (summary — see Section 7 of the report)

- **Operational false positive on heavy maintenance:** The `2 backwashes / 24h`
  ceiling stops the 61-minute patient attacker (`Probe 11`), but blocks
  legitimate maintenance of 3+ filters on the same day. A rate limit cannot, by
  construction, distinguish a patient attacker from a busy technician — only
  work-order/ticket authorization can.
- **Cartoon physics:** `pressure = setpoint` and fixed `-12% / -0.4 bar`
  backwash steps are arithmetic, not a hydraulic model (no head-loss curves, no
  inertia, no PID).
- **`MTTD = 0.000 s` is a clock artifact:** Timestamps have 1-second resolution
  (`%Y-%m-%d %H:%M:%S`), so sub-second local file polling yields `0.000 s`.
- **Silent rule deletion (`D-CHLORINE-OUT-OF-BAND`) & the exact scope of `rule_liveness_check()`:**
  `D-CHLORINE-OUT-OF-BAND` fired in `v1.0`, was silently deleted from `Detector.scan`
  in `v1.1`, and survived 3 versions (`v1.1–v1.3`) with `100% PASS` tests before
  being caught in packaging review and restored in `v1.3.1` (`Probe 13A/13B`).
  The resulting `rule_liveness_check()` is strictly an **invariant that prevents
  a rule in `RULE_ATTACK_MAP` from being removed or rendered unreachable in
  `Detector.scan` (closing the `RULE_ATTACK_MAP ↔ scan` link)**; because it feeds
  self-referential synthetic events, it does **not** guard the `controller ↔ scan`
  link and is never proof that all detections work against real telemetry.
- **Loopback HTTP toy, zero real ICS protocols:** Uses an invented JSON API over
  HTTP (`127.0.0.1`), not `Modbus`, `DNP3`, `IEC-104`, or `S7comm`. It
  demonstrates the adversarial detection-engineering method, not plant
  readiness.
- **Verifier & taxonomy disclosures:** One independent verifier prediction
  (`safety_interlocks` API exposure) was falsified on inspection (it is a
  constructor-only parameter), and LLM-generated ATT&CK labels (`T0879`
  mislabeled `"Damage"` in `v1.0–v1.3`, corrected to `"Damage to Property"` in
  `v1.3.1`) require human review. Read [Section 7 of `hydrostrike_report.md`](hydrostrike_report.md#7-what-cannot-be-claimed-explicit-limitations)
  before citing any number from this directory.

## Licenses

- Code (`hydrostrike_lab.py`, `audit_probes_v1.py`, `audit_probes_v2.py`,
  `audit_probes_v3.py`, `detections/`): Apache-2.0 — see [`LICENSE`](LICENSE).
- Report and documentation (`hydrostrike_report.md`, this file,
  `detections/README.md`): CC BY-NC-SA 4.0 — see
  [`LICENSE-docs`](LICENSE-docs).
