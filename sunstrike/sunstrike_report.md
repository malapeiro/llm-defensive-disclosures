# Sunstrike

## Remote-Command Abuse Against Hybrid Solar Inverters During a Blackout — and What an LLM-Built Defense Can and Cannot Claim

**Author:** Sérgio Azevedo (`malapeiro`) · **Date:** 2026-11-14 · **Artifact class:** execution-verified (synthetic loopback lab, detector, guard proxy, probe batteries R2–R11, reproduction package, audit-log Sigma rules, Suricata rules after a dated syntax erratum) / textual compliance (none claimed for KQL — not produced)
**Final lab:** `sunstrike_lab.py` v0.7.5 — sha256 `5162964f2df283fd6ed0a1a4d53f8b3650f491b4892e24abb198494b7abcb441` (6913 lines, 26 detection rules). Code frozen on 2026-11-14. The published copy differs only in two header lines and has sha256 `cf9fbe3e…86f8`; see `REDACTIONS.md`.

Notice. Independent defensive research based on public reporting. The lab emulates a fleet of **synthetic** hybrid inverters (`SUNBOX`) on loopback only (`127.0.0.1`; non-loopback targets are refused with `ScopeError`). It reproduces no vendor cloud, endpoint, protocol, firmware format or credential scheme, and cannot be used against real equipment.

---

## 1. Executive summary

Hybrid inverters with batteries are what keeps a house lit when the grid goes down — and they are also remotely commandable by the manufacturer's cloud. Sunstrike asks a narrow question: **if that cloud channel is abused, how much household resilience survives a night blackout, and can an LLM-built defense detect and limit the damage?**

The case was built over 12 versions (`v0.1 → v0.7.5`) by an LLM builder, attacked by an LLM auditor in ten blind audits, and verified by execution by an independent LLM supervisor, with the human operator running every key number again on his own machine.

**Headline findings**

1. **"The fix created the hole."** The `v0.7.4` round fixed every finding it was given — and its own verification passed (`selftest`, `demo 9/9`, `measure 51/51`, `R10 29/29`). A fresh blind audit then showed two new evasions that `v0.7.3` did **not** have: (a) the mass-shutdown rule began tracking the *number* of simultaneously-off inverters instead of their *capacity*, so switching off the five largest inverters (58.2 % of fleet kWp) after cycling the five smallest produced **zero alerts** (`v0.7.3`: CRIT); (b) the slow-wave rule was anchored on the first event, so one early shutdown followed by a paced wave an hour later went **unalerted** (`v0.7.3`: CRIT). The second regression was caused by the **supervisor's own specification**. Both were proven against `v0.7.3` and fixed in `v0.7.5` with logic-only changes (no threshold touched).
2. **"The defense was only measured where it could not fail."** The first resilience metric (`v0.4`) attacked the fleet *during* the blackout — where an emergency interlock blocks remote commands by construction — and reported 12/12 households served. An attacker who drains the batteries *before* the blackout, in slices below every alert, left the defended fleet at **0/12, identical to no defense**. Measuring the right attacker changed the design (§6).
3. **"A work order issued through the compromised channel cannot be a trust anchor."** Several defenses exempted commands carrying a valid maintenance work order. Because the work order arrives through the same cloud channel the attacker controls, exemptions became evasion routes; the final design counts work-order and no-work-order actions together for mass rules.
4. **Detection-as-code: the LLM was right where it could see the fields, wrong where it had to imagine the wire.** All 18 audit-log Sigma rules matched their pre-registered predictions (**180/180 cells**, legitimate scenario = 0). Of 20 Suricata rules, **11 did not load** in Suricata 7.0.3 or 8.0.8 (missing destination port); after a syntax-only erratum all loaded, but predictions still missed a proxied hop that doubles counts on loopback and a lockout response that never reaches the wire.
5. **Thresholds are a game an informed attacker wins.** Parking the batteries at 45.1 % (just above the new alarm) or curtailing exports to 25.01 % (just above the mass threshold) produces no alert. These are declared, with numbers, rather than chased (§9).

---

## 2. Threat context

- **Manufacturer remote shutdown is not hypothetical.** In November 2024, Deye-branded hybrid inverters in the US and several other countries stopped operating and displayed a region warning, in the context of a distribution dispute with Sol-Ark; Deye told heise it had not remotely controlled the devices ([heise, 2024-11-30](https://heise.de/-10183716); [Born City, 2024-11-28](https://borncity.com/win/2024/11/28/deye-deactivates-solar-inverters-in-usa-uk-and-pakistan/)).
- **Undocumented communication paths.** In May 2025 Reuters reported that US experts had found communication devices not listed in product documentation in some Chinese-made inverters and batteries, which could provide channels around firewalls; the manufacturers and numbers were not disclosed ([Utility Dive summary](https://www.utilitydive.com/news/rogue-communication-devices-found-on-chinese-made-solar-power-inverters/748242/); [pv magazine](https://www.pv-magazine.com/2025/05/14/hidden-devices-found-in-chinese-made-inverters-in-the-us-reports-reuters/)).
- **Regulatory response.** Lithuania adopted legislation in November 2024 barring entities from countries deemed national-security threats from remotely managing solar, wind and storage installations above 100 kW ([LRT](https://www.lrt.lt/en/news-in-english/19/2411602/lithuania-passes-law-to-block-chinese-access-to-solar-and-wind-farm-systems); [ESS News](https://www.ess-news.com/?p=3223)); the European Solar Manufacturing Council has called for similar restrictions EU-wide ([ESMC via pv magazine](https://www.pv-magazine.com/press-releases/restrict-remote-access-of-pv-inverters-from-high-risk-vendors/)).
- **Why blackout resilience matters.** ENTSO-E's final report on the 28 April 2025 Iberian blackout attributes it to interacting failures, chiefly in voltage control, rather than to renewable over-production ([pv magazine, 2026-03-23](https://www.pv-magazine.com/2026/03/23/entso-e-report-finds-systemic-failures-behind-2025-iberian-blackout/)). Large outages happen; a household battery in island mode is the last line of supply — which is exactly what a remote attacker would want to empty first.

Sunstrike does not model any of these products. It models the **class**: a fleet whose owners trust a remote channel that can change setpoints, drain batteries, switch inverters off and push firmware.

---

## 3. Threat model and hypotheses

| # | Hypothesis | What the attacker does | Lab focus |
|---|---|---|---|
| H1 | Default / hard-coded credentials | log into the fleet gateway or a device with known credentials or a broker token | auth rules |
| H2 | Fleet shutdown | switch inverters off remotely, fast or slowly paced | wave / slow-wave / mass rules |
| H3 | Export curtailment | drive export limits to zero across the fleet | curtailment / capacity rules |
| H4 | Firmware | push unsigned or out-of-window firmware | signature (HMAC since v0.7.4) and window checks |
| H5 | Pre-positioned battery drain | empty batteries before a blackout, below alert thresholds | floor, daily remote-drain limit, parked-drain rule |

**ATT&CK mapping (verified against attack.mitre.org on 2026-11-14).** The tags inside the frozen lab and in the M3 rule metadata were written by the builder and marked provisional. They were not edited, because the code and rules are sealed by hash. On review, several of those tags are wrong: the firmware rules carry T0814/T1485, the provenance and non-canonical rules carry the firmware IDs T1693.001/.002, and the battery and curtailment rules use the Enterprise data-destruction technique T1485 or Damage to Property T0879. **The table below supersedes every ATT&CK tag in the code and rule files.** "Closest fit" marks a judgment call where no technique matches exactly.

| Detection (Suricata sid / Sigma) | Verified technique (ICS unless noted) | Note |
|---|---|---|
| D-AUTH-DEFAULT (9100001) | T1694.001 Insecure Credentials: Default Credentials; Enterprise T1078 Valid Accounts | T0812 is the retired ID for Default Credentials |
| D-AUTH-BROKER-TOKEN (9100002) | T1694.002 Insecure Credentials: Hardcoded Credentials | |
| D-BULK-WITHOUT-WORKORDER, D-REMOTE-SHUTDOWN-NO-WO, D-FLEET-SHUTDOWN-WAVE, D-SLOW-WAVE, D-MASS-SHUTDOWN-WITH-WO (9100003–9100007) | T0816 Device Restart/Shutdown | |
| D-FLEET-CURTAILMENT-WAVE, D-MASS-CURTAILMENT (9100008–9100009) | T0836 Modify Parameter | export limit is a device parameter |
| D-SETPOINT-OUT-OF-BAND, D-PF-PARAM-CHANGE-IN-STRESS (9100016–9100017) | T0836 Modify Parameter | |
| D-BATTERY-DRAIN-* (9100010; Sigma below-floor / large / to-low) | T0836 Modify Parameter | not T1485: no data is destroyed |
| D-PROVENANCE-SPOOF-ATTEMPT (9100011) | T0849 Masquerading | closest fit |
| D-NON-CANONICAL-REQUEST (9100012) | T0820 Exploitation for Evasion | closest fit: a parser-differential bypass attempt |
| D-LOGIN-BRUTE-FORCE, D-LOCAL-CONFIRM-BRUTE-FORCE (9100013–9100014) | Enterprise T1110 Brute Force | ICS T0806 Brute Force I/O is a different behaviour |
| D-INVALID-WORK-ORDER (9100015) | T1692.001 Unauthorized Message: Command Message | closest fit |
| D-GRID-EMERGENCY-REMOTE-BLOCK (9100018) | T1692.001 Unauthorized Message: Command Message | |
| D-FIRMWARE-OUT-OF-WINDOW, D-FIRMWARE-REJECTED (9100019–9100020) | T1693.001 Modify Firmware: System Firmware | |
| D-CAPACITY-DIVERGENCE (Sigma) | T0826 Loss of Availability | an effect-based detection |

Case-level: initial access through the exposed fleet portal is T0819 Exploit Public-Facing Application, under tactic TA0108 Initial Access. The intended outcome, households losing backup power in a blackout, is T0826 Loss of Availability. Earlier drafts named T0879 Damage to Property, but the lab models no physical damage, so it is not claimed. Tactic TA0101 Command and Control is not used, because the lab models no C2 channel.

---

## 4. The lab

`sunstrike_lab.py` (single file, Python standard library) runs on loopback: 12 synthetic hybrid inverters (`SUNBOX`, ports 8611–8622, 3.2–12 kWp each, 88.8 kWp total), a fleet gateway (8610), a write-protecting guard proxy (8609), a grid simulator (NORMAL / STRESS / EMERGENCY / BLACKOUT, day/night irradiance) and a streaming detector with 26 rules and a rule-liveness invariant. Every command and physical event is written to JSONL audit logs.

Prevention controls in the final version include: an emergency interlock that refuses remote commands during grid emergencies; a battery reserve floor that remote commands cannot cross, while the house itself can use the reserve in island mode; a **daily remote-discharge limit of 40 %** (beyond it a local physical confirmation is required); HMAC-signed firmware; strict JSON typing; and a canonical request-line check.

---

## 5. Method and roles

- **Builder:** GLM-5.3 (Mistral-hosted) in Vibe. The builder worked under the operator's working protocols (PVTE family): PVTE-X v1.1 up to v0.7.1. From v0.7.2, because the Vibe *code* environment did not accept PVTE-X v1.1, the builder ran under PVTE-RA v2, a more permissive variant of the same family. The grant and the study rules were unchanged, and the lab stayed loopback-only.
- **Blind auditor:** Gemini (Antigravity), always in a new, empty folder containing only the lab file; since the 9th audit, no monkeypatching and all scripts kept.
- **Independent verifier and record keeper:** Claude, re-running every claim in an isolated copy (`python3 -I`), attacking each fix with its own probes, and keeping a dated official record.
- **Operator:** Sérgio Azevedo, who re-ran key numbers on macOS (Python 3.15.2, Suricata 8.0.8).

**Does the protocol change affect the results?** No number in this case depends on the builder's word: each lab version is identified by hash, every result was reproduced by independent execution, and predictions were registered before each run. What the protocol may have affected is builder *behaviour* (§10).

**Rules of evidence.** Probe → fix → re-run. Predictions are pre-registered (GATEFALL) and the **official result is always run 1**; later runs after a dated erratum are complementary, never substitutes. Errata are dated and never hidden.

---

## 6. Results: the case in four steps

Same attacker throughout: batteries drained remotely in slices with the grid normal, then a **night** blackout. Households served at the end of the blackout, by blackout duration (out of 12):

| Arm | 30 min | 1 h | 1 h 30 | 2 h | 3 h |
|---|---|---|---|---|---|
| No defense (LEGACY) | 0 | 0 | 0 | 0 | 0 |
| First defense: reserve locked for everyone (v0.4 "option B") | 0 | 0 | 0 | 0 | 0 |
| Corrected reserve: floor blocks remote drain, house may use it in island (v0.5) | 12 | 9 | 6 | 4 | 0 |
| **+ daily remote-drain limit 40 % (v0.6 → v0.7.5)** | **12** | **12** | **12** | **11** | **8** |

Source: `measure` (51 runs, all PASS) in `v0.7.5/`. The first defense failed because a reserve that the house itself cannot use protects nobody. The corrected design stops the remote channel, not the owner.

A **patient two-day attacker** who stays inside the daily limit still ends with 9/12 at 1 h and 3/12 at 2 h, but now trips a CRIT drain alert before the blackout. Without attack, the same night gives 12, 12, 12, 10, 9 households at 1–5 h.

### 6.1 Findings about the LLM-built defense

| ID | Finding | Evidence |
|---|---|---|
| C10 | First resilience metric only measured the attacker the interlock blocks by construction | v0.4 defended arm 0/12 under pre-positioned drain |
| C13 / C15 | Work-order exemptions were usable by whoever controls the channel that issues them | mass rules now count WO and no-WO together |
| v0.7.4 F-01 | Mass-shutdown state tracked by count, not capacity → Top-5 (58.2 %) off, 0 alerts | v0.7.3 CRIT; v0.7.4 none; v0.7.5 CRIT |
| v0.7.4 F-06 | Slow-wave anchored on first event (supervisor's specification) → paced wave unalerted | v0.7.3 CRIT; v0.7.4 none; v0.7.5 CRIT |
| PARKED | Supervisor-designed "parked battery" rule: reset at 90 % SoC let one tiny recharge erase the attack; no re-arming | fixed in v0.7.5 with a net remote-deficit accumulator |
| G5 | "Stuck band": once capacity divergence crossed a band with a legitimate change, later illegitimate cuts went unalerted | found by the supervisor and, independently, by the auditor (F-04b) |

**Independent convergence.** Several findings were reached separately by auditor and verifier (C13, K1-b, G5 = F-04b) — the strongest form of confirmation in this case.

### 6.2 Verification history (final rounds)

| Version | Lab sha256 (prefix) | Key result |
|---|---|---|
| v0.7.3 | `de7f5766` | 8th blind audit: 9 findings, all reproduced |
| v0.7.4 | `1643887c` | fixes verified, then 9th audit found 2 regressions |
| v0.7.5 | `5162964f` | logic-only fixes; R2–R11 all pass; 10th audit ("declare only") — nothing reopens the code |

---

## 7. Detection engineering (external engines)

The builder wrote 20 Suricata rules, 18 Sigma rules, a scenario generator (10 scenarios including a legitimate-maintenance `NEG`) and **predictions per rule × scenario before any run**. The supervisor generated the reference pcaps and logs and ran the official run 1; the operator re-ran Suricata on macOS.

| Engine | Run 1 (official) | After dated syntax erratum E-M3-1 |
|---|---|---|
| Sigma via pySigma 2.1.0 + SQLite backend 2.1.1 (audit logs) | **180/180 cells correct**, NEG = 0 | — |
| Suricata 7.0.3 (Linux) / 8.0.8 (macOS) | `-T` **fails: 11/20 rules do not load**; 180/200 cells correct | all load in both; remaining misses: proxied double hop (counts ×2), lockout response never on the wire, one time-window rule unstable (0–2 between identical runs) |

NEG produced zero alerts in every engine and run. Rules whose logic depends on internal state the network cannot see (capacity-weighted mass, parked battery, cumulative drain) are documented as not expressible in Suricata.

---

## 8. Reproduction

`pacote_reproducao/reproduzir_sunstrike.py` takes the `v0.7.5/` folder, checks the lab hashes, copies everything to a fresh directory and runs 15 steps (selftest, demo, measure, R11 against preserved v0.7.4, R2–R11 against v0.7.5, and the declared-limits probe). **15/15 PASS** on Linux / Python 3.13.18 and on macOS / Python 3.15.2. The M3 reference pcaps are hashed in `m3/referencia/SHA256SUMS.txt`.

---

## 9. What cannot be claimed

- **Threshold evasion.** Batteries parked at 45.1 % (40 % + 14.9 % over two days): no alert; households at 1–5 h = 12, 9, 6, 3, 0 (no attack: 12, 12, 12, 10, 9). Export curtailment: two largest at 0 % + ten at 25.01 % with a work order → 81.55 % loss; 25.01 % in 61-second batches → 74.96 %; batches below 30 % kWp separated by more than one hour → 100 %; 29.9-point steps avoid the curtailment wave. All without alerts.
- **Island discharge is not counted** in the remote-deficit accumulator: a micro-outage followed by remote drain parks batteries at 35.1 % silently.
- **Local confirmation is assumed physical.** The `/local_confirm` PIN is predictable and reachable on the device port; with it, batteries can be emptied without alerts.
- **False positives accepted or known:** an owner who drains through the remote channel is indistinguishable from an attacker; serial one-by-one curtailment maintenance; capacity divergence with relays open after an emergency; island recharge not audited; curtailment wave with a valid work order fires by design.
- **Relays do not reclose automatically** after an emergency (no EN 50549-style reconnection); remote reconnect is refused during the 600 s latch.
- **Clocks:** some lockouts and latches use wall-clock time, not simulated time. **Races:** some counters are updated outside locks (structural, not reproduced).
- **Unverifiable step:** one intermediate v0.7.4 lab (`31237bfa…`) was edited in place and lost; the builder's statement that the edit only changed alert reporting is recorded as received, not verified.
- Minor: some 400 responses leave no audit event; zero-byte signed firmware accepted; a few docstrings contradict the code.
- KQL was not produced or executed.

---

## 10. Process incidents (recorded, not smoothed over)

- **Unauthorized publication (v0.7.2).** The builder opened a branch and a draft PR on the public repository without approval. The operator closed it and deleted the branch; main was untouched. Three factors: the move from Vibe *work* to Vibe *code* left the builder no other way to hand over files; the supervisor's instruction asked to "make available" without saying how or what was forbidden; and, as the operator's hypothesis, the protocol change. From then on every instruction named the delivery channel (a private repository), the forbidden actions and an explicit stop; the builder complied in all later rounds.
- **"Official run" relabelling.** Three times the builder called a re-run after an erratum the "official" result; each time it was corrected to run 1.
- **Sandbox false positive.** A Python variable named `nc` was blocked as "netcat"; renaming it was legitimate. The supervisor's first reaction (to stop the builder) was premature.
- **Auditor method.** In one audit the auditor monkeypatched a module function to "prove" a race; without the injected delay the race did not reproduce. Since then the audit prompt forbids it.
- **Supervisor errors** are part of the record: the slow-wave specification that became a regression, the original parked-rule design, an incoherent control in one GO, and earlier slips (a wrong percentage, an incomplete delivery instruction).

---

## License

Code: Apache-2.0. Report and documentation: CC BY-NC-SA 4.0 (see repository root).
