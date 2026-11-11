# Hydrostrike

## Anatomy of European Municipal Water Station HMI/SCADA Sabotage, and How to Harden Against It

**Author:** Sérgio Azevedo (`malapeiro`) · **Date:** 2026-11-07 · **Artifact class:** execution-verified (synthetic loopback lab) / textual compliance (Sigma, KQL; Suricata execution-verified since 2026-11-11, see `detections/suricata/verification/`)
**Subject:** the wave of intrusions and parameter-manipulation attacks against municipal water treatment and pumping stations (*Stacje Uzdatniania Wody* / ETAs) documented across Europe by Poland's Internal Security Agency (ABW) and CERT Polska/CSIRT NASK (including Szczytno, Małdyty, Tolkmicko, Jabłonna Lacka, and Sierakowo), Romania's national water authority disclosures, and ANSSI / CERT-FR / ENISA advisories on internet-exposed water HMIs and PLCs.

Notice. This repository is independent defensive research based exclusively on public sources (ABW and CERT Polska/CSIRT NASK statements, ANSSI/CERT-FR and ENISA advisories, and public reporting). The emulation code does not reproduce any vendor endpoint, industrial protocol, firmware path, password algorithm, or CVE exploit chain; it operates only against the synthetic controller (`HYDROBOX`) defined in this repository, on loopback (`127.0.0.1`; the attack module refuses any non-loopback target with `ScopeError`). It cannot be used against real equipment and adds no capability to anyone seeking to do so. The purpose is adversarial detection engineering and prevention architecture testing, not offense.

---

## 1. Executive summary

Across 2024–2026, municipal water treatment and pumping stations in Europe faced a sustained wave of low-barrier, high-visibility sabotage attempts. In incidents publicly confirmed by Poland's Internal Security Agency (ABW) and CERT Polska (including municipal stations in Tolkmicko, Małdyty, Szczytno, Jabłonna Lacka, and Sierakowo), threat actors accessed internet-exposed SCADA/HMI panels protected by weak or default PINs and passwords (`123456`, `111111`), manipulated pump pressure setpoints, altered dosing parameters, closed outlet valves, forced filter backwash cycles to drain clear-water reservoirs, and suppressed alarms — often recording the HMI screen for propaganda channels.

Just as in the [Froststrike](../froststrike/froststrike_report.md) refrigeration campaign, national agencies (CERT Polska, ANSSI, ENISA) emphasized that the majority of these intrusions did not rely on zero-day exploits: they exploited **direct internet exposure of HMI/SCADA web interfaces, weak or default credentials, and the absence of process-level interlocks between remote management commands and physical plant state**.

This case study reconstructs the sabotage class against a synthetic municipal water station controller ([`hydrostrike_lab.py`](hydrostrike_lab.py)), and subjects both the streaming detection engine and the write-protecting guard proxy to a **three-model adversarial validation loop (`probe → fix → re-run`) across five versions (`v1.0 → v1.1 → v1.2 → v1.3 → v1.3.1`)**:
- **Builder ("Patient"):** GLM 5.3 (Mistral-hosted) operating under the **PVTE-X v1.1** verification protocol.
- **Primary Adversarial Auditor:** Gemini, executing three rounds of adversarial probe scripts ([`audit_probes_v1.py`](audit_probes_v1.py), [`audit_probes_v2.py`](audit_probes_v2.py), [`audit_probes_v3.py`](audit_probes_v3.py)) that uncovered **12 concrete flaws (Probes P1–P12B)** across `v1.0 → v1.2`.
- **Independent External Verifier:** Claude (in a separate Python 3.13 sandbox), which independently reproduced all 12 probes, identified **4 additional structural and false-positive findings (Additions A–D)** for `v1.3`, and then caught a **critical silent regression (`Probe 13A/13B`)** during packaging review that led to **`v1.3.1`**.

**Key defensive and methodological findings from the `v1.0 → v1.3.1` adversarial loop:**
1. **Single-shot LLM defenses fail silently under adversarial probing:** `v1.0` passed its own 6-check demo (`exit 0`), yet failed all 5 Round 1 probes — raising a `CRIT` false positive on a single legitimate daytime filter backwash (`P1`), missing deadhead risk when pump pressure was raised *after* closing `VLV-OUT` (`P2`), allowing 7 backwashes through the Guard to drain the reservoir to **`-6.0%`** (`P3`), letting `"NaN"` bypass `min(max(nan, 2.5), 5.5)` to poison controller state (`P4`), and suffering a critical **parser differential** where `{"muted": "false"}` bypassed the Guard (`"false" is True == False`) while muting all alarms on the Controller (`bool("false") == True`, `P5`).
2. **Fixes themselves introduce second- and third-order vulnerabilities:** `v1.1` fixed `P1–P5` but introduced a **second parser differential** in `Authorization` header keying (`P6`), a shift-wide false positive when 2 filters were washed 7 hours apart (`P7A`), a cross-subsystem underpressure drop (`2.5 bar` setpoint + 2 backwashes = `1.7 bar`, `P8`), and an `elif` chain that masked critical reservoir-drain alerts (`P12A`). `v1.2` then introduced a **third parser differential** on URL path normalization (`/api/login/`, `/api//login` bypassed all 4 Guard blocks, `P9 / Addition C`) and a **classic TOCTOU race condition** where `fleet_lock` was released before two synchronous HTTP calls, allowing 6 concurrent threads to drain the reservoir to `6.0%` and `1.6 bar` (`P10`).
3. **Architectural closure in `v1.3`:** Rather than patching a fourth parser differential or holding a proxy mutex over blocking network I/O (which would create a DoS choke point, `Addition B`), `v1.3` extracts a **single shared request canonicalizer (`canonicalize_request` + `validate_api_body`, `Addition D`)** used by both Guard and Controller, moves the **hydraulic and fleet interlocks atomically into `HydroboxState._backwash` under `self.lock` (`Addition B`)**, implements a **dual-horizon detector (`30m/60m` burst + `24h` shift ceiling, `P11`)**, and scopes `D-DEADHEAD-RISK` to actively running pumps so legitimate valve isolation (`stop pump → close valve`) produces `0 alerts` (`Addition A`).
4. **Central methodological finding — silent rule deletion during LLM refactoring (`D-CHLORINE-OUT-OF-BAND`, `v1.1–v1.3` → fixed in `v1.3.1`):** In `v1.0`, `Detector.scan` actively evaluated `elif ev == "dosing_setpoint":` and fired `D-CHLORINE-OUT-OF-BAND` (`CRIT`). When GLM 5.3 refactored `Detector.scan` in `v1.1` to fix `P1–P2`, it **accidentally deleted the entire `dosing_setpoint` branch**, leaving `"D-CHLORINE-OUT-OF-BAND"` alive only as a dead key in `RULE_ATTACK_MAP` and in the Guard's setpoint clamp. Because our adversarial probe suites (`24/24`, `34/34`, `50/50`) grew exclusively along newly discovered evasion vectors and never re-tested whether pre-existing rules still fired, **this silent deletion survived three consecutive versions (`v1.1`, `v1.2`, `v1.3`) with `100% PASS` validation**: an authenticated insider (`tech` at `10:15`) setting chlorine to a toxic `4.5 mg/L` generated **`0 CRIT, 0 WARN`** (`Probe 13A`). Caught during packaging verification, `v1.3.1` restores `D-CHLORINE-OUT-OF-BAND` (`H1/H2` alerts rise from `16` to **`17 CRIT`**) and adds `rule_liveness_check()` (`Probe 13B`) — an invariant that prevents any rule in `RULE_ATTACK_MAP` from being deleted or rendered unreachable in `Detector.scan` (closing the `RULE_ATTACK_MAP ↔ scan` link, though not the `controller ↔ scan` link; see Section 5.4 and Section 7.4).

---

## 2. Threat context: European municipal water station sabotage

### 2.1 Publicly documented incidents and advisories

| Period / Jurisdiction | Documented Activity | Primary Sources |
|---|---|---|
| **Poland (2024–2026)** | Intrusions into municipal water treatment and pumping stations (*Stacje Uzdatniania Wody*), including **Tolkmicko, Małdyty, Szczytno, Jabłonna Lacka, and Sierakowo**. Attackers accessed internet-facing HMI/SCADA interfaces protected by weak/default PINs (`123456`, `111111`), altered pump activation thresholds, cut off or depressurized supply, forced filter flushing, and changed operator PINs. | ABW (*Agencja Bezpieczeństwa Wewnętrznego*), CERT Polska / CSIRT NASK advisories |
| **France & EU (2024–2026)** | Repeated intrusions targeting exposed PLCs and web HMIs in small and medium water utilities (including Unitronics, Schneider Electric, Rockwell/Allen-Bradley, and web SCADA gateways). Manipulation of pump/valve states, tank overflow/drainage, and HMI defacement. | ANSSI, CERT-FR, ENISA Threat Landscape for OT/ICS |
| **Multi-vector / Contractor Access** | Unauthorized access via shared maintenance credentials, predictable vendor/service access codes on legacy firmware, or exposed remote-management ports (`HTTP/HTTPS`, `VNC`, `Modbus TCP`) left open for external contractors. | CERT Polska, ENISA, WaterISAC / CISA joint advisories |

### 2.2 The physical-operational conflict in water stations

A municipal water treatment station (ETA) runs three coupled physical subsystems:
1. **Filtration (`FLT-01..FLT-04`) and Clear-Water Reservoir (`TK-CLEAR`):** Filters require periodic **backwashing** (reversing treated water flow from `TK-CLEAR` through the filter bed to waste). Automatic backwash runs during low-demand night hours (`03:00–04:30`, 1 filter per night). Each backwash consumes treated water from `TK-CLEAR` and causes a temporary line pressure drop.
2. **High-Lift Distribution Pumps (`PMP-01` active, `PMP-02` standby) and Outlet Valve (`VLV-OUT`):** Maintain public network pressure within `[2.5, 5.5] bar`. Below `2.5 bar`, backflow contamination and loss of fire-hydrant pressure occur; above `5.5 bar` (or when a pump runs against a closed outlet valve `VLV-OUT` — **deadheading**), pipe bursts and pump cavitation/destruction occur.
3. **Disinfection Dosing (`CL2-DOSE`):** Maintains free residual chlorine within `[0.2, 1.0] mg/L`. Below `0.2 mg/L`, biological safety fails; above `1.0 mg/L` (e.g., `4.5 mg/L`), water becomes non-potable/toxic.

**Why naive rules fail:**
- During the scheduled night window (`03:00–04:30`), a backwash event on `FLT-01` is expected (`trigger="SCHEDULED"`). An attacker who forces backwash on **all four filters (`FLT-01..FLT-04`)** via the API at `03:15` blends into the nightly maintenance window unless the detector distinguishes `trigger="API"` from `PLC-SCHED`, tracks multi-filter/repeat backwashes, and monitors reservoir depletion.
- Conversely, during daytime maintenance (`08:00–18:00`), a technician legitimately triggers a manual backwash on a single clogged filter (`P1`), washes two filters 7 hours apart (`P7A`), or **stops `PMP-01` and closes `VLV-OUT` to isolate the line (`Addition A`)**. Naive rules that alert on every `API` backwash or every `VLV-OUT = CLOSED` event flood the SOC with false positives.

---

## 3. Reconstructed attack chain (threat model)

*Note on ATT&CK taxonomy (see also Section 7.6): mappings below have been manually verified against the official MITRE ATT&CK Enterprise and ICS matrices. In particular, `T0879` is **Damage to Property** (not generic "Damage"), and `T0855` is **Unauthorized Command Message**.*

| # | Phase | Description | ATT&CK Mapping (Verified) | Confidence |
|---|---|---|---|---|
| 1 | Reconnaissance | Unauthenticated `GET /api/status` read on an exposed water HMI/SCADA web interface to enumerate reservoir level, active pumps, valve state, and filter IDs | Enterprise `T1596`; ICS `T0883` (*Internet Accessible Device*) | Confirmed (CERT Polska / ANSSI exposure findings) |
| 2a | Initial access (`H1`) | Login to `/api/login` using vendor-default or weak credentials (`admin:123456`) | Enterprise `T1078.001` (*Valid Accounts: Default Accounts*) | High (documented by ABW / CERT Polska in Polish municipal water incidents) |
| 2b | Initial access (`H2`) | Authentication bypass via a predictable daily service code on `/api/service_login` (class of legacy vendor backdoor/service-PIN calculators) | Enterprise `T1190` / ICS `T0819` (*Exploit Public-Facing Application*) | Medium (published vulnerability class across legacy OT/HMI controllers) |
| 3 | Hydraulic & chemical sabotage | Push `PMP-01` setpoint to `8.5 bar` (overpressure), raise chlorine dosing to `4.5 mg/L`, close outlet valve `VLV-OUT` while pumps run (**deadhead**), and force backwash across `FLT-01..FLT-04` to drain `TK-CLEAR` (`78% → 18%`) | ICS `T0855` (*Unauthorized Command Message*) | Confirmed (parameter manipulation pattern in ABW / CERT Polska reports) |
| 4 | Defense evasion | Suppress plant alarms via `POST /api/alarm/mute {"muted": true}` so low-reservoir and overpressure conditions do not page operators at `03:15` | ICS Tactic `TA0107` (*Inhibit Response Function*; see `T0838` *Modify Alarm Settings*) | High |
| 5 | Physical impact | Reservoir depletion below minimum fire/supply reserve (`< 25%`), distribution network depressurization (`< 2.5 bar`) or overpressure/deadhead damage | ICS `T0879` (*Damage to Property*) | Confirmed |

---

## 4. The lab: `HYDROBOX` (`hydrostrike_lab.py`)

[`hydrostrike_lab.py`](hydrostrike_lab.py) (single file, 100% Python 3 standard library, `v1.3.1`) implements four components on `127.0.0.1`:

```
                          ┌──────────────────────────────────────────────────────┐
   attack (H1 / H2) ─────►│  Guard Proxy (prevention artifact, port 8605)        │
   loopback only          │  • Shared request canonicalizer (canonicalize_request)│
                          │  • Default-cred & hidden-service-auth block          │
                          │  • Maintenance-window write gate (08:00–18:00)       │
                          │  • Setpoint band clamps ([2.5,5.5] bar, [0.2,1.0] Cl)│
                          │  • Remote VLV-OUT close & alarm-mute block           │
                          └──────────────────────────┬───────────────────────────┘
                                                     ▼
                          ┌──────────────────────────────────────────────────────┐
                          │  HYDROBOX Synthetic Controller (port 8600)           │
                          │  • 1 clear-water tank (TK-CLEAR, 78%), 4 filters     │
                          │    (FLT-01..04), 2 pumps (PMP-01 active, PMP-02 stby)│
                          │  • Atomic safety interlocks under HydroboxState.lock:│
                          │    - Fleet rate limit (2/1h AND 2/24h)               │
                          │    - Hydraulic interlock (pressure >= 2.5, tank >=40)│
                          │  • Structured JSONL audit trail                      │
                          └──────────────────────────┬───────────────────────────┘
                                                     ▼
                          ┌──────────────────────────────────────────────────────┐
                          │  Streaming Detection Engine (Detector)               │
                          │  D-DEFAULT-CRED-LOGIN · D-HIDDEN-SERVICE-AUTH ·      │
                          │  D-PRESSURE-OUT-OF-BAND · D-CHLORINE-OUT-OF-BAND ·   │
                          │  D-DEADHEAD-RISK · D-FORCED-BACKWASH ·               │
                          │  D-MULTI-FILTER-BACKWASH · D-BACKWASH-ABUSE ·        │
                          │  D-UNDERPRESSURE-DROP · D-ALARM-MUTE ·               │
                          │  D-RESERVOIR-LOW · D-OUT-OF-WINDOW-WRITE             │
                          │  + rule_liveness_check() (RULE_ATTACK_MAP ↔ scan)    │
                          └──────────────────────────────────────────────────────┘
```

### 4.1 Artifact integrity chain (`v1.0 → v1.3.1`)

Every version generated during the adversarial audit was hashed before executing the next probe battery:

| Version | Lines | SHA-256 | Summary of changes |
|---|---:|---|---|
| **`v1.0`** | `1,312` | `e3e5c987a8e9445be709a164555b464ead24283d1f615844ff39e4f13d8ceeda` | Initial build by GLM 5.3 under PVTE-X v1.1. Passes its own 6-check demo (`exit 0`, `10 CRIT` in `H1/H2`, with `D-CHLORINE-OUT-OF-BAND` active), but fails all 5 Round 1 adversarial probes (`P1–P5`). |
| **`v1.1`** | `1,418` | `dcab132b3cbb558b47693f38f7a82c4c67296af315e888bb2d2b398ad1512405` | Fixes Round 1 (`P1–P5`): single daytime backwash FP fixed, `VLV-OUT` close blocked in Guard, `max(0.0, ...)` reservoir floor + per-token backwash limit (`2`), `math.isfinite` rejects `NaN`/`Inf`, strict `bool` check on `/api/alarm/mute`. **Silently deletes `elif ev == "dosing_setpoint":` (`D-CHLORINE-OUT-OF-BAND`) from `Detector.scan` (dropping `H1/H2` from `10` to `9 CRIT`)** and introduces 4 second-order flaws (`P6–P8`). |
| **`v1.2`** | `1,486` | `b2ac74c75a9e5129f2c6699ca352778b98e251875927f2eb424cb3beffd0d23f` | Fixes Round 2 (`P6, P7A, P7B, P8`): station-wide 60-min sliding window, 30-min multi-filter window, `D-BACKWASH-ABUSE`, `D-UNDERPRESSURE-DROP`, and Guard `GET /api/status` hydraulic pre-check (`9 CRIT` in `H1/H2`). Introduces TOCTOU race condition (`P10`) and leaves URL path differential (`P9`), 61-min pacing (`P11`), `elif` masking (`P12A`), standby pump spoofing (`P12B`), valve-isolation FP (`Addition A`), and the silent `D-CHLORINE-OUT-OF-BAND` deletion open. |
| **`v1.3`** | `1,692` | `172e2d23b8b6b7a6bc6b1f2a3b0ec587d9d9b3cf570215deff6e26743dcf3b48` | Fixes Round 3 (`P9–P12B`) + Independent Verifier Addendum (`Additions A–D`): shared `canonicalize_request()` + `validate_api_body()`, atomic controller-side hydraulic and dual-horizon (`2/1h` + `2/24h`) interlocks under `HydroboxState.lock`, independent `if` alert evaluation (`H1/H2` rises from `9` to `16 CRIT`), active-pump-only pressure calculation, and running-pump-scoped `D-DEADHEAD-RISK`. Still missing `D-CHLORINE-OUT-OF-BAND` in `Detector.scan`. |
| **`v1.3.1`** | `1,745` (local patch reconstruction) / `1,770` (GLM sandbox) | `d55c324f2876256746c7289865e3c3a6cc0824a2e57df0d536e77c351a6f3072` (on disk) / `7287caef46de7a2d4713d9837de24da746a04e91e59f6cc127cd041292539089` (GLM sandbox)* | Fixes Packaging Verification Regression (`Probes 13A/13B`): restores `elif ev == "dosing_setpoint":` (`D-CHLORINE-OUT-OF-BAND` `CRIT`) in `Detector.scan` (`H1/H2` rises from `16` to `17 CRIT`), corrects `T0879` title to `"Damage to Property"` in `RULE_ATTACK_MAP`, and adds `rule_liveness_check()` (`15/15` rules firing, `0` dead rules, `7/7` demo criteria). |

*\*Note on `v1.3.1` hash pair: for `v1.3.1`, GLM 5.3 returned a 7-part patch in chat (with the 13 synthetic dicts of `_rule_liveness_events()` formatted on single lines) rather than the full raw file. Applying those 7 modifications deterministically to `v1.3` produces the `1,745`-line file on disk (`d55c324f...`), whereas GLM's internal sandbox file wrapped those dict literals across `+25` lines (`1,770` lines, `7287caef...`). Both hashes are recorded here for auditability.*

### 4.2 Measured demo results in `v1.3.1` (execution-verified)

Run with:

```bash
python3 hydrostrike_lab.py demo --evidence-dir evidence
```

| Phase | Scenario | Controller Events | CRIT | WARN | Lab MTTD (s)* | Guard Blocks | Final Plant State | Outcome |
|---|---|---:|---:|---:|---:|---:|---|---|
| **H1** | Default credentials (`admin/123456`) at `03:15` against legacy controller (`safety_interlocks=False`) | 17 | **17** | **9** | `0.000`* | 0 | Tank `18.0%`, Pressure `6.9 bar`, Cl2 `4.5 mg/L`, Valve `CLOSED`, Alarms `MUTED` | `DETECTED` |
| **H2** | Predictable daily service code (`/api/service_login`) at `03:15` against legacy controller (`safety_interlocks=False`) | 17 | **17** | **9** | `0.000`* | 0 | Tank `18.0%`, Pressure `6.9 bar`, Cl2 `4.5 mg/L`, Valve `CLOSED`, Alarms `MUTED` | `DETECTED` |
| **NEG** | Legitimate technician (`tech`) at `10:15`: in-band trim, 1 manual backwash (`FLT-01`), **hydraulic isolation (`stop PMP-01 → close VLV-OUT → reopen VLV-OUT → start PMP-01`)**, unmute | 12 | **0** | **0** | `-` | 0 | Tank `66.0%`, Pressure `4.2 bar`, Cl2 `0.6 mg/L`, Valve `OPEN`, Alarms `ACTIVE` | `CLEAN` |
| **GUARD** | `H1` chain through Guard Proxy + Controller with `safety_interlocks=True` at `03:15` | 4 | **0** | **0** | `-` | **9** | Tank `66.0%` (after scheduled 03:15 `FLT-01` wash), Pressure `3.6 bar`, Cl2 `0.5 mg/L`, Valve `OPEN`, Alarms `ACTIVE` | `PREVENTED` |

*\*Note on `MTTD = 0.000 s`: this is a 1-second timestamp-format resolution artifact, not real detection latency — see Section 7.3.*

---

## 5. Multi-round adversarial validation (`v1.0 → v1.3.1`)

### 5.1 Round 1 (`audit_probes_v1.py` against `v1.0` → fixed in `v1.1`)

| Probe | Adversarial Vector Tested Against `v1.0` | Measured Result in `v1.0` | Root Cause & `v1.1` Fix |
|---|---|---|---|
| **P1** (`fp_single_backwash`) | Technician `tech` logs in at `10:15` (inside maintenance window) and runs 1 manual backwash on `FLT-01`. | **False Positive:** `CRIT=1` (`D-FORCED-BACKWASH`). *(Note: `v1.0`'s demo `NEG` phase never called `/backwash`, hiding this FP!)* | `v1.0` fired `CRIT` on *every* `trigger == "API"` backwash. `v1.1` added 1 manual backwash to `legit_tech_flow` and scoped `D-FORCED-BACKWASH` to out-of-window or low-reservoir (`< 40%`) events. |
| **P2** (`deadhead_order`) | Close `VLV-OUT` through Guard at `10:15` while `PMP-01` is at `4.0 bar`, then raise `PMP-01` setpoint to `5.5 bar`. | **Guard Bypass & Detector Blindness:** Guard returned `HTTP 200` (`valve=CLOSED`); raising pressure after closing valve produced `CRIT=0` (`D-DEADHEAD-RISK` blind). | `v1.0` checked `pressure > 4.5` only on `valve_command`, and `pump_setpoint` events omitted `"valve"`. `v1.1` blocked remote `VLV-OUT` close in Guard (`G-VALVE-CLOSE-BLOCKED`) and added `"valve"` to `pump_setpoint`. |
| **P3** (`negative_physics`) | Send 7 consecutive backwashes through Guard at `10:15`. | **Total Drain & Negative Physics:** `7 × HTTP 200`; `TK-CLEAR` dropped to **`-6.0%`** and pressure to `1.2 bar`. | `HydroboxState._backwash` lacked `max(0.0, ...)` and Guard had no rate limit on `/backwash`. `v1.1` added `max(0.0, ...)` and `G-BACKWASH-FLEET-LIMIT = 2`. |
| **P4** (`nan_bypass`) | Send `{"value": "NaN"}` to `/api/pump/PMP-01/setpoint` via Guard. | **Clamp & Detector Bypass:** `HTTP 200`; `min(max(float("nan"), 2.5), 5.5)` returned `nan`, poisoning `pressure_bar = nan` with `CRIT=0`. | `float("NaN")` is a valid `float` in Python and all comparisons (`2.5 <= nan <= 5.5`) evaluate to `False`. `v1.1` added `math.isfinite(val)` to `_as_float`. |
| **P5** (`parser_diff_mute`) | Send `{"muted": "false"}` (non-empty string) to `/api/alarm/mute` via Guard at `10:15`. | **Critical Parser Differential (#1):** Guard allowed it (`HTTP 200`), and Controller **muted all alarms (`alarm_muted = True`)**! | Guard checked `body.get("muted") is True` (`False` for `"false"`), whereas Controller evaluated `bool(body.get("muted"))` (`True` for any non-empty string!). `v1.1` enforced `isinstance(muted, bool)`. |

### 5.2 Round 2 (`audit_probes_v2.py` against `v1.1` → fixed in `v1.2`)

Round 2 attacked the `v1.1` fixes themselves and uncovered 4 second-order flaws:

| Probe | Second-Order Vector Tested Against `v1.1` | Measured Result in `v1.1` | Root Cause & `v1.2` Fix |
|---|---|---|---|
| **P6** (`parser_diff_auth`) | Send 7 backwashes through Guard using **1 single session token**, varying only header casing/whitespace (`"Bearer <tok>"`, `"bearer <tok>"`, `"BEARER <tok>"`, `"Bearer <tok>   "`). | **Critical Parser Differential (#2):** All 7 passed (`[200, 200, 200, 200, 200, 200, 200]`), draining `TK-CLEAR` to **`0.0%`**! | `v1.1` keyed `fleet_counts` in Guard by raw `self.headers.get("Authorization")`, while Controller normalized `auth[7:].strip() if auth.lower().startswith("bearer ")`. `v1.2` removed token-keying and made the limit station-wide. |
| **P7A** (`fp_shift_window`) | Technician washes `FLT-01` at `09:00` and `FLT-02` at `16:00` (7 hours apart on the same day). | **False Positive:** `CRIT=1` (`D-MULTI-FILTER-BACKWASH`). | `v1.1` grouped `_api_backwash_filters` by calendar date (`night`). `v1.2` replaced it with a 30-minute sliding window (`BACKWASH_MULTI_WINDOW_S = 1800`). |
| **P7B** (`same_filter_blind`) | Attacker in daytime window runs 3 consecutive backwashes on the **same filter (`FLT-01`)** (`78% → 42%`, `4.0 → 2.8 bar`). | **Blind Spot:** `CRIT=0` (`len(flts) == 1` and `42.0% >= 40.0%`). | `v1.2` added `D-BACKWASH-ABUSE` (`CRIT` on `>= 3` total API backwashes within 60 minutes, even on the same filter). |
| **P8** (`cross_subsystem_drop`) | Set `PMP-01` to `2.5 bar` (in-band, allowed by Guard) + 2 allowed backwashes (`-0.8 bar` total). | **Silent Depressurization:** Network pressure dropped to **`1.7 bar` (`< 2.5 bar` minimum)** through the Guard with **`CRIT=0`**! | Detector never checked `pressure_after < PUMP_BAND[0]` on `filter_backwash`, and Guard checked setpoints and backwashes in isolation. `v1.2` added `D-UNDERPRESSURE-DROP` and hydraulic interlock checks. |

### 5.3 Round 3 + Independent External Verifier Addendum (`audit_probes_v3.py` against `v1.2` → fixed in `v1.3`)

In Round 3, primary auditing (Gemini) and an independent external verification in a separate Python 3.13 sandbox (Claude) converged on `v1.2`, confirming **5 third-order flaws (`P9–P12B`)** and **4 structural/operational requirements (`Additions A–D`)**:

| Item | Third-Order Vector / Independent Finding on `v1.2` | Measured Result in `v1.2` | Architectural Fix in `v1.3` (Verified) |
|---|---|---|---|
| **P9 + Addition C & D** (`parser_diff_path`) | **Critical Parser Differential (#3):** Send `/api/login/`, `/api//login`, `/api/login//`, `/api/alarm/mute//`, `/api//valve/out` through Guard. | **Total Guard Bypass:** All returned **`HTTP 200`** in `v1.2` (`admin:123456` logged in, `alarm_muted=True`, `valve=CLOSED` at `4.0 bar`)! | Controller normalized `parts = [p for p in path.strip("/").split("/") if p]`, while Guard compared `path == "/api/login"` by raw string before computing `parts`. `v1.3` extracts a **single shared `canonicalize_request()` + `validate_api_body()` (`Addition D`)**; all 7 non-canonical path variants return **`HTTP 400`** (`G-BAD-PATH`). |
| **P10 + Addition B** (`toctou_race`) | **TOCTOU Race Condition vs. Proxy Lock DoS:** `v1.2` claimed `fleet_lock` prevented thread races, but released `fleet_lock` *before* two synchronous HTTP calls (`GET /api/status` and `POST`). Firing 6 concurrent threads (`Barrier(6)`) at Guard bypassed both limits. | **Complete Race Bypass in `v1.2`:** `6 × HTTP 200` (vs limit 2), draining tank to **`6.0%`** and pressure to **`1.6 bar`**! | Per **Addition B**, holding `fleet_lock` over blocking HTTP I/O in the proxy is an anti-pattern (creates a DoS choke point if upstream stalls). `v1.3` moves the **fleet (`2/1h`, `2/24h`) and hydraulic interlocks into `HydroboxState._backwash` atomically under `self.lock`**. Verified: 6–7 threads → **max `2 × 200`** (`54.0%`); 3 threads @ `2.9 bar` → **`1 × 200 + 2 × 403`**, final pressure **`2.5 bar`**. |
| **P11** (`patient_attacker`) | **Patient Attacker (>60 min pacing):** Space 3 backwashes by 61 minutes (`08:05` `FLT-01`, `09:06` `FLT-02`, `10:07` `FLT-03`). | **Full Evasion in `v1.2`:** `3 × HTTP 200`, tank `42.0%`, pressure `2.8 bar`, **`CRIT=0, WARN=0`**. | `v1.3` implements a **dual horizon**: `2/1h` burst AND `2/24h` daily ceiling (`C-BACKWASH-DAILY-LIMIT`), plus `D-MULTI-FILTER-BACKWASH` (`>=2` filters/30m OR `>=3` filters/24h) and `D-BACKWASH-ABUSE` (`>=3` cmds/60m OR `>=3` cmds/24h). 3rd paced wash is blocked (`403`) and detected (`CRIT=2`), while Probe 7A (2 filters 7h apart) remains `0 alerts`. |
| **P12A** (`elif_masking`) | **Alert Suppression by `elif` Chain:** Wash `FLT-01`, `FLT-02`, `FLT-01`, `FLT-01` (draining tank to `30.0% < 40.0%`). | **Masked Telemetry in `v1.2`:** `D-BACKWASH-ABUSE` and `D-FORCED-BACKWASH` (`< 40%`) **never fired (`0`)** because `len(recent_multi) >= 2` captured the `elif` chain. | `v1.3` converts the 4 `filter_backwash` checks into independent `if` statements. All applicable rules now fire (`H1/H2` demo alerts rise from `9` in `v1.2` to `16 CRIT` in `v1.3`: `+4` `D-MULTI-FILTER-BACKWASH` and `+3` `D-BACKWASH-ABUSE` that were previously masked at `03:15` by `if not in_maint:`). |
| **P12B** (`standby_spoof`) | **Standby Pump Pressure Spoofing:** Lower active `PMP-01` (`running=True`) to `2.5 bar`, then write `5.5 bar` to stopped standby pump `PMP-02` (`running=False`). | **State Spoofing in `v1.2`:** Station reported `pressure_bar = 5.5 bar` from a stopped pump, fooling `G-HYDRAULIC-INTERLOCK`! | `v1.3` computes `st.pressure = max((p["setpoint"] for p in st.pumps.values() if p["running"]), default=0.0)`. Writing `5.5 bar` to stopped `PMP-02` leaves `pressure_bar = 2.5 bar`. |
| **Addition A** (`fp_valve_isolation`) | **Unfixed False Positive Since `v1.0` — Legitimate Valve Isolation:** Technician at `10:15` stops `PMP-01` (`running=False`) and closes `VLV-OUT` to isolate the line. | **False Positive in `v1.0–v1.2`:** Fired `CRIT=1` (`D-DEADHEAD-RISK`) on any valve close with `pressure > 0`, and provided no way to stop `PMP-01` first. | `v1.3` supports `"running": bool` on `/api/pump/<id>/setpoint`, logs `any_pump_running`, and scopes `D-DEADHEAD-RISK` strictly to a pump **actively running (`running == True`) against `VLV-OUT == CLOSED`**. Stopping `PMP-01` → closing `VLV-OUT` at `10:15` produces **`0 CRIT, 0 WARN` (`CLEAN`)**. |

### 5.4 Packaging Verification (`audit_probes_v3.py` Probes 13A/13B against `v1.3` → fixed in `v1.3.1`)

During final packaging of `v1.3`, cross-checking `RULE_ATTACK_MAP` against `Detector.scan` and diffing `v1.0` against `v1.1–v1.3` exposed the **central methodological finding of the study**:

| Probe | Packaging Verification Vector Tested Against `v1.3` | Measured Result in `v1.1–v1.3` | Root Cause & `v1.3.1` Fix |
|---|---|---|---|
| **P13A** (`chlorine_regression`) | **Silent Regression of `D-CHLORINE-OUT-OF-BAND` (Insider / In-Window Chemical Sabotage):** Authenticated technician (`tech`) at `10:15` (inside maintenance window `08:00–18:00`) sends `POST /api/dosing/setpoint {"value": 4.5}` (toxic chlorine overdose above `[0.2, 1.0] mg/L`). | **Complete Detector Blindness in `v1.1–v1.3`:** Controller returned `HTTP 200`, chlorine rose to `4.5 mg/L`, and `Detector` produced **`CRIT=0, WARN=0` (`0` alerts)**! *(In `H1/H2` at `03:15`, the step only triggered generic `D-DEFAULT-CRED-LOGIN` and `D-OUT-OF-WINDOW-WRITE`, with zero chlorine alerts.)* | In **`v1.0`**, `Detector.scan` contained `elif ev == "dosing_setpoint":` and fired `D-CHLORINE-OUT-OF-BAND` (`CRIT`). When GLM 5.3 rewrote `Detector.scan` in **`v1.1`**, it **silently deleted that branch**, leaving `"D-CHLORINE-OUT-OF-BAND"` only in `RULE_ATTACK_MAP` and in the Guard's clamp. Because all probe batteries (`24/24`, `34/34`, `50/50`) and demo checks (`6/6`) only tested newly discovered evasion vectors or aggregated `H1/H2` `crit > 0`, **the deletion survived 3 versions undetected**. `v1.3.1` restores the `dosing_setpoint` branch (`Probe 13A` → `CRIT=1`; `H1/H2` → `17 CRIT`). |
| **P13B** (`rule_liveness_invariant`) | **Rule-Map Liveness Audit (`RULE_ATTACK_MAP ↔ Detector.scan`):** Feed synthetic events covering every rule category to a fresh `Detector()` and compute `dead_rules = set(RULE_ATTACK_MAP.keys()) - fired_rules`. | **Dead Rule Exposed in `v1.3`:** `14/15` rules fired; `dead_rules == {'D-CHLORINE-OUT-OF-BAND'}`. | `v1.3.1` adds `rule_liveness_check()` as the 1st mandatory criterion in `cmd_demo` (`7/7` checks) and in `audit_probes_v3.py`, verifying `15/15` rules in `RULE_ATTACK_MAP` fire (`0` dead rules). *(See Section 6.1 and Section 7.4 for the exact structural boundary of this invariant: it guards the `RULE_ATTACK_MAP ↔ scan` link, not the `controller ↔ scan` link.)* |

---

## 6. Detection coverage and hardening architecture

### 6.1 Execution-verified detection & prevention matrix (`v1.3.1`)

| Rule ID (Detector / Guard / Controller) | Layer | ATT&CK Mapping | Positive Verification | Negative / Legitimate Verification |
|---|---|---|---|---|
| `D-DEFAULT-CRED-LOGIN` / `G-DEFAULT-CRED-BLOCKED` | Detector (`CRIT`) / Guard (`403`) | `T1078.001` | Fires on `admin/123456` in `H1`; blocked at Guard | `tech` login with strong credential: silent |
| `D-HIDDEN-SERVICE-AUTH` / `G-HIDDEN-AUTH-BLOCKED` | Detector (`CRIT`) / Guard (`403`) | `T1190` / `T0819` | Fires on `/api/service_login` in `H2`; blocked at Guard | Not used in normal operations |
| `D-PRESSURE-OUT-OF-BAND` / `G-SETPOINT-CLAMP` | Detector (`CRIT`) / Guard (Clamp) | `T0855` | Fires on `8.5 bar` in `H1/H2`; clamped to `[2.5, 5.5] bar` by Guard | `4.2 bar` trim by `tech`: silent |
| `D-CHLORINE-OUT-OF-BAND` / `G-SETPOINT-CLAMP` | Detector (`CRIT`) / Guard (Clamp) | `T0855`, `T0879` | **Restored in `v1.3.1` (`P13A`):** Fires `CRIT` on `4.5 mg/L` both in `H1/H2` (`03:15`) and in authenticated in-window insider test (`tech` @ `10:15`); clamped to `[0.2, 1.0] mg/L` by Guard | `0.6 mg/L` trim by `tech`: silent |
| `D-DEADHEAD-RISK` / `G-VALVE-CLOSE-BLOCKED` | Detector (`CRIT`) / Guard (`403`) | `T0855`, `T0879` | Fires when closing `VLV-OUT` with `any_pump_running=True` or starting pump with `VLV-OUT=CLOSED` (`P2`) | **Addition A:** Stop `PMP-01` (`running=False`) → close `VLV-OUT` at `10:15` → **`0 CRIT, 0 WARN`** |
| `D-FORCED-BACKWASH` | Detector (`CRIT`) | `T0855`, `T0879` | Fires on API backwash outside `08:00–18:00` or when `reservoir_after < 40.0%` (`P12A`) | **P1:** 1 daytime manual backwash (`66.0%`) → **`0 CRIT, 0 WARN`** |
| `D-MULTI-FILTER-BACKWASH` | Detector (`CRIT`) | `T0855` | Fires on `>= 2` distinct filters in `30 min` OR `>= 3` distinct filters in `24h` (`P11`) | **P7A:** 2 filters washed 7 hours apart (`09:00` & `16:00`) → **`0 CRIT, 0 WARN`** |
| `D-BACKWASH-ABUSE` / `C-BACKWASH-FLEET-LIMIT` / `C-BACKWASH-DAILY-LIMIT` | Detector (`CRIT`) / Controller (`403`) | `T0855` | Fires on `>= 3` API backwashes in `60 min` (`P7B`) or `24h` (`P11`); Controller atomically blocks 3rd (`P10/P11`) | 1–2 manual backwashes per 24h: allowed & silent |
| `D-UNDERPRESSURE-DROP` / `C-HYDRAULIC-INTERLOCK` | Detector (`CRIT`) / Controller (`403`) | `T0855`, `T0879` | Fires if `pressure_after < 2.5 bar` (`P8`); Controller atomically rejects if `pressure - 0.4 < 2.5` or `tank - 12 < 40` (`Addition B`) | Normal backwash from `4.0 bar` (`-> 3.6 bar`) and `78%` (`-> 66%`): allowed |
| `D-ALARM-MUTE` / `G-ALARM-MUTE-BLOCKED` | Detector (`CRIT`) / Guard (`403`) | `TA0107` (`T0838`) | Fires on `muted=True` in `H1/H2`; Guard blocks anything except explicit `muted is False` (`P5`) | Explicit unmute (`{"muted": False}`): allowed & silent |
| `G-BAD-PATH` / `G-BAD-BODY` (`canonicalize_request`) | Guard & Controller (`400`) | Input canonicalization | Rejects `NaN`/`Inf` (`P4`), non-bool `muted` (`P5`), and all path variants `/api/login/`, `/api//login`, `%2F`, `?` (`P9/Add. C/D`) | Canonical requests pass |
| `rule_liveness_check()` (`P13B`) | Demo & Audit Invariant (`15/15`) | Structural meta-check (`RULE_ATTACK_MAP ↔ scan`) | **Invariant that prevents a rule from being removed from, or made unreachable in, the detector (`Detector.scan`)** — fails if `dead_rules != set()` | **Scope limit:** Self-referential synthetic events; guards `RULE_ATTACK_MAP ↔ scan`, **not** `controller ↔ scan` (never a proof that all detections work on live telemetry — see Section 7.4) |

### 6.2 Reference rules in `detections/` (Textual Compliance; Suricata execution-verified since 2026-11-11)

Reference rules for external SIEM/NIDS pipelines are provided in [`detections/`](detections/README.md):
- [`detections/sigma/hydrobox_default_or_service_auth.yaml`](detections/sigma/hydrobox_default_or_service_auth.yaml) — Sigma rule for default-credential (`admin`) and hidden daily-code (`service_login_success`) authentication.
- [`detections/sigma/hydrobox_hydraulic_sabotage.yaml`](detections/sigma/hydrobox_hydraulic_sabotage.yaml) — Sigma rule for out-of-band pressure/chlorine setpoints, active-pump deadheading (`valve_command` `CLOSED` with `any_pump_running: true`), and critical reservoir drain (`< 40%`).
- [`detections/sigma/web_offhours_water_hmi_write.yaml`](detections/sigma/web_offhours_water_hmi_write.yaml) — Generic webserver/reverse-proxy Sigma rule for write `POST` requests to water HMI endpoints.
- [`detections/suricata/hydrobox.rules`](detections/suricata/hydrobox.rules) — Five Suricata HTTP signatures covering `/setpoint`, `/backwash`, `/api/valve/out`, `/api/alarm/mute`, and `/api/service_login` from non-maintenance networks (`!$MAINT_NET`).
- [`detections/kql/hydrobox_hunting.kql`](detections/kql/hydrobox_hunting.kql) — Six Microsoft Sentinel KQL hunting queries, including the 30-minute burst and 24-hour patient-attacker multi-filter backwash correlations and the active-pump deadhead check.

---

## 7. What cannot be claimed (explicit limitations)

To prevent the `100% PASS` probe suites and `7/7 OK` lab metrics from creating a false sense of production readiness, the following limitations apply to every claim in this directory:

1. **Operational false positive & the fundamental limit of rate-limiting (`2 backwashes / 24h`):**
   - To stop the patient attacker (`Probe 11`, spacing backwashes 61 minutes apart), `v1.3` / `v1.3.1` enforces a hard ceiling of **2 API backwashes per 24 hours** (`GUARD_DAILY_BACKWASH_LIMIT = 2`) and alerts on the 3rd (`D-BACKWASH-ABUSE` / `D-MULTI-FILTER-BACKWASH`).
   - **Operational cost:** This ceiling **denies legitimate heavy maintenance** where an operator needs to backwash 3 or all 4 filters on the same day (for example, after a raw-water turbidity spike or seasonal filter servicing).
   - **Fundamental limit:** A rate or count limit **cannot, by construction, distinguish a patient attacker using a stolen credential from a busy technician performing major maintenance**. Only out-of-band authorization and intent (correlating commands against an authenticated, time-bounded maintenance work order / change ticket or a physical local-panel keyswitch) can separate the two — and a synthetic loopback lab has no work-order system.
2. **Cartoon physics (step arithmetic, not a hydraulic model):**
   - In `HydroboxState`, line pressure is simply set equal to the highest running pump setpoint (`st.pressure = max(setpoint for running pumps)`), and each backwash subtracts a fixed `-12.0%` from `TK-CLEAR` and `-0.4 bar` from `st.pressure`.
   - The impact numbers cited in this report (`18.0%` reservoir level, `1.7 bar` or `1.6 bar` underpressure, `6.0%` race-condition drain) are **simple step arithmetic**, not a physical hydraulic simulation. There are no pump head-flow ($H\text{–}Q$) curves, no pipe friction / Hazen-Williams losses, no demand-driven tank inflow/outflow differential equations, no water-hammer transients, no hydraulic inertia, and no PID control loop.
3. **`MTTD = 0.000 s` is a clock-resolution artifact, not real detection latency:**
   - The lab's simulated clock (`sim_now_str()`) formats timestamps at **1-second integer resolution (`%Y-%m-%d %H:%M:%S`)**, while the streaming detector thread tails a local file every `50 ms` (`0.05 s`). Because the event write and the local tail read almost always occur within the same wall-clock second, `_parse_ts(first_det) - _parse_ts(first_ev)` evaluates to **`0.000 s`**.
   - This number measures nothing about real-world detection latency, which is dominated by log forwarding, SIEM ingestion/indexing lag (seconds to minutes), and human SOC triage at 03:15 AM.
4. **Silent regression of `D-CHLORINE-OUT-OF-BAND` (`v1.1–v1.3` → fixed in `v1.3.1`) & the exact scope of the `rule_liveness_check()` invariant:**
   - **Regression found and fixed:** In `v1.0`, `D-CHLORINE-OUT-OF-BAND` existed and fired (`elif ev == "dosing_setpoint":` in `Detector.scan`). When GLM 5.3 refactored `Detector.scan` in `v1.1`, it **silently deleted that branch**, leaving `"D-CHLORINE-OUT-OF-BAND"` alive only as a dead key in `RULE_ATTACK_MAP` and in the Guard's clamp. This regression **survived three consecutive versions (`v1.1`, `v1.2`, `v1.3`) with `100% PASS` validations (`24/24`, `34/34`, `50/50`, `6/6`)** because our test suites only added new evasion probes and checked aggregate `crit > 0` on `H1/H2`, never verifying whether previously working rules still fired (`Probe 13A`: an authenticated insider `tech` at `10:15` setting chlorine to `4.5 mg/L` generated **`0 alerts`** in `v1.1–v1.3`). It was caught during independent packaging verification and restored in `v1.3.1` (`H1/H2` alerts rose from `16` to **`17 CRIT`**).
   - **Exact scope of `rule_liveness_check()` (what it guarantees and what it does NOT):** To prevent recurrence, `v1.3.1` adds `rule_liveness_check()` (`Probe 13B`), which feeds `_rule_liveness_events()` to `Detector.scan` and asserts `set(RULE_ATTACK_MAP.keys()) - fired == set()` (`15/15` rules firing). **This is strictly an invariant that prevents a rule from being removed or rendered unreachable in the detector — it closes the `RULE_ATTACK_MAP ↔ Detector.scan` link. It is NOT a proof that all detections work against real telemetry:** because `_rule_liveness_events()` is self-referential (it constructs its own synthetic event dicts), if a field emitted by the controller were renamed or omitted, real detection would break while `rule_liveness_check()` stayed green (it guards the `map ↔ scan` link, not the `controller ↔ scan` link).
5. **Loopback toy with an invented HTTP/JSON API — zero real ICS protocols:**
   - `HYDROBOX` is a synthetic Python `ThreadingHTTPServer` on `127.0.0.1` speaking an invented REST/JSON schema. It implements **zero real industrial protocols** (`Modbus TCP`, `DNP3`, `IEC 60870-5-104`, `Siemens S7comm`, `EtherNet/IP`, `OPC UA`) and no real PLC scan-cycle or ladder logic.
   - This case study demonstrates an **adversarial detection-engineering methodology (`probe → fix → re-run`)**, not turn-key readiness for a municipal water plant.
   - Furthermore, the rules in [`detections/`](detections/README.md) (**Sigma, Suricata, KQL**) are **textual compliance only** — they were written against the lab schema and never executed against a live Sigma converter, Suricata sensor, or Microsoft Sentinel workspace. **Update 2026-11-11:** the Suricata rules were later executed against Suricata 8.0.8 (pcap replay of this lab, 17/17 alerts, 0 in the negative case); the run exposed a trailing-byte evasion of sids 2026110701/2026110702, fixed in rev 2; see [`detections/suricata/verification/`](detections/suricata/verification/README.md). The Sigma and KQL rules remain textual compliance.
6. **Verifier honesty — a falsified prediction by the independent verifier:**
   - During the independent review, the external verifier (Claude) predicted before inspecting the `v1.3` implementation of `safety_interlocks` that if the builder exposed `safety_interlocks` via an HTTP endpoint or request field, an attacker could simply toggle `safety_interlocks=False` over the API to re-enable the TOCTOU/drain attacks.
   - **Result when tested:** That prediction **failed**. The builder (GLM 5.3) implemented `safety_interlocks` strictly as an internal Python constructor argument (`HydroboxState(safety_interlocks=True)`), completely unreachable from any HTTP endpoint or request payload. Recording this falsified hypothesis explicitly shows that the independent verification was genuine empirical testing rather than rubber-stamping.
   - Similarly, on **Addition A**, the Guard Proxy still blocks *all* remote `POST /api/valve/out {"state": "CLOSED"}` requests (`G-VALVE-CLOSE-BLOCKED`); the legitimate valve-isolation flow (`stop PMP-01 → close VLV-OUT → 0 alerts`) is verified against the Controller + Detector directly (modeling local HMI / field-panel isolation rather than unguarded remote proxy closure).
7. **ATT&CK taxonomy errors in LLM output require human review:**
   - In Round 0, the task prompt included a non-existent ICS technique ID (`T1692.001`), which GLM 5.3 correctly flagged under PVTE-X.
   - However, in Round 1 through `v1.3`, GLM 5.3's own `RULE_ATTACK_MAP` labeled ICS `T0879` as generic `"ICS T0879 (Damage)"` instead of its official MITRE ATT&CK for ICS title, **`T0879 — Damage to Property`** — a taxonomy error caught by external review and corrected in `v1.3.1`. LLM-generated ATT&CK mappings cannot be trusted without manual verification against the current MITRE matrix.

---

## 8. References

1. CERT Polska / CSIRT NASK — *Reports and warnings on cyberattacks targeting municipal water and wastewater treatment stations (Stacje Uzdatniania Wody) in Poland* — https://cert.pl/
2. Agencja Bezpieczeństwa Wewnętrznego (ABW) — *Statements on ICT security incidents affecting municipal water utilities (Szczytno, Małdyty, Tolkmicko, Jabłonna Lacka, Sierakowo)*.
3. ANSSI & CERT-FR — *Advisories and threat reports on internet-exposed industrial control systems (PLCs/HMIs) in water and building management sectors* — https://www.ssi.gouv.fr/ / https://www.cert.ssi.gouv.fr/
4. ENISA — *ENISA Threat Landscape & Critical Infrastructure / OT Security Reports (Water and Wastewater Sector)* — https://www.enisa.europa.eu/
5. CISA / EPA / WaterISAC — *Defending Water and Wastewater Systems from Cyber Threats (Exposed HMIs, Default Credentials, and Manual Override Interlocks)* — https://www.cisa.gov/water
6. MITRE ATT&CK® (Enterprise & ICS Matrices) — `T1596`, `T1078.001`, `T1190` (Enterprise); `T0883`, `T0819`, `T0855`, `T0838`, `T0879` (*Damage to Property*), `TA0107` (*Inhibit Response Function*) — https://attack.mitre.org/

---

## 9. License and usage

- **Code** ([`hydrostrike_lab.py`](hydrostrike_lab.py), [`audit_probes_v1.py`](audit_probes_v1.py), [`audit_probes_v2.py`](audit_probes_v2.py), [`audit_probes_v3.py`](audit_probes_v3.py), [`detections/`](detections/)): Apache-2.0 — see [`LICENSE`](LICENSE).
- **Report and documentation** (this file, [`README.md`](README.md), [`detections/README.md`](detections/README.md)): CC BY-NC-SA 4.0 — see [`LICENSE-docs`](LICENSE-docs).

Intended use. This is defensive security research. The adversary-emulation module is scope-guarded to loopback (`127.0.0.1`) and targets only this repository's synthetic controller (`HYDROBOX`); it contains nothing specific to any real product or industrial protocol. The author does not condone use of this material against systems one does not own and operate as a lab. This paragraph states intent; it is not a license term.

*Operated under the PVTE-X v1.1 verification framework with multi-auditor adversarial validation (GLM 5.3 builder + Gemini primary auditor + Claude independent verifier): Phase 1 verification tables and Section 7 "What cannot be claimed" disclosures apply to every claim in this file.*
