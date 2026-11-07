# LLM Defensive Disclosures

Sérgio Azevedo (malapeiro) — Defensive security artifacts produced with LLMs: detection engineering, hardening, and prevention tooling for specific threats, each labeled with its verification level.

Contact: sergio.azevedo.security@gmail.com

## Scope and relationship to other repositories

This is the defensive counterpart to `llm-weaponization-disclosures`. Where that repository documents offensive artifacts an LLM produced under guardrail bypass, this one documents **defensive** artifacts produced with the same adversarial-validation method — detectors, detection rules, guard/prevention controls, and hardening labs — against a specific, real-world threat.

It is also distinct from `llm-alignment-research`, which records behavioral and alignment observations at the level of model behavior. Here the unit is a concrete, runnable defensive artifact, not a behavioral observation.

**Inclusion criterion:** a case belongs here if it produced a concrete, runnable defensive artifact — a detector, a set of detection rules, a prevention control, or a hardening lab — for a specific threat, not an abstract recommendation.

## Method

Each case is built and then attacked: probe → fix → re-run, with each round executed and verified. Limits are stated plainly in a "what cannot be claimed" section rather than smoothed over; a case never claims more coverage than was demonstrated.

## Verification levels

Every artifact is labeled with one of two levels, stated plainly and never blurred:

- **Execution-verified** — the artifact (detector, guard, simulation) was run in an isolated environment and confirmed to behave as described.
- **Textual compliance** — the artifact (e.g. Sigma/Suricata/KQL rules) was written against a documented schema and conventions but not executed against its target engine. Lowest evidentiary weight; validate before production use.

## Note on emulation code

Where a case includes adversary-emulation code (to generate the telemetry a defense is tested against), it is sanitized: it targets only the case's own synthetic device, on loopback, and reproduces no real vendor endpoint, protocol, firmware path, password algorithm or exploit chain. It cannot be used against real equipment.

## Case studies

- **[Froststrike](froststrike/)** — Detection engineering and a write-protecting guard proxy for the 2026 European supermarket refrigeration sabotage campaign (Danfoss AK-SM / Copeland-Dixell XWEB class). Synthetic FROSTBOX controller, streaming detection engine, guard proxy, and reference Sigma/Suricata/KQL rules, hardened across four adversarial probe rounds. Verification: **execution-verified** (detection engine and guard proxy); **textual compliance** (Sigma/Suricata/KQL rules). See `froststrike/froststrike_report.md`.
- **[Hydrostrike](hydrostrike/)** — Adversarial detection engineering and atomic interlock hardening for European municipal water treatment and pumping station HMI/SCADA sabotage (ABW / CERT Polska *Stacje Uzdatniania Wody* intrusions and ANSSI / CERT-FR / ENISA advisories). Synthetic HYDROBOX controller, streaming detection engine, guard proxy, and multi-auditor adversarial probe scripts (`v1.0 → v1.3.1`: uncovering and fixing three HTTP/JSON parser differentials, a `NaN` clamp bypass, cross-subsystem underpressure coupling, a `ThreadingHTTPServer` TOCTOU race condition, 61-minute patient-attacker pacing, `elif` alert masking, standby-pump pressure spoofing, a legitimate valve-isolation false positive, and a silent refactoring regression where `D-CHLORINE-OUT-OF-BAND` was deleted in `v1.1` and survived three versions of `100% PASS` validation before being restored with a rule-liveness invariant in `v1.3.1`). Verification: **execution-verified** (synthetic lab, detection engine, guard proxy, and 3 probe batteries); **textual compliance** (Sigma/Suricata/KQL rules). Explicit operational, invariant-scope, and physical-model limitations documented in Section 7 of `hydrostrike/hydrostrike_report.md`.

## Ethics

All work is done in the researcher's own isolated environment against synthetic targets; no production or third-party systems are involved. Emulation code is scope-guarded to loopback and contains nothing specific to a real product.

## License

- **Code**: Apache-2.0 (see `LICENSE`).
- **Reports and documentation**: CC BY-NC-SA 4.0 (see `LICENSE-docs`).

Intentionally more open than the companion `llm-weaponization-disclosures` (CC BY-NC-ND): defensive artifacts are meant to be adopted, adapted and improved, so derivatives are permitted.
