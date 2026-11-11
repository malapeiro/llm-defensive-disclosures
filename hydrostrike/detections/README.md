# Detections — Hydrostrike reference rules

Reference detection content for the `HYDROBOX` lab audit schema (`controller_audit_*.jsonl`).
The Suricata rules are **execution-verified** against Suricata 8.0.8 on pcaps of the
synthetic lab (see [`suricata/verification/`](suricata/verification/README.md)). The Sigma
and KQL rules are **textual compliance** only: they were written against the lab audit
schema and public log conventions, and have **not** been executed against Sigma or
Microsoft Sentinel engines. Map the field names to your own forwarder,
run both the positive (`H1`/`H2`) and negative (`NEG`, including legitimate pump-stop
valve isolation and single daytime backwash) test cases, and validate before production use.

| File | Engine | Covers |
|---|---|---|
| `sigma/hydrobox_default_or_service_auth.yaml` | Sigma | Default-credential (`admin`) and hidden daily-code (`service_login_success`) authentication (`D-DEFAULT-CRED-LOGIN`, `D-HIDDEN-SERVICE-AUTH`) |
| `sigma/hydrobox_hydraulic_sabotage.yaml` | Sigma | Out-of-band pressure/chlorine setpoints, active-pump deadhead (`VLV-OUT` closed with `any_pump_running: true`), underpressure drop (`< 2.5 bar`), and reservoir drain (`< 40%`) |
| `sigma/web_offhours_water_hmi_write.yaml` | Sigma (`webserver` category) | Remote configuration/actuation `POST` requests to water HMI endpoints |
| `suricata/hydrobox.rules` | Suricata 5+ (executed on 8.0.8) | Network-level HTTP signatures for setpoint, backwash, valve, alarm-mute, and hidden service-login endpoints from non-maintenance sources |
| `kql/hydrobox_hunting.kql` | Microsoft Sentinel KQL | Six hunting queries over `HydroboxAudit_CL`, including active-pump deadhead, 30-min multi-filter burst, and 24-hour patient-attacker backwash correlation |

## Caveats

- **TLS/HTTPS (Suricata):** `suricata/hydrobox.rules` inspects `http.method` and `http.uri`,
  which are only visible on plaintext HTTP or behind a TLS-terminating reverse proxy / sensor.
- **Rate limits vs. maintenance intent (KQL queries #4 and #5):** As documented in Section 7.1
  of [`hydrostrike_report.md`](../hydrostrike_report.md), any threshold on daily backwash count
  (`>= 3` in 24h) will false-positive on legitimate heavy maintenance of 3+ filters unless
  correlated with an out-of-band maintenance ticket / work-order ID.
- **Active-pump deadhead scoping (Sigma & KQL query #2):** Per `Addition A` in the adversarial
  audit, closing `VLV-OUT` after stopping all pumps (`any_pump_running == false`) is a legitimate
  hydraulic isolation procedure. Detection rules must require `any_pump_running == true` (or
  commanding `running == true` while `valve == "CLOSED"`).
