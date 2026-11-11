# Detections — Froststrike reference rules

Reference detection content for the FROSTBOX lab audit schema (`evidence/audit_*.jsonl`).
The Suricata rules are **execution-verified** against Suricata 8.0.8 on pcaps of the
synthetic lab (see [`suricata/verification/`](suricata/verification/README.md)). The two
audit-log Sigma rules are **execution-verified** against the lab audit log with pySigma and
SQLite (see [`sigma/verification/`](sigma/verification/README.md)). The webserver-category
Sigma rule and the KQL queries are **textual compliance**. In every case, validate against your own
pipeline: map the log source fields to whatever your forwarder emits, run the positive
and negative cases from the lab demo, and only then promote to production.

| File | Engine | Covers |
|---|---|---|
| `sigma/frostbox_setpoint_band.yaml` | Sigma | Out-of-band setpoint writes (D-SETPOINT-RANGE) |
| `sigma/frostbox_service_auth.yaml` | Sigma | Hidden daily-code service auth path (D-SERVICE-AUTH) |
| `sigma/web_offhours_ot_config.yaml` | Sigma (webserver category) | Off-hours config POSTs via reverse-proxy logs |
| `suricata/frostbox.rules` | Suricata 5+ (executed on 8.0.8) | Network-level signatures for config-write and hidden-auth endpoints |
| `kql/frostbox_hunting.kql` | Microsoft Sentinel KQL | Hunting queries over an ingested audit table |

## Caveats

- **TLS/HTTPS (Suricata):** the signatures in `suricata/frostbox.rules` inspect
  `http.method` / `http.uri`, which are only visible when the traffic toward the
  supervisory interfaces is plaintext HTTP, or when TLS is terminated or
  intercepted at the sensor (TLS-terminating reverse proxy, SSL-split/ICAP
  tap). Against HTTPS pass-through traffic these rules see nothing — deploy
  them at a point where the traffic is decrypted, and rely on the log-based
  rules (Sigma, KQL) where it is not.
- **Store timezone (KQL):** queries #2, #4 and #5 in `kql/frostbox_hunting.kql`
  compare event time against the store's *local* maintenance and defrost
  windows, using `datetime_utc_to_local(TimeGenerated, store_tz)` with
  `store_tz` set to `"Europe/Lisbon"` by default. Set it per store/site; a UTC
  hour comparison drifts by the offset and mis-flags window edges.
- **One query at a time (KQL):** run each hunting query individually. The
  `let store_tz` declaration is repeated in each query that needs it; pasting
  the whole file into a single execution window fails on let-redefinition.

Field names (`cs-method`, `c-uri`) in the webserver Sigma rule follow the Sigma
`webserver` log-source category used by SigmaHQ rules; adapt them if your proxy
log schema differs.
