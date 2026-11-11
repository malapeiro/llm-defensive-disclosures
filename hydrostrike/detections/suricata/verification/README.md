# Suricata verification — Hydrostrike

**Verification level: execution-verified** (Suricata 8.0.8, offline pcap replay of the
synthetic HYDROBOX lab). Covers [`../hydrobox.rules`](../hydrobox.rules) only; the Sigma and
KQL rules of this lab remain textual compliance. The rules were not changed by this run.

## Method

1. The synthetic lab runs on loopback (`127.0.0.1`) and is attacked with its own
   `attack` chain (variants `h1` and `h2`) or with the small clients in this directory.
2. `tcpdump` records the loopback traffic of the lab port to a pcap.
3. Suricata replays the pcap offline (`-r`), loading only this lab's rule file (`-S`),
   with `-k none` because macOS loopback captures carry invalid checksums.
4. The two address groups are set on the command line:
   - **positive case:** `MAINT_NET=10.99.0.0/24`, so the `127.0.0.1` client is outside the maintenance network;
   - **negative case:** `MAINT_NET=127.0.0.1`, so the same traffic comes from a permitted source.
5. The expected alert count was written down before each run and compared with the result.

Environment of the recorded run: Suricata 8.0.8 (Homebrew), macOS on Apple Silicon,
Python 3.15.2, 2026-11-11, repository at commit `5747111`.

## Results

`suricata -T`: 5 rules loaded, 0 failed.

### Attack chain `h1` + `h2` (`pcaps/hydro_attack.pcap`, 285 packets, 20 HTTP requests)

| sid | Rule | Expected | Observed |
|---|---|---|---|
| 2026110701 | pump / chlorine setpoint write | 4 | 4 |
| 2026110702 | filter backwash command | 8 | 8 |
| 2026110703 | outlet valve actuation | 2 | 2 |
| 2026110704 | alarm suppression | 2 | 2 |
| 2026110705 | hidden daily-code service login | 1 | 1 |

Positive case: 17/17 alerts. Negative case: 0 alerts, with the same 20 HTTP requests parsed.
Six of the eight backwash requests are refused by the controller interlocks (HTTP 403); the
rule matches on the request, so they still alert.

### URI-suffix evasion attempts (`pcaps/hydro_edge.pcap`)

The suffix evasion found in Froststrike was tried here. HYDROBOX rejects every variant, so
nothing is executed and there is no detection gap:

| Request | Lab response | Alert |
|---|---|---|
| `/api/pump/PMP-01/setpoint` (control) | 200 | yes |
| `/api/pump/PMP-01/setpoint?x=1` | 400 | no |
| `/api/pump/PMP-01/setpoint;x` | 404 | no |
| `/api/pump/PMP-01/setpoint#x` | 404 | no |
| `/api/filter/FLT-01/backwash?x=1` | 400 | no |
| `/api/filter/FLT-01/backwash;x` | 404 | no |
| `/api/filter/FLT-01/backwash#x` | 404 | no |

The rules still use `endswith`. That is safe only because this controller refuses
non-canonical paths; against a controller that tolerates suffixes the same rules would be
evadable, as shown in `froststrike/detections/suricata/verification/`.

## Limits

- **Synthetic telemetry.** The traffic comes from the lab in this repository, on loopback.
  This is not validation against a real controller or a production network.
- **Source-based, not behaviour-based.** The rules alert on any config/actuation request from
  outside `$MAINT_NET`. A legitimate technician working from outside that network raises the
  same alerts as the attacker.
- **Plaintext HTTP only.** `http.method` / `http.uri` are visible only on plaintext HTTP or
  where TLS is terminated at the sensor.
- **One engine version.** Executed on Suricata 8.0.8 only.

## Reproduce

```bash
bash verify.sh              # replays the committed pcaps; prints PASS/FAIL per scenario
bash verify.sh --mutation   # removes each rule in turn and confirms its alerts disappear
```

`verify.sh` exits non-zero on any mismatch, so a rule that is deleted or broken later
fails the check (rule-liveness). To regenerate a capture instead of using the committed one
(needs `sudo` for `tcpdump`):

```bash
bash capture.sh attack     # or: edge
PCAP_DIR=./recapture bash verify.sh
```

The pcaps contain only loopback traffic of the synthetic lab, including its built-in weak
credentials and session tokens, which are already public in the lab source.

## Who did what

The runs were executed by the author on his own machine. Claude (Anthropic) wrote the capture
and verification scripts, read the Suricata logs and drafted this note. Mistral Vibe reviewed
the claims that rest on reading the lab and rule source code; it did not execute anything.
