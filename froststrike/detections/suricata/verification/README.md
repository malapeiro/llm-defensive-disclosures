# Suricata verification — Froststrike

**Verification level: execution-verified** (Suricata 8.0.8, offline pcap replay of the
synthetic FROSTBOX lab). Covers [`../frostbox.rules`](../frostbox.rules) only; the Sigma and
KQL rules of this lab remain textual compliance.

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

`suricata -T`: 4 rules loaded, 0 failed.

### Attack chain `h1` + `h2` (`pcaps/frost_attack.pcap`, 610 packets, 42 HTTP requests)

| sid | Rule | Expected | Observed |
|---|---|---|---|
| 2026110101 | setpoint write | 12 | 12 |
| 2026110102 | forced defrost | 12 | 12 |
| 2026110103 | alarm configuration change | 12 | 12 |
| 2026110104 | hidden service-code login | 1 | 1 |

Positive case: 37/37 alerts. Negative case: 0 alerts, with the same 42 HTTP requests parsed.
These counts are identical for rev 2 and rev 3 of the rule file.

### Finding: URI-suffix evasion of sids 2026110101 and 2026110102 (rev 2)

Rev 2 of both rules required the URI to end in `/setpoint` or `/defrost`
(`content:"..."; endswith;`). The FROSTBOX handler routes on `urlparse(self.path).path`,
which drops the query string, path parameters and fragment. A request with any of those
suffixes is therefore executed by the controller but does not end in `/setpoint`, and the
rule stays silent. The rule passed `suricata -T` and looked correct; the gap only showed
when the rules were run against traffic the controller actually accepts.

`pcaps/frost_evasion.pcap` and `pcaps/frost_edge.pcap`, fresh server each:

| Request | Lab response | Effect | rev 2 | rev 3 |
|---|---|---|---|---|
| `/api/case/FZ-01/setpoint` (control) | 200 | setpoint -20 -> 41 | alert | alert |
| `/api/case/FZ-02/setpoint?x=1` | 200 | setpoint -20 -> 42 | **silent** | alert |
| `/api/case/FZ-03/setpoint;x` | 200 | setpoint -20 -> 43 | **silent** | alert |
| `/api/case/FZ-02/setpoint#x` | 200 | executed | **silent** | alert |
| `/api/case/CH-01/defrost` (control) | 200 | executed | alert | alert |
| `/api/case/CH-02/defrost?x=1` | 200 | executed | **silent** | alert |
| `/api/case/CH-03/defrost;x` | 200 | executed | **silent** | alert |
| `/api/case/CH-01/defrost#x` | 200 | executed | **silent** | alert |
| `/api/alarm/config?x=1` | 200 | executed | alert | alert |
| `/api/case/FZ-03/setpointx` (near miss) | 404 | rejected | silent | silent |
| `/api/case/FZ-03/setpoint/extra` (near miss) | 404 | rejected | silent | silent |
| `/api/case/CH-02/defrostx` (near miss) | 404 | rejected | silent | silent |

Alert totals per pcap: evasion 3 (rev 2) vs 7 (rev 3); edge 1 (rev 2) vs 3 (rev 3).
Sid 2026110103 was never affected because it does not anchor the match.

### Fix (rev 3)

```
2026110101: content:"/setpoint"; pcre:"/\/setpoint(?:[?\x3b#]|$)/";
2026110102: content:"/defrost";  pcre:"/\/defrost(?:[?\x3b#]|$)/";
```

`\x3b` is the semicolon, which cannot appear literally inside a Suricata rule option.
With rev 3 every request the controller executes raises an alert and every request it
rejects stays silent, and the attack-chain counts are unchanged (37 / 0).

To see the rev 2 behaviour again:

```bash
git show 5747111:froststrike/detections/suricata/frostbox.rules > /tmp/frostbox_rev2.rules
RULES=/tmp/frostbox_rev2.rules bash verify.sh   # the two evasion scenarios FAIL
```

## Limits

- **Synthetic telemetry.** The traffic comes from the lab in this repository, on loopback.
  This is not validation against a real controller or a production network.
- **Source-based, not behaviour-based.** The rules alert on any config/actuation request from
  outside `$MAINT_NET`. A legitimate technician working from outside that network raises the
  same alerts as the attacker.
- **Plaintext HTTP only.** `http.method` / `http.uri` are visible only on plaintext HTTP or
  where TLS is terminated at the sensor.
- **One engine version.** Executed on Suricata 8.0.8 only.
- **Suffix list.** The pcre covers the three separators the lab's router ignores (`?`, `;`, `#`).
  A different controller may normalise URIs differently; re-derive the list for your target.

## Note on the recorded run

The first capture scripts stopped the lab server with `SIGINT`, which background jobs of a
non-interactive shell ignore, so the first evasion attempt reached a stale server left over
from the attack capture. The scripts were fixed (`SIGTERM` plus a port-in-use check) and the
evasion capture was repeated against a fresh server; `frost_evasion.pcap` is the repeat.

## Reproduce

```bash
bash verify.sh              # replays the committed pcaps; prints PASS/FAIL per scenario
bash verify.sh --mutation   # removes each rule in turn and confirms its alerts disappear
```

`verify.sh` exits non-zero on any mismatch, so a rule that is deleted or broken later
fails the check (rule-liveness). To regenerate a capture instead of using the committed one
(needs `sudo` for `tcpdump`):

```bash
bash capture.sh attack     # or: evasion | edge
PCAP_DIR=./recapture bash verify.sh
```

The pcaps contain only loopback traffic of the synthetic lab, including its built-in weak
credentials and session tokens, which are already public in the lab source.

## Who did what

The runs were executed by the author on his own machine. Claude (Anthropic) wrote the capture
and verification scripts, read the Suricata logs and drafted this note. Mistral Vibe reviewed
the claims that rest on reading the lab and rule source code; it did not execute anything.
