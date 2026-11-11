# Suricata verification — Hydrostrike

**Verification level: execution-verified** (Suricata 8.0.8, offline pcap replay of the
synthetic HYDROBOX lab). Covers [`../hydrobox.rules`](../hydrobox.rules) only; the Sigma and
KQL rules of this lab remain textual compliance. The run exposed a trailing-byte evasion of
sids 2026110701 and 2026110702, fixed in rev 2 (see below).

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
Python 3.15.2, 2026-11-11, repository at commit `5747111` (attack and edge captures) and at
`4211db6` plus the rev 2 change (trailing-byte capture).

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
nothing is executed and these suffixes open no detection gap:

| Request | Lab response | Alert |
|---|---|---|
| `/api/pump/PMP-01/setpoint` (control) | 200 | yes |
| `/api/pump/PMP-01/setpoint?x=1` | 400 | no |
| `/api/pump/PMP-01/setpoint;x` | 404 | no |
| `/api/pump/PMP-01/setpoint#x` | 404 | no |
| `/api/filter/FLT-01/backwash?x=1` | 400 | no |
| `/api/filter/FLT-01/backwash;x` | 404 | no |
| `/api/filter/FLT-01/backwash#x` | 404 | no |

After this capture the rules were left on `endswith`, on the reasoning that this controller
refuses non-canonical paths. That reasoning was incomplete: the canonicalizer only sees the
path after `http.server` has parsed the request line, as the next section shows.

### Finding: trailing-byte evasion of sids 2026110701 and 2026110702 (rev 1)

Python's `http.server` splits the request line with `str.split()`, which treats `0x09`,
`0x0b`, `0x0c`, `0x1c`-`0x1f`, `0x85` and `0xa0` as whitespace. One such byte right after
the path is dropped before `canonicalize_request` runs, so `POST /api/pump/PMP-01/setpoint\xa0`
is routed as the canonical request. Suricata keeps some of these bytes in the URI, and
`endswith` then fails.

`pcaps/hydro_rawbyte.pcap` (`rawbyte_client.py`, raw socket, fresh server), per request
from `eve.json`:

| Byte after the path | Lab response | rev 1 | rev 2 |
|---|---|---|---|
| none (control, setpoint and backwash) | 200 | alert | alert |
| `0x0b`, `0x0c` | 200 (backwash `0x0c`: 403, interlock) | alert | alert |
| `0xa0`, `0x85` | 200 | **silent** | alert |
| `0x1c`, `0x1f` | 200 | **silent** | alert |
| `0x09`, `0x1d`, `0x1e` | 200 | not recorded | alert |
| `0xa0` then `x` (near miss) | 400 | silent | silent |
| `0x01` (near miss) | 404 | silent | silent |

The rev 1 column comes from a first capture with six trailing bytes: 5 of the 10 routed
requests raised no alert (four setpoint writes, one backwash). `0x09`, `0x1d` and `0x1e`
were added to the client afterwards and were only run against rev 2. Suricata ends the URI
at `0x09`, `0x0b` and `0x0c` itself, so those requests always looked canonical.

### Fix (rev 2)

```
2026110701: http.uri.raw; content:"/setpoint"; pcre:"/\/setpoint[\x09\x0b\x0c\x1c-\x1f\x85\xa0]?$/";
2026110702: http.uri.raw; content:"/backwash"; pcre:"/\/backwash[\x09\x0b\x0c\x1c-\x1f\x85\xa0]?$/";
```

With rev 2, each of the 13 requests in the capture that the controller routes raises an
alert and both rejected requests stay silent; the attack-chain and suffix counts are
unchanged (17 / 0, 1). The Python detection engine and the guard proxy are not affected:
they see the request after `http.server` has dropped the byte.

## Limits

- **Synthetic telemetry.** The traffic comes from the lab in this repository, on loopback.
  This is not validation against a real controller or a production network.
- **Source-based, not behaviour-based.** The rules alert on any config/actuation request from
  outside `$MAINT_NET`. A legitimate technician working from outside that network raises the
  same alerts as the attacker.
- **Plaintext HTTP only.** `http.method` / `http.uri` are visible only on plaintext HTTP or
  where TLS is terminated at the sensor.
- **One engine version.** Executed on Suricata 8.0.8 only.
- **Trailing-byte list.** The bytes in the pcre are the ones Python's `http.server` drops. A
  different controller may parse the request line differently; re-derive the list for your
  target. Nine trailing bytes and two near misses were tested, one byte per request.
- **Raw URI.** Since rev 2 the two anchored rules read `http.uri.raw`, with no percent-decoding,
  which fits this lab's canonicalizer (it rejects encoded paths).

## Reproduce

```bash
bash verify.sh              # replays the committed pcaps; prints PASS/FAIL per scenario
bash verify.sh --mutation   # removes each rule in turn and confirms its alerts disappear
```

`verify.sh` exits non-zero on any mismatch, so a rule that is deleted or broken later
fails the check (rule-liveness). To regenerate a capture instead of using the committed one
(needs `sudo` for `tcpdump`):

```bash
bash capture.sh attack     # or: edge | rawbyte
PCAP_DIR=./recapture bash verify.sh
```

The pcaps contain only loopback traffic of the synthetic lab, including its built-in weak
credentials and session tokens, which are already public in the lab source.

## Who did what

The runs were executed by the author on his own machine. Claude (Anthropic) wrote the capture
and verification scripts, read the Suricata logs and drafted this note. Mistral Vibe reviewed
the claims that rest on reading the lab and rule source code; it did not execute anything.

For the trailing-byte finding: a review by Qwen suggested a further edge battery (the
specific cases it proposed did not hold when tested). Claude found the trailing-byte
behaviour by running the lab without Suricata, wrote the client and the rev 2 candidate, and
read the logs; the author ran the captures and Suricata.
