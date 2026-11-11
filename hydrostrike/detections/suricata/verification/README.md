# Suricata verification — Hydrostrike

**Verification level: execution-verified** (Suricata 8.0.8, offline pcap replay of the
synthetic HYDROBOX lab). Covers [`../hydrobox.rules`](../hydrobox.rules) only; the Sigma and
KQL rules of this lab remain textual compliance. The run exposed a trailing-byte evasion and
then a wider request-line tokenisation gap; both are fixed (see below).

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

`suricata -T`: 5 rules loaded, 0 failed (6 rules since sid 2026110706 was added; `verify.sh`
checks the loaded-rule count on every replay).

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

### Finding 2: request-line tokenisation (rev 2 and the prefix-anchored rules)

The trailing-byte finding was one case of a wider difference. Python's `http.server`
tokenises the whole request line with `str.split()`: any run of `0x09`-`0x0d`, `0x1c`-`0x20`,
`0x85` or `0xa0` separates the three words, and leading or trailing runs are dropped.
Suricata 8.0.8 splits the line differently, so the two can disagree on what the method and
the URI are.

Measurement first, rules unchanged (rev 2), 25 setpoint request lines, per request from
`eve.json` (each request carries its case label in the `User-Agent` header). The lab
executed 22 of them; 10 of those raised no alert:

| Request line (setpoint) | What Suricata 8.0.8 parsed | rev 2 |
|---|---|---|
| run of bytes after the path (`\xa0\xa0`, `\x1c\x85`, `\x0b\x1f\xa0`) | bytes stay in the URI | **silent** (3) |
| lone CR after the path | URI ends at the CR | alert |
| CR then `\xa0` after the path | both bytes stay in the URI | **silent** |
| space mixed with `\xa0` (` \xa0 `, `\xa0 \xa0`) | bytes and space stay in the URI | **silent** (2) |
| `\xa0` or `\x1c` in place of the space before the version | `HTTP/1.1` is glued to the URI, no protocol | **silent** (2) |
| `\xa0` in place of the space after `POST` (alone, or both separators) | the path ends up in the method token | **silent** (2) |
| tab as either separator, two spaces, byte before the path, before `POST` or after the version, `HTTP/1.0`, `0.9`, `1.9` | method and URI as expected (a byte before the path stays in the URI) | alert |
| no version (lab: 400) | URI as expected, no protocol | alert |
| `\xa0\xa0x`, four words (lab: 400) | bytes stay in the URI | silent |

A byte before the path also breaks a `startswith` match, and `canonicalize_request` accepts a path without its leading slash (`api/valve/out`). That was confirmed on the
lab side only; the previous rules were not run against those requests.

### Fix (rev 3 of 2026110701/2026110702, rev 2 of 2026110703-2026110705, new 2026110706)

```
2026110701: http.uri.raw; content:"/setpoint"; pcre:"/\/setpoint(?:[\x09-\x0d\x1c-\x20\x85\xa0]+HTTP\/0*[01]\.\d+)?[\x09-\x0d\x1c-\x20\x85\xa0]*$/";
2026110702: same pattern with /backwash
2026110703: http.uri.raw; content:"api/valve/out"; pcre:"/^[\x09-\x0d\x1c-\x20\x85\xa0]*\/?api\/valve\/out/";
2026110704, 2026110705: same pattern with api/alarm/mute and api/service_login
2026110706: http.method; content:"/api/";   (new: API path inside the method token)
```

The anchored rules accept any run of the separator bytes after the path, and a version
token glued to the URI. The prefix rules accept separator bytes before the path and a
missing leading slash. The new rule fires when Suricata's method token contains the API
path, which is what it parses when a separator byte replaces the space after the method.

`pcaps/hydro_reqline.pcap` (`reqline_client.py`, 50 requests over all endpoints that have a rule,
fresh server), per request from `eve.json`: all 39 requests the lab routes raise an
alert, by their endpoint sid or by 2026110706. Of the 11 requests the lab rejects, 8 stay
silent and 3 alert: the setpoint requests without a version (400), with `0x01` before the path (404) and with
an absolute URI (400). Those three were listed as accepted over-alerts in `verify.sh`
before the run. Total 42/42; the counts of the other captures are unchanged.

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
  target.
- **Tested request lines only.** The request-line battery covers the forms listed above, mostly
  with `0xa0` as the odd separator. It is not a proof over every byte in every position, and
  header lines and bodies were not varied.
- **Over-alerts on rejected requests.** Three requests that the lab rejects still alert (see
  Finding 2). The rules match the request, not the response.
- **Method-token rule.** sid 2026110706 depends on how Suricata 8.0.8 fills `http.method` for a
  request line it cannot split; another engine version may behave differently.
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
bash capture.sh attack     # or: edge | rawbyte | reqline
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

For the request-line finding: Qwen pointed out, from a Python-side probe, that runs of bytes
pass the one-byte pattern and proposed a lone CR (runs confirmed; a lone CR alone is not an
evasion, because Suricata also ends the URI there). Claude extended the battery to the
separator and prefix forms, wrote the client and the rules, and read the logs; the author ran
the captures and Suricata. The first run with the fix executed the previous client and rules,
because the updated files had not reached the working copy; it was repeated after comparing
file checksums, and `hydro_reqline.pcap` is the repeat.
