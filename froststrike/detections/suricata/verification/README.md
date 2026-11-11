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
6. From the matrix capture on, the check is per request: `capture.sh` records each request's
   label, client port and lab status, and writes a manifest with the checksums of the lab and
   the client; `verify.sh` refuses to replay a capture whose generators no longer match, and
   `check_requests.py` applies the routed/rejected invariant to every request.

Environment of the recorded run: Suricata 8.0.8 (Homebrew), macOS on Apple Silicon,
Python 3.15.2, 2026-11-11, repository at commit `5747111` (attack, evasion and edge captures)
and at `4211db6` plus the rev 4 change (trailing-byte capture).

## Results

`suricata -T`: 4 rules loaded, 0 failed (5 rules since sid 2026110105 was added; `verify.sh`
checks the loaded-rule count on every replay).

### Attack chain `h1` + `h2` (`pcaps/frost_attack.pcap`, 610 packets, 42 HTTP requests)

| sid | Rule | Expected | Observed |
|---|---|---|---|
| 2026110101 | setpoint write | 12 | 12 |
| 2026110102 | forced defrost | 12 | 12 |
| 2026110103 | alarm configuration change | 12 | 12 |
| 2026110104 | hidden service-code login | 1 | 1 |

Positive case: 37/37 alerts. Negative case: 0 alerts, with the same 42 HTTP requests parsed.
These counts are identical for rev 2, rev 3 and rev 4 of the rule file.

### Finding: URI-suffix evasion of sids 2026110101 and 2026110102 (rev 2)

Rev 2 of both rules required the URI to end in `/setpoint` or `/defrost`
(`content:"..."; endswith;`). The FROSTBOX handler routes on `urlparse(self.path).path`,
which drops the query string, path parameters and fragment. A request with any of those
suffixes is therefore executed by the controller but does not end in `/setpoint`, and the
rule stays silent. The rule passed `suricata -T` and looked correct; the gap only showed
when the rules were run against traffic the controller actually accepts.

`pcaps/frost_evasion.pcap` and `pcaps/frost_edge.pcap`, fresh server each:

| Request | pcap | Lab response | Effect | rev 2 | rev 3 |
|---|---|---|---|---|---|
| `/api/case/FZ-01/setpoint` (control) | evasion, edge | 200 | setpoint -20 -> 41 | alert | alert |
| `/api/case/FZ-02/setpoint?x=1` | evasion | 200 | setpoint -20 -> 42 | **silent** | alert |
| `/api/case/FZ-03/setpoint;x` | evasion | 200 | setpoint -20 -> 43 | **silent** | alert |
| `/api/case/FZ-02/setpoint#x` | edge | 200 | executed | **silent** | alert |
| `/api/case/CH-01/defrost` (control) | evasion | 200 | executed | alert | alert |
| `/api/case/CH-02/defrost?x=1` | evasion | 200 | executed | **silent** | alert |
| `/api/case/CH-03/defrost;x` | evasion | 200 | executed | **silent** | alert |
| `/api/case/CH-01/defrost#x` | edge | 200 | executed | **silent** | alert |
| `/api/alarm/config?x=1` | evasion | 200 | executed | alert | alert |
| `/api/case/FZ-03/setpointx` (near miss) | edge | 404 | rejected | silent | silent |
| `/api/case/FZ-03/setpoint/extra` (near miss) | edge | 404 | rejected | silent | silent |
| `/api/case/CH-02/defrostx` (near miss) | edge | 404 | rejected | silent | silent |

Alert totals per pcap: evasion 3 (rev 2) vs 7 (rev 3); edge 1 (rev 2) vs 3 (rev 3).
Sid 2026110103 was never affected because it does not anchor the match.

### Fix (rev 3)

```
2026110101: content:"/setpoint"; pcre:"/\/setpoint(?:[?\x3b#]|$)/";
2026110102: content:"/defrost";  pcre:"/\/defrost(?:[?\x3b#]|$)/";
```

`\x3b` is the semicolon, which cannot appear literally inside a Suricata rule option.
With rev 3, every tested request that the controller executes raises an alert and every
tested request that it rejects stays silent (the 12 rows in the table above; 13 requests,
because the setpoint control is sent in both captures, with values 41 and 44), and the
attack-chain counts are unchanged (37 / 0).

To see the rev 2 behaviour again:

```bash
git show 5747111:froststrike/detections/suricata/frostbox.rules > /tmp/frostbox_rev2.rules
RULES=/tmp/frostbox_rev2.rules bash verify.sh   # the two evasion scenarios FAIL
```

### Finding 2: trailing-byte evasion of sids 2026110101 and 2026110102 (rev 3)

Python's `http.server` splits the request line with `str.split()`, which treats `0x09`,
`0x0b`, `0x0c`, `0x1c`-`0x1f`, `0x85` and `0xa0` as whitespace. One such byte right after
the path is dropped before the handler sees it, so `POST /api/case/FZ-01/setpoint\x1c`
is routed and executed as `/setpoint`. Suricata keeps some of these bytes in the URI, and
rev 3 only accepted `?`, `;`, `#` or end of buffer after the path.

`pcaps/frost_rawbyte.pcap` (`rawbyte_client.py`, raw socket, fresh server), per request
from `eve.json`:

| Byte after the path | Lab response | rev 3 | rev 4 |
|---|---|---|---|
| none (control, setpoint and defrost) | 200 | alert | alert |
| `0x0b`, `0x0c` | 200 | alert | alert |
| `0xa0`, `0x85` | 200 | alert | alert |
| `0x1c`, `0x1f` | 200 | **silent** | alert |
| `0x09`, `0x1d`, `0x1e` | 200 | not recorded | alert |
| `0xa0` then `x` (near miss) | 400 | alert | silent |
| `0x01` (near miss) | 404 | silent | silent |

The rev 3 column comes from a first capture with six trailing bytes; `0x09`, `0x1d` and
`0x1e` were added to the client afterwards and were only run against rev 4. Suricata ends
the URI at `0x09`, `0x0b` and `0x0c` itself, so those requests always looked canonical.
Why rev 3 matched `0xa0` and `0x85` in the normalised `http.uri` was not investigated.

The first run reported 9 alerts where 10 were expected, which reads as one miss. The
per-request log shows two misses (`0x1c`, `0x1f`) and one alert on a rejected request
(`0xa0x`, HTTP 400). Per-sid totals can hide a miss behind an unrelated hit; the
per-request view in `eve.json` is the evidence, the totals are only the regression check.

### Fix (rev 4)

```
2026110101: http.uri.raw; content:"/setpoint"; pcre:"/\/setpoint(?:[?\x3b#]|[\x09\x0b\x0c\x1c-\x1f\x85\xa0]?$)/";
2026110102: http.uri.raw; content:"/defrost";  pcre:"/\/defrost(?:[?\x3b#]|[\x09\x0b\x0c\x1c-\x1f\x85\xa0]?$)/";
```

The match moved from `http.uri` to `http.uri.raw` because the controller routes on the raw
path, and the pcre accepts one trailing byte from the set above. With rev 4, each of the
13 requests in the capture that the controller executes raises an alert and both rejected
requests stay silent; the counts of the other three captures are unchanged (37 / 0, 7, 3).

### Finding 3: request-line tokenisation (rev 4 and the prefix-anchored rules)

The trailing-byte finding was one case of a wider difference. Python's `http.server`
tokenises the whole request line with `str.split()`: any run of `0x09`-`0x0d`, `0x1c`-`0x20`,
`0x85` or `0xa0` separates the three words, and leading or trailing runs are dropped.
Suricata 8.0.8 splits the line differently, so the two can disagree on what the method and
the URI are.

Measurement first, rules unchanged (rev 4), 25 setpoint request lines, per request from
`eve.json` (each request carries its case label in the `User-Agent` header). The lab
executed 22 of them; 10 of those raised no alert:

| Request line (setpoint) | What Suricata 8.0.8 parsed | rev 4 |
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

A byte before the path also breaks a `startswith` match. That was confirmed on the
lab side only; the previous rules were not run against those requests.

### Fix (rev 5 of 2026110101/2026110102, rev 3 of 2026110104, new 2026110105)

```
2026110101: http.uri.raw; content:"/setpoint"; pcre:"/\/setpoint(?:[?\x3b#]|(?:[\x09-\x0d\x1c-\x20\x85\xa0]+HTTP\/0*[01]\.\d+)?[\x09-\x0d\x1c-\x20\x85\xa0]*$)/";
2026110102: same pattern with /defrost
2026110104: http.uri.raw; content:"/api/service/login"; pcre:"/^[\x00-\x20\x85\xa0]*(?:[A-Za-z][A-Za-z0-9+.\-]*:\/\/[^\/?#]*)?\/api\/service\/login/";
2026110105: http.method; content:"/api/";   (new: API path inside the method token)
```

The anchored rules accept any run of the separator bytes after the path, and a version
token glued to the URI. The service-login rule accepts the bytes that `urlparse` strips
before the path and an absolute URI. The new rule fires when Suricata's method token
contains the API path, which is what it parses when a separator byte replaces the space
after the method.

`pcaps/frost_reqline.pcap` (`reqline_client.py`, 44 requests over all endpoints that have a rule,
fresh server), per request from `eve.json`: all 38 requests the lab routes raise an
alert, by their endpoint sid or by 2026110105. Of the 6 requests the lab rejects, 3 stay
silent and 3 alert: the setpoint request without a version (400), the setpoint and alarm requests without a
leading slash (404; the `/alarm` rule is unanchored, as before). Those three were listed as accepted over-alerts in `verify.sh`
before the run. Total 41/41; the counts of the other captures are unchanged.

### Finding 4: method-glue without the leading slash, glued version tokens, and a byte x position matrix

Three questions were put to the rules after the request-line fix. The check is now per
request by construction: `reqline_client.py --cases` records label, client port and lab
status for every request, and `check_requests.py` joins `eve.json` to those cases by client
port. The invariant was fixed before the run: a request the lab routes (200, 401, 403) must
raise at least one alert; a request it rejects must raise none, unless its label is listed
in [`overalerts_frost.txt`](overalerts_frost.txt), in which case it must alert.

`pcaps/frost_matrix.pcap`, 443 requests, fresh server, Python 3.15.2, Suricata 8.0.8 on macOS:

| Part of the battery | Requests | Result with rev 5 / sid 2026110105 rev 1 | Result with the rules below |
|---|---|---|---|
| 10 separator bytes x 5 positions x 4 forms, on setpoint and service login (plus 2 controls) | 402 | no routed request silent | no routed request silent |
| version tokens, spaced and glued to the path with `0xa0` | 28 | no routed request silent; glued invalid versions silent | no routed request silent; glued invalid versions alert (listed) |
| `0xa0` after the method, combined with a path without its leading slash | 12 | lab answers 404; silent | lab answers 404; method-token rule alerts (listed) |

The middle column was replayed on a Linux source build of Suricata 8.0.8 against the same
committed capture, not on macOS.

- **Method-glue without the leading slash.** FROSTBOX answers 404 to `POST<0xa0>api/case/...`,
  so this is not an evasion here. In HYDROBOX it was (see its verification README), and the
  method-token rule was widened in both labs for consistency.
- **Glued version tokens.** `http.server` in Python 3.10 parses the version with `int()` and
  executes `HTTP/+1.1`, `HTTP/-1.1` and `HTTP/1.1_0`; from 3.11 on (checked on 3.11, 3.12, 3.13
  and, in this capture, 3.15.2) it answers 400. On a Python 3.10.20 server the three glued
  forms were executed and rev 5 was silent (Linux capture, not committed). On the reference
  environment there is no evasion; the pattern was still made independent of the version
  value, because a version separated by a space never reaches the URI buffer either.
- **Matrix.** Positions: after the method, before the version, after the path, before the
  method, after the version. Forms: the byte alone, doubled, after a space, followed by `0xa0`.
  Bytes: `09 0b 0c 0d 1c 1d 1e 1f 85 a0`. No routed request was silent, with the previous
  rules or with the new ones.

### Fix (rev 6 of 2026110101/2026110102, rev 2 of 2026110105)

```
2026110101: ... pcre:"/\/setpoint(?:[?\x3b#]|(?:[\x09-\x0d\x1c-\x20\x85\xa0]+HTTP\/[^\x09-\x0d\x1c-\x20\x85\xa0]*)?[\x09-\x0d\x1c-\x20\x85\xa0]*$)/";
2026110105: http.method; content:"/";   (any slash in the method token, not only "/api/")
```

Result: all 414 routed requests alert. Of the 28 rejected requests, 27 are listed
over-alerts and all of them alert; the remaining one (service login without its leading slash) is silent.
The counts of every earlier capture are unchanged, and `verify.sh --mutation` passes.

### What rev 3 matched on 0xa0 (diagnostic)

Rev 3 read the normalised `http.uri` and alerted on `/setpoint<0xa0>`, `/setpoint<0x85>` and
the rejected `/setpoint<0xa0>x`, but not on `/setpoint<0x1c>`. Replaying
`pcaps/frost_rawbyte.pcap` with [`diag_uri_normalisation.rules`](diag_uri_normalisation.rules)
shows why: for those three requests `http.uri` contains `/setpoint?` and no `0xa0`/`0x85`,
while `http.uri.raw` keeps the byte; `0x1c` stays in `http.uri` as it is. Suricata 8.0.8
replaces bytes of `0x80` and above with `?` in the normalised URI, and rev 3 accepted `?`
after the path. Neither "the URI ends at the byte" nor "the byte is removed" holds: the
`endswith` diagnostic does not match those requests. Same result on macOS and on Linux.

## Limits

- **Synthetic telemetry.** The traffic comes from the lab in this repository, on loopback.
  This is not validation against a real controller or a production network.
- **Source-based, not behaviour-based.** The rules alert on any config/actuation request from
  outside `$MAINT_NET`. A legitimate technician working from outside that network raises the
  same alerts as the attacker.
- **Plaintext HTTP only.** `http.method` / `http.uri` are visible only on plaintext HTTP or
  where TLS is terminated at the sensor.
- **One engine version.** Executed on Suricata 8.0.8 only.
- **Suffix list.** The pcre covers the three separators the lab's router ignores (`?`, `;`, `#`)
  and the trailing bytes that Python's `http.server` drops. Both lists are properties of this
  lab's HTTP stack; a different controller may parse the request line and normalise URIs
  differently, so re-derive them for your target.
- **Raw URI.** Since rev 4 the two anchored rules read `http.uri.raw`, with no percent-decoding.
  That fits this lab, which does not decode the path; a controller that decodes it would
  accept forms these rules do not see.
- **Tested request lines only.** The batteries cover the forms listed above: ten separator bytes
  in five positions and four forms on two endpoints, and the other forms mostly with `0xa0`.
  Longer runs, three or more odd separators at once, header lines and bodies were not varied.
- **Python version.** The lab's behaviour on a request line depends on the Python release (the
  version check changed in 3.11). The recorded runs use Python 3.15.2; the manifest of each new
  capture records the interpreter, and `check_requests.py` takes the lab's own response as the
  ground truth, so a different interpreter changes the expectation with it.
- **Manifests.** Only captures made from this change on carry a manifest. The earlier pcaps
  were captured before manifests existed and are replayed without that check.
- **Over-alerts on rejected requests.** Three requests that the lab rejects still alert (see
  Finding 3). The rules match the request, not the response.
- **Method-token rule.** sid 2026110105 depends on how Suricata 8.0.8 fills `http.method` for a
  request line it cannot split; another engine version may behave differently.

## Note on the recorded run

The first capture scripts stopped the lab server with `SIGINT`, which background jobs of a
non-interactive shell ignore, so the first evasion attempt reached a stale server left over
from the attack capture. The scripts were fixed (`SIGTERM` plus a port-in-use check) and the
evasion capture was repeated against a fresh server; `frost_evasion.pcap` is the repeat.

The first request-line run with the fix executed the previous client and rules, because the
updated files had not reached the working copy. It was repeated after comparing file
checksums; `frost_reqline.pcap` is the repeat.

`verify.sh` appended to the logs of an earlier run when the same `WORK_DIR` was reused, which
doubled every count. It now clears each scenario directory first. The matrix battery and the
rule changes were tried on a Linux source build of Suricata 8.0.8 before the recorded macOS
run; that build reproduced the counts of every committed capture.

## Reproduce

```bash
bash verify.sh              # replays the committed pcaps; prints PASS/FAIL per scenario
bash verify.sh --mutation   # removes each rule in turn and confirms its alerts disappear
```

`verify.sh` exits non-zero on any mismatch, so a rule that is deleted or broken later
fails the check (rule-liveness). To regenerate a capture instead of using the committed one
(needs `sudo` for `tcpdump`):

```bash
bash capture.sh attack     # or: evasion | edge | rawbyte | reqline | matrix
PCAP_DIR=./recapture bash verify.sh
```

The matrix capture has three files; copy them together, or `verify.sh` fails closed:

```bash
bash capture.sh matrix && cp recapture/frost_matrix.* pcaps/
WORK_DIR=./logs bash verify.sh      # per_request.tsv of each scenario is kept in ./logs
```

The pcaps contain only loopback traffic of the synthetic lab, including its built-in weak
credentials and session tokens, which are already public in the lab source.

## Who did what

The runs were executed by the author on his own machine. Claude (Anthropic) wrote the capture
and verification scripts, read the Suricata logs and drafted this note. Mistral Vibe reviewed
the claims that rest on reading the lab and rule source code; it did not execute anything.

For the trailing-byte finding: a review by Qwen suggested a further edge battery (the
specific cases it proposed did not hold when tested). Claude found the trailing-byte
behaviour by running the lab without Suricata, wrote the client and the rev 4 candidate, and
read the logs; the author ran the captures and Suricata.

For the request-line finding: Qwen pointed out, from a Python-side probe, that runs of bytes
pass the one-byte pattern and proposed a lone CR (runs confirmed; a lone CR alone is not an
evasion, because Suricata also ends the URI there). Claude extended the battery to the
separator and prefix forms, wrote the client and the rules, and read the logs; the author ran
the captures and Suricata.

For the matrix finding: Qwen proposed the glued version tokens (from a Python 3.10 probe), the
method-glue combined with a missing leading slash, the byte x position matrix, the diagnostic
rules and the manifest. Claude built Suricata 8.0.8 from source on Linux, ran the labs under
Python 3.10 to 3.13, wrote the client extension, `check_requests.py`, the manifest, the rule
changes and the over-alert lists, and read the logs. The method-glue case was confirmed in
HYDROBOX; the version case applies to Python 3.10 only; neither of the two explanations
proposed for the rev 3 behaviour held. The author ran the captures and Suricata on macOS.
