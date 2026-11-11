#!/usr/bin/env python3
"""Per-request check of a Suricata replay against the cases a client recorded.

Usage: check_requests.py EVE_JSON CASES_JSONL OVERALERTS_TXT [--out TABLE.tsv]

CASES_JSONL is written by reqline_client.py --cases during the capture: one line
per request with its label, client source port and the lab's response status.
Every request uses its own TCP connection, so eve.json events are joined to the
cases by client port (no dependency on Suricata producing an http event).

Invariant, fixed before any run:
  * a request the lab routed (200, 401, 403, or an HTTP/0.9-style 200) must
    raise at least one alert;
  * a request the lab rejected (anything else) must raise none, unless its
    label matches a pattern in OVERALERTS_TXT, in which case it must alert.
Exit status 1 on any violation. The totals are printed for information only.
"""
import collections, fnmatch, json, sys

ROUTED = {"200", "401", "403", "200(0.9)"}

argv = sys.argv[1:]
out = None
if "--out" in argv:
    i = argv.index("--out")
    out = argv[i + 1]
    del argv[i:i + 2]
eve_path, cases_path, over_path = argv

cases = [json.loads(l) for l in open(cases_path) if l.strip()]
patterns = [l.strip() for l in open(over_path) if l.strip() and not l.lstrip().startswith("#")]
ports = {c["sport"] for c in cases}
if len(ports) != len(cases):
    sys.exit("check_requests: client ports are not unique in %s" % cases_path)

alerts = collections.defaultdict(list)
http = {}
with open(eve_path, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        port = next((p for p in (e.get("src_port"), e.get("dest_port")) if p in ports), None)
        if port is None:
            continue
        if e.get("event_type") == "alert":
            alerts[port].append(e["alert"]["signature_id"])
        elif e.get("event_type") == "http" and port not in http:
            h = e.get("http", {})
            http[port] = (h.get("http_method"), h.get("url"), h.get("protocol"))

rows, bad = [], []
n_routed = n_rejected = n_over = 0
per_sid = collections.Counter()
for c in cases:
    label, st, port = c["label"], str(c["status"]), c["sport"]
    sids = sorted(alerts.get(port, []))
    per_sid.update(sids)
    listed = any(fnmatch.fnmatchcase(label, p) for p in patterns)
    if label == "login":
        verdict = "ok" if not sids else "UNEXPECTED-ALERT"
    elif st in ROUTED:
        n_routed += 1
        verdict = "ok" if sids else "EVASION"
    else:
        n_rejected += 1
        if listed:
            n_over += 1
            verdict = "ok (listed over-alert)" if sids else "LISTED-OVER-ALERT-DID-NOT-ALERT"
        else:
            verdict = "ok" if not sids else "UNLISTED-OVER-ALERT"
    m, u, p = http.get(port, ("<no http event>", "", ""))
    rows.append((label, st, ",".join(str(s) for s in sids) or "-", verdict, repr(m), repr(u), repr(p)))
    if not verdict.startswith("ok"):
        bad.append(rows[-1])

if out:
    with open(out, "w") as fh:
        fh.write("label\tlab_status\tsids\tverdict\thttp.method\turl\tprotocol\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")

for r in bad:
    print("  %-22s %-40s lab=%-8s sids=%-12s method=%s url=%s" % (r[3], r[0], r[1], r[2], r[4], r[5]))
print("  per request: %d cases, %d routed, %d rejected (%d listed over-alerts), %d violations | alerts per sid: %s"
      % (len(cases), n_routed, n_rejected, n_over, len(bad),
         " ".join("%d=%d" % kv for kv in sorted(per_sid.items())) or "none"))
sys.exit(1 if bad else 0)
