#!/usr/bin/env python3
"""Edge-case client for the Suricata verification (loopback only).

Usage: python3 edge_client.py frost PORT   |   python3 edge_client.py hydro PORT
Sends control, evasion and near-miss requests and records the lab response.
"""
import http.client, json, sys

LAB, PORT = sys.argv[1], int(sys.argv[2])


def req(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
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


if LAB == "frost":
    st, resp = req("POST", "/api/login", {"user": "admin", "pass": "admin123"})
    auth = {"Authorization": "Bearer " + resp["token"]}
    sp = {"value": 44.0}
    tests = [
        ("CONTROL       setpoint", "/api/case/FZ-01/setpoint", sp),
        ("EVASION-#      setpoint#x", "/api/case/FZ-02/setpoint#x", sp),
        ("EVASION-#      defrost#x", "/api/case/CH-01/defrost#x", {}),
        ("NEAR-MISS     setpointx", "/api/case/FZ-03/setpointx", sp),
        ("NEAR-MISS     setpoint/extra", "/api/case/FZ-03/setpoint/extra", sp),
        ("NEAR-MISS     defrostx", "/api/case/CH-02/defrostx", {}),
    ]
else:
    st, resp = req("POST", "/api/login", {"username": "admin", "password": "123456"})
    auth = {"Authorization": "Bearer " + resp["session"]}
    sp = {"value": 8.5}
    tests = [
        ("CONTROL       setpoint", "/api/pump/PMP-01/setpoint", sp),
        ("EVASION-?      setpoint?x=1", "/api/pump/PMP-01/setpoint?x=1", sp),
        ("EVASION-;      setpoint;x", "/api/pump/PMP-01/setpoint;x", sp),
        ("EVASION-#      setpoint#x", "/api/pump/PMP-01/setpoint#x", sp),
        ("EVASION-?      backwash?x=1", "/api/filter/FLT-01/backwash?x=1", {}),
        ("EVASION-;      backwash;x", "/api/filter/FLT-01/backwash;x", {}),
        ("EVASION-#      backwash#x", "/api/filter/FLT-01/backwash#x", {}),
    ]
print("login -> %s" % st)
for label, path, body in tests:
    st, _ = req("POST", path, body, auth)
    print("%-30s %-34s HTTP %s" % (label, path, st))
