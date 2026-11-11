"""Trailing-byte test client for the Suricata verification (loopback only).

Usage: python3 rawbyte_client.py frost PORT   |   python3 rawbyte_client.py hydro PORT

Python's http.server splits the request line with str.split(), which also treats
0x09, 0x0b, 0x0c, 0x1c-0x1f, 0x85 and 0xa0 as whitespace. One such byte right after the
path is therefore dropped by the lab, and the request is routed as if it were not
there. This client sends those requests over a raw socket (http.client refuses the
bytes) so that the capture shows what Suricata puts in http.uri for them.
"""
import json, socket, sys

LAB, PORT = sys.argv[1], int(sys.argv[2])
HOST = "127.0.0.1"   # loopback only, never a parameter
TRAIL = [b"\xa0", b"\x85", b"\x0b", b"\x0c", b"\x1c", b"\x1f", b"\x09", b"\x1d", b"\x1e"]


def raw(path, body, token=None):
    data = json.dumps(body).encode()
    head = b"POST " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    head += b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(data)
    head += b"Connection: close\r\n"
    if token:
        head += b"Authorization: Bearer " + token.encode() + b"\r\n"
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(head + b"\r\n" + data)
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    status = buf.split(b" ", 2)[1].decode() if buf.startswith(b"HTTP/") else "???"
    return status, buf.split(b"\r\n\r\n", 1)[-1]


if LAB == "frost":
    st, resp = raw(b"/api/login", {"user": "admin", "pass": "admin123"})
    token = json.loads(resp)["token"]
    a, a_body = b"/api/case/FZ-01/setpoint", {"value": 45.0}
    b, b_body = b"/api/case/CH-01/defrost", {}
else:
    st, resp = raw(b"/api/login", {"username": "admin", "password": "123456"})
    token = json.loads(resp)["session"]
    a, a_body = b"/api/pump/PMP-01/setpoint", {"value": 8.5}
    b, b_body = b"/api/filter/FLT-01/backwash", {}
print("login -> %s" % st)

tests = [("CONTROL", a, a_body)]
tests += [("TRAIL 0x%02x" % t[0], a + t, a_body) for t in TRAIL]
tests += [("CONTROL", b, b_body)]
tests += [("TRAIL 0x%02x" % t[0], b + t, b_body) for t in TRAIL[:1] + TRAIL[3:4]]
tests += [("NEAR-MISS 0xa0 + x", a + b"\xa0x", a_body),   # two tokens: 400
          ("NEAR-MISS 0x01", a + b"\x01", a_body)]         # not whitespace: 404
for label, path, body in tests:
    st, _ = raw(path, body, token)
    print("%-20s %-40r HTTP %s" % (label, path.decode("latin-1"), st))
