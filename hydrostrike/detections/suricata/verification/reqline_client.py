"""Request-line tokenisation test client for the Suricata verification (loopback only).

Usage: python3 reqline_client.py frost PORT   |   python3 reqline_client.py hydro PORT

Python's http.server tokenises the request line with str.split(): any run of
0x09-0x0d, 0x1c-0x20, 0x85 or 0xa0 separates the three words, and leading or
trailing runs are dropped. This client sends request lines that are not
"METHOD SP URI SP VERSION" on the wire and records what the lab does with them.
Each request carries its case label in the User-Agent header, so that Suricata's
eve.json http events can be matched to the cases.
"""
import json, socket, sys

LAB, PORT = sys.argv[1], int(sys.argv[2])
HOST = "127.0.0.1"   # loopback only, never a parameter
V = b"HTTP/1.1"


def raw(line, body, label, token=None, extra=b""):
    data = json.dumps(body).encode()
    head = line + b"\r\nHost: 127.0.0.1\r\nUser-Agent: " + label.encode() + b"\r\n"
    head += b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(data)
    head += b"Connection: close\r\n" + extra
    if token:
        head += b"Authorization: Bearer " + token.encode() + b"\r\n"
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(head + b"\r\n" + data)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    s.close()
    if buf.startswith(b"HTTP/"):
        return buf.split(b" ", 2)[1].decode(), buf.split(b"\r\n\r\n", 1)[-1]
    return ("200(0.9)" if buf.startswith(b"{") else "???"), buf


# form name -> request line for path P
FORMS = [
    ("c01-control",          lambda P: b"POST " + P + b" " + V),
    # runs of bytes after the path
    ("s01-a0-a0",            lambda P: b"POST " + P + b"\xa0\xa0 " + V),
    ("s02-1c-85",            lambda P: b"POST " + P + b"\x1c\x85 " + V),
    ("s03-0b-1f-a0",         lambda P: b"POST " + P + b"\x0b\x1f\xa0 " + V),
    ("s04-cr",               lambda P: b"POST " + P + b"\r " + V),
    ("s05-cr-a0",            lambda P: b"POST " + P + b"\r\xa0 " + V),
    ("s06-two-spaces",       lambda P: b"POST " + P + b"  " + V),
    ("s07-sp-a0-sp",         lambda P: b"POST " + P + b" \xa0 " + V),
    ("s08-a0-sp-a0",         lambda P: b"POST " + P + b"\xa0 \xa0 " + V),
    # the byte is the separator itself
    ("p01-a0-second-sep",    lambda P: b"POST " + P + b"\xa0" + V),
    ("p02-1c-second-sep",    lambda P: b"POST " + P + b"\x1c" + V),
    ("p03-tab-second-sep",   lambda P: b"POST " + P + b"\t" + V),
    ("p04-a0-first-sep",     lambda P: b"POST\xa0" + P + b" " + V),
    ("p05-tab-first-sep",    lambda P: b"POST\t" + P + b" " + V),
    ("p06-a0-both-seps",     lambda P: b"POST\xa0" + P + b"\xa0" + V),
    ("p07-a0-before-path",   lambda P: b"POST \xa0" + P + b" " + V),
    ("p08-leading-a0",       lambda P: b"\xa0POST " + P + b" " + V),
    ("p09-leading-space",    lambda P: b" POST " + P + b" " + V),
    ("p10-a0-after-version", lambda P: b"POST " + P + b" " + V + b"\xa0"),
    # version token
    ("v01-http-1.0",         lambda P: b"POST " + P + b" HTTP/1.0"),
    ("v02-http-0.9",         lambda P: b"POST " + P + b" HTTP/0.9"),
    ("v03-http-1.9",         lambda P: b"POST " + P + b" HTTP/1.9"),
    # other spellings of the path
    ("u01-x01-before-path",  lambda P: b"POST \x01" + P + b" " + V),
    ("u02-absolute-uri",     lambda P: b"POST http://127.0.0.1" + P + b" " + V),
    ("u03-no-leading-slash", lambda P: b"POST " + P[1:] + b" " + V),
    # expected to be rejected by both labs
    ("n01-no-version",       lambda P: b"POST " + P),
    ("n02-a0-a0-x",          lambda P: b"POST " + P + b"\xa0\xa0x " + V),
    ("n03-four-words",       lambda P: b"POST " + P + b" x " + V),
]
ALL = [name for name, _ in FORMS]
SHORT = ["c01-control", "s01-a0-a0", "p01-a0-second-sep", "p04-a0-first-sep"]
PREFIX = ["c01-control", "p04-a0-first-sep", "p07-a0-before-path",
          "u01-x01-before-path", "u02-absolute-uri", "u03-no-leading-slash"]

if LAB == "frost":
    st, resp = raw(b"POST /api/login HTTP/1.1", {"user": "admin", "pass": "admin123"}, "login")
    token = json.loads(resp)["token"]
    # (key, path, body, extra headers, cases)
    ENDPOINTS = [
        ("setpoint", b"/api/case/FZ-01/setpoint", {"value": 45.0}, b"", ALL),
        ("defrost",  b"/api/case/CH-01/defrost", {}, b"", SHORT),
        ("alarm",    b"/api/alarm/config", {"case": "FZ-01", "enabled": False, "high_threshold": 60.0}, b"", PREFIX),
        ("svclogin", b"/api/service/login", {}, b"X-Service-Code: 000000\r\n", PREFIX),
    ]
else:
    st, resp = raw(b"POST /api/login HTTP/1.1", {"username": "admin", "password": "123456"}, "login")
    token = json.loads(resp)["session"]
    ENDPOINTS = [
        ("setpoint", b"/api/pump/PMP-01/setpoint", {"value": 8.5}, b"", ALL),
        ("backwash", b"/api/filter/FLT-01/backwash", {}, b"", SHORT),
        ("valve",    b"/api/valve/out", {"state": "CLOSED"}, b"", PREFIX),
        ("mute",     b"/api/alarm/mute", {"muted": True}, b"", PREFIX),
        ("svclogin", b"/api/service_login", {"code": "000000"}, b"", PREFIX),
    ]
print("login -> %s" % st)

forms = dict(FORMS)
for key, path, body, extra, cases in ENDPOINTS:
    for name in cases:
        label = "%s-%s" % (key, name)
        line = forms[name](path)
        st, _ = raw(line, body, label, token, extra)
        print("%-32s %-62r HTTP %s" % (label, line.decode("latin-1"), st))
