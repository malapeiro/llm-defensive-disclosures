"""Request-line tokenisation test client for the Suricata verification (loopback only).

Usage: python3 reqline_client.py LAB PORT [SCENARIO] [--cases FILE]
       LAB = frost | hydro ; SCENARIO = reqline (default) | matrix

Python's http.server tokenises the request line with str.split(): any run of
0x09-0x0d, 0x1c-0x20, 0x85 or 0xa0 separates the three words, and leading or
trailing runs are dropped. This client sends request lines that are not
"METHOD SP URI SP VERSION" on the wire and records what the lab does with them.

Each request uses its own TCP connection and carries its case label in the
User-Agent header. With --cases, one JSON line per request is written (label,
client source port, lab status, request line in hex), so that check_requests.py
can join Suricata's eve.json to the cases per request.

  reqline : the fixed battery of the request-line finding (44 / 50 requests).
  matrix  : 10 separator bytes x 5 positions x 4 forms on one end-anchored and
            one prefix-anchored endpoint, version tokens (spaced and glued to
            the path), and method-glue combined with a missing leading slash.
"""
import json, socket, sys

args = [a for a in sys.argv[1:] if a != "--cases"]
CASES = sys.argv[sys.argv.index("--cases") + 1] if "--cases" in sys.argv else None
if CASES:
    args.remove(CASES)
LAB, PORT = args[0], int(args[1])
SCENARIO = args[2] if len(args) > 2 else "reqline"
HOST = "127.0.0.1"   # loopback only, never a parameter
V = b"HTTP/1.1"
cases_fh = open(CASES, "w") if CASES else None


def raw(line, body, label, token=None, extra=b""):
    data = json.dumps(body).encode()
    head = line + b"\r\nHost: 127.0.0.1\r\nUser-Agent: " + label.encode() + b"\r\n"
    head += b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(data)
    head += b"Connection: close\r\n" + extra
    if token:
        head += b"Authorization: Bearer " + token.encode() + b"\r\n"
    s = socket.create_connection((HOST, PORT), timeout=5)
    sport = s.getsockname()[1]
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
        st = buf.split(b" ", 2)[1].decode()
    else:
        st = "200(0.9)" if buf.startswith(b"{") else "???"
    if cases_fh:
        cases_fh.write(json.dumps({"label": label, "sport": sport, "status": st,
                                   "line_hex": line.hex()}) + "\n")
    return st, buf.split(b"\r\n\r\n", 1)[-1]


def send(label, line, body, token, extra=b""):
    st, _ = raw(line, body, label, token, extra)
    print("%-36s %-64r HTTP %s" % (label, line.decode("latin-1"), st))


# ---------------------------------------------------------------- reqline battery
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
    # (key, path, body, extra headers, reqline cases)
    ENDPOINTS = [
        ("setpoint", b"/api/case/FZ-01/setpoint", {"value": 45.0}, b"", ALL),
        ("defrost",  b"/api/case/CH-01/defrost", {}, b"", SHORT),
        ("alarm",    b"/api/alarm/config", {"case": "FZ-01", "enabled": False, "high_threshold": 60.0}, b"", PREFIX),
        ("svclogin", b"/api/service/login", {}, b"X-Service-Code: 000000\r\n", PREFIX),
    ]
    MATRIX_ENDPOINTS = ["setpoint", "svclogin"]
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
    MATRIX_ENDPOINTS = ["setpoint", "valve"]
print("login -> %s" % st)
BYKEY = {e[0]: e for e in ENDPOINTS}

if SCENARIO == "reqline":
    forms = dict(FORMS)
    for key, path, body, extra, cases in ENDPOINTS:
        for name in cases:
            send("%s-%s" % (key, name), forms[name](path), body, token, extra)

# ---------------------------------------------------------------- matrix battery
elif SCENARIO == "matrix":
    BYTES = [0x09, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0]

    def seps(b):
        b = bytes([b])
        return [("one", b), ("dup", b + b), ("spb", b" " + b), ("ba0", b + b"\xa0")]

    # 1. separator byte x position x form, on one end-anchored and one prefix-anchored endpoint
    for key in MATRIX_ENDPOINTS:
        _, path, body, extra, _ = BYKEY[key]
        send("m-%s-control" % key, b"POST " + path + b" " + V, body, token, extra)
        for b in BYTES:
            for form, sep in seps(b):
                tag = "%s-%s-%02x" % (key, form, b)
                send("m-msep-" + tag, b"POST" + sep + path + b" " + V, body, token, extra)
                send("m-vsep-" + tag, b"POST " + path + sep + V, body, token, extra)
                send("m-tail-" + tag, b"POST " + path + sep + b" " + V, body, token, extra)
                send("m-lead-" + tag, sep + b"POST " + path + b" " + V, body, token, extra)
                send("m-vend-" + tag, b"POST " + path + b" " + V + sep, body, token, extra)

    # 2. version tokens, spaced and glued to the path with 0xa0 (end-anchored endpoint)
    _, path, body, extra, _ = BYKEY["setpoint"]
    VERSIONS = [("1.1", b"1.1"), ("plus1.1", b"+1.1"), ("minus1.1", b"-1.1"), ("1.1_0", b"1.1_0"),
                ("1.10", b"1.10"), ("01.1", b"01.1"), ("1.01", b"1.01"), ("0.9", b"0.9"),
                ("2.0", b"2.0"), ("1.1x", b"1.1x"), ("1", b"1"), ("1.1.1", b"1.1.1")]
    for name, v in VERSIONS:
        send("v-sp-%s" % name, b"POST " + path + b" HTTP/" + v, body, token, extra)
        send("v-glue-%s" % name, b"POST " + path + b"\xa0HTTP/" + v, body, token, extra)
    send("v-glue-1.1-then-a0", b"POST " + path + b"\xa0HTTP/1.1\xa0", body, token, extra)
    send("v-glue-1.1-then-sp", b"POST " + path + b"\xa0HTTP/1.1 ", body, token, extra)
    send("v-glue-1.1-then-word", b"POST " + path + b"\xa0HTTP/1.1 x", body, token, extra)
    send("v-sp-lowercase-http", b"POST " + path + b" http/1.1", body, token, extra)

    # 3. method-glue combined with a missing leading slash, every endpoint that has a rule
    for key, path, body, extra, _ in ENDPOINTS:
        send("b-%s-mglue-noslash" % key, b"POST\xa0" + path[1:] + b" " + V, body, token, extra)
        send("b-%s-mglue-noslash-vglue" % key, b"POST\xa0" + path[1:] + b"\xa0" + V, body, token, extra)
        send("b-%s-noslash" % key, b"POST " + path[1:] + b" " + V, body, token, extra)
else:
    sys.exit("unknown scenario: %s" % SCENARIO)

if cases_fh:
    cases_fh.close()
