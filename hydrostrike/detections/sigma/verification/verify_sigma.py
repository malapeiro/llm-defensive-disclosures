#!/usr/bin/env python3
"""Execution check of the lab's Sigma rules against the lab's own audit log.

Usage (from this directory):
    python3 verify_sigma.py              # replay the committed fixtures
    python3 verify_sigma.py --capture    # regenerate the fixtures from the lab, then stop
    python3 verify_sigma.py --mutation   # show that a broken selection is caught

Requires: pip install pysigma pysigma-backend-sqlite

What it does
  * loads each fixture (one audit JSONL file) into an in-memory SQLite table "logs";
  * compiles each audit-log Sigma rule with pySigma's SQLite backend and runs the SQL;
  * compares the matched rows with (a) the counts written below before the first run and
    (b) an independent predicate written in plain Python from the rule's description;
  * does the same for every named selection of a multi-selection rule, so that a selection
    nothing in the fixtures exercises is reported as such instead of passing silently.
The webserver-category rules are only compiled: the lab does not emit a webserver log.

Fixtures (fixtures/): h1, h2 and negative come from `<lab> demo`; branches comes from a
short loopback session that drives the rule branches the demo does not reach. A manifest
pins the lab file and the fixtures; the replay fails closed when they no longer match.
"""
import copy, hashlib, http.client, json, os, platform, shutil, sqlite3, subprocess, sys, tempfile, time

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

HERE = os.path.dirname(os.path.abspath(__file__))
RULE_DIR = os.path.dirname(HERE)
LAB_DIR = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FIX = os.path.join(HERE, "fixtures")
SQL_DIR = os.path.join(HERE, "compiled_sql")
FIXTURES = ["h1", "h2", "negative", "branches"]
LAB = "frost" if os.path.exists(os.path.join(LAB_DIR, "froststrike_lab.py")) else "hydro"


def between(v, lo, hi):
    return v is not None and lo <= v <= hi


if LAB == "frost":
    LAB_FILE, PORT = "froststrike_lab.py", 8610
    DEMO_FILES = {"h1": "audit_h1.jsonl", "h2": "audit_h2.jsonl", "negative": "audit_negative.jsonl"}
    COMPILE_ONLY = ["web_offhours_ot_config.yaml"]
    # Expected matches per fixture, written before the first run (2026-11-11).
    EXPECT = {
        "frostbox_service_auth.yaml":  {"h1": 0, "h2": 1, "negative": 0, "branches": 0},
        "frostbox_setpoint_band.yaml": {"h1": 6, "h2": 6, "negative": 0, "branches": 6},
    }
    EXPECT_SELECTION = {  # selection -> total over all fixtures
        "frostbox_setpoint_band.yaml": {"freezer_too_high": 7, "freezer_too_low": 2,
                                        "chilled_too_high": 7, "chilled_too_low": 2},
    }
    SELECTION_BASE = {"frostbox_setpoint_band.yaml": "selection_event and {}"}

    def _band(e):
        if e.get("event") != "CFG_SETPOINT":
            return False
        case, new = str(e.get("case", "")), e.get("new")
        if case.startswith("FZ-"):
            return not between(new, -30, -15)
        if case.startswith("CH-"):
            return not between(new, 0, 6)
        return False

    ORACLE = {
        "frostbox_service_auth.yaml": lambda e: e.get("event") == "AUTH_SERVICE_CODE" and e.get("outcome") == "success",
        "frostbox_setpoint_band.yaml": _band,
    }
else:
    LAB_FILE, PORT = "hydrostrike_lab.py", 8600
    DEMO_FILES = {"h1": "controller_audit_H1.jsonl", "h2": "controller_audit_H2.jsonl",
                  "negative": "controller_audit_NEG.jsonl"}
    COMPILE_ONLY = ["web_offhours_water_hmi_write.yaml"]
    EXPECT = {
        "hydrobox_default_or_service_auth.yaml": {"h1": 1, "h2": 1, "negative": 0, "branches": 1},
        "hydrobox_hydraulic_sabotage.yaml":      {"h1": 6, "h2": 6, "negative": 0, "branches": 9},
    }
    EXPECT_SELECTION = {
        "hydrobox_default_or_service_auth.yaml": {"selection_default_cred": 2, "selection_service_code": 1},
        "hydrobox_hydraulic_sabotage.yaml": {
            "pressure_high": 3, "pressure_low": 2, "chlorine_high": 3, "chlorine_low": 2,
            "deadhead_on_valve_close": 3, "deadhead_on_pump_run": 1,
            # The v1.3 controller rejects a backwash that would end below 2.5 bar
            # (backwash_rejected), so the lab cannot emit an event for this selection.
            "backwash_underpressure": 0,
            "backwash_reservoir_drain": 4, "alarm_suppression": 3},
    }
    SELECTION_BASE = {}

    def _sabotage(e):
        ev, new = e.get("event"), e.get("new")
        if ev == "pump_setpoint":
            if not between(new, 2.5, 5.5):
                return True
            return e.get("valve") == "CLOSED" and e.get("running") is True and new > 0
        if ev == "dosing_setpoint":
            return not between(new, 0.2, 1.0)
        if ev == "valve_command":
            return e.get("state") == "CLOSED" and e.get("any_pump_running") is True
        if ev == "filter_backwash":
            return e.get("pressure_after", 99) < 2.5 or (e.get("trigger") == "API" and e.get("reservoir_after", 100) < 40.0)
        if ev == "alarm_mute":
            return e.get("muted") is True
        return False

    ORACLE = {
        "hydrobox_default_or_service_auth.yaml": lambda e: (e.get("event") == "login_success" and e.get("cred_class") == "default") or e.get("event") == "service_login_success",
        "hydrobox_hydraulic_sabotage.yaml": _sabotage,
    }


# ------------------------------------------------------------------ helpers
def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def load(name):
    with open(os.path.join(FIX, name + ".jsonl")) as fh:
        return [json.loads(l) for l in fh if l.strip()]


def table(events, cols):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logs (_line INTEGER, %s)" % ", ".join('"%s"' % c for c in cols))
    for i, e in enumerate(events):
        vals = [i]
        for c in cols:
            v = e.get(c)
            if isinstance(v, bool):
                v = int(v)
            elif isinstance(v, (list, dict)):
                v = json.dumps(v)
            vals.append(v)
        db.execute("INSERT INTO logs VALUES (%s)" % ",".join("?" * len(vals)), vals)
    return db


def compile_rule(rule):
    queries = sqliteBackend().convert(SigmaCollection.from_yaml(yaml.safe_dump(rule, sort_keys=False)))
    assert len(queries) == 1, queries
    return queries[0]


def matched(sql, db):
    q = sql.replace("SELECT * FROM", "SELECT _line FROM", 1)
    return sorted(r[0] for r in db.execute(q))


def selections(rule):
    return [k for k in rule["detection"] if k != "condition"]


def single(rule, name, sel):
    r = copy.deepcopy(rule)
    r["detection"]["condition"] = SELECTION_BASE.get(name, "{}").format(sel)
    return r


def mutate(rule, sel):
    """Break one selection: change the value of its first field so that it matches nothing."""
    r = copy.deepcopy(rule)
    key = next(iter(r["detection"][sel]))
    v = r["detection"][sel][key]
    if isinstance(v, bool):
        v = not v
    elif isinstance(v, (int, float)):
        v = v + 100000 if "|gt" in key else v - 100000
    else:
        v = str(v) + "_MUTATED"
    r["detection"][sel][key] = v
    return r


def evaluate(rule, name, data):
    """-> (per-fixture counts, oracle agreement, per-selection totals)"""
    sql = compile_rule(rule)
    counts, agree = {}, True
    for fx in FIXTURES:
        events, db = data[fx]
        got = matched(sql, db)
        counts[fx] = len(got)
        want = [i for i, e in enumerate(events) if ORACLE[name](e)]
        if got != want:
            agree = False
    per_sel = {}
    for sel in EXPECT_SELECTION.get(name, {}):
        q = compile_rule(single(rule, name, sel))
        per_sel[sel] = sum(len(matched(q, data[fx][1])) for fx in FIXTURES)
    return sql, counts, agree, per_sel


# ------------------------------------------------------------------ capture
def call(method, path, body=None, token=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)   # loopback only
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse()
    data = r.read()
    try:
        return r.status, json.loads(data)
    except ValueError:
        return r.status, {}


def branches_session():
    if LAB == "frost":
        _, j = call("POST", "/api/login", {"user": "admin", "pass": "admin123"})
        t = j["token"]
        for case, v in [("FZ-02", -40.0), ("CH-02", -5.0), ("FZ-03", -18.0), ("CH-03", 3.0),
                        ("FZ-01", -15.0), ("FZ-01", -30.0), ("CH-01", 6.0), ("CH-01", 0.0),
                        ("FZ-02", -14.9), ("FZ-02", -30.1), ("CH-02", 6.1), ("CH-02", -0.1)]:
            call("POST", "/api/case/%s/setpoint" % case, {"value": v}, t)
        call("POST", "/api/service/login", {}, headers={"X-Service-Code": "000000"})   # wrong code
        call("POST", "/api/login", {"user": "admin", "pass": "wrong"})
    else:
        _, j = call("POST", "/api/login", {"username": "admin", "password": "123456"})
        t = j["session"]
        call("POST", "/api/login", {"username": "admin", "password": "wrong"})
        call("POST", "/api/service_login", {"code": "000000"})                         # wrong code
        for v in (1.0, 2.5, 5.5, 5.6, 2.4, 4.0):
            call("POST", "/api/pump/PMP-01/setpoint", {"value": v}, t)
        for v in (0.05, 0.2, 1.0, 1.1, 0.19, 0.5):
            call("POST", "/api/dosing/setpoint", {"value": v}, t)
        call("POST", "/api/valve/out", {"state": "CLOSED"}, t)        # pump running: deadhead
        call("POST", "/api/pump/PMP-01/setpoint", {"value": 4.2}, t)  # running against a closed valve
        call("POST", "/api/valve/out", {"state": "OPEN"}, t)
        call("POST", "/api/alarm/mute", {"muted": True}, t)
        call("POST", "/api/alarm/mute", {"muted": False}, t)


def capture():
    lab = os.path.join(LAB_DIR, LAB_FILE)
    os.makedirs(FIX, exist_ok=True)
    tmp = tempfile.mkdtemp()
    subprocess.run([sys.executable, lab, "demo", "--evidence-dir", tmp], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for fx, src in DEMO_FILES.items():
        shutil.copy(os.path.join(tmp, src), os.path.join(FIX, fx + ".jsonl"))
    out = os.path.join(FIX, "branches.jsonl")
    if os.path.exists(out):
        os.remove(out)
    srv = subprocess.Popen([sys.executable, lab, "serve", "--port", str(PORT), "--audit", out],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        branches_session()
        time.sleep(0.5)
    finally:
        srv.terminate()
        srv.wait()
    shutil.rmtree(tmp, ignore_errors=True)
    with open(os.path.join(FIX, "manifest.txt"), "w") as fh:
        fh.write("captured_utc=%s\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        fh.write("lab_file=%s\nlab_sha256=%s\n" % (LAB_FILE, sha(lab)))
        fh.write("python=%s\nos=%s %s\n" % (platform.python_version(), platform.system(), platform.machine()))
        for fx in FIXTURES:
            fh.write("%s_sha256=%s\n" % (fx, sha(os.path.join(FIX, fx + ".jsonl"))))
    print("fixtures written to", FIX)


def manifest_ok():
    m = dict(l.strip().split("=", 1) for l in open(os.path.join(FIX, "manifest.txt")) if "=" in l)
    if m["lab_sha256"] != sha(os.path.join(LAB_DIR, LAB_FILE)):
        return "lab file differs from manifest"
    for fx in FIXTURES:
        if m[fx + "_sha256"] != sha(os.path.join(FIX, fx + ".jsonl")):
            return "fixture %s differs from manifest" % fx
    return None


# ------------------------------------------------------------------ main
def main():
    if "--capture" in sys.argv:
        return capture()
    import sigma
    from importlib.metadata import version
    print("pySigma %s, pysigma-backend-sqlite %s, SQLite %s, Python %s"
          % (version("pysigma"), version("pysigma-backend-sqlite"), sqlite3.sqlite_version, platform.python_version()))
    why = manifest_ok()
    if why:
        print("FAIL  %s - run --capture again before replaying" % why)
        return 1
    loaded = {fx: load(fx) for fx in FIXTURES}
    # One schema for every fixture: a field that some fixture lacks is NULL there. A field
    # that no fixture has at all makes the rule's SQL fail, which is the right outcome.
    cols = sorted({k for ev in loaded.values() for e in ev for k in e})
    data = {fx: (ev, table(ev, cols)) for fx, ev in loaded.items()}
    print("fixtures: " + ", ".join("%s=%d events" % (fx, len(data[fx][0])) for fx in FIXTURES) + " [manifest ok]")
    fail = 0
    os.makedirs(SQL_DIR, exist_ok=True)

    if "--mutation" in sys.argv:
        for name in EXPECT:
            rule = yaml.safe_load(open(os.path.join(RULE_DIR, name)))
            for sel in selections(rule):
                _, counts, agree, _ = evaluate(mutate(rule, sel), name, data)
                caught = counts != EXPECT[name] or not agree
                exercised = EXPECT_SELECTION.get(name, {}).get(sel, 1) > 0
                if caught:
                    print("PASS  %s: selection %s broken -> the check fails (%s)" % (name, sel, counts))
                elif not exercised:
                    print("NOTE  %s: selection %s broken -> not caught; no fixture exercises it" % (name, sel))
                else:
                    print("FAIL  %s: selection %s broken -> not caught" % (name, sel))
                    fail = 1
        print("RESULT: %s" % ("FAIL" if fail else "PASS"))
        return fail

    for name in EXPECT:
        rule = yaml.safe_load(open(os.path.join(RULE_DIR, name)))
        sql, counts, agree, per_sel = evaluate(rule, name, data)
        open(os.path.join(SQL_DIR, name.replace(".yaml", ".sql")), "w").write(sql + "\n")
        ok = counts == EXPECT[name] and agree
        fail |= not ok
        print("%s  %s | %s | oracle %s" % ("PASS" if ok else "FAIL", name,
              " ".join("%s:%d/%d" % (fx, counts[fx], EXPECT[name][fx]) for fx in FIXTURES),
              "agrees row by row" if agree else "DISAGREES"))
        for sel, want in EXPECT_SELECTION.get(name, {}).items():
            got = per_sel[sel]
            ok = got == want
            fail |= not ok
            note = "" if want else "  (not exercised by any fixture)"
            print("  %s  selection %-26s %d/%d%s" % ("PASS" if ok else "FAIL", sel, got, want, note))
    for name in COMPILE_ONLY:
        rule = yaml.safe_load(open(os.path.join(RULE_DIR, name)))
        sql = compile_rule(rule)
        open(os.path.join(SQL_DIR, name.replace(".yaml", ".sql")), "w").write(sql + "\n")
        print("COMPILED ONLY  %s (no webserver log in the lab; not executed)" % name)
    print("RESULT: %s" % ("FAIL" if fail else "PASS"))
    return fail


if __name__ == "__main__":
    sys.exit(main())
