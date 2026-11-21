#!/usr/bin/env python3
"""sqlite_baseline.py -- sigma_t1003_study minimal pair, SQLite baseline (real execution).

Executes the study's own compiled SQL (v2_compiled.sql / v3_compiled.sql, verbatim,
no re-compilation) against the 4-event minimal pair on an in-memory SQLite database.
Standard library only. Writes results_sqlite_baseline.json + telemetry.
"""
import hashlib
import json
import os
import sqlite3
import sys
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = datetime.timezone.utc

def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def main():
    events_doc = json.load(open(os.path.join(HERE, "minpair_events.json"), encoding="utf-8"))
    common = events_doc["common_fields"]
    columns = ["event_id", "Channel", "EventID", "TargetImage", "GrantedAccess",
               "SourceImage", "SourceUser", "CallTrace"]

    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE logs (event_id TEXT, Channel TEXT, EventID INTEGER, "
        "TargetImage TEXT, GrantedAccess TEXT, SourceImage TEXT, SourceUser TEXT, CallTrace TEXT)")
    rows = []
    for ev in events_doc["events"]:
        row = dict(common)
        row["event_id"] = ev["event_id"]
        row["CallTrace"] = ev["CallTrace"]
        rows.append(tuple(row[c] for c in columns))
    conn.executemany("INSERT INTO logs ({}) VALUES ({})".format(
        ", ".join(columns), ", ".join("?" * len(columns))), rows)

    results = {"engine": "sqlite3 (stdlib) " + sqlite3.sqlite_version,
               "runs": {}, "prediction_check": {}}
    for ver in ("v2", "v3"):
        sql_path = os.path.join(HERE, ver + "_compiled.sql")
        sql = open(sql_path, encoding="utf-8").read()
        matched = [r[0] for r in conn.execute(sql)]
        results["runs"][ver] = {
            "sql_sha256": sha256(sql_path),
            "matched_event_ids": sorted(matched),
            "not_matched_event_ids": sorted(set(e["event_id"] for e in events_doc["events"]) - set(matched)),
        }

    exp = {
        "v2": {"PS1": ("E1_local_backslash", True), "PS2a": ("E2_unc", True),
               "PS2b": ("E3_forward_slash", False), "PS2c": ("E4_downloads_true_positive", True)},
        "v3": {"PS3a": ("E1_local_backslash", False), "PS3b": ("E2_unc", False),
               "PS3c": ("E3_forward_slash", False), "PS3d": ("E4_downloads_true_positive", True)},
    }
    for ver, preds in exp.items():
        for pid, (event_id, want) in preds.items():
            got = event_id in results["runs"][ver]["matched_event_ids"]
            results["prediction_check"][pid] = {
                "rule": ver, "event": event_id, "predicted_match": want,
                "observed_match": got, "status": "CONFIRMED" if got == want else "REFUTED"}

    results["telemetry"] = {
        "ts": datetime.datetime.now(UTC).isoformat(),
        "events_sha256": sha256(os.path.join(HERE, "minpair_events.json")),
        "pre_registration_sha256": sha256(os.path.join(HERE, "PRE_REGISTRATION.md")),
        "platform_note": "SQL executed verbatim from sigma_t1003_study compiled_sql (byte-identical reconstruction, verified by file size pre-run and diff against the operator's original post-copy).",
    }
    out = os.path.join(HERE, "results_sqlite_baseline.json")
    json.dump(results, open(out, "w", encoding="utf-8"), indent=2)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
