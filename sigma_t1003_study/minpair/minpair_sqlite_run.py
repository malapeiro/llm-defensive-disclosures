#!/usr/bin/env python3
"""minpair_sqlite_run.py -- sigma_t1003_study minimal pair, SQLite side.

RUN IN THE SQLITE VENV (pySigma 2.0.2 / backend-sqlite 2.1.1 /
pipeline-sysmon 3.0.0 / pipeline-windows 3.0.0 -- same stack as the study,
see freeze_sqlite.txt).

  python3 minpair_sqlite_run.py --rules-dir <path-to>/sigma_t1003_study/rules

Reproduces the study's compile recipe verbatim
(sysmon_pipeline() + windows_logsource_pipeline(), sqlite backend), compares
the compiled SQL against v2_compiled.sql / v3_compiled.sql with an EXACT
taxonomy (byte_identical_exact vs identical_modulo_trailing_newline, with the
three sha256s reported), executes it against the 4-event minimal pair on an
in-memory SQLite database, and records all versions. Produces
results_sqlite_mac.json.

Fixes:
- v1.1 (2026-11-21): SigmaString imports from sigma.types (was sigma.rule,
  ImportError on pySigma 2.0.2 -- operator errata).
- v1.2 (2026-11-21): identity label corrected. The reference files end with a
  trailing newline; the compiled SQL does not (operator audit: v2 file
  ad6c9ca9... / minus newline 695bc527...; v3 fe681956... / 6850139c...).
  Output now reports byte_identical_exact AND identical_modulo_trailing_newline
  separately, plus the three hashes. The load-bearing identity claim for the
  study reproduction is identical_modulo_trailing_newline.
"""
import argparse
import datetime
import hashlib
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = datetime.timezone.utc
COLUMNS = ["event_id", "Channel", "EventID", "TargetImage", "GrantedAccess",
           "SourceImage", "SourceUser", "CallTrace"]


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def version(name):
    import importlib.metadata as md
    try:
        return md.version(name)
    except Exception as e:
        return "UNAVAILABLE (%s)" % e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-dir", required=True)
    args = ap.parse_args()

    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.pipelines.windows import windows_logsource_pipeline
    from sigma.types import SigmaString

    events_doc = json.load(open(os.path.join(HERE, "minpair_events.json"), encoding="utf-8"))
    common = events_doc["common_fields"]

    # runtime anchor: pySigma core collapse in THIS interpreter
    collapse_s = list(SigmaString("\\").s)

    pipeline = sysmon_pipeline() + windows_logsource_pipeline()
    backend = sqliteBackend(processing_pipeline=pipeline)

    rows = []
    for ev in events_doc["events"]:
        doc = dict(common)
        doc["event_id"] = ev["event_id"]
        doc["CallTrace"] = ev["CallTrace"]
        rows.append(doc)

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE logs (event_id TEXT, Channel TEXT, EventID INTEGER, "
                 "TargetImage TEXT, GrantedAccess TEXT, SourceImage TEXT, "
                 "SourceUser TEXT, CallTrace TEXT)")
    conn.executemany("INSERT INTO logs ({}) VALUES ({})".format(
        ", ".join(COLUMNS), ",".join("?" * len(COLUMNS))),
        [tuple(d[c] for c in COLUMNS) for d in rows])

    expected = {"v2": ["E1_local_backslash", "E2_unc", "E4_downloads_true_positive"],
                "v3": ["E4_downloads_true_positive"]}

    results = {
        "side": "sqlite",
        "versions": {
            "python": sys.version.split()[0],
            "sqlite_runtime": sqlite3.sqlite_version,
            "pysigma": version("pysigma"),
            "pysigma_backend_sqlite": version("pysigma-backend-sqlite"),
            "pysigma_pipeline_sysmon": version("pysigma-pipeline-sysmon"),
            "pysigma_pipeline_windows": version("pysigma-pipeline-windows"),
        },
        "sigma_collapse_runtime": {"SigmaString('\\\\').s": collapse_s,
                                   "matches_single_backslash": collapse_s == ["\\"]},
        "runs": {},
    }

    for ver in ("v2", "v3"):
        rule_path = os.path.join(args.rules_dir, "proc_access_win_lsass_memdump_%s.yml" % ver)
        collection = SigmaCollection.from_yaml(open(rule_path, encoding="utf-8").read())
        q = backend.convert(collection)[0]

        # --- identity taxonomy vs the study's compiled SQL (Fix v1.2) ---
        ref_path = os.path.join(HERE, "%s_compiled.sql" % ver)
        ref_bytes = open(ref_path, "rb").read()
        ref_no_nl = ref_bytes.rstrip(b"\n")
        q_bytes = q.encode("utf-8")
        byte_identical_exact = q_bytes == ref_bytes
        identical_modulo_trailing_newline = q_bytes == ref_no_nl

        matched = sorted(r[0] for r in conn.execute(q))
        results["runs"][ver] = {
            "rule_sha256": sha256(rule_path),
            "compiled_sql": q,
            "compiled_sql_sha256_runtime": hashlib.sha256(q_bytes).hexdigest(),
            "reference_sql_file_sha256": hashlib.sha256(ref_bytes).hexdigest(),
            "reference_sql_sha256_no_trailing_newline": hashlib.sha256(ref_no_nl).hexdigest(),
            "byte_identical_exact": byte_identical_exact,
            "identical_modulo_trailing_newline": identical_modulo_trailing_newline,
            "matched_event_ids": matched,
            "vs_baseline_prediction_matrix": "MATCH" if matched == expected[ver]
                                             else "DIVERGENT (record as-is, see PRE_REGISTRATION verdict rules)",
        }

    results["telemetry"] = {"ts": datetime.datetime.now(UTC).isoformat(),
                            "events_sha256": sha256(os.path.join(HERE, "minpair_events.json")),
                            "pre_registration_sha256": sha256(os.path.join(HERE, "PRE_REGISTRATION.md"))}
    json.dump(results, open(os.path.join(HERE, "results_sqlite_mac.json"), "w", encoding="utf-8"), indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
