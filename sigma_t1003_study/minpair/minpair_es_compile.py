#!/usr/bin/env python3
"""minpair_es_compile.py -- sigma_t1003_study minimal pair, Elastic/Lucene side.

RUN IN THE ELASTIC VENV (pySigma 1.5.1 / pysigma-backend-elasticsearch 2.1.1 /
pipeline-sysmon 2.0.0 / pipeline-windows 2.0.1 -- pip resolution constraint:
pysigma-backend-elasticsearch requires pysigma<2.0.0, see freeze_es.txt and
the dated amendment in PRE_REGISTRATION.md).

  python3 minpair_es_compile.py --rules-dir <path-to>/sigma_t1003_study/rules

Compiles v2/v3 to Lucene (query_string) in two variants:
  - no-pipeline: raw field names (TargetImage, CallTrace, ...) -- the variant
    consumed by es_query_v2.json / es_query_v3.json against sigma-minpair,
    because the index schema is the events' own field names;
  - with-pipeline (sysmon+windows, best effort): recorded for the file, not
    consumed unless the field names match the index.
Also regenerates es_bulk.ndjson (one bulk action line BEFORE EACH document),
emits a suggested es_mapping.json from the field names found in the no-pipeline
query, checks the pySigma core collapse in THIS interpreter, and records all
versions. Produces results_es_compile.json.

Fixes:
- v1.1 (2026-11-21): SigmaString imports from sigma.types (was sigma.rule,
  ImportError on pySigma -- operator errata; same location in 1.5.1).
- v1.2 (2026-11-21): bulk NDJSON generator emitted ONE index action line for
  all documents; ES bulk requires one action line BEFORE EACH document.
  Caught mid-run by operator/Claude during the 2026-11-21 run: the ingest used
  es_bulk_fixed.ndjson (sha256 9c32b775...); the buggy es_bulk.ndjson
  (c8cab5c3...) stays hashed in hashes_run_2026-11-21.txt as history.
  Generator fixed to interleave action lines per document.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = datetime.timezone.utc
INDEX = "sigma-minpair"


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def version(name):
    import importlib.metadata as md
    try:
        return md.version(name)
    except Exception as e:
        return "UNAVAILABLE (%s)" % e


def load_pipelines():
    """Best-effort sysmon+windows pipelines; returns (pipeline_or_None, note)."""
    try:
        from sigma.pipelines.sysmon import sysmon_pipeline
        from sigma.pipelines.windows import windows_logsource_pipeline
        return sysmon_pipeline() + windows_logsource_pipeline(), \
            "loaded from sigma.pipelines.{sysmon,windows}"
    except Exception as e1:
        try:
            from sigma.pipelines.Scripts import sysmon as sysmon_mod
            from sigma.pipelines.Scripts import windows as windows_mod
            fns = []
            for mod in (sysmon_mod, windows_mod):
                fns += [getattr(mod, n) for n in dir(mod)
                        if callable(getattr(mod, n)) and n.endswith("pipeline")]
            pipe = []
            for f in fns:
                try:
                    pipe.extend(f())
                except Exception:
                    pass
            if pipe:
                return pipe, "loaded from sigma.pipelines.Scripts (pySigma 1.x layout)"
            return None, "pipeline import failed both layouts: %s" % e1
        except Exception as e2:
            return None, "pipeline import failed both layouts: %s / %s" % (e1, e2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-dir", required=True)
    args = ap.parse_args()

    from sigma.collection import SigmaCollection
    import sigma.backends.elasticsearch as es_mod
    from sigma.types import SigmaString

    # --- pick the Lucene-style backend class defensively ---
    cls = None
    cls_name = None
    for name in ("LuceneBackend", "ElasticsearchLuceneBackend", "elasticsearchLuceneBackend"):
        cand = getattr(es_mod, name, None)
        if cand is not None:
            cls, cls_name = cand, name
            break
    if cls is None:
        raise SystemExit("Lucene backend class not found; available: %r"
                         % [n for n in dir(es_mod) if n.endswith("Backend")])

    events_doc = json.load(open(os.path.join(HERE, "minpair_events.json"), encoding="utf-8"))
    common = events_doc["common_fields"]

    collapse_s = list(SigmaString("\\").s)

    pipeline, pipeline_note = load_pipelines()

    # bulk NDJSON for the 4 synthetic events (Fix v1.2: action line per document)
    rows = []
    for ev in events_doc["events"]:
        doc = dict(common)
        doc["event_id"] = ev["event_id"]
        doc["CallTrace"] = ev["CallTrace"]
        rows.append(doc)
    action = '{"index": {"_index": "%s"}}' % INDEX
    bulk_lines = []
    for doc in rows:
        bulk_lines.append(action)
        bulk_lines.append(json.dumps(doc))
    with open(os.path.join(HERE, "es_bulk.ndjson"), "w", encoding="utf-8") as f:
        f.write("\n".join(bulk_lines) + "\n")

    results = {
        "side": "elasticsearch_lucene",
        "versions": {
            "python": sys.version.split()[0],
            "pysigma": version("pysigma"),
            "pysigma_backend_elasticsearch": version("pysigma-backend-elasticsearch"),
            "pysigma_pipeline_sysmon": version("pysigma-pipeline-sysmon"),
            "pysigma_pipeline_windows": version("pysigma-pipeline-windows"),
            "es_backend_class": cls_name,
        },
        "sigma_collapse_runtime": {"SigmaString('\\\\').s": collapse_s,
                                   "matches_single_backslash": collapse_s == ["\\"]},
        "pipeline_load": {"used": pipeline is not None, "note": pipeline_note},
        "runs": {},
    }

    no_pipeline_queries = {}
    for ver in ("v2", "v3"):
        rule_path = os.path.join(args.rules_dir, "proc_access_win_lsass_memdump_%s.yml" % ver)
        yaml_text = open(rule_path, encoding="utf-8").read()

        entry = {"rule_sha256": sha256(rule_path)}

        # variant 1: no pipeline (consumed by the index whose schema is the events' fields)
        try:
            luc = cls()
            q_plain = luc.convert(SigmaCollection.from_yaml(yaml_text))[0]
            entry["lucene_query_no_pipeline"] = q_plain
            no_pipeline_queries[ver] = q_plain
        except Exception as e:
            entry["lucene_query_no_pipeline_error"] = str(e)

        # variant 2: with pipelines, best effort (recorded, consumed only if fields align)
        if pipeline is not None:
            try:
                luc_p = cls(processing_pipeline=pipeline)
                entry["lucene_query_with_pipeline"] = luc_p.convert(SigmaCollection.from_yaml(yaml_text))[0]
            except Exception as e:
                entry["lucene_query_with_pipeline_error"] = str(e)

        results["runs"][ver] = entry

    # field names referenced by the consumed (no-pipeline) queries -> suggested mapping
    if not no_pipeline_queries:
        raise SystemExit("No-pipeline compile failed for BOTH rules (see errors above); "
                         "no es_query_*.json generated -- report to the operator session.")
    fields = set()
    for q in no_pipeline_queries.values():
        fields.update(re.findall(r"([A-Za-z_][A-Za-z0-9_.]*):", q))
    fields.discard("AND"); fields.discard("OR"); fields.discard("NOT")
    mapping = {"mappings": {"properties": {
        f: ({"type": "long"} if f == "EventID" else {"type": "keyword"}) for f in sorted(fields)}}}
    mapping["mappings"]["properties"]["event_id"] = {"type": "keyword"}
    json.dump(mapping, open(os.path.join(HERE, "es_mapping.json"), "w", encoding="utf-8"), indent=2)
    results["index_fields_referenced"] = sorted(fields)

    # _search bodies relying on query_string with default field resolution
    for ver in ("v2", "v3"):
        if ver not in no_pipeline_queries:
            continue
        json.dump({"query": {"query_string": {"query": no_pipeline_queries[ver]}}},
                  open(os.path.join(HERE, "es_query_%s.json" % ver), "w", encoding="utf-8"), indent=2)
        if "lucene_query_with_pipeline" in results["runs"][ver]:
            json.dump({"query": {"query_string": {"query": results["runs"][ver]["lucene_query_with_pipeline"]}}},
                      open(os.path.join(HERE, "es_query_%s_pipelined.json" % ver), "w", encoding="utf-8"), indent=2)

    results["telemetry"] = {"ts": datetime.datetime.now(UTC).isoformat(),
                            "events_sha256": sha256(os.path.join(HERE, "minpair_events.json")),
                            "pre_registration_sha256": sha256(os.path.join(HERE, "PRE_REGISTRATION.md"))}
    json.dump(results, open(os.path.join(HERE, "results_es_compile.json"), "w", encoding="utf-8"), indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
