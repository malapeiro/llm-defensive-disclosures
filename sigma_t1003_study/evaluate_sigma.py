#!/usr/bin/env python3
"""
Deterministic Sigma Rule & Selection-Level Evaluation Harness (T1003.001 Study).

Evaluates official and LLM-hardened versions (v0 -> v1 -> v2 -> v3) of SigmaHQ rule
`proc_access_win_lsass_memdump.yml` (5ef9853e-4d0e-4a70-846f-a9ca37d876da) against
the 725-file real EVTX corpus:
  - EVTX-ATTACK-SAMPLES (278 .evtx files)
  - SigmaHQ regression_data/rules/windows (447 .evtx files)

Compiler & pipeline versions:
  - pySigma 2.0.2 (`sigma.types.SigmaString`, `sigma.collection.SigmaCollection`)
  - pysigma-backend-sqlite 2.1.1 (`sqliteBackend`)
  - pysigma-pipeline-sysmon 3.0.0 (`sysmon_pipeline`)
  - pysigma-pipeline-windows 3.0.0 (`windows_logsource_pipeline`)

Measures BOTH:
  1. Full boolean `condition:` execution via pySigma sqliteBackend
  2. Individual `selection_*` and `filter_*` block activation matrix across all 15
     exhaustive Sysmon EventID 10 files touching `lsass.exe` in the corpus.
"""

import argparse
import copy
import hashlib
import json
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml
from evtx import PyEvtxParser
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

STUDY_DIR = Path(__file__).resolve().parent
DEFAULT_WORK_DIR = STUDY_DIR.parent.parent / "sigma_work"

RULE_VERSIONS = {
    "v0": STUDY_DIR / "rules" / "proc_access_win_lsass_memdump_v0.yml",
    "v1": STUDY_DIR / "rules" / "proc_access_win_lsass_memdump_v1.yml",
    "v2": STUDY_DIR / "rules" / "proc_access_win_lsass_memdump_v2.yml",
    "v3": STUDY_DIR / "rules" / "proc_access_win_lsass_memdump_v3.yml",
}

# Exhaustive, provenance-traceable oracle for all 15 .evtx files in the 725-file corpus
# that contain Sysmon EventID 10 (ProcessAccess) touching lsass.exe.
# Exhaustiveness is enforced programmatically by verify_oracle_exhaustiveness().
LSASS_SYSMON10_ORACLE = {
    # --- 7 v0 True Positives (T1003.001 LSASS dumps detected by official v0 rule) ---
    "EVTX-ATTACK-SAMPLES:Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x1000", "0x1410", "0x1fffff"],
        "source_images": [
            r"c:\Users\IEUser\Desktop\PPLdump.exe",
            r"C:\Windows\system32\services.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); PPLdump KnownDLL hijack dumping lsass.exe via services.exe (0x1fffff, dbgcore.DLL).",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/sysmon_10_11_lsass_memdump.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x1fffff"],
        "source_images": [
            r"C:\Users\grace\Desktop\sysinternal\procdump.exe",
            r"C:\Windows\system32\taskmgr.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); procdump.exe and taskmgr.exe dumping lsass.exe (0x1fffff, dbghelp.dll).",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x1fffff"],
        "source_images": [
            r"C:\Users\IEUser\Desktop\Outflank-Dumpert\Dumpert\x64\Release\Outflank-Dumpert.exe",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Users\IEUser\Desktop\AndrewSpecial\AndrewSpecial.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); Outflank-Dumpert (exe + rundll32 DLL) and AndrewSpecial dumping lsass.exe (0x1fffff).",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "CredAccess - LSASS Access",
        "granted_access": ["0x1fffff"],
        "source_images": [
            r"C:\Users\Books\Desktop\Procdump\procdump.exe",
            r"C:\Users\Books\AppData\Local\Temp\procdump64.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access, evtx_data.csv (Credential Access), and Sysmon RuleName='CredAccess - LSASS Access'.",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x143a"],
        "source_images": [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); PowerShell Invoke-Mimikatz accessing lsass.exe with 0x143a.",
    },
    "EVTX-ATTACK-SAMPLES:Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": True,
        "folder_tactic": "Defense Evasion",
        "csv_tactic": "Defense Evasion",
        "sysmon_rulename": "Suspicious ImageLoad - Possible Memdump (EventID 7)",
        "granted_access": ["0x1fffff"],
        "source_images": [
            r"c:\Users\Public\BYOV\ZAM64\ppldump.exe",
        ],
        "provenance": "[INTERPRETATION: Multi-tactic sample] Stored in Defense Evasion/ folder (evtx_data.csv: Defense Evasion), but filename explicitly encodes 'CA_Memdump' (Credential Access Memdump) and executes ppldump.exe -> lsass.exe (0x1fffff).",
    },
    "SigmaHQ-Reg:process_access/proc_access_win_susp_dbgcore_dbghelp_load/9f5c1d59-33be-4e60-bcab-85d2f566effd.evtx": {
        "category": "TP_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "SigmaHQ-Reg:process_access",
        "csv_tactic": "N/A (SigmaHQ regression_data)",
        "sysmon_rulename": "-",
        "granted_access": ["0x1fffff"],
        "source_images": [
            r"C:\Users\Public\wsass\WerFaultSecure.exe",
        ],
        "provenance": "Documented in SigmaHQ regression_data info.yml as Positive Detection Test for rule 9f5c1d59-33be-4e60-bcab-85d2f566effd (tags: attack.credential-access, attack.t1003.001).",
    },

    # --- 4 v0 False Negatives in Credential Access/ (Documented T1003.001 missed by v0) ---
    "EVTX-ATTACK-SAMPLES:Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx": {
        "category": "FN_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x1f1fff"],
        "source_images": [
            r"\\VBOXSVR\HTools\voice_mail.msg.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); Meterpreter hashdump accessing lsass.exe with GrantedAccess=0x1f1fff and CallTrace containing UNKNOWN(...).",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/babyshark_mimikatz_powershell.evtx": {
        "category": "FN_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "technique_id=T1003,technique_name=Credential Dumping",
        "granted_access": ["0x1010"],
        "source_images": [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access, evtx_data.csv (Credential Access), and embedded Sysmon RuleName='technique_id=T1003,technique_name=Credential Dumping'; PowerShell Mimikatz accessing lsass.exe with 0x1010.",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx": {
        "category": "FN_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "Credential Access",
        "sysmon_rulename": "",
        "granted_access": ["0x1010"],
        "source_images": [
            r"C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe",
            r"c:\Users\admin\Desktop\mimi\x64\mimikatz.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Credential Access and evtx_data.csv (Credential Access); mimikatz.exe sekurlsa::logonpasswords accessing lsass.exe with 0x1010.",
    },
    "EVTX-ATTACK-SAMPLES:Credential Access/tutto_malseclogon.evtx": {
        "category": "FN_V0_CRED_DUMP",
        "is_interpretation": False,
        "folder_tactic": "Credential Access",
        "csv_tactic": "N/A (added after evtx_data.csv)",
        "sysmon_rulename": "-",
        "granted_access": ["0x1410"],
        "source_images": [
            r"Z:\bouss\Downloads\MalSeclogon-master\x64\Debug\MalSeclogon.exe",
        ],
        "provenance": "Documented by placement in EVTX-ATTACK-SAMPLES/Credential Access; MalSeclogon.exe accessing lsass.exe with 0x1410.",
    },

    # --- 1 Multi-Technique Bundle in AutomatedTestingTools/ (Interpreted T1003.001 event) ---
    "EVTX-ATTACK-SAMPLES:AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx": {
        "category": "FN_V0_INTERPRETED_BUNDLE",
        "is_interpretation": True,
        "folder_tactic": "AutomatedTestingTools",
        "csv_tactic": "N/A (multi-tactic bundle)",
        "sysmon_rulename": "",
        "granted_access": ["0x1010"],
        "source_images": [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ],
        "provenance": "[INTERPRETATION: Multi-tactic Atomic Red Team bundle] Stored in AutomatedTestingTools/; event row 643 shows powershell.exe -> lsass.exe (0x1010, CallTrace ending in UNKNOWN(0000026DBFD67240)) 0.5s before gsecdump -a and procdump.exe -ma lsass.exe.",
    },

    # --- 3 Non-T1003 Tactics Touching lsass.exe (Discovery, Persistence, Privilege Escalation) ---
    "EVTX-ATTACK-SAMPLES:Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx": {
        "category": "NON_T1003_OTHER_TACTIC",
        "is_interpretation": False,
        "folder_tactic": "Discovery",
        "csv_tactic": "Discovery",
        "sysmon_rulename": "",
        "granted_access": ["0x1410"],
        "source_images": [
            r"D:\m.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Discovery and evtx_data.csv (Discovery); Meterpreter process listing (ps) querying lsass.exe with 0x1410 (T1057 Process Discovery, not T1003 Credential Dumping).",
    },
    "EVTX-ATTACK-SAMPLES:Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx": {
        "category": "NON_T1003_OTHER_TACTIC",
        "is_interpretation": False,
        "folder_tactic": "Persistence",
        "csv_tactic": "Persistence",
        "sysmon_rulename": "",
        "granted_access": ["0x1410"],
        "source_images": [
            r"c:\python27\python.exe",
        ],
        "provenance": "Documented in EVTX-ATTACK-SAMPLES/Persistence and evtx_data.csv (Persistence); python.exe (_ctypes.pyd) querying lsass.exe with 0x1410 during WMI Event Subscription (T1546.003).",
    },
    "EVTX-ATTACK-SAMPLES:Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.evtx": {
        "category": "NON_T1003_OTHER_TACTIC",
        "is_interpretation": True,
        "folder_tactic": "Privilege Escalation",
        "csv_tactic": "Privilege Escalation",
        "sysmon_rulename": "",
        "granted_access": ["0x101ffb"],
        "source_images": [
            r"c:\python27\python.exe",
        ],
        "provenance": "[INTERPRETATION: Non-T1003 LSASS abuse] Documented in EVTX-ATTACK-SAMPLES/Privilege Escalation and evtx_data.csv (Privilege Escalation); winpwnage.py opens lsass.exe with 0x101ffb to inherit SYSTEM handle and spawn cmd.exe as child of lsass.exe (T1134.004 Parent PID Spoofing / Handle Inheritance, not T1003 credential dump).",
    },
}


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_evtx_xml(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    row = {}
    for child in root:
        cname = strip_ns(child.tag)
        if cname == "System":
            for sys_el in child:
                sname = strip_ns(sys_el.tag)
                if sname == "Provider":
                    row["Provider_Name"] = sys_el.attrib.get("Name", "")
                elif sname == "EventID":
                    try:
                        row["EventID"] = int(sys_el.text or 0)
                    except ValueError:
                        row["EventID"] = 0
                elif sname == "Channel":
                    row["Channel"] = sys_el.text or ""
                elif sname == "Computer":
                    row["Computer"] = sys_el.text or ""
                elif sname == "TimeCreated":
                    row["SystemTime"] = sys_el.attrib.get("SystemTime", "")
        elif cname in ("EventData", "UserData"):
            for data_el in child.iter():
                if strip_ns(data_el.tag) == "Data":
                    name = data_el.attrib.get("Name")
                    if name:
                        row[name] = data_el.text if data_el.text is not None else ""
    return row


def build_corpus_db(
    db_path: Path,
    evtx_attack_dir: Path,
    sigma_reg_dir: Path,
) -> sqlite3.Connection:
    if db_path.exists():
        return sqlite3.connect(str(db_path))

    if not evtx_attack_dir.exists() or not sigma_reg_dir.exists():
        raise FileNotFoundError(
            f"Corpus directories not found: {evtx_attack_dir} or {sigma_reg_dir}. "
            "Pass --db, --evtx-attack-dir, and --sigma-reg-dir."
        )

    print(f"[*] Building SQLite corpus database at {db_path} ...")
    sources = []
    for p in sorted(evtx_attack_dir.rglob("*.evtx")):
        rel = f"EVTX-ATTACK-SAMPLES:{p.relative_to(evtx_attack_dir)}"
        sources.append((rel, p))
    for p in sorted(sigma_reg_dir.rglob("*.evtx")):
        rel = f"SigmaHQ-Reg:{p.relative_to(sigma_reg_dir)}"
        sources.append((rel, p))

    all_rows = []
    col_map = {"sample_file": "sample_file", "eventid": "EventID"}
    unreadable = []

    for rel, path in sources:
        try:
            parser = PyEvtxParser(str(path))
            for rec in parser.records():
                try:
                    parsed = parse_evtx_xml(rec["data"])
                    parsed["sample_file"] = rel
                    norm_row = {}
                    for k, v in parsed.items():
                        kl = k.lower()
                        if kl not in col_map:
                            col_map[kl] = k
                        canon_k = col_map[kl]
                        norm_row[canon_k] = v if canon_k == "EventID" else str(v)
                    all_rows.append(norm_row)
                except Exception:
                    pass
        except Exception as e:
            unreadable.append((rel, str(e)))

    conn = sqlite3.connect(str(db_path))
    cols = list(col_map.values())
    col_defs = ", ".join(
        [f'"{c}" INTEGER' if c == "EventID" else f'"{c}" TEXT' for c in cols]
    )
    conn.execute(f"CREATE TABLE logs ({col_defs})")
    conn.execute("CREATE INDEX idx_channel_eventid ON logs (Channel, EventID)")
    conn.execute("CREATE INDEX idx_sample_file ON logs (sample_file)")

    placeholders = ", ".join(["?"] * len(cols))
    col_names = ", ".join([f'"{c}"' for c in cols])
    batch = [[r.get(c, None) for c in cols] for r in all_rows]
    conn.executemany(f"INSERT INTO logs ({col_names}) VALUES ({placeholders})", batch)
    conn.commit()
    print(f"[+] Indexed {len(all_rows)} events from {len(sources) - len(unreadable)} readable .evtx files.")
    return conn


def verify_oracle_exhaustiveness(conn: sqlite3.Connection) -> None:
    """
    Programmatically verifies that LSASS_SYSMON10_ORACLE covers 100% of files in the
    725-file corpus that have EventID=10 mentioning 'lsass' in ANY column, with zero
    unlabeled files and zero phantom entries.
    """
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(logs)")
    cols = [r[1] for r in cur.fetchall() if r[1] != "EventID"]
    where_any_lsass = " OR ".join([f'LOWER("{c}") LIKE "%lsass%"' for c in cols])
    cur.execute(
        f"SELECT DISTINCT sample_file FROM logs WHERE EventID = 10 AND ({where_any_lsass}) ORDER BY sample_file"
    )
    actual_files = {r[0] for r in cur.fetchall()}
    oracle_files = set(LSASS_SYSMON10_ORACLE.keys())

    missing_from_oracle = actual_files - oracle_files
    extra_in_oracle = oracle_files - actual_files
    if missing_from_oracle or extra_in_oracle:
        raise AssertionError(
            f"Oracle exhaustiveness check failed! "
            f"Missing from oracle: {sorted(missing_from_oracle)}; "
            f"Extra in oracle: {sorted(extra_in_oracle)}"
        )


def get_backend() -> sqliteBackend:
    pipeline = sysmon_pipeline() + windows_logsource_pipeline()
    return sqliteBackend(processing_pipeline=pipeline)


def compile_sigma_yaml(yaml_str: str, backend: sqliteBackend) -> str:
    collection = SigmaCollection.from_yaml(yaml_str)
    queries = backend.convert(collection)
    if not queries:
        raise ValueError("pySigma produced 0 SQL queries for rule.")
    return queries[0]


def evaluate_rule_yaml(conn: sqlite3.Connection, yaml_str: str) -> dict:
    verify_oracle_exhaustiveness(conn)
    backend = get_backend()
    raw_doc = yaml.safe_load(yaml_str)
    rule_sql = compile_sigma_yaml(yaml_str, backend)

    cur = conn.cursor()
    cur.execute(f"SELECT sample_file, COUNT(*) FROM ({rule_sql}) GROUP BY sample_file ORDER BY sample_file")
    rule_matches = {row[0]: row[1] for row in cur.fetchall()}

    # Evaluate each selection_* and filter_* block independently
    detection = raw_doc.get("detection", {})
    block_names = [k for k in detection.keys() if k != "condition"]
    block_matches = {}
    block_sqls = {}
    block_lsass_e10_matches = {}

    for bname in block_names:
        sub_doc = copy.deepcopy(raw_doc)
        sub_doc["detection"] = {
            bname: copy.deepcopy(detection[bname]),
            "condition": bname,
        }
        sub_yaml = yaml.safe_dump(sub_doc, sort_keys=False)
        try:
            b_sql = compile_sigma_yaml(sub_yaml, backend)
            block_sqls[bname] = b_sql
            cur.execute(f"SELECT sample_file, COUNT(*) FROM ({b_sql}) GROUP BY sample_file ORDER BY sample_file")
            block_matches[bname] = {row[0]: row[1] for row in cur.fetchall()}
            cur.execute(
                f'SELECT sample_file, COUNT(*) FROM ({b_sql}) WHERE LOWER(TargetImage) LIKE "%\\lsass.exe" GROUP BY sample_file ORDER BY sample_file'
            )
            block_lsass_e10_matches[bname] = {row[0]: row[1] for row in cur.fetchall()}
        except Exception as e:
            block_sqls[bname] = f"ERROR: {e}"
            block_matches[bname] = {}
            block_lsass_e10_matches[bname] = {}

    lsass_sysmon10_matrix = {}
    summary_by_category = {
        "TP_V0_CRED_DUMP": {"total": 0, "fired": 0, "files_fired": [], "files_missed": []},
        "FN_V0_CRED_DUMP": {"total": 0, "fired": 0, "files_fired": [], "files_missed": []},
        "FN_V0_INTERPRETED_BUNDLE": {"total": 0, "fired": 0, "files_fired": [], "files_missed": []},
        "NON_T1003_OTHER_TACTIC": {"total": 0, "fired": 0, "files_fired": [], "files_missed": []},
    }

    for sample_file, meta in sorted(LSASS_SYSMON10_ORACLE.items()):
        cat = meta["category"]
        fired = sample_file in rule_matches
        summary_by_category[cat]["total"] += 1
        if fired:
            summary_by_category[cat]["fired"] += 1
            summary_by_category[cat]["files_fired"].append(sample_file)
        else:
            summary_by_category[cat]["files_missed"].append(sample_file)

        active_blocks_any_event = [
            bname for bname in block_names if sample_file in block_matches.get(bname, {})
        ]
        active_blocks_on_lsass_target = [
            bname for bname in block_names if sample_file in block_lsass_e10_matches.get(bname, {})
        ]
        lsass_sysmon10_matrix[sample_file] = {
            "category": cat,
            "is_interpretation": meta["is_interpretation"],
            "folder_tactic": meta["folder_tactic"],
            "csv_tactic": meta["csv_tactic"],
            "granted_access": meta["granted_access"],
            "source_images": meta["source_images"],
            "provenance": meta["provenance"],
            "rule_fired": fired,
            "matched_events": rule_matches.get(sample_file, 0),
            "active_blocks_on_lsass_target": active_blocks_on_lsass_target,
            "active_blocks_any_event_in_file": active_blocks_any_event,
        }

    outside_lsass15_matches = {
        f: cnt for f, cnt in rule_matches.items() if f not in LSASS_SYSMON10_ORACLE
    }

    return {
        "id": raw_doc.get("id"),
        "title": raw_doc.get("title"),
        "logsource": raw_doc.get("logsource"),
        "condition": detection.get("condition"),
        "block_names": block_names,
        "compiled_sql": rule_sql,
        "total_matched_files": len(rule_matches),
        "total_matched_events": sum(rule_matches.values()),
        "summary_by_category": summary_by_category,
        "outside_lsass15_matches": outside_lsass15_matches,
        "rule_matches": rule_matches,
        "block_file_counts": {b: len(m) for b, m in block_matches.items()},
        "block_lsass_target_file_counts": {b: len(m) for b, m in block_lsass_e10_matches.items()},
        "lsass_sysmon10_matrix": lsass_sysmon10_matrix,
    }


def main():
    ap = argparse.ArgumentParser(description="Evaluate Sigma rules at rule and selection level.")
    ap.add_argument("--rule", type=str, help="Path to single Sigma YAML rule to evaluate")
    ap.add_argument("--all-versions", action="store_true", help="Evaluate v0, v1, v2, v3 and write compiled_sql/ and results/")
    ap.add_argument("--db", type=str, default=str(DEFAULT_WORK_DIR / "evtx_corpus.db"), help="Path to SQLite corpus DB")
    ap.add_argument("--evtx-attack-dir", type=str, default=str(DEFAULT_WORK_DIR / "EVTX-ATTACK-SAMPLES"), help="Path to EVTX-ATTACK-SAMPLES")
    ap.add_argument("--sigma-reg-dir", type=str, default=str(DEFAULT_WORK_DIR / "sigma" / "regression_data" / "rules" / "windows"), help="Path to SigmaHQ regression_data/rules/windows")
    ap.add_argument("--dump-json", type=str, help="Write evaluation JSON to path (single rule mode)")
    args = ap.parse_args()

    conn = build_corpus_db(
        Path(args.db),
        Path(args.evtx_attack_dir),
        Path(args.sigma_reg_dir),
    )
    verify_oracle_exhaustiveness(conn)

    if args.all_versions or not args.rule:
        sql_dir = STUDY_DIR / "compiled_sql"
        res_dir = STUDY_DIR / "results"
        sql_dir.mkdir(parents=True, exist_ok=True)
        res_dir.mkdir(parents=True, exist_ok=True)

        print("=== T1003.001 Sigma Study: Full Trajectory (v0 -> v1 -> v2 -> v3) ===\n")
        for ver, rpath in RULE_VERSIONS.items():
            yaml_text = rpath.read_text(encoding="utf-8")
            sha256 = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
            res = evaluate_rule_yaml(conn, yaml_text)
            res["version"] = ver
            res["sha256"] = sha256
            res["path"] = str(rpath.relative_to(STUDY_DIR))

            (sql_dir / f"{ver}_compiled.sql").write_text(res["compiled_sql"] + "\n", encoding="utf-8")
            (res_dir / f"{ver}_eval.json").write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")

            s = res["summary_by_category"]
            print(
                f"[{ver}] SHA-256={sha256[:16]}... | "
                f"TP={s['TP_V0_CRED_DUMP']['fired']}/7 | "
                f"FN={s['FN_V0_CRED_DUMP']['fired']}/4 | "
                f"Bundle={s['FN_V0_INTERPRETED_BUNDLE']['fired']}/1 | "
                f"FP(NON_T1003)={s['NON_T1003_OTHER_TACTIC']['fired']}/3 | "
                f"Total={res['total_matched_files']} files ({res['total_matched_events']} ev)"
            )
            print(f"     Block hits (lsass target): {res['block_lsass_target_file_counts']}")
        return

    target_path = Path(args.rule)
    yaml_text = target_path.read_text(encoding="utf-8")
    sha256 = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
    res = evaluate_rule_yaml(conn, yaml_text)
    res["sha256"] = sha256
    res["path"] = str(target_path)

    print(f"=== {res['title']} ({res['id']}) ===")
    print(f"  File      : {target_path}")
    print(f"  SHA-256   : {sha256}")
    print(f"  Condition : {res['condition']}")
    print(f"  Block hits (lsass target) : {res['block_lsass_target_file_counts']}")
    print(f"  Rule hits : {res['total_matched_files']} files ({res['total_matched_events']} events)")
    for cat, info in res["summary_by_category"].items():
        print(f"  {cat}: {info['fired']}/{info['total']} fired")

    if args.dump_json:
        Path(args.dump_json).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
