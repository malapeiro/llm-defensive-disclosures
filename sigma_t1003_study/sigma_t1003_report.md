# Sigma T1003.001 Hardening Study

## Parser-Semantic Blindness in LLM Self-Validation: Hardening `proc_access_win_lsass_memdump.yml` Against Real EVTX Telemetry

**Author:** Sérgio Azevedo (`malapeiro`) · **Date:** 2026-11-07 · **Artifact class:** execution-verified (`pySigma 2.0.2` + `pysigma-backend-sqlite 2.1.1` against 725 real `.evtx` files / 37,841 Windows events)  
**Subject:** iterative LLM hardening (`v0 → v1 → v2 → v3`) of official SigmaHQ rule [`proc_access_win_lsass_memdump.yml`](rules/proc_access_win_lsass_memdump_v0.yml) (`5ef9853e-4d0e-4a70-846f-a9ca37d876da`, MITRE ATT&CK `T1003.001` — OS Credential Dumping: LSASS Memory) evaluated against the combined [`EVTX-ATTACK-SAMPLES`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) and [`SigmaHQ regression_data`](https://github.com/SigmaHQ/sigma/tree/master/regression_data/rules/windows) corpus.

---

## Introduction — a two-study investigation into LLM self-validation blindness

This repository documents defensive security engineering carried out through a **three-model adversarial loop**: a *builder* LLM (GLM 5.3) produces an artifact, a *primary adversarial auditor* (Gemini) attacks it and runs it against a corpus, and an *independent external verifier* (Claude) reproduces every measurement in a separate environment and rules on what the numbers mean. The point of the third role is epistemic: no claim of success is accepted on the word of the model that produced it.

Two studies here reach the same conclusion from opposite ends of the stack. In **Hydrostrike**, a synthetic ICS/water-station lab, the builder's iterative "hardening" silently deleted a working public-health detection rule (chlorine over-dosing) that then survived three versions at *100% passing* validation — because every test battery grew along the attack axis and none re-checked whether the rules already present still fired. In this **Sigma / T1003.001** study, the builder was asked to harden a *real, published* SigmaHQ rule for LSASS credential dumping against *real* attack samples, judged by a *real* production compiler (pySigma) over a labeled corpus — a ground truth external to all three models. Across four rounds the builder recovered the requested detections without regressing the originals, but twice introduced failures its own self-test declared absent: first a speculative over-generalization opening two false positives, then a "fix" that passed its self-test and the Sigma schema check yet left both false positives firing in the real engine.

The unifying finding is not that language models write bad detections. It is more specific and more useful: **an LLM validates its output against its own mental model of what a construct means, and that model diverges from the executing engine.** The recurring defect across both studies is a *semantic/parser differential* — `is True` vs. `bool()`, HTTP header normalization, URL-path normalization, and here the Sigma escape sequence `\\` — and in every case the model's self-test inherits the same wrong belief, so it passes while the artifact is broken. The only mechanism that caught each one was execution in the real target plus independent re-measurement. When, in the final round, the builder was shown the real compiler's output, it diagnosed and corrected its own error. The prescription that follows is therefore constructive: **never trust an LLM's self-test for a rule or a guard; close the loop with the real executor, and verify it from outside the model that wrote it.**

---

## 1. Executive Summary & Version Trajectory (`v0 → v1 → v2 → v3`)

Official SigmaHQ rule [`proc_access_win_lsass_memdump.yml`](rules/proc_access_win_lsass_memdump_v0.yml) (`v0`) detects LSASS memory dumping via Sysmon EventID 10 (`ProcessAccess`). To avoid flooding enterprise SOCs with false positives, the SigmaHQ maintainers explicitly commented out low-privilege access masks such as `0x1010` (`PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`) and `0x1410` (`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION`). As a result, when evaluated against all **725 readable `.evtx` files (`37,841` events)** in the combined `EVTX-ATTACK-SAMPLES` + `SigmaHQ regression_data` corpus, `v0` detects **7 of the 11 documented `T1003.001` LSASS dump samples (`7 TP`)** and misses **4 documented `T1003.001` samples (`4 FN`)** plus 1 multi-tactic Atomic Red Team bundle.

We gave the builder model (GLM 5.3) the complete `v0` rule (including the maintainers' `# Too many false positives` comments), the 7 `TP` samples, and the 4 `FN` samples (`0x1f1fff` Meterpreter `hashdump`, `0x1010` PowerShell `babyshark`, `0x1010` `mimikatz.exe`, and `0x1410` `MalSeclogon.exe`), asking it to recover the 4 `FN`s without regressing any of the 7 `TP`s or opening false positives. Every resulting rule version was evaluated independently by both Gemini's [`evaluate_sigma.py`](evaluate_sigma.py) harness and Claude's isolated container environment using `pySigma 2.0.2` (`sqliteBackend 2.1.1`).

| Version | Rule Artifact | SHA-256 (`rules/*.yml`) | `TP_V0` (`7` files) | `FN_V0` (`4` files) | `FN_BUNDLE` (`1` file) | `NON_T1003` (`3` files) | Rest of Corpus (`710` files) | Total Files (Events) Fired in `pySigma` | Builder's Own Self-Test Claim |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`v0`** | [`proc_access_win_lsass_memdump_v0.yml`](rules/proc_access_win_lsass_memdump_v0.yml) | `6a4c3d27947f011dadc67c78a8547be67a04d5fdb8f8add537b4d9603d00e65a` | **7 / 7** | **0 / 4** | **0 / 1** | **0 / 3** | **0 / 710** | **7 (17 ev.)** | Official SigmaHQ baseline |
| **`v1`** | [`proc_access_win_lsass_memdump_v1.yml`](rules/proc_access_win_lsass_memdump_v1.yml) | `9e078d830a123ce7b5a6b9691f812f7d41e395b64b04399e9ed3a57981522a9e` | **7 / 7** | **4 / 4** | **1 / 1** | **2 / 3 (2 FP)** | **0 / 710** | **14 (25 ev.)** | *"17/17 PASS (0 FP)"* — tested only against 6 synthetic negatives; missed both real `0x1410` FPs |
| **`v2`** | [`proc_access_win_lsass_memdump_v2.yml`](rules/proc_access_win_lsass_memdump_v2.yml) | `853f22173642983d74887a3b399643387b6c53e01c8a2e53808f53c74424f676` | **7 / 7** | **4 / 4** | **1 / 1** | **2 / 3 (2 FP!)** | **0 / 710** | **14 (25 ev.)** | *"19/19 PASS (FP1 & FP2 closed)"* — ad-hoc Python evaluator treated YAML `'- \\'` as `\\`, whereas `pySigma` `SigmaString` collapsed it to `\`, compiling `OR CallTrace LIKE '%\\%' ESCAPE '\'` (**tautology**) |
| **`v3`** | [`proc_access_win_lsass_memdump_v3.yml`](rules/proc_access_win_lsass_memdump_v3.yml) | `52f3516463798f9fa3a5ae5d5a3a881b670950f74b22eea2ffaf100ca2a597ba` | **7 / 7** | **4 / 4** | **1 / 1** | **0 / 3 (0 FP)** | **0 / 710** | **12 (23 ev.)** | *"19/19 PASS"* — verified on real `pySigma` `sqliteBackend` after removing `'- \\'` |

---

## 2. Experimental Setup & Exhaustive 15-File Ground-Truth Oracle

### 2.1 Compiler, Pipeline, and Corpus Specifications

All measurements were executed deterministically against an indexed SQLite database (`37,841` Windows events parsed via `evtx 0.15.0`) using:
- **`pySigma`**: `2.0.2`
- **`pysigma-backend-sqlite`**: `2.1.1` (`sqliteBackend`)
- **`pysigma-pipeline-sysmon`**: `3.0.0` (`sysmon_pipeline`: maps `process_access` → `Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=10`)
- **`pysigma-pipeline-windows`**: `3.0.0` (`windows_logsource_pipeline`)
- **Corpus (`725` readable `.evtx` files):**
  - `278` `.evtx` files from `sbousseaden/EVTX-ATTACK-SAMPLES` (`37,364` events across all MITRE ATT&CK tactics; `39` files in `Credential Access/`).
  - `447` `.evtx` files from `SigmaHQ/sigma/regression_data/rules/windows` (`477` official rule-regression events).

### 2.2 Programmatic Oracle Exhaustiveness (`15 / 15` Files)

To prevent hand-picked oracle bias, [`verify_oracle_exhaustiveness()`](evaluate_sigma.py#L283-L303) queries every column of every `EventID = 10` record across all 725 `.evtx` files for the substring `lsass` (case-insensitive) and asserts exact set equality (`actual_files == set(LSASS_SYSMON10_ORACLE.keys())`). Any unlabeled `.evtx` file or phantom dictionary entry raises an immediate `AssertionError`.

Across the entire 725-file corpus, **exactly 15 `.evtx` files** contain Sysmon EventID 10 (`ProcessAccess`) events touching `lsass.exe`. Their provenance is traced below to repository folder structure, [`evtx_data.csv`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/evtx_data.csv) tactic mappings, embedded Sysmon `RuleName` tags, and `SigmaHQ` `info.yml` metadata. Where a label requires analytical judgment beyond single-tactic folder metadata, it is explicitly marked **`[INTERPRETATION]`**:

| # | Sample File (`.evtx`) | Oracle Category | Repository Folder | `evtx_data.csv` Tactic | Embedded Sysmon `RuleName` | `GrantedAccess` (`SourceImage` on `lsass.exe`) | Provenance & Interpretation Notes |
| :-: | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` | `TP_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x1000`, `0x1410`, `0x1fffff` (`PPLdump.exe`, `services.exe`) | **Documented:** KnownDLL hijack dumping `lsass.exe` via `C:\Windows\system32\services.exe` (`0x1fffff`, `dbgcore.DLL`). |
| **2** | `sysmon_10_11_lsass_memdump.evtx` | `TP_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x1fffff` (`procdump.exe`, `taskmgr.exe`) | **Documented:** `procdump.exe` and `C:\Windows\system32\taskmgr.exe` dumping `lsass.exe` (`dbghelp.dll`). |
| **3** | `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | `TP_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x1fffff` (`Outflank-Dumpert.exe`, `rundll32.exe`, `AndrewSpecial.exe`) | **Documented:** Direct-syscall / `rundll32.exe` LSASS dumpers (`0x1fffff`). |
| **4** | `sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` | `TP_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | `CredAccess - LSASS Access` | `0x1fffff` (`procdump.exe`, `procdump64.exe`) | **Documented:** Process reflection LSASS dump (`0x1fffff`). |
| **5** | `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | `TP_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x143a` (`powershell.exe`) | **Documented:** PowerShell `Invoke-Mimikatz` opening `lsass.exe` with `0x143a`. |
| **6** | `DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | `TP_V0_CRED_DUMP` | `Defense Evasion/` | `Defense Evasion` | `Suspicious ImageLoad - Possible Memdump` (EID 7) | `0x1fffff` (`c:\Users\Public\BYOV\ZAM64\ppldump.exe`) | **`[INTERPRETATION: Multi-tactic sample]`** Stored under `Defense Evasion/` (BYOVD driver `zam64.sys`), but filename explicitly encodes `CA_Memdump` and executes `ppldump.exe` against `lsass.exe` (`0x1fffff`). |
| **7** | `9f5c1d59-33be-4e60-bcab-85d2f566effd.evtx` | `TP_V0_CRED_DUMP` | `SigmaHQ-Reg:process_access/` | *(SigmaHQ)* | `-` | `0x1fffff` (`C:\Users\Public\wsass\WerFaultSecure.exe`) | **Documented:** Official SigmaHQ positive regression test (`info.yml` tagged `attack.credential-access`, `attack.t1003.001`). |
| **8** | `CA_sysmon_hashdump_cmd_meterpreter.evtx` | `FN_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x1f1fff` (`\\VBOXSVR\HTools\voice_mail.msg.exe`) | **Documented:** Meterpreter `hashdump` accessing `lsass.exe` with `0x1f1fff` and `UNKNOWN(...)` call frames. Missed by `v0` (`0x1f1fff` not in `GrantedAccess`). |
| **9** | `babyshark_mimikatz_powershell.evtx` | `FN_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | `technique_id=T1003,technique_name=Credential Dumping` | `0x1010` (`powershell.exe` ×2) | **Documented:** PowerShell Mimikatz accessing `lsass.exe` with `0x1010` and `CallTrace` containing only `ntdll.dll|KERNELBASE.dll`. Missed by `v0` (`0x1010` commented out). |
| **10** | `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | `FN_V0_CRED_DUMP` | `Credential Access/` | `Credential Access` | *(empty)* | `0x1010` (`...\mimikatz.exe`) | **Documented:** `mimikatz.exe sekurlsa::logonpasswords` accessing `lsass.exe` with `0x1010`. Missed by `v0` (`0x1010` commented out). |
| **11** | `tutto_malseclogon.evtx` | `FN_V0_CRED_DUMP` | `Credential Access/` | *(post-CSV addition)* | `-` | `0x1410` (`Z:\bouss\Downloads\...\MalSeclogon.exe`) | **Documented:** `MalSeclogon.exe` handle manipulation on `lsass.exe` (`0x1410`, `SourceUser=MSEDGEWIN10\IEUser`). Missed by `v0` (`0x1410` commented out). |
| **12** | `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `FN_V0_INTERPRETED_BUNDLE` | `AutomatedTestingTools/` | *(multi-tactic bundle)* | *(empty on EID 10)* | `0x1010` (`powershell.exe`, `UNKNOWN(...)`) | **`[INTERPRETATION: Multi-tactic bundle]`** Atomic Red Team recording in `AutomatedTestingTools/`; event `rowid 643` (`powershell.exe -> lsass.exe`, `0x1010`, `CallTrace` ending in `UNKNOWN(0000026DBFD67240)`) fires 0.5s before `gsecdump -a` and `procdump.exe -ma lsass.exe`. Tracked separately from the 4 single-tactic `FN`s. |
| **13** | `discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx` | `NON_T1003_OTHER_TACTIC` | `Discovery/` | `Discovery` | *(empty)* | `0x1410` (`D:\m.exe`) | **Documented (`T1057` Process Discovery):** Meterpreter `ps` process enumeration opening `lsass.exe` with `0x1410` (`ntdll.dll|KERNELBASE.dll|UNKNOWN(...)|kernel32.dll`). See Section 7.5 on technique-scope attribution. |
| **14** | `sysmon_20_21_1_CommandLineEventConsumer.evtx` | `NON_T1003_OTHER_TACTIC` | `Persistence/` | `Persistence` | *(empty)* | `0x1410` (`c:\python27\python.exe`) | **Documented (`T1546.003` WMI Event Subscription):** `python.exe` (`_ctypes.pyd|python27.dll`) opening `lsass.exe` with `0x1410`. |
| **15** | `sysmon_privesc_from_admin_to_system_handle_inheritance.evtx` | `NON_T1003_OTHER_TACTIC` | `Privilege Escalation/` | `Privilege Escalation` | *(empty)* | `0x101ffb` (`c:\python27\python.exe`) | **`[INTERPRETATION: Non-T1003 LSASS abuse]`** `winpwnage.py -u elevate -i 1 -p cmd.exe` opens `lsass.exe` with `0x101ffb` to inherit a `SYSTEM` handle and spawn `cmd.exe` with `ParentImage=\lsass.exe` (`T1134.004` Parent PID Spoofing / Handle Inheritance, not credential dumping). |

---

## 3. Frozen Baseline (`v0`) Analysis

In [`proc_access_win_lsass_memdump_v0.yml`](rules/proc_access_win_lsass_memdump_v0.yml) (compiled SQL in [`compiled_sql/v0_compiled.sql`](compiled_sql/v0_compiled.sql)), `detection:` has a single `selection` block and three filters:

```yaml
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1038'
            - '0x1438'
            - '0x143a'
            - '0x1fffff' # Too many false positives
            # - '0x01000'  # Too many false positives
            # - '0x1010'   # Too many false positives
            # - '0x1400'  # Too many false positives
            # - '0x1410' # Too many false positives
            # - '0x40'   # Too many false positives
        CallTrace|contains:
            - 'dbgcore.dll'
            - 'dbghelp.dll'
            - 'kernel32.dll'
            - 'kernelbase.dll'
            - 'ntdll.dll'
    filter_main_system_user:
        SourceUser|contains:
            - 'AUTHORI'
            - 'AUTORI'
...
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
```

Why is `v0` an ideal stress test for LLM detection engineering?
1. **System binaries in `TP`s prevent naive path filtering:** Four of the 7 `v0` true positives execute from `C:\Windows\System32\` (`services.exe` in sample #1, `taskmgr.exe` in sample #2, `rundll32.exe` in sample #3, and `powershell.exe` in sample #5). A global filter excluding `C:\Windows\System32\` (such as the one in companion SigmaHQ rule `proc_access_win_lsass_susp_access_flag.yml`) immediately destroys 4 of the 7 `TP`s.
2. **Low-privilege masks (`0x1010`, `0x1410`) collide with non-dump activity:** Unconditionally uncommenting `0x1010` and `0x1410` in `selection` recovers samples #9 (`babyshark`), #10 (`mimikatz`), and #11 (`MalSeclogon`), but immediately triggers false positives on samples #13 (`Discovery` `0x1410`) and #14 (`Persistence` `0x1410`) because all of them contain `ntdll.dll` and `kernelbase.dll` in their `CallTrace`.

---

## 4. Round-by-Round Adversarial Trajectory (`v0 → v1 → v2 → v3`)

### 4.1 Round 1 (`v0 → v1`): Over-Generalization & Unchecked Synthetic Self-Tests

Given the fair briefing (the `v0` rule, the 7 `TP`s, the 4 `FN`s, and the SigmaHQ maintainers' false-positive warning), GLM 5.3 produced [`proc_access_win_lsass_memdump_v1.yml`](rules/proc_access_win_lsass_memdump_v1.yml) (`SHA-256: 9e078d830a123ce7...`), splitting `detection:` into three `OR` branches:
1. **`selection_main`**: preserved `v0`'s `selection` verbatim and added `'0x1f1fff'`, recovering sample #8 (`CA_sysmon_hashdump_cmd_meterpreter.evtx`) while retaining all `7/7` `v0` `TP`s (`0` TP regressions).
2. **`selection_lowaccess_interpreter`**: allowed `GrantedAccess: ['0x1010', '0x1410']` when `SourceImage|endswith` matched `\powershell.exe`, `\pwsh.exe`, `\wscript.exe`, `\cscript.exe`, `\mshta.exe`, **`\python.exe`**, or **`\pythonw.exe`**.
3. **`selection_lowaccess_untrusted_path`**: allowed `GrantedAccess: ['0x1010', '0x1410']` globally, gated only by `not 1 of filter_lowaccess_*` (`SourceImage|startswith` for `C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`, `C:\ProgramData\`, plus Sysinternals filenames).

**What GLM's self-test claimed vs. what happened on the real corpus:**
- GLM built a synthetic 17-case harness (11 positive + 6 invented negative cases such as `wmiprvse.exe` in `C:\Windows\System32\` and an agent in `C:\ProgramData\`) and reported **`17/17 PASS (0 FP)`**.
- When compiled via `pySigma` ([`compiled_sql/v1_compiled.sql`](compiled_sql/v1_compiled.sql)) and executed against the 725-file corpus ([`results/v1_eval.json`](results/v1_eval.json)), `v1` fired on **14 files (25 events)**, opening **2 false positives**:
  - **`FP1` (`Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx`):** `SourceImage: D:\m.exe` (`0x1410`) bypassed `filter_lowaccess_system_paths` and fired `selection_lowaccess_untrusted_path`.
  - **`FP2` (`Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx`):** `SourceImage: c:\python27\python.exe` (`0x1410`) fired **both** `selection_lowaccess_interpreter` (because GLM speculatively added `\python.exe`, which none of the 4 `FN`s used) **and** `selection_lowaccess_untrusted_path` (because `c:\python27\` is outside the 4 filtered system directories).

### 4.2 Round 2 (`v1 → v2`): The Smoking Gun — `SigmaString("\\\\").s == ['\\']` and the SQL `LIKE` Tautology

For Round 2, we gave GLM the exact real event fields (`SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`) of `FP1` and `FP2` and asked for a `v2` rule that closed both FPs without losing the 7 `TP`s or 4 `FN`s — providing **zero hints** on how to separate them.

GLM diagnosed that:
1. `\python.exe` and `\pythonw.exe` did not belong in `selection_lowaccess_interpreter` and removed them.
2. In `FP1` (`D:\m.exe`) and `FP2` (`c:\python27\python.exe`), `CallTrace` contained only system DLLs (`ntdll.dll`, `KERNELBASE.dll`, `kernel32.dll`, `python27.dll`) or `UNKNOWN(...)`, whereas in `FN3` (`mimikatz.exe`) and `FN4` (`MalSeclogon.exe`) the executable's own module path in a user/writable folder (`\Users\`, `\Downloads\`) appeared in `CallTrace`.

GLM therefore restricted `selection_lowaccess_untrusted_path` in [`proc_access_win_lsass_memdump_v2.yml`](rules/proc_access_win_lsass_memdump_v2.yml) (`SHA-256: 853f22173642983d...`) as follows:

```yaml
    selection_lowaccess_untrusted_path:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
        CallTrace|contains:
            - '\Users\'
            - '\Temp\'
            - '\Windows\Temp\'
            - '\ProgramData\'
            - '\Downloads\'
            - '\PerfLogs\'
            - '\\'
```

GLM ran `sigma check` (`0 errors`) and its own Python test harness (which now included `FP1` and `FP2` as negative test cases) and declared: **`19/19 PASS — FP1 Fechado, FP2 Fechado`**.

**When we ran `v2` through the real `pySigma` compiler ([`compiled_sql/v2_compiled.sql`](compiled_sql/v2_compiled.sql)) and executed it against the corpus ([`results/v2_eval.json`](results/v2_eval.json)), `v2` still fired on the exact same 14 files (25 events) — neither `FP1` nor `FP2` had closed!**

#### Why the Self-Test Passed While the Real Engine Failed

Look at the SQL compiled by `pySigma 2.0.2` (`pysigma-backend-sqlite 2.1.1`) for `selection_lowaccess_untrusted_path` in [`compiled_sql/v2_compiled.sql`](compiled_sql/v2_compiled.sql):

```sql
(TargetImage LIKE '%\\lsass.exe' ESCAPE '\'
 AND (GrantedAccess='0x1010' OR GrantedAccess='0x1410')
 AND (CallTrace LIKE '%\\Users\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\Temp\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\Windows\\Temp\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\ProgramData\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\Downloads\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\PerfLogs\\%' ESCAPE '\'
   OR CallTrace LIKE '%\\%' ESCAPE '\'))
```

Look at the seventh disjunct:
```sql
OR CallTrace LIKE '%\\%' ESCAPE '\'
```
With `ESCAPE '\'`, the pattern `'%\\%'` matches **any string containing a single literal backslash (`\`)**. Because every Windows `CallTrace` contains paths like `C:\Windows\SYSTEM32\ntdll.dll`, `CallTrace LIKE '%\\%' ESCAPE '\'` evaluates to **`TRUE` on 100% of Windows `ProcessAccess` events**!

Why did `- '\\'` compile to "contains a single backslash" whereas `- '\Users\'` compiled to "contains `\Users\`"?
1. In single-quoted YAML, `'\Users\'` is the 7-character string `\Users\`, and `'\\'` is the 2-character string `\\` (intended by GLM to match UNC paths `\\server\share`).
2. Inside `pySigma`'s core string parser (`sigma.types.SigmaString`), backslash `\` is the Sigma escape character (used to escape wildcards `\*`, `\?`, and backslash itself `\\`):
   - When `SigmaString` parses `\Users\`, `\U` is not an escape sequence, so both backslashes are retained literally:
     ```python
     >>> from sigma.types import SigmaString
     >>> SigmaString(r"\Users\\").s
     ['\\Users\\']
     ```
   - When `SigmaString` parses `\\` (two backslashes from YAML `'- \\'`), the first backslash escapes the second, **collapsing the string into a single literal backslash `\`**:
     ```python
     >>> SigmaString(r"\\").s
     ['\\']
     ```
3. When `sqliteBackend` converts `SigmaString.s == ['\\']` under `contains`, it escapes that single backslash for SQL `LIKE ... ESCAPE '\'`, yielding `CallTrace LIKE '%\\%' ESCAPE '\'`.
4. **Why GLM's self-test was blind (`19/19 PASS`):** Instead of invoking `pySigma` in its test script, GLM loaded the YAML with `yaml.safe_load` and checked `any(pat in call_trace for pat in patterns)` in raw Python. In raw Python, `'\\\\' in call_trace` looks for two consecutive backslashes (`\\`), which are absent from `FP1` and `FP2`. The self-test shared the author's wrong mental model of Sigma escaping, so it passed green while all six path restrictions in `selection_lowaccess_untrusted_path` were silently short-circuited by `OR TRUE`.

### 4.3 Round 3 (`v2 → v3`): Closing the Loop with the Real Compiler

In Round 3, we showed GLM only two things:
1. The empirical measurement that `FP1` and `FP2` still fired in `v2` via `selection_lowaccess_untrusted_path`.
2. The raw SQL query generated by `pySigma` ([`compiled_sql/v2_compiled.sql`](compiled_sql/v2_compiled.sql)).

We did **not** explain `SigmaString` escaping or tell GLM which line to edit.

Confronted with `OR CallTrace LIKE '%\\%' ESCAPE '\'` in the compiled SQL, GLM:
1. Immediately identified `- '\\'` as the root cause of the `LIKE` tautology and noted that none of the 4 `FN`s required UNC matching in branch 3 (`FN1` Meterpreter `\\VBOXSVR\...` is caught by `selection_main` via `0x1f1fff`).
2. Abandoned its ad-hoc Python substring evaluator, installed `pysigma-backend-sqlite` + `sysmon` + `windows-logsources`, and compiled `v3` into a real SQLite table.
3. **Caught its own silent edit failure using the real engine:** On its first attempt to strip `- '\\'` in `v3`, GLM's string-replacement command failed silently due to backslash escaping — the exact same friction Claude encountered when testing the fix in shell. Because GLM now executed the compiled `pySigma` SQL against SQLite before delivering, it saw `FP1` and `FP2` *still* firing, inspected the SQL, saw `CallTrace LIKE '%\\%' ESCAPE '\'` was still present, removed the line cleanly, and re-verified.

When evaluated on the full 725-file corpus ([`results/v3_eval.json`](results/v3_eval.json), compiled SQL in [`compiled_sql/v3_compiled.sql`](compiled_sql/v3_compiled.sql)), [`proc_access_win_lsass_memdump_v3.yml`](rules/proc_access_win_lsass_memdump_v3.yml) (`SHA-256: 52f3516463798f9f...`) converged across all three independent environments (GLM's `pySigma` run, Gemini's `pySigma` harness, and Claude's `pySigma` and raw evaluators):
- **`TP_V0_CRED_DUMP`**: **7 / 7** (`17` events)
- **`FN_V0_CRED_DUMP`**: **4 / 4** (`5` events)
- **`FN_V0_INTERPRETED_BUNDLE`**: **1 / 1** (`1` event)
- **`NON_T1003_OTHER_TACTIC`**: **0 / 3** (`0` events — both `FP1` and `FP2` closed)
- **Rest of 725-file corpus**: **0 / 710**

---

## 5. Selection-Level Activation Matrix (`7 → 7 → 2`)

Just as in Hydrostrike (`Probe 12A` / `Probe 13A`), measuring only whether the top-level rule fired hides internal branch pathologies. [`evaluate_sigma.py`](evaluate_sigma.py) compiles and executes every `selection_*` and `filter_*` block as an isolated rule (`condition: <block_name>`) across all 15 `lsass.exe` `EventID = 10` files.

### 5.1 Block-Level File Counts (`TargetImage = *\lsass.exe`)

| Detection / Filter Block | `v0` | `v1` | `v2` (Tautology `- '\\'`) | `v3` (`- '\\'` removed) | Structural Diagnosis |
| :--- | :-: | :-: | :-: | :-: | :--- |
| `selection` / `selection_main` | `7` | `8` | `8` | **`8`** | Matches the 7 `v0` `TP`s + `FN1` (`CA_sysmon_hashdump_cmd_meterpreter.evtx`, `0x1f1fff`). |
| `selection_lowaccess_interpreter` | — | `3` | `2` | **`2`** | In `v1`, matched `babyshark`, `PanacheSysmon`, and `FP2` (`python.exe`). Removing `\python.exe` in `v2`/`v3` drops hits from `3 → 2`. |
| **`selection_lowaccess_untrusted_path`** | — | **`7`** | **`7`** ⚠️ | **`2`** ✅ | **The `7 → 7 → 2` signature:** In `v1` (unconstrained `CallTrace`), matched all 7 files with `0x1010`/`0x1410`. In `v2`, despite adding 6 path filters to `CallTrace|contains`, it **remained stuck at `7`** because `- '\\'` compiled to `LIKE '%\\%'`. Removing `- '\\'` in `v3` drops hits to **`2`** (`mimikatz.exe` and `MalSeclogon.exe` only). |
| `filter_lowaccess_system_paths` | — | `6` | `6` | **`6`** | Matches events where `SourceImage` starts with `C:\Windows\`. |
| `filter_main_system_user` | `0` *(1)* | `0` *(1)* | `0` *(1)* | **`0` *(1)*** | `0` hits on `TargetImage=*\lsass.exe` (`SourceUser` is `NULL` in 13/15 files; see Section 7.3); `1` hit on a non-LSASS `svchost.exe` event inside `tutto_malseclogon.evtx`. |
| `filter_optional_thor` / `sysmon` / `sysinternals` | `0` | `0` | `0` | **`0`** | `0` hits in corpus. |

### 5.2 Per-Sample Block Activation Table (`v0 → v1 → v2 → v3`)

 abbreviations: `M` = `selection` / `selection_main`, `I` = `selection_lowaccess_interpreter`, `U` = `selection_lowaccess_untrusted_path`, `F_sys` = `filter_lowaccess_system_paths`.

| # | Sample File (`.evtx`) | Category | `v0` Fired (Blocks) | `v1` Fired (Blocks) | `v2` Fired (Blocks) | `v3` Fired (Blocks) |
| :-: | :--- | :---: | :--- | :--- | :--- | :--- |
| **1** | `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M, U, F_sys`) | ✅ (`M, U, F_sys`) | ✅ (`M, F_sys`) |
| **2** | `sysmon_10_11_lsass_memdump.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) |
| **3** | `sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) |
| **4** | `sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) |
| **5** | `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) | ✅ (`M, F_sys`) |
| **6** | `DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) |
| **7** | `9f5c1d59-33be-4e60-bcab-85d2f566effd.evtx` | `TP_V0` | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) |
| **8** | `CA_sysmon_hashdump_cmd_meterpreter.evtx` | `FN_V0` | ❌ (`—`) | ✅ (`M`) | ✅ (`M`) | ✅ (`M`) |
| **9** | `babyshark_mimikatz_powershell.evtx` | `FN_V0` | ❌ (`—`) | ✅ (`I, U, F_sys`) | ✅ (`I, U, F_sys`) | ✅ (`I, F_sys`) |
| **10** | `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | `FN_V0` | ❌ (`—`) | ✅ (`U`) | ✅ (`U`) | ✅ (`U`) |
| **11** | `tutto_malseclogon.evtx` | `FN_V0` | ❌ (`—`) | ✅ (`U`) | ✅ (`U`) | ✅ (`U`) |
| **12** | `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `FN_BUNDLE` | ❌ (`—`) | ✅ (`I, U, F_sys`) | ✅ (`I, U, F_sys`) | ✅ (`I, F_sys`) |
| **13** | `discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx` | `NON_T1003` | ✅ TN (`—`) | ❌ **FP** (`U`) | ❌ **FP** (`U`) | ✅ **TN** (`—`) |
| **14** | `sysmon_20_21_1_CommandLineEventConsumer.evtx` | `NON_T1003` | ✅ TN (`—`) | ❌ **FP** (`I, U`) | ❌ **FP** (`U`) | ✅ **TN** (`—`) |
| **15** | `sysmon_privesc_from_admin_to_system_handle_inheritance.evtx` | `NON_T1003` | ✅ TN (`—`) | ✅ TN (`—`) | ✅ TN (`—`) | ✅ **TN** (`—`) |

Look at rows **#1, #9, #12, #13, and #14**: in `v1` and `v2`, block `U` (`selection_lowaccess_untrusted_path`) activated across all 5 of those files (`7` files total), proving visually that `v2`'s `CallTrace|contains` filter was completely inert until `- '\\'` was removed in `v3`.

---

## 6. Reproducibility & Artifact Inventory

### 6.1 Directory Contents

- [`evaluate_sigma.py`](evaluate_sigma.py) — deterministic `pySigma` + `SQLite` evaluation harness with programmatic 15-file oracle exhaustiveness verification (`verify_oracle_exhaustiveness`) and block-level decomposition.
- [`rules/`](rules/) — the four Sigma YAML rules evaluated in this study:
  - [`proc_access_win_lsass_memdump_v0.yml`](rules/proc_access_win_lsass_memdump_v0.yml) (`SHA-256: 6a4c3d27947f011dadc67c78a8547be67a04d5fdb8f8add537b4d9603d00e65a`)
  - [`proc_access_win_lsass_memdump_v1.yml`](rules/proc_access_win_lsass_memdump_v1.yml) (`SHA-256: 9e078d830a123ce7b5a6b9691f812f7d41e395b64b04399e9ed3a57981522a9e`)
  - [`proc_access_win_lsass_memdump_v2.yml`](rules/proc_access_win_lsass_memdump_v2.yml) (`SHA-256: 853f22173642983d74887a3b399643387b6c53e01c8a2e53808f53c74424f676`)
  - [`proc_access_win_lsass_memdump_v3.yml`](rules/proc_access_win_lsass_memdump_v3.yml) (`SHA-256: 52f3516463798f9fa3a5ae5d5a3a881b670950f74b22eea2ffaf100ca2a597ba`)
- [`compiled_sql/`](compiled_sql/) — exact SQL queries generated by `pySigma 2.0.2` (`sqliteBackend 2.1.1` + `sysmon 3.0.0` + `windows 3.0.0`):
  - [`v0_compiled.sql`](compiled_sql/v0_compiled.sql), [`v1_compiled.sql`](compiled_sql/v1_compiled.sql), [`v2_compiled.sql`](compiled_sql/v2_compiled.sql) (containing the smoking-gun `OR CallTrace LIKE '%\\%' ESCAPE '\'`), and [`v3_compiled.sql`](compiled_sql/v3_compiled.sql).
- [`results/`](results/) — complete rule-level and block-level evaluation outputs across the 725-file corpus:
  - [`v0_eval.json`](results/v0_eval.json), [`v1_eval.json`](results/v1_eval.json), [`v2_eval.json`](results/v2_eval.json), [`v3_eval.json`](results/v3_eval.json).

### 6.2 How to Reproduce

```bash
# 1. Install exact compiler and parser versions in a Python 3.12+ virtualenv
pip install evtx==0.15.0 pysigma==2.0.2 pysigma-backend-sqlite==2.1.1 \
            pysigma-pipeline-sysmon==3.0.0 pysigma-pipeline-windows==3.0.0 pyyaml

# 2. Clone the external ground-truth repositories
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
git clone https://github.com/SigmaHQ/sigma.git

# 3. Run the full v0 -> v1 -> v2 -> v3 evaluation
python3 evaluate_sigma.py --all-versions \
    --db ./evtx_corpus.db \
    --evtx-attack-dir ./EVTX-ATTACK-SAMPLES \
    --sigma-reg-dir ./sigma/regression_data/rules/windows
```

---

## Section 7 — Limitations and epistemic boundaries

To keep the `100% PASS` batteries and the clean v3 result from being read as production readiness, the following limits apply to every claim in this directory.

1. **Narrow demonstrated scope.** The study exercises a *single* rule (`proc_access_win_lsass_memdump`), a *single* technique (`T1003.001`), a *single* backend (pySigma → SQLite), and a corpus of 725 `.evtx` files of which only 15 touch `lsass.exe` through Sysmon EventID 10. The failure mechanism — a self-test blind to engine semantics — is almost certainly general, but what is *demonstrated here is one instance of it*, not a law.

2. **The escaping defect: parser-level cause, backend-scoped proof.** The collapse of the intended UNC pattern `'\\'` to a single literal backslash occurs in pySigma's core string parser, not in any one backend: `SigmaString("\\\\").s == ['\\']` (verified on pySigma 2.0.2). Every pySigma backend therefore receives a "contains one backslash" predicate, which is a tautology against any Windows path. However, the *end-to-end reopening of the two false positives* was executed and proven only on `pysigma-backend-sqlite 2.1.1`, where it compiles to `CallTrace LIKE '%\%' ESCAPE '\'`. Whether the same predicate is equally tautological after compilation to other targets (Splunk SPL, Elastic DSL, etc.) was **not** tested and must not be assumed.

3. **An un-exercised filter.** In 13 of the 15 `lsass`-touching files the `SourceUser` field is absent (NULL), because the captures predate `SourceUser` in Sysmon EventID 10. The rule's `filter_main_system_user` (`AUTHORI`/`AUTORI`) is therefore effectively inert across most of the corpus; its real-world behavior is not established by these measurements.

4. **The false-positive axis is under-powered.** The corpus contains no clean enterprise administrative telemetry — no EDR, antivirus, backup agent, or legitimate monitoring tool opening `lsass` with a low-access mask. The negatives used are samples drawn from *other attack techniques*. Consequently `0/710` outside the `lsass` set does **not** establish that the rule is false-positive-clean in production; it establishes only that it does not fire on these particular files. The two false positives found are real; the absence of further ones is not evidence.

5. **One of the two false positives is a scoping call, not a pure benign.** `CommandLineEventConsumer` (a WMI persistence consumer, `python27`) is an unambiguous false positive for a credential-dumping rule. `discovery_meterpreter_ps_cmd_process_listing` is a Meterpreter process-listing event (`T1057`): the session is malicious, but its `lsass` access is enumeration, not dumping. Counting it as a false positive is correct *within the rule's stated scope* (credential dumping) but reflects technique misattribution rather than a wholly benign event. Both are reported with this distinction.

6. **The conclusion is constructive, and the verifier's own fallibility is on record.** When shown the real compiler's SQL, the builder correctly diagnosed and removed its own escaping bug — and, in doing so, hit and caught the identical silent string-replacement failure that the verifier had hit earlier, precisely because it re-ran in the real engine before delivering. The result is therefore not "LLMs cannot write detections" but "an LLM's self-validation is blind to engine semantics it has not executed." Separately, the single divergence observed in the entire study — the verifier's raw-substring evaluator disagreeing with pySigma on v2 — was not noise to be reconciled away but the *diagnostic* that localized the escaping bug; at v3, all independent measurements (builder's final pySigma run, auditor's pySigma harness, and the verifier's pySigma and raw evaluators) converged with zero divergence.
