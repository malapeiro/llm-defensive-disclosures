"""Supervisor (Claude) — conta alertas Suricata por sid em cada pcap de referência do M3.
Uso: python3 -I m3_suricata_contar.py <pasta_com_pcaps_e_regras>   (só biblioteca padrão)"""
import sys, os, json, subprocess, collections, tempfile, re
D = os.path.abspath(sys.argv[1]); R = os.path.join(D, "sunstrike_m3.rules")
CEN = ["NEG","H1","H2","H3","H4","H5","NONCANON","MASS","SLOW","EMERG"]
print(subprocess.run(["suricata", "-V"], capture_output=True, text=True).stdout.strip())
t = subprocess.run(["suricata", "-T", "-S", R, "-l", tempfile.mkdtemp()], capture_output=True, text=True)
bad = sorted(set(re.findall(r"sid:(\d+)", t.stdout + t.stderr)))
print("suricata -T:", "PASS" if t.returncode == 0 else "FAIL", "| não carregam:", len(bad), bad)
sids = sorted(set(re.findall(r"sid:(\d+);", open(R).read())))
res = {}
for c in CEN:
    od = tempfile.mkdtemp()
    subprocess.run(["suricata", "-r", os.path.join(D, c + ".pcap"), "-S", R, "-k", "none", "-l", od], capture_output=True, text=True)
    cnt = collections.Counter()
    ev = os.path.join(od, "eve.json")
    if os.path.exists(ev):
        for line in open(ev):
            j = json.loads(line)
            if j.get("event_type") == "alert": cnt[str(j["alert"]["signature_id"])] += 1
    res[c] = cnt
print("sid      " + " ".join("%8s" % c for c in CEN))
for s in sids: print("%s  " % s + " ".join("%8d" % res[c].get(s, 0) for c in CEN))
