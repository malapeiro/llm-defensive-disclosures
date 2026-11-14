"""Supervisor (Claude) — RUN 1 OFICIAL do M3. Uso:
python3 -I m3_avaliar_supervisor.py <pasta_m3_run> <ficheiro_regras> <saida_dir>
- Suricata: suricata -r <cenario>.pcap -S <regras> -k none ; conta alertas por sid (eve.json).
- Sigma: carrega TODOS os *.jsonl da pasta de evidência do cenário numa tabela SQLite `logs`
  (vista `events`), converte cada regra com o backend SQLite do pySigma e conta linhas.
- Compara com M3_PREVISOES.md (tabelas A e B)."""
import sys, os, re, json, glob, sqlite3, subprocess, collections, hashlib
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
RUN, RULES, OUT = (os.path.abspath(x) for x in sys.argv[1:4]); os.makedirs(OUT, exist_ok=True)
CEN = ["NEG","H1","H2","H3","H4","H5","NONCANON","MASS","SLOW","EMERG"]
prev = open(os.path.join(RUN, "M3_PREVISOES.md"), encoding="utf-8").read()
def parse_cell(c):
    c = c.strip(); lc = c.lower()
    if lc.startswith("não") or lc.startswith("nao"): return ("eq", 0)
    m = re.match(r"sim\s*×\s*(\d+)", lc)
    if m: return ("eq", int(m.group(1)))
    m = re.search(r"\((.*)\)", c)
    if m:
        inner = m.group(1)
        if "≥" in inner: return ("ge", int(re.search(r"≥\s*(\d+)", inner).group(1)))
        nums = [int(x) for x in re.findall(r"(\d+)\s+[a-zç_]", inner.lower())] or [int(x) for x in re.findall(r"\d+", inner)]
        return ("eq", sum(nums) if "+" in inner else nums[0])
    return ("ge", 1)
def table(section_start, section_end, keycol):
    s = prev[prev.index(section_start):prev.index(section_end)]; rows = {}
    for line in s.splitlines():
        if not line.startswith("|") or "---" in line: continue
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        if cells[0] in ("sid", "Regra Sigma"): continue
        key = cells[keycol]; vals = cells[-10:]
        rows[key] = {c: (v, parse_cell(v)) for c, v in zip(CEN, vals)}
    return rows
A = table("## A.", "## B.", 0); B = table("## B.", "## C.", 0)
ok = lambda exp, n: (n == exp[1]) if exp[0] == "eq" else (n >= exp[1])
rep = ["# M3 — RUN 1 OFICIAL (supervisor) — resultados", ""]
# --- Suricata
v = subprocess.run(["suricata", "-V"], capture_output=True, text=True).stdout.strip()
rep += ["## Suricata (%s)" % v, ""]
t = subprocess.run(["suricata", "-T", "-S", RULES, "-l", OUT], capture_output=True, text=True)
bad = sorted(set(re.findall(r"sid:(\d+)", t.stdout + t.stderr)))
rep += ["- `suricata -T`: %s; regras que NÃO carregam: %d → %s" % ("PASS" if t.returncode == 0 else "FAIL", len(bad), ", ".join(bad) or "nenhuma"), ""]
obs_s = {}
for c in CEN:
    pc = os.path.join(RUN, c + ".pcap"); od = os.path.join(OUT, "suricata_" + c); os.makedirs(od, exist_ok=True)
    r = subprocess.run(["suricata", "-r", pc, "-S", RULES, "-k", "none", "-l", od], capture_output=True, text=True)
    cnt = collections.Counter()
    ev = os.path.join(od, "eve.json")
    if os.path.exists(ev):
        for line in open(ev):
            j = json.loads(line)
            if j.get("event_type") == "alert": cnt[str(j["alert"]["signature_id"])] += 1
    obs_s[c] = (cnt, r.returncode, hashlib.sha256(open(pc, "rb").read()).hexdigest())
rep += ["| sid | " + " | ".join(CEN) + " |", "|---" * (len(CEN) + 1) + "|"]
tot = wrong = 0; wrong_list = []
for sid, row in A.items():
    cells = []
    for c in CEN:
        txt, exp = row[c]; n = obs_s[c][0].get(sid, 0); good = ok(exp, n); tot += 1
        if not good: wrong += 1; wrong_list.append("Suricata %s %s: previsto «%s», observado %d%s" % (sid, c, txt, n, " (não carregou)" if sid in bad else ""))
        cells.append(("%d" % n) + ("" if good else " ✗"))
    rep.append("| %s%s | %s |" % (sid, " (não carrega)" if sid in bad else "", " | ".join(cells)))
rep += ["", "Suricata: %d/%d células certas; %d erradas." % (tot - wrong, tot, wrong), ""]
# --- Sigma
rules = {}
for f in sorted(glob.glob(os.path.join(RUN, "sigma", "*.yml"))):
    y = open(f, encoding="utf-8").read(); title = re.search(r'title:\s*"?SUNSTRIKE\s+(D-[A-Z0-9-]+)', y).group(1)
    rules[title] = sqliteBackend().convert(SigmaCollection.from_yaml(y))
evid = {}
for c in CEN:
    lg = open(os.path.join(RUN, "gen_%s.log" % c), encoding="utf-8").read()
    evid[c] = os.path.join(RUN, re.search(r"evidencia:\s*(\S+)", lg).group(1))
obs_g = {}
for c in CEN:
    db = sqlite3.connect(":memory:"); rows = []; keys = set()
    for jf in sorted(glob.glob(os.path.join(evid[c], "*.jsonl"))):
        for line in open(jf, encoding="utf-8"):
            if line.strip(): d = json.loads(line); rows.append(d); keys |= set(d)
    keys = sorted(keys); db.execute("CREATE TABLE logs (%s)" % ",".join('"%s"' % k for k in keys)); db.execute("CREATE VIEW events AS SELECT * FROM logs")
    for d in rows:
        db.execute("INSERT INTO logs VALUES (%s)" % ",".join("?" * len(keys)), [(json.dumps(d[k]) if isinstance(d.get(k), (dict, list)) else d.get(k)) for k in keys])
    def q_count(q):
        while True:
            try: return len(db.execute(q).fetchall())
            except sqlite3.OperationalError as e:
                m = re.match(r"no such column: (\S+)", str(e))
                if not m: raise
                db.execute('ALTER TABLE logs ADD COLUMN "%s"' % m.group(1)); db.execute("DROP VIEW events"); db.execute("CREATE VIEW events AS SELECT * FROM logs")
    obs_g[c] = {t: sum(q_count(q) for q in qs) for t, qs in rules.items()}; obs_g[c]["_linhas"] = len(rows)
rep += ["## Sigma (pySigma + backend SQLite; tabela `logs` com todas as linhas *.jsonl da evidência do cenário)", "",
        "| regra | " + " | ".join(CEN) + " |", "|---" * (len(CEN) + 1) + "|"]
tot2 = wrong2 = 0
for name, row in B.items():
    cells = []
    for c in CEN:
        txt, exp = row[c]; n = obs_g[c].get(name, -1); good = ok(exp, n); tot2 += 1
        if not good: wrong2 += 1; wrong_list.append("Sigma %s %s: previsto «%s», observado %d" % (name, c, txt, n))
        cells.append(("%d" % n) + ("" if good else " ✗"))
    rep.append("| %s | %s |" % (name, " | ".join(cells)))
rep += ["", "Sigma: %d/%d células certas; %d erradas." % (tot2 - wrong2, tot2, wrong2), "",
        "## NEG (tem de ser zero)", "- Suricata: %s" % dict(obs_s["NEG"][0]), "- Sigma: %s" % {k: v for k, v in obs_g["NEG"].items() if v and k != "_linhas"}, "",
        "## Previsões erradas (%d)" % len(wrong_list)] + ["- " + w for w in wrong_list] + ["", "## Hashes dos pcaps de referência"] + ["- %s.pcap `%s`" % (c, obs_s[c][2]) for c in CEN]
open(os.path.join(OUT, "M3_RUN1_OFICIAL.md"), "w", encoding="utf-8").write("\n".join(rep))
print("\n".join(rep))
