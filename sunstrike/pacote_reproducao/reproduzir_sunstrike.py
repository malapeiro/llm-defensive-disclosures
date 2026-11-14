#!/usr/bin/env python3
"""SUNSTRIKE — pacote de reprodução do caso (código congelado na v0.7.5).

Uso:   python3 -I reproduzir_sunstrike.py <pasta_v0.7.5>
Faz:   confirma os hashes, copia tudo para uma pasta nova repro_run_<UTC>/,
       corre selftest, demo, measure, os probes R2–R11 (v0.7.5) e o R11 contra
       a v0.7.4 preservada ("antes"), e a probe do supervisor com os números
       declarados. Compara cada resultado com o esperado e sai com 0 se tudo
       bater, 1 se não. Só biblioteca padrão; só loopback.
"""
import hashlib, os, re, shutil, subprocess, sys, time

LAB_V075 = "cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d788ae2fb723320b091cb86f8"
LAB_V074 = "c039ab6174e309ddfd4158f6a865abda22471518a6f2119358a772b1069c62c1"
PROBES = ["r2", "r3", "r4", "r5", "r6", "r7_v071", "r8", "r9", "r10", "r11"]
HERE = os.path.dirname(os.path.abspath(__file__))

def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()

def main():
    if len(sys.argv) != 2:
        print(__doc__); return 2
    src = os.path.abspath(sys.argv[1])
    lab, pre = os.path.join(src, "sunstrike_lab.py"), os.path.join(src, "sunstrike_lab_pre_r11_fixes.py")
    for p, h, n in ((lab, LAB_V075, "lab v0.7.5"), (pre, LAB_V074, "lab v0.7.4 preservada")):
        if not os.path.isfile(p) or sha(p) != h:
            print("FALHA: %s em falta ou com hash errado: %s" % (n, p)); return 1
    run = os.path.abspath("repro_run_" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    depois, antes, out = (os.path.join(run, x) for x in ("depois_v075", "antes_v074", "outputs"))
    for d in (depois, antes, out):
        os.makedirs(d)
    shutil.copy2(lab, depois)
    for p in PROBES:
        shutil.copy2(os.path.join(src, "sunstrike_probes_%s.py" % p), depois)
    shutil.copy2(pre, os.path.join(antes, "sunstrike_lab.py"))
    shutil.copy2(os.path.join(src, "sunstrike_probes_r11.py"), antes)
    shutil.copy2(os.path.join(HERE, "probe_supervisor_declarados.py"), run)

    py = [sys.executable, "-I"]
    steps = [
        ("selftest", depois, py + ["sunstrike_lab.py", "selftest"], [r"RESULTADO: PASS"]),
        ("demo", depois, py + ["sunstrike_lab.py", "demo"], [r"RESULTADO FINAL: PASS \(9/9"]),
        ("measure", depois, py + ["sunstrike_lab.py", "measure"], [r"RESULTADO FINAL: PASS \(51 corridas"]),
        ("R11 antes (v0.7.4)", antes, py + ["sunstrike_probes_r11.py"], [r"16/16 previsões confirmadas \(lab v0\.7\.4\)"]),
    ]
    exp = {"r8": r"11/11 previsões confirmadas", "r9": r"7/7 previsões confirmadas",
           "r10": r"29/29 previsões confirmadas", "r11": r"16/16 previsões confirmadas \(lab v0\.7\.5\)"}
    for p in PROBES:
        steps.append(("%s (v0.7.5)" % p.upper(), depois, py + ["sunstrike_probes_%s.py" % p],
                      [exp.get(p, r"PREVISÕES ERRADAS: 0\b")]))
    steps.append(("declarados (supervisor)", run, py + ["probe_supervisor_declarados.py", depois], [
        r"\[A1-PARK-35\.1\].*D-BATTERY-PARKED-DRAIN', 'CRIT'.*casas com luz 1\.\.8h=\[11, 7, 3, 0",
        r"\[A1-PARK-45\.1\].*SoC=\[45\.1\] alertas=\[\] \| casas com luz 1\.\.8h=\[12, 9, 6, 3, 0",
        r"\[A1-CTRL\] sem ataque \| casas com luz 1\.\.8h=\[12, 12, 12, 10, 9",
        r"\[A2-0\.0051\].*queda real=40\.00 pp ledger=40\.00",
        r"\[A4-CURTAIL-26\].*div=74\.0% alertas=\[\]",
        r"\[A5-HMAC\].*-> 403 \| legitima HMAC -> 200"]))

    print("SUNSTRIKE — reprodução | Python %s | %s\nlab v0.7.5 %s… OK | v0.7.4 %s… OK\nsaída: %s\n"
          % (sys.version.split()[0], sys.platform, LAB_V075[:12], LAB_V074[:12], run))
    fails = 0
    for i, (name, cwd, cmd, pats) in enumerate(steps, 1):
        t0 = time.time()
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1200)
            txt, rc = r.stdout + r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            txt, rc = "TIMEOUT", -1
        fn = os.path.join(out, "%02d_%s.txt" % (i, re.sub(r"[^\w]+", "_", name).strip("_")))
        open(fn, "w", encoding="utf-8").write(txt)
        miss = [p for p in pats if not re.search(p, txt)]
        ok = rc == 0 and not miss
        fails += not ok
        print("%-26s %s  (%4.0f s)%s" % (name, "PASS" if ok else "FAIL", time.time() - t0,
              "" if ok else "  rc=%s em falta: %s" % (rc, miss)))
    print("\nRESULTADO: %s — %d/%d passos" % ("TUDO BATE" if not fails else "HÁ DIFERENÇAS", len(steps) - fails, len(steps)))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
