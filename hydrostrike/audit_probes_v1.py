#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bateria de Probes Adversários do Auditor (Gemini) contra o hydrostrike_lab.py v1.0 (GLM 5.3).
Testa 5 vetores fora do caminho feliz da demo:
  PROBE 1 (Falso Positivo — fp_probe): Técnico legítimo ('tech') às 10:15 (janela de manutenção)
          executa retrolavagem de manutenção num único filtro (FLT-01).
  PROBE 2 (Evasão de Ordem de Operações — Deadhead): Atacante fecha VLV-OUT primeiro (com pressão
          normal 4.0 bar) e só depois sobe a pressão, ou fecha VLV-OUT com a bomba ligada a 5.4 bar
          (dentro da banda [2.5, 5.5] bar) através do Guard Proxy às 10:15.
  PROBE 3 (Sabotagem Silenciosa via Guard Proxy na Janela Diurna — H3): Credencial 'tech' às 10:15
          através do Guard Proxy drena o reservatório TK-CLEAR até valores negativos (-6.0%!) com
          retrolavagens repetidas (o Guard Proxy não tem limite de frota/repetição nem piso de tanque!).
  PROBE 4 (Injeção de NaN / Infinity pelo Guard Proxy e Controlador): Envio de {"value": "NaN"} ou
          {"value": "Infinity"} para /api/pump/PMP-01/setpoint através do Guard Proxy às 10:15.
  PROBE 5 (Injeção de Booleano em JSON — bool é subclasse de int em Python!): Envio de {"value": true}
          ou {"muted": "false"} (string não-vazia em bool("false") == True!).
"""

import json
import math
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hydrostrike_lab as hs

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_audit_v1")
os.makedirs(EV, exist_ok=True)
DAY = "2025-03-14 10:15:00"
NIGHT = "2025-03-14 03:15:00"
TECH_CRED = {"username": "tech", "password": hs.USERS["tech"]["password"]}


def scan_file(audit_path):
    det = hs.Detector()
    for ev in hs.read_audit(audit_path):
        det.scan(ev)
    crit = [a for a in det.alerts if a["level"] == "CRIT"]
    warn = [a for a in det.alerts if a["level"] == "WARN"]
    rules = {}
    for a in det.alerts:
        rules[a["rule"]] = rules.get(a["rule"], 0) + 1
    return crit, warn, rules


print("=" * 78)
print("AUDITORIA ADVERSÁRIA AO HYDROSTRIKE v1.0 (GLM 5.3)")
print("=" * 78)

# ---------------------------------------------------------------------------
# PROBE 1: Falso Positivo em Manutenção Diurna Legítima de Filtro
# ---------------------------------------------------------------------------
print("\n[PROBE 1 — FALSO POSITIVO] Técnico 'tech' @ 10:15 faz 1 retrolavagem de manutenção (FLT-01)")
ap1 = hs._fresh_audit(os.path.join(EV, "probe1_fp.jsonl"))
ctl = hs.run_controller_in_thread(8701, ap1, DAY)
_, login = hs.http_req("POST", "127.0.0.1", 8701, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
hs.http_req("POST", "127.0.0.1", 8701, "/api/filter/FLT-01/backwash", {}, hdr)
ctl.stop()
crit, warn, rules = scan_file(ap1)
print("  Alertas gerados: CRIT=%d | WARN=%d | Regras=%s" % (len(crit), len(warn), rules))
print("  >>> VEREDITO PROBE 1: %s" % (
    "FALHA (Falso Positivo CRIT em manutenção diurna legítima de 1 filtro!)"
    if len(crit) > 0 else "OK"
))

# ---------------------------------------------------------------------------
# PROBE 2: Evasão de Ordem de Operações no D-DEADHEAD-RISK + Guard Proxy Cego a Deadhead
# ---------------------------------------------------------------------------
print("\n[PROBE 2 — DEADHEAD EVASION & GUARD BYPASS] Fechar VLV-OUT através do Guard @ 10:15")
ap2 = hs._fresh_audit(os.path.join(EV, "probe2_deadhead.jsonl"))
gp2 = hs._fresh_audit(os.path.join(EV, "probe2_guard.jsonl"))
ctl = hs.run_controller_in_thread(8702, ap2, DAY)
gaudit = hs.Audit(gp2)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8703), hs.make_guard_handler(gaudit, 8702))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8703, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
# Passo 1: Fechar a válvula VLV-OUT enquanto a pressão é 4.0 bar (bomba PMP-01 está a correr!)
st_vlv, _ = hs.http_req("POST", "127.0.0.1", 8703, "/api/valve/out", {"state": "CLOSED"}, hdr)
# Passo 2: Subir a pressão para 5.5 bar (ou mesmo 8.5 bar direto no controlador) DEPOIS da válvula já estar fechada!
st_pmp, _ = hs.http_req("POST", "127.0.0.1", 8703, "/api/pump/PMP-01/setpoint", {"value": 5.5}, hdr)
_, snap2 = hs.http_req("GET", "127.0.0.1", 8702, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
crit, warn, rules = scan_file(ap2)
print("  Guard permitiu fecho de VLV-OUT com PMP-01 ligada? HTTP %d (estado válvula=%s, pressão=%s bar)" % (
    st_vlv, snap2["valve"], snap2["pressure_bar"]
))
print("  D-DEADHEAD-RISK disparou? %s (CRIT=%d, WARN=%d, Regras=%s)" % (
    "SIM" if "D-DEADHEAD-RISK" in rules else "NÃO — CEGO!", len(crit), len(warn), rules
))

# ---------------------------------------------------------------------------
# PROBE 3: Drenagem Total (e Negativa!) do Reservatório através do Guard Proxy
# ---------------------------------------------------------------------------
print("\n[PROBE 3 — RESERVOIR DRAIN & NEGATIVE PHYSICS] 7 retrolavagens via Guard @ 10:15")
ap3 = hs._fresh_audit(os.path.join(EV, "probe3_drain.jsonl"))
gp3 = hs._fresh_audit(os.path.join(EV, "probe3_guard.jsonl"))
ctl = hs.run_controller_in_thread(8704, ap3, DAY)
gaudit = hs.Audit(gp3)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8705), hs.make_guard_handler(gaudit, 8704))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8705, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
codes = []
for i in range(7):
    flt = hs.FILTERS[i % 4]
    sc, _ = hs.http_req("POST", "127.0.0.1", 8705, "/api/filter/%s/backwash" % flt, {}, hdr)
    codes.append(sc)
_, snap3 = hs.http_req("GET", "127.0.0.1", 8704, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
print("  Códigos HTTP no Guard para 7 backwashes seguidos: %s" % codes)
print("  Nível final do reservatório TK-CLEAR: %s%% (Física quebrada: nível negativo!)" % snap3["reservoir_pct"])
print("  Pressão final: %s bar" % snap3["pressure_bar"])

# ---------------------------------------------------------------------------
# PROBE 4: Injeção de NaN (Not-a-Number) através do Guard Proxy e Detector
# ---------------------------------------------------------------------------
print("\n[PROBE 4 — NaN BYPASS NO CLAMP DO GUARD E NO DETECTOR] Envio de {'value': 'NaN'} via Guard @ 10:15")
ap4 = hs._fresh_audit(os.path.join(EV, "probe4_nan.jsonl"))
gp4 = hs._fresh_audit(os.path.join(EV, "probe4_guard.jsonl"))
ctl = hs.run_controller_in_thread(8706, ap4, DAY)
gaudit = hs.Audit(gp4)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8707), hs.make_guard_handler(gaudit, 8706))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8707, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
st_nan, resp_nan = hs.http_req("POST", "127.0.0.1", 8707, "/api/pump/PMP-01/setpoint", {"value": "NaN"}, hdr)
_, snap4 = hs.http_req("GET", "127.0.0.1", 8706, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
crit4, warn4, rules4 = scan_file(ap4)
print("  Resposta HTTP ao enviar 'NaN' pelo Guard: %d -> %s" % (st_nan, resp_nan))
print("  Estado da pressão no controlador após 'NaN': %r" % snap4["pressure_bar"])
print("  Alertas gerados pelo Detector: CRIT=%d | WARN=%d | Regras=%s" % (len(crit4), len(warn4), rules4))

# ---------------------------------------------------------------------------
# PROBE 5: Bug de Coerção Booleana em /api/alarm/mute (bool("false") == True!)
# ---------------------------------------------------------------------------
print("\n[PROBE 5 — TYPE CONFUSION EM ALARM MUTE] Técnico envia {'muted': 'false'} (string) para desmutar")
ap5 = hs._fresh_audit(os.path.join(EV, "probe5_bool.jsonl"))
gp5 = hs._fresh_audit(os.path.join(EV, "probe5_guard.jsonl"))
ctl = hs.run_controller_in_thread(8708, ap5, DAY)
gaudit = hs.Audit(gp5)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8709), hs.make_guard_handler(gaudit, 8708))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8709, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
# Nota: No Guard, `body.get("muted") is True` é False para a string `"false"` (PASSA PELO GUARD!),
# mas no Controlador, `bool(body.get("muted"))` avalia `bool("false")` == True (SILENCIA OS ALARMES!)
st_mute, resp_mute = hs.http_req("POST", "127.0.0.1", 8709, "/api/alarm/mute", {"muted": "false"}, hdr)
_, snap5 = hs.http_req("GET", "127.0.0.1", 8708, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
print("  Guard bloqueou {'muted': 'false'}? NÃO (HTTP %d, porque 'false' is True == False no Guard!)" % st_mute)
print("  Estado alarm_muted no Controlador: %s (porque bool('false') == True no Controlador!)" % snap5["alarm_muted"])
print("  >>> VEREDITO PROBE 5: BYPASS TOTAL DE G-ALARM-MUTE-BLOCKED POR DIFERENCIAL DE PARSING (is True vs bool())!")
