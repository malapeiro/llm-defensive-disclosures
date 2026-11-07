#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bateria de Probes Adversários do Auditor — RONDA 2 contra hydrostrike_lab.py v1.1 (GLM 5.3).
1. Confirma regressão da Ronda 1 (P1–P5 fechados na v1.1).
2. Lança 3 NOVOS vetores adversários de 2.ª ordem contra as próprias correções da v1.1:
   - PROBE 6 (Bypass do G-BACKWASH-FLEET-LIMIT por Diferencial de Normalização do Header Authorization):
     O Guard indexa `fleet_counts` pela string bruta `self.headers.get("Authorization")`, mas o
     Controlador extrai o token com `auth[7:].strip() if auth.lower().startswith("bearer ")`!
     Variando o case ("Bearer " vs "bearer " vs "BEARER ") ou espaços no fim ("Bearer <tok> "),
     um único token faz bypass infinito ao limite de 2 retrolavagens e drena o reservatório a 0.0%!
   - PROBE 7 (Falso Positivo de Turno Completo vs. Ponto Cego de Mesma-Unidade na v1.1):
     (7a - Falso Positivo): Técnico legítimo lava FLT-01 de manhã (09:00) e FLT-02 à tarde (16:00)
          com 7 horas de intervalo -> `D-MULTI-FILTER-BACKWASH` dispara CRIT!
     (7b - Ponto Cego): Atacante em janela diurna faz 3 retrolavagens seguidas no MESMO filtro (FLT-01),
          drenando o reservatório de 78% para 42% (acima do limiar 40%) e baixando a pressão para 2.8 bar
          -> 0 alertas CRIT (`len(flts) == 1` e `42% >= 40%`)!
   - PROBE 8 (Subpressão Silenciosa Induzida por Retrolavagem — Acoplamento Bomba + Backwash):
     Atacante ajusta pressão para o limite inferior permitido pelo Guard (2.5 bar — dentro da banda!)
     e executa 2 retrolavagens permitidas pelo Guard (cada uma reduz a pressão em 0.4 bar -> 1.7 bar,
     abaixo do mínimo de 2.5 bar da rede!), mas o Detector NUNCA verifica `pressure_after < PUMP_BAND[0]`
     nos eventos `filter_backwash` -> rede despressurizada (1.7 bar) com 0 CRIT!
"""

import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hydrostrike_lab as hs

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_audit_v2")
os.makedirs(EV, exist_ok=True)
DAY = "2025-03-14 10:15:00"
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
print("AUDITORIA ADVERSÁRIA — RONDA 2 SOBRE HYDROSTRIKE v1.1 (GLM 5.3)")
print("=" * 78)

# ---------------------------------------------------------------------------
# PROBE 6: Bypass de G-BACKWASH-FLEET-LIMIT via Header Normalization Differential
# ---------------------------------------------------------------------------
print("\n[PROBE 6 — GUARD FLEET-LIMIT BYPASS] 1 único token com variações de case/espaços em Authorization")
ap6 = hs._fresh_audit(os.path.join(EV, "probe6_header_diff.jsonl"))
gp6 = hs._fresh_audit(os.path.join(EV, "probe6_guard.jsonl"))
ctl = hs.run_controller_in_thread(8801, ap6, DAY)
gaudit = hs.Audit(gp6)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8802), hs.make_guard_handler(gaudit, 8801))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8802, "/api/login", TECH_CRED)
tok = login["session"]

# Usamos EXATAMENTE o mesmo token `tok`, mas variamos o prefixo/espaços que o Controlador ignora (.lower() e .strip())
header_variants = [
    "Bearer " + tok,
    "Bearer " + tok,
    "bearer " + tok,
    "bearer " + tok,
    "BEARER " + tok,
    "BEARER " + tok,
    "Bearer " + tok + "   ",
]
statuses = []
for i, hval in enumerate(header_variants):
    flt = hs.FILTERS[i % 4]
    sc, _ = hs.http_req("POST", "127.0.0.1", 8802, "/api/filter/%s/backwash" % flt, {}, {"Authorization": hval})
    statuses.append(sc)

_, snap6 = hs.http_req("GET", "127.0.0.1", 8801, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
print("  Códigos HTTP das 7 retrolavagens com o MESMO token: %s" % statuses)
print("  Reservatório final após bypass do Guard: %s%% (drenado a ZERO pelo Guard!)" % snap6["reservoir_pct"])
print("  >>> VEREDITO PROBE 6: %s" % (
    "FALHA CRÍTICA (Bypass total de G-BACKWASH-FLEET-LIMIT por diferencial de parsing do header Authorization!)"
    if all(s == 200 for s in statuses) else "OK"
))

# ---------------------------------------------------------------------------
# PROBE 7A & 7B: Falso Positivo de Turno Completo (09:00 vs 16:00) + Ponto Cego no Mesmo Filtro
# ---------------------------------------------------------------------------
print("\n[PROBE 7A — FALSO POSITIVO DE TURNO] Técnico lava FLT-01 às 09:00 e FLT-02 às 16:00 (7h depois)")
ap7a = hs._fresh_audit(os.path.join(EV, "probe7a_fp_shift.jsonl"))
ctl = hs.run_controller_in_thread(8803, ap7a, "2025-03-14 09:00:00")
_, login = hs.http_req("POST", "127.0.0.1", 8803, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
hs.http_req("POST", "127.0.0.1", 8803, "/api/filter/FLT-01/backwash", {}, hdr)
hs.set_sim_time("2025-03-14 16:00:00")  # 7 horas mais tarde!
hs.http_req("POST", "127.0.0.1", 8803, "/api/filter/FLT-02/backwash", {}, hdr)
ctl.stop()
crit7a, warn7a, rules7a = scan_file(ap7a)
print("  Alertas em 2 filtros com 7h de intervalo: CRIT=%d | WARN=%d | Regras=%s" % (len(crit7a), len(warn7a), rules7a))

print("\n[PROBE 7B — PONTO CEGO NO MESMO FILTRO] 3 retrolavagens seguidas em FLT-01 @ 10:15 (78% -> 42%)")
ap7b = hs._fresh_audit(os.path.join(EV, "probe7b_same_filter.jsonl"))
try:
    ctl = hs.run_controller_in_thread(8804, ap7b, DAY, safety_interlocks=False)
except TypeError:
    ctl = hs.run_controller_in_thread(8804, ap7b, DAY)
_, login = hs.http_req("POST", "127.0.0.1", 8804, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
for _ in range(3):
    hs.http_req("POST", "127.0.0.1", 8804, "/api/filter/FLT-01/backwash", {}, hdr)
_, snap7b = hs.http_req("GET", "127.0.0.1", 8804, "/api/status")
ctl.stop()
crit7b, warn7b, rules7b = scan_file(ap7b)
print("  Reservatório caiu para %s%%, pressão caiu para %s bar | CRIT=%d | WARN=%d | Regras=%s" % (
    snap7b["reservoir_pct"], snap7b["pressure_bar"], len(crit7b), len(warn7b), rules7b
))

# ---------------------------------------------------------------------------
# PROBE 8: Subpressão Silenciosa Induzida por Backwash (Acoplamento Setpoint 2.5 bar + 2 Backwashes -> 1.7 bar)
# ---------------------------------------------------------------------------
print("\n[PROBE 8 — SUBPRESSÃO SILENCIOSA VIA GUARD] Setpoint no limite da banda (2.5 bar) + 2 backwashes (FLT-01) -> 1.7 bar")
ap8 = hs._fresh_audit(os.path.join(EV, "probe8_underpressure.jsonl"))
gp8 = hs._fresh_audit(os.path.join(EV, "probe8_guard.jsonl"))
ctl = hs.run_controller_in_thread(8805, ap8, DAY)
gaudit = hs.Audit(gp8)
gserver = hs.ThreadingHTTPServer(("127.0.0.1", 8806), hs.make_guard_handler(gaudit, 8805))
threading.Thread(target=gserver.serve_forever, daemon=True).start()

_, login = hs.http_req("POST", "127.0.0.1", 8806, "/api/login", TECH_CRED)
hdr = {"Authorization": "Bearer " + login["session"]}
# 1. Baixar setpoint para 2.5 bar (permitido pelo Guard porque está dentro de [2.5, 5.5] bar)
hs.http_req("POST", "127.0.0.1", 8806, "/api/pump/PMP-01/setpoint", {"value": 2.5}, hdr)
# 2. Fazer 2 retrolavagens em FLT-01 (permitidas pelo Guard porque <= GUARD_FLEET_LIMIT=2)
hs.http_req("POST", "127.0.0.1", 8806, "/api/filter/FLT-01/backwash", {}, hdr)
hs.http_req("POST", "127.0.0.1", 8806, "/api/filter/FLT-01/backwash", {}, hdr)
_, snap8 = hs.http_req("GET", "127.0.0.1", 8805, "/api/status")
gserver.shutdown(); gserver.server_close(); gaudit.close(); ctl.stop()
crit8, warn8, rules8 = scan_file(ap8)
print("  Pressão final na rede pública: %s bar (ABAIXO da banda mínima [2.5, 5.5] bar!)" % snap8["pressure_bar"])
print("  Alertas CRIT gerados pelo Detector: CRIT=%d | WARN=%d | Regras=%s" % (len(crit8), len(warn8), rules8))
print("  >>> VEREDITO PROBE 8: %s" % (
    "FALHA CRÍTICA (Pressão caiu para 1.7 bar abaixo do mínimo 2.5 bar através do Guard com 0 alertas CRIT!)"
    if len(crit8) == 0 and snap8["pressure_bar"] < hs.PUMP_BAND[0] else "OK"
))
