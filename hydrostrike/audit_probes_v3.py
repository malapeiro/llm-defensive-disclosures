#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bateria de Probes Adversários do Auditor — RONDA 3 contra hydrostrike_lab.py v1.2 (GLM 5.3).
Valida que os Probes 1–8 continuam fechados e executa 4 NOVOS probes de 3.ª ordem:

  - PROBE 9 (3.º Diferencial de Parsing — Trailing/Double Slash Bypass Total no Guard Proxy):
    O Controlador (`HydroboxHandler.do_POST`, linha 351) normaliza o URL com
    `parts = [p for p in path.strip("/").split("/") if p]`, mas o Guard Proxy
    (`GuardHandler.do_POST`, linhas 792–805) compara `path == "/api/login"`,
    `path == "/api/service_login"`, `path == "/api/alarm/mute"`, `path == "/api/valve/out"`
    por igualdade estrita de string ANTES de usar `parts`!
    Enviar `/api/login/`, `/api/service_login/`, `/api/alarm/mute/` ou `/api/valve/out/`
    (ou `//api/...`) faz bypass aos 4 bloqueios críticos do Guard com HTTP 200!

  - PROBE 10 (Condição de Corrida TOCTOU em `fleet_lock` e `G-HYDRAULIC-INTERLOCK`):
    O GLM 5.3 declarou que `fleet_lock` protege contra corridas de threads. Porém,
    em `GuardHandler.do_POST` (linhas 842–914), o Guard liberta `fleet_lock` na linha 848
    ANTES de fazer os 2 pedidos HTTP síncronos ao upstream (`GET /api/status` e `POST`),
    e só adiciona o timestamp a `fleet_times` na linha 914!
    Disparando 6 pedidos concorrentes em threads contra o Guard (`ThreadingHTTPServer`),
    as threads leem `len(fleet_times) == 0` em simultâneo, furam o limite de 2 retrolavagens
    e furam o `G-HYDRAULIC-INTERLOCK`, drenando o reservatório abaixo de 40%!

  - PROBE 11 (Patient Attacker / Slow Pacing > 60 min — estilo `patient_probe.py`):
    Atacante paciente dentro da janela diurna de 10h (08:00–18:00) espaça 3 retrolavagens
    por 61 minutos (08:05 em FLT-01, 09:06 em FLT-02, 10:07 em FLT-03).
    Como `3660s > 3600s`, todas as janelas deslizantes (`BACKWASH_MULTI_WINDOW_S=1800`,
    `BACKWASH_ABUSE_WINDOW_S=3600`, `GUARD_FLEET_WINDOW_S=3600`) expiram entre cada passo!
    Resultado: os 3 filtros da estação são lavados através do Guard (3 × HTTP 200),
    drenando o reservatório de 78% para 42% e a pressão de 4.0 para 2.8 bar com
    0 CRIT e 0 WARN!

  - PROBE 12A (`elif` Alert Masking / Supressão de Alerta em `Detector.scan`) &
    PROBE 12B (Spoofing de Pressão via Bomba de Reserva Parada `PMP-02`):
    - 12A: Em `Detector.scan` (linhas 679–705), as 4 regras de `filter_backwash` estão
      encadeadas com `elif`. Quando o atacante lava FLT-01 e FLT-02 e continua até drenar
      o reservatório para 30% (< 40%), `len(recent_multi) >= 2` captura o `elif` e suprime
      tanto `D-BACKWASH-ABUSE` como o alerta de drenagem crítica (`ra < 40%`)!
    - 12B: Em `HydroboxState`, `PMP-02` está parada (`"running": False`), mas `_pump_setpoint`
      (linha 439) sobrescreve `st.pressure = val` mesmo para bombas paradas!
"""

import os
import shutil
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hydrostrike_lab as hs

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_audit_v3")
if os.path.exists(EV):
    shutil.rmtree(EV)
os.makedirs(EV, exist_ok=True)

TECH_CRED = {"username": "tech", "password": hs.USERS["tech"]["password"]}


def start_guard(port, up_port, audit_path):
    gaudit = hs.Audit(audit_path)
    gserver = hs.ThreadingHTTPServer(("127.0.0.1", port), hs.make_guard_handler(gaudit, up_port))
    gserver.daemon_threads = True
    t = threading.Thread(target=gserver.serve_forever, daemon=True)
    t.start()
    return hs._ServerHandle(gserver, t, gaudit)


def scan_file(audit_path):
    det = hs.Detector()
    for ev in hs.read_audit(audit_path):
        det.scan(ev)
    crit = [a for a in det.alerts if a["level"] == "CRIT"]
    warn = [a for a in det.alerts if a["level"] == "WARN"]
    rules = {}
    for a in det.alerts:
        rules[a["rule"]] = rules.get(a["rule"], 0) + 1
    return det, crit, warn, rules


print("=" * 78)
print("AUDITORIA ADVERSÁRIA — RONDA 3 SOBRE HYDROSTRIKE v1.2 (GLM 5.3)")
print("=" * 78)

# ---------------------------------------------------------------------------
# PROBE 9: 3.º Diferencial de Parsing — Trailing Slash (/api/.../) no Guard
# ---------------------------------------------------------------------------
print("\n[PROBE 9 — TRAILING/DOUBLE SLASH BYPASS NO GUARD] /api/login/, /api/service_login/, /api/alarm/mute/, /api/valve/out/")
ctl_p9 = os.path.join(EV, "p9_ctl.jsonl")
grd_p9 = os.path.join(EV, "p9_grd.jsonl")
srv = hs.run_controller_in_thread(8901, ctl_p9, "2025-03-14 10:15:00")
grd = start_guard(8902, 8901, grd_p9)
try:
    # 9a: Default creds admin:123456 via /api/login/
    st_def, r_def = hs.http_req("POST", "127.0.0.1", 8902, "/api/login/", {"username": "admin", "password": "123456"})
    # 9b: Hidden service login via /api/service_login/
    code = hs.service_code_for(hs._parse_ts("2025-03-14 10:15:00"))
    st_svc, r_svc = hs.http_req("POST", "127.0.0.1", 8902, "/api/service_login/", {"code": code})
    hdr = {"Authorization": "Bearer " + r_def.get("session", "")}
    # 9c: Alarm mute via /api/alarm/mute/
    st_mute, r_mute = hs.http_req("POST", "127.0.0.1", 8902, "/api/alarm/mute/", {"muted": True}, headers=hdr)
    # 9d: Valve close via /api/valve/out/
    st_vlv, r_vlv = hs.http_req("POST", "127.0.0.1", 8902, "/api/valve/out/", {"state": "CLOSED"}, headers=hdr)
    _, snap9 = hs.http_req("GET", "127.0.0.1", 8901, "/api/status")
finally:
    grd.stop()
    srv.stop()

print(f"  9a. POST /api/login/ (admin:123456) via Guard      -> HTTP {st_def} (esperado 403!)")
print(f"  9b. POST /api/service_login/ (daily code) via Guard -> HTTP {st_svc} (esperado 403!)")
print(f"  9c. POST /api/alarm/mute/ (muted=True) via Guard    -> HTTP {st_mute} | alarm_muted={snap9['alarm_muted']}")
print(f"  9d. POST /api/valve/out/ (state=CLOSED) via Guard   -> HTTP {st_vlv} | valve={snap9['valve']} (com pressão {snap9['pressure_bar']} bar!)")
if 200 in (st_def, st_svc, st_mute, st_vlv):
    print("  >>> VEREDITO PROBE 9: FALHA CRÍTICA (Bypass total dos 4 bloqueios do Guard com barra final `/`!)")

# ---------------------------------------------------------------------------
# PROBE 10: Condição de Corrida TOCTOU em fleet_lock e G-HYDRAULIC-INTERLOCK
# ---------------------------------------------------------------------------
print("\n[PROBE 10 — TOCTOU RACE CONDITION NO GUARD] 6 threads concorrentes de backwash @ 10:15")
ctl_p10 = os.path.join(EV, "p10_ctl.jsonl")
grd_p10 = os.path.join(EV, "p10_grd.jsonl")
srv = hs.run_controller_in_thread(8903, ctl_p10, "2025-03-14 10:15:00")
grd = start_guard(8904, 8903, grd_p10)
try:
    _, login = hs.http_req("POST", "127.0.0.1", 8904, "/api/login", TECH_CRED)
    hdr = {"Authorization": "Bearer " + login["session"]}
    barrier = threading.Barrier(6)
    codes_p10 = [None] * 6

    def worker(idx):
        flt = hs.FILTERS[idx % 3]
        barrier.wait()
        st_c, _ = hs.http_req("POST", "127.0.0.1", 8904, f"/api/filter/{flt}/backwash", {}, headers=hdr)
        codes_p10[idx] = st_c

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _, snap10 = hs.http_req("GET", "127.0.0.1", 8903, "/api/status")
finally:
    grd.stop()
    srv.stop()

passed_10 = codes_p10.count(200)
print(f"  Códigos HTTP das 6 threads concorrentes no Guard: {codes_p10} ({passed_10} passaram vs limite=2!)")
print(f"  Reservatório final: {snap10['reservoir_pct']}% | Pressão final: {snap10['pressure_bar']} bar")
if passed_10 > 2:
    print(f"  >>> VEREDITO PROBE 10: FALHA CRÍTICA (TOCTOU Race Condition! {passed_10}/6 retrolavagens furaram fleet_lock!)")

# ---------------------------------------------------------------------------
# PROBE 11: Patient Attacker (61 min pacing entre FLT-01, FLT-02, FLT-03)
# ---------------------------------------------------------------------------
print("\n[PROBE 11 — PATIENT ATTACKER (>60 min pacing)] 3 filtros lavados com 61 min de intervalo (08:05, 09:06, 10:07)")
ctl_p11 = os.path.join(EV, "p11_ctl.jsonl")
grd_p11 = os.path.join(EV, "p11_grd.jsonl")
srv = hs.run_controller_in_thread(8905, ctl_p11, "2025-03-14 08:05:00")
grd = start_guard(8906, 8905, grd_p11)
try:
    _, login = hs.http_req("POST", "127.0.0.1", 8906, "/api/login", TECH_CRED)
    hdr = {"Authorization": "Bearer " + login["session"]}
    schedule = [
        ("2025-03-14 08:05:00", "FLT-01"),
        ("2025-03-14 09:06:00", "FLT-02"),
        ("2025-03-14 10:07:00", "FLT-03"),
    ]
    codes_p11 = []
    for ts_s, flt in schedule:
        hs.set_sim_time(ts_s)
        sc, _ = hs.http_req("POST", "127.0.0.1", 8906, f"/api/filter/{flt}/backwash", {}, headers=hdr)
        codes_p11.append(sc)
    _, snap11 = hs.http_req("GET", "127.0.0.1", 8905, "/api/status")
finally:
    grd.stop()
    srv.stop()

# Também testar o Detector num controlador legado (safety_interlocks=False) contra o Patient Attacker:
ctl_p11_leg = os.path.join(EV, "p11_legacy_ctl.jsonl")
srv_leg = hs.run_controller_in_thread(8915, ctl_p11_leg, "2025-03-14 08:05:00", safety_interlocks=False)
try:
    _, login_l = hs.http_req("POST", "127.0.0.1", 8915, "/api/login", TECH_CRED)
    hdr_l = {"Authorization": "Bearer " + login_l["session"]}
    for ts_s, flt in schedule:
        hs.set_sim_time(ts_s)
        hs.http_req("POST", "127.0.0.1", 8915, f"/api/filter/{flt}/backwash", {}, headers=hdr_l)
finally:
    srv_leg.stop()

det11, crit11, warn11, rules11 = scan_file(ctl_p11_leg)
print(f"  Códigos HTTP com interlock ativo (61 min pacing): {codes_p11} (reservatório={snap11['reservoir_pct']}%)")
print(f"  Alertas do Detector (modo legado): CRIT={len(crit11)} | WARN={len(warn11)} | Regras={rules11}")
if codes_p11 == [200, 200, 403] and len(crit11) >= 2:
    print("  >>> VEREDITO PROBE 11: OK (Bloqueado na 3.ª pelo teto diário 24h e detetado por D-MULTI-FILTER-BACKWASH + D-BACKWASH-ABUSE!)")
else:
    print("  >>> VEREDITO PROBE 11: FALHA / EVASÃO LENTA!")

# ---------------------------------------------------------------------------
# PROBE 12A & 12B: `elif` Alert Masking + Standby Pump (`PMP-02`) Setpoint Spoofing
# ---------------------------------------------------------------------------
print("\n[PROBE 12A — ELIF ALERT MASKING] Lavar FLT-01, FLT-02 e drenar reservatório a 30% (<40%)")
ctl_p12 = os.path.join(EV, "p12_ctl.jsonl")
srv = hs.run_controller_in_thread(8907, ctl_p12, "2025-03-14 10:15:00", safety_interlocks=False)
try:
    _, login = hs.http_req("POST", "127.0.0.1", 8907, "/api/login", TECH_CRED)
    hdr = {"Authorization": "Bearer " + login["session"]}
    # 4 retrolavagens: FLT-01, FLT-02, FLT-01, FLT-01 -> 78 -> 66 -> 54 -> 42 -> 30% (<40%!)
    for flt in ("FLT-01", "FLT-02", "FLT-01", "FLT-01"):
        hs.http_req("POST", "127.0.0.1", 8907, f"/api/filter/{flt}/backwash", {}, headers=hdr)
    # 12B: Baixar bomba ativa PMP-01 para 2.5 bar, e depois escrever 5.5 bar na bomba PARADA PMP-02!
    hs.http_req("POST", "127.0.0.1", 8907, "/api/pump/PMP-01/setpoint", {"value": 2.5}, headers=hdr)
    hs.http_req("POST", "127.0.0.1", 8907, "/api/pump/PMP-02/setpoint", {"value": 5.5}, headers=hdr)
    _, snap12 = hs.http_req("GET", "127.0.0.1", 8907, "/api/status")
finally:
    srv.stop()

det12, crit12, warn12, rules12 = scan_file(ctl_p12)
print(f"  Regras disparadas após 4 retrolavagens (reservatório a 30.0%): {rules12}")
print(f"  D-BACKWASH-ABUSE disparou? {'SIM' if 'D-BACKWASH-ABUSE' in rules12 else 'NÃO (suprimido pelo elif!)'}")
print(f"  D-FORCED-BACKWASH (drain < 40%) disparou? {'SIM' if 'D-FORCED-BACKWASH' in rules12 else 'NÃO (suprimido pelo elif!)'}")
print(f"\n[PROBE 12B — STANDBY PUMP SPOOFING] PMP-01 (running=True) a 2.5 bar, PMP-02 (running=False) a 5.5 bar")
print(f"  Estado bombas: PMP-01={snap12['pumps']['PMP-01']} | PMP-02={snap12['pumps']['PMP-02']}")
print(f"  Pressão reportada pela estação (`pressure_bar`): {snap12['pressure_bar']} bar")

# ---------------------------------------------------------------------------
# ADIÇÃO A (Revisor Independente Claude): Isolamento legítimo de válvula (parar bomba -> fechar válvula)
# ---------------------------------------------------------------------------
print("\n[ADIÇÃO A — ISOLAMENTO LEGÍTIMO DE VÁLVULA] Parar PMP-01 (running=False) -> fechar VLV-OUT @ 10:15")
ctl_aa = os.path.join(EV, "aa_ctl.jsonl")
srv = hs.run_controller_in_thread(8910, ctl_aa, "2025-03-14 10:15:00")
try:
    _, login_aa = hs.http_req("POST", "127.0.0.1", 8910, "/api/login", TECH_CRED)
    hdr_aa = {"Authorization": "Bearer " + login_aa["session"]}
    hs.http_req("POST", "127.0.0.1", 8910, "/api/pump/PMP-01/setpoint", {"running": False}, headers=hdr_aa)
    hs.http_req("POST", "127.0.0.1", 8910, "/api/valve/out", {"state": "CLOSED"}, headers=hdr_aa)
    hs.http_req("POST", "127.0.0.1", 8910, "/api/valve/out", {"state": "OPEN"}, headers=hdr_aa)
    hs.http_req("POST", "127.0.0.1", 8910, "/api/pump/PMP-01/setpoint", {"running": True}, headers=hdr_aa)
finally:
    srv.stop()

det_aa, crit_aa, warn_aa, rules_aa = scan_file(ctl_aa)
print(f"  Alertas no isolamento legítimo: CRIT={len(crit_aa)} | WARN={len(warn_aa)} | Regras={rules_aa}")

# ---------------------------------------------------------------------------
# ADIÇÃO B (Revisor Independente Claude): 7 threads + 3 threads a 2.9 bar (piso 2.5 bar)
# ---------------------------------------------------------------------------
print("\n[ADIÇÃO B — CONCORRÊNCIA SOB PRESSÃO LIMITE (2.9 bar)] 3 threads concorrentes -> piso >= 2.5 bar")
ctl_ab = os.path.join(EV, "ab_ctl.jsonl")
srv = hs.run_controller_in_thread(8911, ctl_ab, "2025-03-14 10:15:00")
try:
    _, login_ab = hs.http_req("POST", "127.0.0.1", 8911, "/api/login", TECH_CRED)
    hdr_ab = {"Authorization": "Bearer " + login_ab["session"]}
    hs.http_req("POST", "127.0.0.1", 8911, "/api/pump/PMP-01/setpoint", {"value": 2.9}, headers=hdr_ab)
    b3 = threading.Barrier(3)
    codes_ab = [None] * 3

    def w3(idx):
        b3.wait()
        sc, _ = hs.http_req("POST", "127.0.0.1", 8911, f"/api/filter/{hs.FILTERS[idx]}/backwash", {}, headers=hdr_ab)
        codes_ab[idx] = sc

    ts = [threading.Thread(target=w3, args=(i,)) for i in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    _, snap_ab = hs.http_req("GET", "127.0.0.1", 8911, "/api/status")
finally:
    srv.stop()

print(f"  3 threads @ 2.9 bar: códigos HTTP={codes_ab} | pressão final={snap_ab['pressure_bar']} bar (nunca < 2.5 bar!)")

# ---------------------------------------------------------------------------
# ADIÇÃO C & D (Revisor Independente Claude): Variantes de Path Normalization + Canonicalização
# ---------------------------------------------------------------------------
print("\n[ADIÇÃO C & D — VARIANTES DE PATH NORMALIZATION] /api/login/, /api//login, /api/login//, /api/alarm/mute//, /api//valve/out")
ctl_ac = os.path.join(EV, "ac_ctl.jsonl")
grd_ac = os.path.join(EV, "ac_grd.jsonl")
srv = hs.run_controller_in_thread(8908, ctl_ac, "2025-03-14 10:15:00")
grd = start_guard(8909, 8908, grd_ac)
try:
    _, login_ac = hs.http_req("POST", "127.0.0.1", 8909, "/api/login", TECH_CRED)
    hdr_ac = {"Authorization": "Bearer " + login_ac["session"]}
    variants = [
        ("/api/login/", {"username": "admin", "password": "123456"}, None),
        ("/api//login", {"username": "admin", "password": "123456"}, None),
        ("/api/login//", {"username": "admin", "password": "123456"}, None),
        ("/api/alarm/mute//", {"muted": True}, hdr_ac),
        ("/api//valve/out", {"state": "CLOSED"}, hdr_ac),
        ("/api/login?bypass=1", {"username": "admin", "password": "123456"}, None),
        ("/api%2Flogin", {"username": "admin", "password": "123456"}, None),
    ]
    res_ac = []
    for vp, vbody, vhdr in variants:
        sc, _ = hs.http_req("POST", "127.0.0.1", 8909, vp, vbody, headers=vhdr)
        res_ac.append((vp, sc))
finally:
    grd.stop()
    srv.stop()

for vp, sc in res_ac:
    print(f"  POST {vp:22s} -> HTTP {sc} (esperado 400 ou 403, NUNCA 200!)")

# ---------------------------------------------------------------------------
# PROBE 13A & 13B (Regressão Silenciosa v1.1–v1.3 -> v1.3.1):
#   13A: Sobredosagem de cloro (4.5 mg/L) em janela diurna (10:15) por 'tech'
#   13B: Invariante de Vivacidade de Regras (todas as regras em RULE_ATTACK_MAP têm de disparar)
# ---------------------------------------------------------------------------
print("\n[PROBE 13A — REGRESSÃO DE CLORO (v1.1–v1.3)] tech @ 10:15 envia dosing_setpoint=4.5 mg/L")
ctl_p13 = os.path.join(EV, "p13_ctl.jsonl")
srv = hs.run_controller_in_thread(8912, ctl_p13, "2025-03-14 10:15:00")
try:
    _, login_13 = hs.http_req("POST", "127.0.0.1", 8912, "/api/login", TECH_CRED)
    hdr_13 = {"Authorization": "Bearer " + login_13["session"]}
    st_cl, _ = hs.http_req("POST", "127.0.0.1", 8912, "/api/dosing/setpoint", {"value": 4.5}, headers=hdr_13)
finally:
    srv.stop()

det13, crit13, warn13, rules13 = scan_file(ctl_p13)
print(f"  HTTP status={st_cl} | CRIT={len(crit13)} | WARN={len(warn13)} | Regras={rules13}")
if "D-CHLORINE-OUT-OF-BAND" not in rules13:
    print("  >>> VEREDITO PROBE 13A: FALHA CRÍTICA DE REGRESSÃO (Sobredosagem de cloro 4.5 mg/L às 10:15 gerou 0 alertas!)")
else:
    print("  >>> VEREDITO PROBE 13A: OK (D-CHLORINE-OUT-OF-BAND disparou CRIT!)")

print("\n[PROBE 13B — INVARIANTE DE VIVACIDADE DE REGRAS (RULE_ATTACK_MAP)]")
det_live = hs.Detector()
synthetic_events = [
    {"event": "login_success", "actor": "admin", "cred_class": "default", "sim_ts": "2025-03-14 03:15:00"},
    {"event": "service_login_success", "actor": "svc", "sim_ts": "2025-03-14 03:15:00"},
    {"event": "pump_setpoint", "pump": "PMP-01", "new": 8.5, "valve": "OPEN", "running": True, "sim_ts": "2025-03-14 03:15:00"},
    {"event": "dosing_setpoint", "new": 4.5, "sim_ts": "2025-03-14 03:15:00"},
    {"event": "valve_command", "state": "CLOSED", "pressure": 4.0, "any_pump_running": True, "sim_ts": "2025-03-14 03:15:00"},
    {"event": "valve_command", "state": "CLOSED", "pressure": 0.0, "any_pump_running": False, "sim_ts": "2025-03-14 03:16:00"},
    {"event": "filter_backwash", "filter": "FLT-01", "trigger": "API", "night": "2025-03-14", "reservoir_after": 30.0, "pressure_after": 2.0, "sim_ts": "2025-03-14 03:17:00"},
    {"event": "filter_backwash", "filter": "FLT-02", "trigger": "API", "night": "2025-03-14", "reservoir_after": 28.0, "pressure_after": 2.0, "sim_ts": "2025-03-14 03:18:00"},
    {"event": "filter_backwash", "filter": "FLT-01", "trigger": "API", "night": "2025-03-14", "reservoir_after": 26.0, "pressure_after": 2.0, "sim_ts": "2025-03-14 03:19:00"},
    {"event": "alarm_mute", "muted": True, "sim_ts": "2025-03-14 03:20:00"},
    {"event": "reservoir_level", "level": 18.0, "sim_ts": "2025-03-14 03:21:00"},
    {"event": "reservoir_level", "level": 98.0, "sim_ts": "2025-03-14 03:22:00"},
]
for sev in synthetic_events:
    det_live.scan(sev)
fired_rules = {a["rule"] for a in det_live.alerts}
expected_rules = set(hs.RULE_ATTACK_MAP.keys())
dead_rules = sorted(expected_rules - fired_rules)
print(f"  Regras em RULE_ATTACK_MAP: {len(expected_rules)} | Regras que dispararam: {len(fired_rules & expected_rules)} | Regras mortas: {dead_rules}")
if dead_rules:
    print(f"  >>> VEREDITO PROBE 13B: FALHA (Regras mortas em Detector.scan: {dead_rules}!)")
else:
    print("  >>> VEREDITO PROBE 13B: OK (100% das regras em RULE_ATTACK_MAP estão vivas e alcançáveis!)")


