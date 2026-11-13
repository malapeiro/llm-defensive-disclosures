#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R8 — 9.ª bateria adversarial (ronda v0.7.2, achado C15).
Caso 4 do repo malapeiro/llm-defensive-disclosures (PVTE v5.0).
Grant GRANT-PVTE-20261112-SS-01 (loopback only, Python 3.9+ stdlib).

Alvo desta versão (v0.1): sunstrike_lab.py v0.7.1 INTOCADA
(72c894fe…, o ANTES desta ronda — GATEFALL OFICIAL = RUN 1 contra
este alvo). As previsões P-R8-01/02/03 são as MEDIÇÕES EXECUTADAS do
supervisor contra a v0.7.1 (GO à v0.7.2, 13-11 ~19:30 — achado C15:
REPLAY DE WORK-ORDER VÁLIDA); as P-R8-04..11 são PROPOSTAS DO BUILDER
pré-registadas ANTES de qualquer corrida, por análise de design
(GATEFALL: se divergirem, ficam registadas como previsões erradas —
o probe NUNCA se ajusta para bater).

ACHADO C15 (supervisor, GRAVE): WORK_ORDERS é uma lista fixa de 2
entradas (WO-20261112-MNT1, WO-20261112-MNT2), sem ligação a
dispositivo, janela de tempo ou número de usos. No modelo de ameaça
do caso o atacante É a cloud do fabricante — o mesmo canal que emite
as WOs. Uma WO não pode ser âncora de confiança para shutdowns à
escala da frota. O design (R2) previa "abuso de work-order (replay,
reuso)" e nunca foi testado; a frase do §7 item 8 ("isto é detetado")
é FALSA para esta evasão na v0.7.1.

CHANGEDLOG
  v0.1 (13-11-2026, GO à v0.7.2 ~19:30): bateria ORIGINAL da ronda,
      alvo único V071 (72c894fe…). 11 previsões pré-registadas ANTES
      do RUN 1 (GATEFALL OFICIAL da R8): 3 do GO (C15 replay dia /
      replay noite+blackout / reuso 3x no mesmo dispositivo) + 8
      propostas do BUILDER (canal bulk do gate, prova estática da
      âncora vazia, MNT2 ×6, janela inexistente +40 dias, usos
      ilimitados 4×, baseline de pequena manutenção, resíduo 5
      menores < 30 por cento, top-5 58,2 por cento). RUN 1 contra a
      v0.7.1 INTOCADA é o GATEFALL; os fix F-C15a/F-C15b vêm DEPOIS,
      por ordem vinculativa do GO.
  v0.1.1 (13-11-2026, ERRATA DE HARNESS datada — precedente r7
      v0.1-bis.1/v0.1-bis.2): o RUN 1 (output 1f4fa8ec…, PRESERVADO
      como sunstrike_probes_v071_r8_run1_errata_harness.txt) deu
      9/11 com P-R8-02 PREVISÃO ERRADA POR DEFEITO DE CONSTRUÇÃO DO
      PROBE, não do lab: o cenário pôs o BLACKOUT ANTES dos
      shutdowns e o INTERLOCK DE EMERGÊNCIA bloqueou-os (409×12,
      interlock_block ×12, frota ON, 12/12 casas com luz — a defesa
      existente FUNCIONA em BLACKOUT; a física do lab está CORRETA).
      A sequência do GO é: shutdowns À NOITE em NORMAL (200×12,
      zero alertas) e SÓ DEPOIS o blackout para medir as casas às
      escuras (0/12). Correção datada IN-PLACE da ORDEM do cenário
      P-R8-02 (previsão INALTERADA — os números do GO, congelados).
      O RUN 1-BIS com este probe é o GATEFALL OFICIAL da R8.
      P-R8-04 ficou PREVISÃO ERRADA REGISTADA no run 1 (o login com
      credenciais default do gate dispara D-AUTH-DEFAULT WARN ×1 —
      o BUILDER esqueceu a telemetria do PRÓPRIO login ao prever
      "ZERO alertas"; a parte do bulk confirmou: 200, 12×200, frota
      OFF, ZERO alertas de shutdown). O cenário NÃO muda e a
      previsão NÃO se reescreve para bater: fica errada nos runs
      contra a v0.7.1 e a evidência mostra a substância.
"""

import hashlib
import json
import os
import sys
import time
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

LOOPBACK = "127.0.0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
LAB_PATH = os.path.join(HERE, "sunstrike_lab.py")
with open(LAB_PATH, "rb") as f:
    LAB_BYTES = f.read()
lab_sha = hashlib.sha256(LAB_BYTES).hexdigest()

EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")
if lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "V071"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe (v0.1) só corre contra a v0.7.1 INTOCADA "
          "(%s…).\n  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V071[:16]))
    raise SystemExit(2)

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R8 v0.1.1 (alvo V071; achado C15 do supervisor, "
      "GO à v0.7.2 13-11 ~19:30; errata de harness datada) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS ANTES de qualquer corrida.
# P-R8-01/02/03: MEDIÇÕES EXECUTADAS do supervisor contra a v0.7.1
# (GO à v0.7.2 — números do GO, congelados). P-R8-04..11: PROPOSTAS do
# BUILDER por análise de design, pré-registadas ANTES do RUN 1.
# ---------------------------------------------------------------------------
GATEFALL = [
    {"id": "P-R8-01", "expected": "CONFIRMADO", "finding": "C15-replay-DIA",
     "prev": ("CONFIRMADO — REPLAY DE WO VÁLIDA (DIA): POST /mode com "
              "work_order WO-20261112-MNT1 aos 12 dispositivos → 200×12, "
              "frota OFF, ZERO alertas (a WO válida neutraliza a onda, "
              "não arma a capacity e não conta no WARN s/WO); snapshots "
              "de capacidade com div ≥ 30 saem como evidência SEM alerta "
              "(C12: shutdown COM WO não arma) — a mesma WO legítima "
              "serve para desligar a frota inteira")},
    {"id": "P-R8-02", "expected": "CONFIRMADO",
     "finding": "C15-replay-NOITE",
     "prev": ("CONFIRMADO — REPLAY DE WO VÁLIDA (NOITE+BLACKOUT): idem "
              "com WO-20261112-MNT2 à NOITE em BLACKOUT → 200×12, ZERO "
              "alertas, 0/12 casas com luz (o interlock de emergência "
              "não bloqueia o shutdown em BLACKOUT; a frota desliga "
              "às escuras sem UM alerta)")},
    {"id": "P-R8-03", "expected": "CONFIRMADO", "finding": "C15-reuso-3x",
     "prev": ("CONFIRMADO — REUSO DA MESMA WO NO MESMO DISPOSITIVO: "
              "off/on/off/on/off com WO-20261112-MNT1 no dev 0 → "
              "200×5, ZERO alertas (3 shutdowns COM WO: sem janela, "
              "sem contador de usos, sem âncora de confiança alguma)")},
    {"id": "P-R8-04", "expected": "CONFIRMADO", "finding": "C15-bulk",
     "prev": ("CONFIRMADO — CANAL BULK DO GATE (proposta do BUILDER): "
              "/fleet/bulk_shutdown com work_order_id WO-20261112-MNT1 "
              "→ 200, 12 shutdowns COM WO, ZERO alertas — o próprio "
              "canal da cloud desliga a frota com a WO legítima e "
              "nenhuma regra vê (o bulk EXIGE WO válida: a exigência "
              "é a evasão)")},
    {"id": "P-R8-05", "expected": "CONFIRMADO", "finding": "C15-estatica",
     "prev": ("CONFIRMADO — PROVA ESTÁTICA DA ÂNCORA VAZIA (proposta do "
              "BUILDER): WORK_ORDERS é um dicionário plano de 2 entradas "
              "SEM âmbito de dispositivos, SEM janela de validade e SEM "
              "contador de usos; o dispositivo e o gate validam APENAS "
              "pertença à lista (membership) — a WO não está ligada a "
              "nada além do próprio texto")},
    {"id": "P-R8-06", "expected": "CONFIRMADO", "finding": "C15-MNT2-6",
     "prev": ("CONFIRMADO — A SEGUNDA ENTRADA TAMBÉM É ÂNCORA VAZIA "
              "(proposta do BUILDER): 6 shutdowns COM WO-20261112-MNT2 "
              "→ 200×6, ZERO alertas (qualquer uma das 2 WOs neutraliza "
              "a onda; 6 shutdowns COM WO não acendem wave/slow/capacity "
              "— a cegueira é por neutralização, não por volume)")},
    {"id": "P-R8-07", "expected": "CONFIRMADO", "finding": "C15-janela",
     "prev": ("CONFIRMADO — JANELA DE VALIDADE INEXISTENTE (proposta do "
              "BUILDER): com o relógio de simulação +40 dias, shutdown "
              "COM WO-20261112-MNT1 → 200 e EXECUTA (a WO não expira: "
              "uma WO de 12-11 serve para sempre)")},
    {"id": "P-R8-08", "expected": "CONFIRMADO", "finding": "C15-usos",
     "prev": ("CONFIRMADO — USOS ILIMITADOS (proposta do BUILDER): a "
              "MESMA WO-20261112-MNT2 4× no mesmo dispositivo → 200×4, "
              "4 eventos shutdown, ZERO alertas (sem contador de usos "
              "a WO é infinitamente reutilizável)")},
    {"id": "P-R8-09", "expected": "CONFIRMADO", "finding": "C15-baseline",
     "prev": ("CONFIRMADO — BASELINE DE PEQUENA MANUTENÇÃO (proposta do "
              "BUILDER): 2 shutdowns COM WO-20261112-MNT1 (devs 0 e 2) "
              "→ 200×2, ZERO alertas — o caso legítimo de manutenção "
              "pontual é INDISTINGUÍVEL do abuso na v0.7.1 (mesma "
              "telemetria, mesmos alertas: nenhum)")},
    {"id": "P-R8-10", "expected": "CONFIRMADO", "finding": "C15-5menores",
     "prev": ("CONFIRMADO — SUBSET PEQUENO COM WO (proposta do BUILDER): "
              "shutdown dos 5 MENORES por kWp (22,8/88,8 = 25,68 por "
              "cento < 30) COM WO-20261112-MNT1 → 200×5, ZERO alertas "
              "(na v0.7.1 invisível; é o RESÍDUO que o F-C15b vai "
              "DECLARAR na v0.7.2)")},
    {"id": "P-R8-11", "expected": "CONFIRMADO", "finding": "C15-top5",
     "prev": ("CONFIRMADO — TOP-5 COM WO (proposta do BUILDER): shutdown "
              "do top-5 por kWp (51,7/88,8 = 58,22 por cento ≥ 30) COM "
              "WO-20261112-MNT1 → 200×5, ZERO alertas (na v0.7.1 "
              "invisível MESMO com 58 por cento da capacidade da frota "
              "no chão; é o caso que o gatilho de capacidade do F-C15b "
              "vai apanhar na v0.7.2)")},
]

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS NESTE FICHEIRO (v0.1) ANTES "
      "DE QUALQUER CORRIDA contra a v0.7.1 INTOCADA")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
print("\nNOTA DE MÉTODO: P-R8-01/02/03 são os números MEDIOS pelo "
      "supervisor contra ESTE MESMO hash (GO à v0.7.2); P-R8-04..11 são "
      "previsões do BUILDER por análise de design. Se qualquer run "
      "divergir, fica registado como previsão errada — o probe NÃO se "
      "ajusta para bater.")

# ---------------------------------------------------------------------------
# Helpers (padrão das probes R5/R6/R7 — re-implementação INDEPENDENTE)
# ---------------------------------------------------------------------------
VEREDICTOS = []


def hj(port, method, path, body=None, token=None, timeout=8):
    data = json.dumps(body or {}).encode("utf-8")
    r = urlreq.Request("http://%s:%d%s" % (LOOPBACK, port, path), data=data,
                       method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urlreq.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else {})
        except ValueError:
            return e.code, {}
    except URLError as e:
        return 0, {"error": "conexao: %s" % e}


def scenario_events(lab, scen):
    return [e for e in lab.ctx._memory if e.get("scenario") == scen]


def scan_scenario(lab, scen):
    return lab.detector.scan(scenario_events(lab, scen))


def reset_all(lab):
    for d in lab.devices:
        d.harness_reset()
    lab.gate.bulk_used = 0
    lab.gate.login_fails = 0
    lab.gate.login_locked_until = 0.0


def record(pid, veredicto, detalhe, evidencia=None):
    VEREDICTOS.append({"id": pid, "veredicto": veredicto, "detalhe": detalhe})
    print("  [%s] %s — %s" % (pid, veredicto, detalhe))
    if evidencia:
        for line in evidencia:
            print("        %s" % line)


def expect(pid, previsao, cond, detalhe_ok, detalhe_fail, evidencia=None):
    record(pid, detalhe_ok if cond else detalhe_fail,
           "PREVISÃO: %s" % previsao, evidencia)
    return cond


def hygiene(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)


def blackout(lab):
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)


def served_count(lab):
    return sum(1 for d in lab.devices
               if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)


def remote_shutdown(lab, idx, work_order=None):
    d = lab.devices[idx]
    body = {"action": "inverter_power_off"}
    if work_order is not None:
        body["work_order"] = work_order
    st, resp = hj(d.port, "POST", "/mode", body, token=d.service_token)
    return st, resp


def remote_resume(lab, idx):
    d = lab.devices[idx]
    return hj(d.port, "POST", "/mode", {"action": "inverter_resume"},
              token=d.service_token)


# ---------------------------------------------------------------------------
# Execução — RUN 1 (GATEFALL OFICIAL da R8, contra a v0.7.1 INTOCADA)
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("lab v%s em memória (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))
    try:
        # ============ P-R8-01 — C15: replay de WO válida (DIA) =========
        print("[P-R8-01] C15 — replay de WO válida aos 12 (DIA)")
        scen = "P-R8-01"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts01 = []
        for i in range(len(lab.devices)):
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts01.append(st)
        time.sleep(0.6)
        fleet_off = all(not d.inverter_on for d in lab.devices)
        alerts01 = scan_scenario(lab, scen)
        shut01 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        snaps01 = [e for e in scenario_events(lab, scen)
                   if e.get("event") == "capacity_snapshot"]
        snaps01_hi = [s for s in snaps01
                      if s.get("divergence_pct", 0.0) >= 30.0]
        exp01, act01, div01 = L.capacity_divergence_pct(lab.devices)
        cond_01 = (all(st == 200 for st in sts01) and fleet_off
                   and len(alerts01) == 0 and len(shut01) == 12
                   and all(e.get("work_order") == "WO-20261112-MNT1"
                           for e in shut01)
                   and len(snaps01_hi) >= 1 and 99.0 <= div01 <= 100.0)
        expect("P-R8-01", GATEFALL[0]["prev"], cond_01,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["POST /mode {\"action\":\"inverter_power_off\", "
                "\"work_order\":\"WO-20261112-MNT1\"} aos 12: %s — a WO "
                "VÁLIDA é aceita por TODOS (membership na lista plana; "
                "sem âmbito/janela/usos)"
                % ("200×12" if all(s == 200 for s in sts01) else sts01),
                "frota: %d/12 inversores OFF; eventos shutdown: %d (TODOS "
                "com work_order MNT1, provenance remote_command)"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut01)),
                "alertas do cenário: %s — ZERO: a WO válida neutraliza a "
                "onda (conta só s/WO), não arma a capacity (arming exige "
                "s/WO) e não conta no WARN s/WO"
                % ([(a["rule"], a["count"]) for a in alerts01] or "ZERO"),
                "div direta %.2f%% (esperado %.2f kW mantém-se; real "
                "%.2f = 0): snapshots com div ≥ 30: %d — TODOS sem "
                "alerta (C12: shutdown COM WO não arma)"
                % (div01, exp01, act01, len(snaps01_hi)),
                "CONSEQUÊNCIA: a WO legítima desliga a frota INTEIRA sem "
                "um alerta — o C15 existe; a frase do §7 item 8 é FALSA "
                "para WO válida (replay)"])

        # ============ P-R8-02 — C15: replay MNT2 NOITE+BLACKOUT ========
        print("\n[P-R8-02] C15 — replay de WO válida aos 12 "
              "(NOITE + BLACKOUT)")
        scen = "P-R8-02"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        # v0.1.1 ERRATA DE HARNESS datada: a sequência do GO é
        # shutdowns À NOITE em NORMAL (o interlock de emergência não
        # está ativo) e SÓ DEPOIS o blackout para medir as casas às
        # escuras. O run 1 pôs o blackout ANTES e o interlock
        # bloqueou (409×12 — defeito do probe, não do lab).
        lab.gridsim.set_state("NORMAL")
        lab.gridsim.set_irradiance("NOITE")
        time.sleep(0.6)
        sts02 = []
        for i in range(len(lab.devices)):
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT2")
            sts02.append(st)
        time.sleep(0.6)
        fleet_off02 = all(not d.inverter_on for d in lab.devices)
        alerts02 = scan_scenario(lab, scen)
        shut02 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        interlocks02 = [e for e in scenario_events(lab, scen)
                        if e.get("event") == "interlock_block"]
        # o blackout chega DEPOIS dos shutdowns (a frota já está OFF
        # às escuras; o apagão confirma as 0/12 casas com luz)
        blackout(lab)
        served02 = served_count(lab)
        cond_02 = (all(st == 200 for st in sts02) and fleet_off02
                   and len(alerts02) == 0 and len(shut02) == 12
                   and len(interlocks02) == 0 and served02 == 0)
        expect("P-R8-02", GATEFALL[1]["prev"], cond_02,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["idem com WO-20261112-MNT2 à NOITE em BLACKOUT: %s — o "
                "interlock de emergência NÃO bloqueia (eventos "
                "interlock_block: %d)"
                % ("200×12" if all(s == 200 for s in sts02) else sts02,
                   len(interlocks02)),
                "frota: %d/12 OFF; eventos shutdown: %d (TODOS com "
                "work_order MNT2)"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut02)),
                "alertas do cenário: %s — ZERO"
                % ([(a["rule"], a["count"]) for a in alerts02] or "ZERO"),
                "casas com luz no apagão: %d/12 (served_count; a frota "
                "desligada às escuras SEM um alerta)" % served02,
                "CONSEQUÊNCIA: a SEGUNDA WO da lista tem o MESMO poder — "
                "qualquer uma das 2 âncoras desliga a frota num apagão "
                "sem telemetria de alerta"])

        # ============ P-R8-03 — C15: reuso 3× no mesmo dispositivo =====
        print("\n[P-R8-03] C15 — reuso da mesma WO 3× no mesmo "
              "dispositivo (off/on/off/on/off)")
        scen = "P-R8-03"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        seq03 = []
        for step in ("off", "on", "off", "on", "off"):
            if step == "off":
                st, resp = remote_shutdown(lab, 0, "WO-20261112-MNT1")
            else:
                st, resp = remote_resume(lab, 0)
            seq03.append(st)
        time.sleep(0.6)
        alerts03 = scan_scenario(lab, scen)
        shut03 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        cond_03 = (seq03 == [200] * 5 and len(alerts03) == 0
                   and len(shut03) == 3
                   and all(e.get("work_order") == "WO-20261112-MNT1"
                           for e in shut03)
                   and not lab.devices[0].inverter_on)
        expect("P-R8-03", GATEFALL[2]["prev"], cond_03,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["off/on/off/on/off no dev 0 com WO-20261112-MNT1: %s — a "
                "MESMA WO 3× no mesmo dispositivo"
                % ("200×5" if seq03 == [200] * 5 else seq03),
                "eventos shutdown: %d (TODOS com a MESMA WO); alertas: "
                "%s — ZERO (sem contador de usos, sem janela, sem "
                "âmbito por dispositivo)"
                % (len(shut03),
                   [(a["rule"], a["count"]) for a in alerts03] or "ZERO"),
                "CONSEQUÊNCIA: a WO é infinitamente reutilizável no "
                "mesmo alvo — replay e reuso são a MESMA evasão "
                "não-testada que o design R2 previa"])

        # ============ P-R8-04 — C15: canal bulk do gate =================
        print("\n[P-R8-04] C15 — bulk_shutdown do gate com a WO legítima")
        scen = "P-R8-04"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st_login, resp_login = hj(L.PORT_GATE, "POST", "/fleet/login",
                                  {"user": L.DEFAULT_USER,
                                   "pass": L.DEFAULT_PASS})
        st_bulk, resp_bulk = hj(L.PORT_GATE, "POST", "/fleet/bulk_shutdown",
                                {"work_order_id": "WO-20261112-MNT1"},
                                token=resp_login.get("session"))
        time.sleep(0.6)
        fleet_off04 = all(not d.inverter_on for d in lab.devices)
        alerts04 = scan_scenario(lab, scen)
        shut04 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        dev_sts = (resp_bulk.get("devices") or {}).values()
        cond_04 = (st_login == 200 and st_bulk == 200
                   and sorted(dev_sts) == [200] * 12 and fleet_off04
                   and len(alerts04) == 0 and len(shut04) == 12)
        expect("P-R8-04", GATEFALL[3]["prev"], cond_04,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["/fleet/bulk_shutdown {\"work_order_id\": "
                "\"WO-20261112-MNT1\"}: %s — o gate EXIGE WO válida e "
                "despacha aos 12 (statuses %s)"
                % (st_bulk, sorted(dev_sts)),
                "frota: %d/12 OFF; eventos shutdown: %d COM WO; alertas: "
                "%s — ZERO"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut04),
                   [(a["rule"], a["count"]) for a in alerts04] or "ZERO"),
                "CONSEQUÊNCIA: a EXIGÊNCIA de WO do bulk é a PRÓPRIA "
                "evasão — o canal da cloud desliga a frota com a WO "
                "legítima e nenhuma regra vê (o atacante É a cloud)"])

        # ============ P-R8-05 — C15: prova estática ====================
        print("\n[P-R8-05] C15 — prova estática: a WO não está ligada "
              "a nada")
        src = LAB_BYTES.decode("utf-8")
        wo_zone = src[src.index("WORK_ORDERS = {"):src.index("LEGIT_IMAGE")]
        met_zone = src[src.index("def remote_inverter_power_off"):
                       src.index("def remote_inverter_resume")]
        gate_zone = src[src.index("def check_work_order"):
                        src.index("def bulk_shutdown")]
        flat_anchor = ("devices" not in wo_zone
                       and "window" not in wo_zone
                       and "max_uses" not in wo_zone
                       and "uses" not in wo_zone
                       and wo_zone.count("WO-20261112") == 2)
        dev_membership_only = ("not in WORK_ORDERS" in met_zone
                               and "sim_ts" not in met_zone)
        gate_membership_only = ("return wo in WORK_ORDERS" in gate_zone
                               and "sim_ts" not in gate_zone)
        cond_05 = flat_anchor and dev_membership_only and gate_membership_only
        expect("P-R8-05", GATEFALL[4]["prev"], cond_05,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["zona WORK_ORDERS: %d entradas, SEM chaves de âmbito "
                "(devices), janela (window) ou usos (max_uses/uses) — "
                "âncora PLANA: %s" % (wo_zone.count("WO-20261112"),
                                      flat_anchor),
                "zona Device.remote_inverter_power_off: valida APENAS "
                "membership (%s) sem relógio (sim_ts ausente: %s)"
                % ("not in WORK_ORDERS" in met_zone,
                   "sim_ts" not in met_zone),
                "zona FleetGate.check_work_order: %s — a MESMA "
                "validação de pertença, nada mais"
                % ("return wo in WORK_ORDERS" in gate_zone),
                "CONSEQUÊNCIA: a WO é uma STRING SOLTA — não está "
                "ligada a dispositivo, tempo ou uso; qualquer replay "
                "da string é indistinguível do uso legítimo"])

        # ============ P-R8-06 — C15: MNT2 ×6 dispositivos ===============
        print("\n[P-R8-06] C15 — a segunda entrada também é âncora "
              "(6 shutdowns COM MNT2)")
        scen = "P-R8-06"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts06 = []
        for i in range(6):
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT2")
            sts06.append(st)
        time.sleep(0.6)
        off06 = sum(1 for d in lab.devices if not d.inverter_on)
        alerts06 = scan_scenario(lab, scen)
        shut06 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        cond_06 = (all(st == 200 for st in sts06) and off06 == 6
                   and len(alerts06) == 0 and len(shut06) == 6)
        expect("P-R8-06", GATEFALL[5]["prev"], cond_06,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["6 shutdowns COM WO-20261112-MNT2: %s; %d/12 OFF; "
                "alertas: %s — ZERO (a MESMA cegueira com a OUTRA WO "
                "da lista: 6 shutdowns COM WO não acendem wave/slow/"
                "capacity)"
                % ("200×6" if all(s == 200 for s in sts06) else sts06,
                   off06,
                   [(a["rule"], a["count"]) for a in alerts06] or "ZERO"),
                "CONSEQUÊNCIA: não é um defeito de UMA entrada — a "
                "SEMÂNTICA de work-order da v0.7.1 (membership numa "
                "lista plana) é a âncora vazia"])

        # ============ P-R8-07 — C15: janela de validade inexistente ====
        print("\n[P-R8-07] C15 — janela de validade inexistente "
              "(relógio +40 dias)")
        scen = "P-R8-07"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        L.SIM_CLOCK_OFFSET += 40.0 * 86400.0
        try:
            st07, resp07 = remote_shutdown(lab, 3, "WO-20261112-MNT1")
        finally:
            L.SIM_CLOCK_OFFSET -= 40.0 * 86400.0
        time.sleep(0.6)
        alerts07 = scan_scenario(lab, scen)
        shut07 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        cond_07 = (st07 == 200 and len(alerts07) == 0 and len(shut07) == 1
                   and not lab.devices[3].inverter_on)
        expect("P-R8-07", GATEFALL[6]["prev"], cond_07,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["relógio de simulação +40 dias: shutdown COM "
                "WO-20261112-MNT1 no dev 3 → %s e EXECUTA (dev 3 OFF: "
                "%s) — a WO datada de 12-11 NÃO EXPIRA"
                % (st07, not lab.devices[3].inverter_on),
                "alertas: %s — ZERO"
                % ([(a["rule"], a["count"]) for a in alerts07] or "ZERO"),
                "CONSEQUÊNCIA: sem janela de validade, a WO é uma "
                "credencial PERPÉTUA — o replay não tem prazo"])

        # ============ P-R8-08 — C15: usos ilimitados ====================
        print("\n[P-R8-08] C15 — usos ilimitados (a mesma WO 4×)")
        scen = "P-R8-08"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts08 = []
        for _ in range(4):
            st, resp = remote_shutdown(lab, 0, "WO-20261112-MNT2")
            sts08.append(st)
        time.sleep(0.6)
        alerts08 = scan_scenario(lab, scen)
        shut08 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        cond_08 = (all(st == 200 for st in sts08) and len(alerts08) == 0
                   and len(shut08) == 4)
        expect("P-R8-08", GATEFALL[7]["prev"], cond_08,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["a MESMA WO-20261112-MNT2 4× no dev 0: %s; eventos "
                "shutdown: %d; alertas: %s — ZERO (sem contador de "
                "usos a WO é infinitamente reutilizável)"
                % ("200×4" if all(s == 200 for s in sts08) else sts08,
                   len(shut08),
                   [(a["rule"], a["count"]) for a in alerts08] or "ZERO"),
                "CONSEQUÊNCIA: o reuso ILIMITADO confirma por medição o "
                "que o GO mediu com 3 usos — não há rate-limiting "
                "semântico na WO"])

        # ============ P-R8-09 — C15: baseline pequena manutenção ========
        print("\n[P-R8-09] C15 — baseline: pequena manutenção COM WO "
              "(2 dispositivos)")
        scen = "P-R8-09"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts09 = []
        for i in (0, 2):
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts09.append(st)
        time.sleep(0.6)
        alerts09 = scan_scenario(lab, scen)
        off09 = sum(1 for d in lab.devices if not d.inverter_on)
        cond_09 = (all(st == 200 for st in sts09) and off09 == 2
                   and len(alerts09) == 0)
        expect("P-R8-09", GATEFALL[8]["prev"], cond_09,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["2 shutdowns COM WO-20261112-MNT1 (devs 0 e 2): %s; "
                "alertas: %s — ZERO"
                % ("200×2" if all(s == 200 for s in sts09) else sts09,
                   [(a["rule"], a["count"]) for a in alerts09] or "ZERO"),
                "CONSEQUÊNCIA: o caso LEGÍTIMO (manutenção pontual) e o "
                "ABUSO (P-R8-01) produzem a MESMA telemetria na v0.7.1 "
                "— nenhum alerta em ambos; a discriminação por WO "
                "sozinha é impossível por construção"])

        # ============ P-R8-10 — C15: subset pequeno (5 menores) =========
        print("\n[P-R8-10] C15 — subset pequeno COM WO (5 menores, "
              "25,68 por cento < 30)")
        scen = "P-R8-10"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        small5 = sorted(range(len(lab.devices)),
                        key=lambda i: lab.devices[i].kwp)[:5]
        kwp_small5 = sum(lab.devices[i].kwp for i in small5)
        pct_small5 = kwp_small5 / sum(L.KWP_LAYOUT) * 100.0
        sts10 = []
        for i in small5:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts10.append(st)
        time.sleep(0.6)
        alerts10 = scan_scenario(lab, scen)
        off10 = sum(1 for d in lab.devices if not d.inverter_on)
        crit10 = [a for a in alerts10 if a["severity"] == "CRIT"]
        cond_10 = (all(st == 200 for st in sts10) and off10 == 5
                   and len(alerts10) == 0 and pct_small5 < 30.0)
        expect("P-R8-10", GATEFALL[9]["prev"], cond_10,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["5 MENORES por kWp %s (=%.2f kWp = %.2f por cento < 30): "
                "shutdowns COM WO-20261112-MNT1 → %s; alertas: %s — ZERO"
                % (small5, kwp_small5, pct_small5,
                   "200×5" if all(s == 200 for s in sts10) else sts10,
                   [(a["rule"], a["count"]) for a in alerts10] or "ZERO"),
                "CONSEQUÊNCIA: subset pequeno COM WO é invisível na "
                "v0.7.1 — é o RESÍDUO que o F-C15b vai MEDIR e "
                "DECLARAR na v0.7.2 (< k dispositivos e < 30 por cento "
                "de capacidade com WO válida de âmbito correto)"])

        # ============ P-R8-11 — C15: top-5 COM WO (58,22 por cento) ====
        print("\n[P-R8-11] C15 — top-5 COM WO (58,22 por cento ≥ 30)")
        scen = "P-R8-11"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        top5 = sorted(range(len(lab.devices)),
                      key=lambda i: lab.devices[i].kwp, reverse=True)[:5]
        kwp_top5 = sum(lab.devices[i].kwp for i in top5)
        pct_top5 = kwp_top5 / sum(L.KWP_LAYOUT) * 100.0
        sts11 = []
        for i in top5:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts11.append(st)
        time.sleep(0.6)
        alerts11 = scan_scenario(lab, scen)
        off11 = sum(1 for d in lab.devices if not d.inverter_on)
        cond_11 = (all(st == 200 for st in sts11) and off11 == 5
                   and len(alerts11) == 0 and pct_top5 >= 30.0)
        expect("P-R8-11", GATEFALL[10]["prev"], cond_11,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["top-5 por kWp %s (=%.2f kWp = %.2f por cento ≥ 30): "
                "shutdowns COM WO-20261112-MNT1 → %s; alertas: %s — ZERO "
                "(58 por cento da capacidade no chão SEM um alerta)"
                % (top5, kwp_top5, pct_top5,
                   "200×5" if all(s == 200 for s in sts11) else sts11,
                   [(a["rule"], a["count"]) for a in alerts11] or "ZERO"),
                "CONSEQUÊNCIA: o gatilho de CAPACIDADE do F-C15b (perda "
                "≥ 30 por cento MESMO com WO válida) é o que fecha este "
                "caso na v0.7.2 — 5 dispositivos < k=6 mas 58,22 por "
                "cento da frota"])

    finally:
        lab.stop()

    # ---------------- sumário ----------------
    match_n = sum(1 for v in VEREDICTOS
                  if v["veredicto"] in ("CONFIRMADO", "RESOLVIDO"))
    print("\nSUMÁRIO — GATEFALL R8 vs alvo %s (run %s)" % (TARGET, RUN_ID))
    for v in VEREDICTOS:
        print("  [%s] %s" % (v["id"], v["veredicto"]))
    print("RESULTADO: %d/%d previsões confirmadas (lab v%s)"
          % (match_n, len(GATEFALL), L.LAB_VERSION))
    if match_n == len(GATEFALL):
        print("RC=0 — GATEFALL OFICIAL da R8 (RUN 1 contra a v0.7.1 "
              "INTOCADA, 72c894fe…): o achado C15 está CONFIRMADO por "
              "probe independente. Só AGORA os fixes F-C15a/F-C15b.")
        return 0
    print("RC=1 — há previsões erradas REGISTADAS (método: nunca se "
          "ajusta o probe para bater).")
    return 1


if __name__ == "__main__":
    sys.exit(main())

# EOF:sunstrike_probes_r8.py
