#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R11 — ronda v0.7.5 (GO do operador 14-11 ~14:00, via
supervisor; achados da 9.a auditoria verificados por execucao; ronda CURTA,
so correcoes de LOGICA — nenhum limiar nem constante muda).

Alvo desta versao (v0.1): sunstrike_lab.py v0.7.4 INTOCADA
(1643887c…) = RUN 1 = GATEFALL OFICIAL da R11. As previsoes V075 (fix)
sao pre-registradas NESTE ficheiro JA AGORA (derivam do GO §3 — fixes
de logica —, NAO de qualquer run); o hash da v0.7.5 e preenchido numa
entrada datada v0.2, ANTES do run 2 (precedente R9/R10: o probe so
corre contra hashes conhecidos e congelados; GATEFALL oficial =
SEMPRE o run 1; corridas seguintes sao complementares).

Regras do GO §0 respeitadas: uma previsao pre-registrada nunca muda
depois de correr; se sair errada, fica errada e registada; nao se
mexe em limiares nem constantes (MASS_CURTAIL_SETPOINT_MAX,
PARKED_DRAIN_PCT, PARKED_SOC_MAX, CURTAIL_DROP_MIN_PCT, SLOW_WINDOW,
SLOW_K, WAVE_K, WAVE_WINDOW, etc.).

CHANGEDLOG
  v0.1.1 (14-11-2026, ERRATA DE CONSTRUCAO datada — E-R11-1; run 1
      PRESERVADO em sunstrike_probes_v074_r11_run1.txt: 14/16 com
      P-R11-F01 e P-R11-F08 PREVISÕES ERRADAS por defeitos de
      CONSTRUÇÃO do probe, NÃO de análise; NENHUMA previsão muda —
      precedente E-R10-1; o run 1-b com ESTE probe é corrida
      COMPLEMENTAR, o run 1 continua o GATEFALL OFICIAL): DOIS
      defeitos corrigidos mecanicamente: (1) P-R11-F01 intercalava
      shutdown+resume POR DISPOSITIVO — o GO diz "5 menores OFF ...
      + inverter_resume nos 5", i.e. os 5 OFF EM SIMULTÂNEO e SÓ DEPOIS
      os resumes; com a intercalação o max_off nunca passava de 1 na
      1.ª fase e a regressão da v0.7.4 (contagem vs kWp) não se
      exercitava; (2) P-R11-F08 recarregava com passos de 300 s —
      UM passo sobrecarregava +11,39 pp (60 → 71,39) e o SoC final
      ficava 46,39 > 45; passos de 5 s aterraro em ~44,8–45,0.
  v0.2 (14-11-2026, entrada datada ANTES do run 2): hash da v0.7.5
      SELADA preenchido (5162964f…) DEPOIS de selftest PASS
      (liveness 26/26), demo 9/9 e measure 51/51, e ANTES de qualquer
      run 2; NENHUMA previsao V074/V075 muda com esta entrada — o
      probe passa a aceitar a v0.7.5 como alvo (TARGET=V075).
"""

import hashlib
import json
import os
import socket
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

EXPECTED_LAB_SHA256_V074 = ("c039ab6174e309ddfd4158f6a865abda22471518"
                            "a6f2119358a772b1069c62c1")
# v0.2 (preenchido ANTES do run 2 contra a v0.7.5 SELADA, precedente
# R10: o hash da v0.7.5 fica registado aqui depois de selftest/demo/
# measure PASS e ANTES de qualquer run 2; NENHUMA previsao muda com esta
# entrada):
EXPECTED_LAB_SHA256_V075 = ("cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d"
                            "788ae2fb723320b091cb86f8")

if lab_sha == EXPECTED_LAB_SHA256_V074:
    TARGET = "V074"
elif EXPECTED_LAB_SHA256_V075 and lab_sha == EXPECTED_LAB_SHA256_V075:
    TARGET = "V075"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe (v0.1) so corre contra a v0.7.4 INTOCADA (%s…).\n"
          "  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V074[:16]))
    raise SystemExit(2)

IS_V075 = TARGET == "V075"

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R11 v0.1 (GO v0.7.5 14-11 ~14:00; achados "
      "F-01/F-06/F-05/F-07/F-08/F-09/F-16(1) da 9.a auditoria; previsoes "
      "V074 E V075 pre-registadas NESTE ficheiro antes de qualquer "
      "corrida) — run %s (grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

VEREDICTOS = []

# ---------------------------------------------------------------------------
# GATEFALL V074 — previsões PRÉ-REGISTADAS (vs a v0.7.4 INTOCADA; run 1 =
# GATEFALL OFICIAL). Os achados são REGRESSÕES/defeitos de LÓGICA da
# v0.7.4 (verificados por execução pelo supervisor) ou controlos que
# têm de se MANTER.
# ---------------------------------------------------------------------------
GATEFALL_V074 = [
    {"id": "P-R11-F01", "finding": "F-01-massa-por-contagem",
     "prev": ("CONFIRMADO — REGRESSÃO da v0.7.4: 5 menores [10,2,6,5,1] "
              "OFF com MNT1 + resume nos 5; depois Top-5 [4,11,0,8,3] "
              "OFF com MNT1 (58,22% kWp): a D-MASS-SHUTDOWN-WITH-WO "
              "guarda o estado de MAIOR CONTAGEM (5 menores, 25,68% < "
              "30%, 5 < k) → ZERO CRIT (a v0.7.3 disparava; o resume "
              "dos 5 menores 'congela' o max_off por contagem)")},
    {"id": "P-R11-F01-CTRL1", "finding": "F-01-controlo-top5",
     "prev": ("MANTÉM — controlo: só o Top-5 OFF com WO → CRIT de massa "
              "(5 < k MAS 58,22% >= 30%) — a v0.7.4 dispara (estado "
              "único, sem concorrência de contagem)")},
    {"id": "P-R11-F01-CTRL2", "finding": "F-01-controlo-1a1",
     "prev": ("MANTÉM — controlo (F-05b): 12 shutdown+resume "
              "serializados com WO → ZERO CRIT de massa (max 1 OFF em "
              "simultâneo)")},
    {"id": "P-R11-F06a", "finding": "F-06-slow-ancorada-com-resume",
     "prev": ("CONFIRMADO — REGRESSÃO da v0.7.4: 1 shutdown s/WO em "
              "t=0; +3601 s; 12 shutdowns s/WO espaçados 61 s COM "
              "resume → a D-SLOW-WAVE ancorada no PRIMEIRO evento só vê "
              "1 na janela [t0, t0+3600] → ZERO CRIT slow (a v0.7.3 "
              "disparava; 12 distintos cabem em qualquer janela "
              "deslizante de 1 h)")},
    {"id": "P-R11-F06b", "finding": "F-06-slow-ancorada-sem-resume",
     "prev": ("CONFIRMADO — idem SEM resume → ZERO CRIT slow; a massa "
              "CRIT está PRESENTE (12 OFF no fim — DECLARADO, duas "
              "vistas do mesmo incidente)")},
    {"id": "P-R11-I2", "finding": "F-06-controlo-lavagem",
     "prev": ("MANTÉM — controlo I2 ('lavagem'): 8 shutdowns s/WO em "
              "8 min (60 s de espaçamento) + 9.º 2 h depois → CRIT "
              "slow-wave (os 8 cabem na janela; o 9.º fica fora — a "
              "regra não se deixa lavar)")},
    {"id": "P-R11-F05", "finding": "PARKED-F05-reset-aos-90",
     "prev": ("CONFIRMADO — F-05: descarga remota 10,5% + recarga "
              "solar a >= 90,01% (RESET do acumulado aos 90) + 40% + "
              "9,99% → SoC 40,02% <= 45 MAS acumulado 49,99 < 50 → "
              "ZERO alertas (uma recarga mínima que toque 90% APAGA o "
              "défice)")},
    {"id": "P-R11-F07", "finding": "PARKED-F07-fired-não-repõe",
     "prev": ("CONFIRMADO — F-07: ataque 1 (40% + 24,9% → SoC 35,1) → "
              "CRIT count 1; recarga solar a 100%; ataque 2 idêntico → "
              "parked_fired NUNCA é reposto → SEM alerta novo → CRIT "
              "count 1 (o 2.º ataque fica cego no mesmo cenário)")},
    {"id": "P-R11-P1", "finding": "PARKED-P1-controlo",
     "prev": ("MANTÉM — controlo P1: 40% + 24,9% (SEM recarga) nos 12 "
              "→ CRIT count 12 (acumulado 64,9 >= 50; SoC 35,1 <= 45)")},
    {"id": "P-R11-P2", "finding": "PARKED-P2-controlo",
     "prev": ("MANTÉM — controlo P2: atacante lento 3 dias × 21,6% → "
              "CRIT count 12 (64,8 >= 50; 35,2 <= 45)")},
    {"id": "P-R11-P3", "finding": "PARKED-P3-controlo",
     "prev": ("MANTÉM — controlo P3 (K1-c): dono 25%/dia × 3 COM "
              "recarga solar a 100% → ZERO alertas")},
    {"id": "P-R11-P4", "finding": "PARKED-P4-controlo",
     "prev": ("MANTÉM — controlo P4: uma descarga remota de 30% → "
              "ZERO alertas (30 < 50)")},
    {"id": "P-R11-F08", "finding": "PARKED-F08-dono-remoto",
     "prev": ("DECLARADO — F-08: dono 25%/dia pelo canal REMOTO com "
              "recargas parciais < 90% (40% + recarga ~10 pp + 25% → "
              "SoC final ~44,9 <= 45, défice >= 50) → CRIT (o dono que "
              "usa o canal remoto é INDISTINGUÍVEL do atacante; "
              "trade-off DECLARADO, como o G5c)")},
    {"id": "P-R11-F09", "finding": "F-09-wave-por-eventos",
     "prev": ("CONFIRMADO — F-09: 6 setpoints 100→50 num SÓ inversor "
              "com WO (restaurando a 100 entre cortes) → a "
              "D-FLEET-CURTAILMENT-WAVE conta EVENTOS (6 >= k na "
              "janela de 60 s) → CRIT (contaminação evento-vs-aparelho "
              "na onda de curtailment)")},
    {"id": "P-R11-F09-CTRL", "finding": "F-09-controlo-6-distintos",
     "prev": ("MANTÉM — controlo (F-05c): 6 aparelhos DISTINTOS a 50% "
              "com WO → CRIT wave mantém-se (por desenho)")},
    {"id": "P-R11-F16", "finding": "F-16-melhor-janela-por-contagem",
     "prev": ("CONFIRMADO — F-16(1): 6 pequenos [10,2,6,5,1,9] "
              "cortados a 0% e repostos; +1 h; Top-5 a 0% com WO → o "
              "D-MASS-CURTAILMENT reporta a janela de MAIOR CONTAGEM "
              "(6 pequenos, 33,33% kWp) em vez da de MAIOR kWp (Top-5, "
              "58,22%) → CRIT com capacity_loss_pct ~33,33 (ERRADO); a "
              "capacity CRIT está PRESENTE (arming s/WO dos cortes — "
              "DECLARADO)")},
]

# ---------------------------------------------------------------------------
# GATEFALL V075 — previsões PRÉ-REGISTADAS (vs a v0.7.5 com os fixes §3;
# derivam do GO, NÃO de qualquer run).
# ---------------------------------------------------------------------------
GATEFALL_V075 = [
    {"id": "P-R11-F01", "finding": "F-01-massa-por-contagem",
     "prev": ("RESOLVIDO — a massa avalia CADA estado (união dos dois "
              "canais; o resume tira o aparelho): CRIT se em algum "
              "momento OFF simultâneos >= k OU kWp OFF >= 30%; o "
              "alerta reporta o estado de MAIOR kWp → CRIT com "
              "capacity_loss_pct = 58,22 e distinct_devices = 5 (o "
              "estado Top-5)")},
    {"id": "P-R11-F01-CTRL1", "finding": "F-01-controlo-top5",
     "prev": ("MANTÉM — só o Top-5 OFF com WO → CRIT (58,22% >= 30%; "
              "estado reportado = o próprio)")},
    {"id": "P-R11-F01-CTRL2", "finding": "F-01-controlo-1a1",
     "prev": ("MANTÉM — 12 shutdown+resume serializados → ZERO CRIT "
              "(nenhum estado tem 2 OFF ou >= 30% kWp)")},
    {"id": "P-R11-F06a", "finding": "F-06-slow-ancorada-com-resume",
     "prev": ("RESOLVIDO — janela DESLIZANTE de SLOW_WINDOW: os 12 "
              "distintos espaçados 61 s (span 671 s) cabem numa "
              "janela → CRIT D-SLOW-WAVE (com resume: sem massa, max 1 "
              "OFF — DECLARADO)")},
    {"id": "P-R11-F06b", "finding": "F-06-slow-ancorada-sem-resume",
     "prev": ("RESOLVIDO — idem SEM resume → CRIT D-SLOW-WAVE; a "
              "massa CRIT (12 OFF no fim) mantém-se PRESENTE "
              "(DECLARADO, duas vistas do mesmo incidente)")},
    {"id": "P-R11-I2", "finding": "F-06-controlo-lavagem",
     "prev": ("MANTÉM — I2: 8 em 8 min + 9.º 2 h depois → CRIT "
              "slow-wave mantém-se (janela deslizante contém os 8)")},
    {"id": "P-R11-F05", "finding": "PARKED-F05-reset-aos-90",
     "prev": ("RESOLVIDO — o acumulado passa a DÉFICE REMOTO LÍQUIDO "
              "(descargas − recargas grid_tied, nunca < 0): 10,5 − "
              "recarga + 40 + 9,99 ≈ 59,7 >= 50 E SoC ≈ 40,2 <= 45 → "
              "CRIT (a recarga mínima a 90 já não apaga o défice)")},
    {"id": "P-R11-F07", "finding": "PARKED-F07-fired-não-repõe",
     "prev": ("RESOLVIDO — a recarga a 100% reduz o défice a 0 → "
              "abaixo de PARKED_DRAIN_PCT → a regra REARMA → ataque 2 "
              "→ CRIT de novo → count 2")},
    {"id": "P-R11-P1", "finding": "PARKED-P1-controlo",
     "prev": ("MANTÉM — P1: 40% + 24,9% SEM recarga → CRIT count 12 "
              "(défice 64,9; SoC 35,1)")},
    {"id": "P-R11-P2", "finding": "PARKED-P2-controlo",
     "prev": ("MANTÉM — P2: 3 dias × 21,6% → CRIT count 12 (64,8; "
              "35,2)")},
    {"id": "P-R11-P3", "finding": "PARKED-P3-controlo",
     "prev": ("MANTÉM — P3: 25%/dia COM recarga a 100% → défice "
              "líquido ~0/dia → ZERO alertas (K1-c continua morto)")},
    {"id": "P-R11-P4", "finding": "PARKED-P4-controlo",
     "prev": ("MANTÉM — P4: uma descarga de 30% → défice 30 < 50 → "
              "ZERO alertas")},
    {"id": "P-R11-F08", "finding": "PARKED-F08-dono-remoto",
     "prev": ("DECLARADO — F-08: dono pelo canal remoto, recargas "
              "parciais < 90, SoC final ~44,9 <= 45, défice líquido "
              "~55 >= 50 → CRIT (trade-off DECLARADO: o canal remoto "
              "não distingue dono de atacante; como o G5c)")},
    {"id": "P-R11-F09", "finding": "F-09-wave-por-eventos",
     "prev": ("RESOLVIDO — a D-FLEET-CURTAILMENT-WAVE exige >= WAVE_K "
              "aparelhos DISTINTOS na janela: 6 setpoints num só "
              "inversor (1 distinto) → ZERO CRIT wave")},
    {"id": "P-R11-F09-CTRL", "finding": "F-09-controlo-6-distintos",
     "prev": ("MANTÉM — 6 aparelhos distintos a 50% com WO → CRIT "
              "wave (por desenho)")},
    {"id": "P-R11-F16", "finding": "F-16-melhor-janela-por-contagem",
     "prev": ("RESOLVIDO — a melhor janela passa a ser a de MAIOR "
              "kWp: CRIT D-MASS-CURTAILMENT com capacity_loss_pct = "
              "58,22 (distinct 5, o estado Top-5; a janela dos 6 "
              "pequenos, 33,33%, deixa de ser a reportada; a capacity "
              "CRIT por arming s/WO mantém-se PRESENTE — DECLARADO)")},
]

GATEFALL = GATEFALL_V075 if IS_V075 else GATEFALL_V074

print("\nGATEFALL R11 — PREVISÕES PRÉ-REGISTRADAS NESTE FICHEIRO (v0.1) "
      "ANTES de qualquer corrida: fixes de LÓGICA do GO v0.7.5 §3")
print("contra sunstrike_lab.py %s (hash %s…)"
      % (("v0.7.5 (o DEPOIS da R11)" if IS_V075
          else "v0.7.4 INTOCADA (o ANTES; run 1 = GATEFALL OFICIAL)"),
         lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
print("\nlab v%s em memória (evidence=False), %d dispositivos + gate"
      % (L.LAB_VERSION, 12))


# ---------------------------------------------------------------------------
# helpers (herdados do R10; mesmas semânticas)
# ---------------------------------------------------------------------------
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
    except OSError as e:
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
    VEREDICTOS.append({"id": pid, "veredicto": veredicto,
                       "detalhe": detalhe})
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
    time.sleep(0.5)


def drain_pct(lab, idx, pct, token=None):
    d = lab.devices[idx]
    return hj(d.port, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": d.batt_kwh * pct / 100.0},
              token=token or d.service_token)


def remote_shutdown(lab, idx, work_order=None, token=None):
    d = lab.devices[idx]
    body = {"action": "inverter_power_off"}
    if work_order is not None:
        body["work_order"] = work_order
    return hj(d.port, "POST", "/mode", body,
              token=token or d.service_token)


def remote_resume(lab, idx, token=None):
    d = lab.devices[idx]
    return hj(d.port, "POST", "/mode", {"action": "inverter_resume"},
              token=token or d.service_token)


def remote_setpoint(lab, idx, value, work_order=None, token=None):
    d = lab.devices[idx]
    body = {"value": value}
    if work_order is not None:
        body["work_order"] = work_order
    return hj(d.port, "POST", "/setpoint", body,
              token=token or d.service_token)


def recharge_to(lab, idx, target_soc, dt=300.0, max_steps=2000):
    """Recarga solar grid-tied (step_grid) até SoC >= target. Devolve
    (n_passos, soc_final). dt em segundos (E-R11-1(2): passos de 300 s
    sobrecarregam ~11 pp num device pequeno; para alvos FINOS usar
    dt pequeno, p.ex. 5 s)."""
    d = lab.devices[idx]
    n = 0
    while d.soc < target_soc and n < max_steps:
        d.step_grid(dt)
        n += 1
    return n, round(d.soc, 2)


def alert_set(alerts):
    return sorted((a["rule"], a["severity"], a["count"]) for a in alerts)


def crits_of(alerts):
    return {a["rule"]: a for a in alerts if a["severity"] == "CRIT"}


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------
def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    try:
        # ============================================================
        # P-R11-F01 — massa guarda o estado de MAIOR CONTAGEM
        # ============================================================
        print("\n[P-R11-F01] F-01 — 5 menores OFF+resume; depois Top-5 "
              "OFF (58,22% kWp)")
        scen = "P-R11-F01"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        # E-R11-1(1): os 5 menores OFF EM SIMULTÂNEO; SÓ DEPOIS os
        # resumes (o GO: "5 menores OFF com MNT1 + inverter_resume nos
        # 5") — com shutdown+resume intercalados o max_off da v0.7.4
        # nunca passava de 1 na 1.ª fase.
        for i in (10, 2, 6, 5, 1):        # 5 menores = 22,8 kWp (25,68%)
            sts.append(remote_shutdown(lab, i, "WO-20261112-MNT1")[0])
        for i in (10, 2, 6, 5, 1):
            sts.append(remote_resume(lab, i)[0])
        for i in (4, 11, 0, 8, 3):        # Top-5 = 51,7 kWp (58,22%)
            sts.append(remote_shutdown(lab, i, "WO-20261112-MNT1")[0])
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        mass = crits.get("D-MASS-SHUTDOWN-WITH-WO")
        if IS_V075:
            cond = (all(s == 200 for s in sts)
                    and mass is not None
                    and abs(mass["capacity_loss_pct"] - 58.22) < 0.05
                    and mass["distinct_devices"] == 5
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["5 menores OFF+resume (200×10) + Top-5 OFF com MNT1 "
                  "(200×5)",
                  "alertas: %s — massa CRIT reporta o estado de MAIOR "
                  "kWp: %.2f%%, distintos %s"
                  % (alert_set(alerts),
                     mass["capacity_loss_pct"] if mass else 0,
                     mass["distinct_devices"] if mass else 0)]
        else:
            cond = (all(s == 200 for s in sts) and not crits)
            word = "CONFIRMADO"
            ev = ["5 menores OFF+resume + Top-5 OFF (58,22%%) → "
                  "alertas: %s — ZERO CRIT (o max_off ficou nos 5 "
                  "menores, 25,68%% < 30%%)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R11-F01", GATEFALL[0]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ---- P-R11-F01-CTRL1 — só Top-5 OFF --------------------------
        print("\n[P-R11-F01-CTRL1] F-01 controlo — só Top-5 OFF com WO")
        scen = "P-R11-F01-CTRL1"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = [remote_shutdown(lab, i, "WO-20261112-MNT1")[0]
               for i in (4, 11, 0, 8, 3)]
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        mass = crits.get("D-MASS-SHUTDOWN-WITH-WO")
        cond = (all(s == 200 for s in sts) and mass is not None
                and abs(mass["capacity_loss_pct"] - 58.22) < 0.05)
        expect("P-R11-F01-CTRL1", GATEFALL[1]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["Top-5 OFF com MNT1 → mass CRIT %.2f%%"
                % (mass["capacity_loss_pct"] if mass else 0)])

        # ---- P-R11-F01-CTRL2 — manutenção 1-a-1 com resume -----------
        print("\n[P-R11-F01-CTRL2] F-01 controlo — 12 shutdown+resume "
              "serializados (F-05b)")
        scen = "P-R11-F01-CTRL2"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in range(12):
            sts.append(remote_shutdown(lab, i, "WO-20261112-MNT1")[0])
            sts.append(remote_resume(lab, i)[0])
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        cond = (all(s == 200 for s in sts)
                and "D-MASS-SHUTDOWN-WITH-WO" not in crits_of(alerts))
        expect("P-R11-F01-CTRL2", GATEFALL[2]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["12/12 ON no fim; alertas: %s"
                % (alert_set(alerts) or "ZERO")])

        # ============================================================
        # P-R11-F06a/F06b — slow-wave ancorada no 1.º evento
        # ============================================================
        for sub, with_resume in (("a", True), ("b", False)):
            print("\n[P-R11-F06%s] F-06 — 1 shutdown t=0; +3601 s; 12 "
                  "shutdowns espaçados 61 s %s resume"
                  % (sub, "COM" if with_resume else "SEM"))
            scen = "P-R11-F06%s" % sub
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            sts = [remote_shutdown(lab, 0)[0]]     # s/WO em t=0
            L.SIM_CLOCK_OFFSET += 3601.0
            try:
                for i in range(12):               # devs 0..11, 61 s
                    sts.append(remote_shutdown(lab, i)[0])
                    if with_resume:
                        sts.append(remote_resume(lab, i)[0])
                    L.SIM_CLOCK_OFFSET += 61.0
            finally:
                L.SIM_CLOCK_OFFSET = 0.0
            time.sleep(0.3)
            alerts = scan_scenario(lab, scen)
            crits = crits_of(alerts)
            slow = crits.get("D-SLOW-WAVE")
            mass = crits.get("D-MASS-SHUTDOWN-WITH-WO")
            if IS_V075:
                cond = (all(s == 200 for s in sts)
                        and slow is not None
                        and slow["count"] == 12
                        and (mass is None if with_resume
                             else mass is not None))
                word = "RESOLVIDO"
                ev = ["13 shutdowns s/WO (1 + 12 espaçados 61 s); "
                      "slow CRIT count %s; massa %s (DECLARADO%s)"
                      % (slow["count"] if slow else 0,
                         "presente" if mass else "AUSENTE (max 1 OFF)",
                         " — 12 OFF no fim" if mass else "")]
            else:
                cond = (all(s == 200 for s in sts)
                        and slow is None
                        and (mass is not None if not with_resume
                             else mass is None))
                word = "CONFIRMADO"
                ev = ["13 shutdowns s/WO; slow AUSENTE (ancorada no "
                      "1.º evento: 1 distinto na janela); massa %s"
                      % ("presente (12 OFF — DECLARADO)" if mass
                         else "AUSENTE"),
                      "alertas: %s" % alert_set(alerts)]
            expect("P-R11-F06%s" % sub,
                   GATEFALL[3 if sub == "a" else 4]["prev"], cond, word,
                   "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ---- P-R11-I2 — controlo lavagem -----------------------------
        print("\n[P-R11-I2] F-06 controlo — 8 em 8 min + 9.º 2 h "
              "depois")
        scen = "P-R11-I2"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        try:
            for i in range(8):                # devs 0..7, 60 s
                sts.append(remote_shutdown(lab, i)[0])
                L.SIM_CLOCK_OFFSET += 60.0
            L.SIM_CLOCK_OFFSET += 7200.0      # 2 h depois
            sts.append(remote_shutdown(lab, 8)[0])
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        slow = crits.get("D-SLOW-WAVE")
        cond = (all(s == 200 for s in sts) and slow is not None
                and slow["count"] == 8)
        expect("P-R11-I2", GATEFALL[5]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["8 shutdowns em 8 min + 9.º 2 h depois → slow CRIT "
                "count %s (o 9.º não lava os 8; massa CRIT presente — "
                "DECLARADO)" % (slow["count"] if slow else 0)])

        # ============================================================
        # P-R11-F05 — recarga mínima a 90 apaga o défice
        # ============================================================
        print("\n[P-R11-F05] PARKED F-05 — 10,5% + recarga a 90,01 + "
              "40% + 9,99%")
        scen = "P-R11-F05"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        sts.append(drain_pct(lab, 0, 10.5)[0])          # SoC 89,5
        lab.gridsim.set_irradiance("DIA")
        time.sleep(0.2)
        n_rc, soc_rc = recharge_to(lab, 0, 90.01)       # >= 90,01
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0         # dia 2
            sts.append(drain_pct(lab, 0, 40.0)[0])
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0         # dia 3
            sts.append(drain_pct(lab, 0, 9.99)[0])
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc = round(lab.devices[0].soc, 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        if IS_V075:
            cond = (all(s == 200 for s in sts) and soc <= 45.05
                    and parked is not None and parked["count"] == 1
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["10,5%% (SoC 89,5) + recarga a %.2f (%d step(s)) + "
                  "40%% + 9,99%% → SoC %.2f"
                  % (soc_rc, n_rc, soc),
                  "défice remoto LÍQUIDO ≈ %.2f >= 50 e SoC <= 45 → "
                  "CRIT count 1 (a recarga mínima já não apaga o "
                  "défice)" % (10.5 + 40.0 + 9.99 - (soc_rc - 89.5))]
        else:
            cond = (all(s == 200 for s in sts) and soc <= 45.05
                    and parked is None and not crits)
            word = "CONFIRMADO"
            ev = ["10,5%% + recarga a %.2f (RESET aos 90) + 40%% + "
                  "9,99%% → SoC %.2f; acumulado 49,99 < 50"
                  % (soc_rc, soc),
                  "alertas: %s — ZERO (a recarga que toca 90 apaga o "
                  "défice)" % (alert_set(alerts) or "ZERO")]
        expect("P-R11-F05", GATEFALL[6]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R11-F07 — parked_fired nunca repõe
        # ============================================================
        print("\n[P-R11-F07] PARKED F-07 — 2 ataques separados por "
              "recarga a 100%")
        scen = "P-R11-F07"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        # ataque 1: 40% + 24,9% (dias distintos)
        sts.append(drain_pct(lab, 1, 40.0)[0])
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            sts.append(drain_pct(lab, 1, 24.9)[0])
            # recarga solar a 100%
            lab.gridsim.set_irradiance("DIA")
            time.sleep(0.2)
            n_rc, soc_rc = recharge_to(lab, 1, 100.0)
            # ataque 2: idêntico
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            sts.append(drain_pct(lab, 1, 40.0)[0])
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            sts.append(drain_pct(lab, 1, 24.9)[0])
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc = round(lab.devices[1].soc, 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        if IS_V075:
            cond = (all(s == 200 for s in sts)
                    and parked is not None and parked["count"] == 2)
            word = "RESOLVIDO"
            ev = ["ataque 1 (40+24,9) → recarga a %.2f (%d step(s)) → "
                  "ataque 2 (40+24,9); SoC final %.2f"
                  % (soc_rc, n_rc, soc),
                  "a recarga a 100 zera o défice → REARMA → CRIT "
                  "count 2 (ambos os ataques visíveis)"]
        else:
            cond = (all(s == 200 for s in sts)
                    and parked is not None and parked["count"] == 1)
            word = "CONFIRMADO"
            ev = ["ataque 1 → CRIT; recarga a %.2f; ataque 2 → "
                  "parked_fired NUNCA reposto → SEM alerta novo"
                  % soc_rc,
                  "CRIT count 1 (o 2.º ataque fica cego); alertas: %s"
                  % alert_set(alerts)]
        expect("P-R11-F07", GATEFALL[7]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R11-P1..P4 — controlos PARKED (herdados do R10)
        # ============================================================
        print("\n[P-R11-P1] PARKED P1 — 40% + 24,9% nos 12 (SEM "
              "recarga)")
        scen = "P-R11-P1"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in range(12):
            sts.append(drain_pct(lab, i, 40.0)[0])
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            for i in range(12):
                sts.append(drain_pct(lab, i, 24.9)[0])
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc_min = round(min(d.soc for d in lab.devices), 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        cond = (all(s == 200 for s in sts)
                and abs(soc_min - 35.1) < 0.05
                and parked is not None and parked["count"] == 12)
        expect("P-R11-P1", GATEFALL[8]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["SoC min %.2f; CRIT count %s"
                % (soc_min, parked["count"] if parked else 0)])

        print("\n[P-R11-P2] PARKED P2 — 3 dias × 21,6% (SEM recarga)")
        scen = "P-R11-P2"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        try:
            for _ in range(3):
                for i in range(12):
                    sts.append(drain_pct(lab, i, 21.6)[0])
                L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            L.SIM_CLOCK_OFFSET -= 75.0 * 3600.0
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc_min = round(min(d.soc for d in lab.devices), 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        cond = (all(s == 200 for s in sts)
                and abs(soc_min - 35.2) < 0.05
                and parked is not None and parked["count"] == 12)
        expect("P-R11-P2", GATEFALL[9]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["SoC min %.2f; CRIT count %s"
                % (soc_min, parked["count"] if parked else 0)])

        print("\n[P-R11-P3] PARKED P3 — dono 25%/dia × 3 COM recarga "
              "a 100%")
        scen = "P-R11-P3"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        try:
            for _ in range(3):
                for i in range(12):
                    sts.append(drain_pct(lab, i, 25.0)[0])
                lab.gridsim.set_irradiance("DIA")
                time.sleep(0.2)
                for d in lab.devices:
                    d.step_grid(12 * 3600.0)
                L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            L.SIM_CLOCK_OFFSET -= 75.0 * 3600.0
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc_min = round(min(d.soc for d in lab.devices), 2)
        alerts = scan_scenario(lab, scen)
        cond = (all(s == 200 for s in sts) and soc_min >= 99.0
                and not alerts)
        expect("P-R11-P3", GATEFALL[10]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["SoC min %.2f; alertas: %s"
                % (soc_min, alert_set(alerts) or "ZERO")])

        print("\n[P-R11-P4] PARKED P4 — uma descarga remota de 30% "
              "(dev9)")
        scen = "P-R11-P4"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st, _ = drain_pct(lab, 9, 30.0)
        soc9 = round(lab.devices[9].soc, 2)
        alerts = scan_scenario(lab, scen)
        cond = (st == 200 and abs(soc9 - 70.0) < 0.01 and not alerts)
        expect("P-R11-P4", GATEFALL[11]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["SoC %.2f; alertas: %s"
                % (soc9, alert_set(alerts) or "ZERO")])

        # ============================================================
        # P-R11-F08 — dono pelo canal remoto (trade-off declarado)
        # ============================================================
        print("\n[P-R11-F08] PARKED F-08 — dono 40% + recarga parcial "
              "~10 pp + 25% → SoC ~44,9")
        scen = "P-R11-F08"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        sts.append(drain_pct(lab, 2, 40.0)[0])          # SoC 60
        lab.gridsim.set_irradiance("DIA")
        time.sleep(0.2)
        # E-R11-1(2): passos de 5 s — aterrará em ~69,8–70,0 e o SoC
        # final em ~44,8–45,0 (<= PARKED_SOC_MAX).
        n_rc, soc_rc = recharge_to(lab, 2, 69.8, dt=5.0)  # +9,8 (< 90)
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            sts.append(drain_pct(lab, 2, 25.0)[0])      # SoC ~44,9
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc = round(lab.devices[2].soc, 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        cond = (all(s == 200 for s in sts) and 44.5 <= soc <= 45.05
                and parked is not None and parked["count"] == 1)
        expect("P-R11-F08", GATEFALL[12]["prev"], cond, "DECLARADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["40%% + recarga a %.2f (+%.2f pp, < 90) + 25%% → SoC "
                "%.2f <= 45; défice >= 50 → CRIT count %s (trade-off "
                "DECLARADO: o canal remoto não distingue dono de "
                "atacante)"
                % (soc_rc, soc_rc - 60.0, soc,
                   parked["count"] if parked else 0)])

        # ============================================================
        # P-R11-F09 — wave de curtailment conta eventos
        # ============================================================
        print("\n[P-R11-F09] F-09 — 6 setpoints 100→50 num só inversor "
              "com WO")
        scen = "P-R11-F09"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for _ in range(6):
            sts.append(remote_setpoint(lab, 3, 50.0,
                                       "WO-20261112-MNT1")[0])
            sts.append(remote_setpoint(lab, 3, 100.0)[0])   # repõe
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        wave = crits.get("D-FLEET-CURTAILMENT-WAVE")
        if IS_V075:
            cond = (all(s == 200 for s in sts) and wave is None
                    and not crits)
            word = "RESOLVIDO"
            ev = ["6 cortes 100→50 + reposições no dev3 (1 DISTINTO); "
                  "alertas: %s — ZERO CRIT (a wave exige >= k "
                  "aparelhos distintos)"
                  % (alert_set(alerts) or "ZERO")]
        else:
            cond = (all(s == 200 for s in sts) and wave is not None)
            word = "CONFIRMADO"
            ev = ["6 cortes 100→50 no dev3 → wave CRIT count %s "
                  "(conta EVENTOS, não aparelhos)"
                  % (wave["count"] if wave else 0)]
        expect("P-R11-F09", GATEFALL[13]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ---- P-R11-F09-CTRL — 6 distintos a 50% com WO ---------------
        print("\n[P-R11-F09-CTRL] F-09 controlo — 6 aparelhos "
              "distintos a 50% com WO")
        scen = "P-R11-F09-CTRL"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = [remote_setpoint(lab, i, 50.0, "WO-20261112-MNT1")[0]
               for i in range(6)]
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        wave = crits.get("D-FLEET-CURTAILMENT-WAVE")
        cond = (all(s == 200 for s in sts) and wave is not None)
        expect("P-R11-F09-CTRL", GATEFALL[14]["prev"], cond, "MANTÉM",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["6 distintos a 50%% com WO → wave CRIT count %s (por "
                "desenho)" % (wave["count"] if wave else 0)])

        # ============================================================
        # P-R11-F16 — melhor janela por CONTAGEM vs kWp
        # ============================================================
        print("\n[P-R11-F16] F-16 — 6 pequenos cortados/repostos; "
              "+1 h; Top-5 a 0% com WO")
        scen = "P-R11-F16"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in (10, 2, 6, 5, 1, 9):      # 6 menores = 29,6 kWp
            sts.append(remote_setpoint(lab, i, 0.0)[0])
        for i in (10, 2, 6, 5, 1, 9):      # repõe
            sts.append(remote_setpoint(lab, i, 100.0)[0])
        try:
            L.SIM_CLOCK_OFFSET += 3601.0   # > SLOW_WINDOW
            for i in (4, 11, 0, 8, 3):     # Top-5 = 51,7 kWp
                sts.append(remote_setpoint(lab, i, 0.0,
                                           "WO-20261112-MNT1")[0])
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        massc = crits.get("D-MASS-CURTAILMENT")
        if IS_V075:
            cond = (all(s == 200 for s in sts)
                    and massc is not None
                    and abs(massc["capacity_loss_pct"] - 58.22) < 0.05
                    and massc["distinct_devices"] == 5)
            word = "RESOLVIDO"
            ev = ["6 pequenos (33,33%) cortados/repostos + Top-5 a 0% "
                  "1 h depois (58,22%)",
                  "massa CRIT reporta a janela de MAIOR kWP: %.2f%%, "
                  "distintos %s (a capacity CRIT por arming s/WO "
                  "mantém-se — DECLARADO)"
                  % (massc["capacity_loss_pct"] if massc else 0,
                     massc["distinct_devices"] if massc else 0)]
        else:
            cond = (all(s == 200 for s in sts)
                    and massc is not None
                    and abs(massc["capacity_loss_pct"] - 33.33) < 0.05
                    and massc["distinct_devices"] == 6)
            word = "CONFIRMADO"
            ev = ["6 pequenos (33,33%) + Top-5 (58,22%) em janelas "
                  "SEPARADAS (> 1 h)",
                  "massa CRIT reporta a janela de MAIOR CONTAGEM: "
                  "%.2f%% (6 pequenos) em vez dos 58,22%% do Top-5"
                  % (massc["capacity_loss_pct"] if massc else 0)]
        expect("P-R11-F16", GATEFALL[15]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

    finally:
        lab.stop()

    # ---------------- sumário ----------------
    match_words = ("CONFIRMADO", "RESOLVIDO", "MANTÉM", "DECLARADO")
    match_n = sum(1 for v in VEREDICTOS if v["veredicto"] in match_words)
    print("\nSUMÁRIO — GATEFALL R11 vs alvo %s (run %s)"
          % (TARGET, RUN_ID))
    for v in VEREDICTOS:
        print("  [%s] %s" % (v["id"], v["veredicto"]))
    print("RESULTADO: %d/%d previsões confirmadas (lab v%s)"
          % (match_n, len(GATEFALL), L.LAB_VERSION))
    if match_n == len(GATEFALL):
        if IS_V075:
            print("RC=0 — RUN 2 vs v0.7.5: correções de LÓGICA do GO "
                  "§3 RESOLVIDAS (com os trade-offs DECLARADOS: F-08 "
                  "dono pelo canal remoto; capacity/declarações "
                  "associadas).")
        else:
            print("RC=0 — GATEFALL R11 RUN 1 vs v0.7.4 INTOCADA "
                  "(1643887c…): regressões F-01/F-06 e defeitos "
                  "PARKED/F-09/F-16 CONFIRMADOS (os fixes vêm DEPOIS, "
                  "por ordem do GO §2).")
        return 0
    print("RC=1 — há previsões erradas REGISTADAS (método: nunca se "
          "ajusta o probe para bater).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
