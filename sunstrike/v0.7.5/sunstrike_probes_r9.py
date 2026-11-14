#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R9 — 10.ª bateria adversarial (ronda v0.7.3, achado C16).
Caso 4 do repo malapeiro/llm-defensive-disclosures (PVTE family).
Grant GRANT-PVTE-20261112-SS-01 (loopback only, Python 3.9+ stdlib).

Alvo desta versão (v0.1): sunstrike_lab.py v0.7.2 INTOCADA
(1c433df1…, o ANTES — GATEFALL OFICIAL = RUN 1, sempre, mesmo com
defeito do probe; precedentes R3, R5, R8). As previsões V072 foram
pré-registadas NESTE FICHEIRO ANTES de qualquer corrida contra a
v0.7.2 (o probe recusa qualquer outro hash por construção: nenhuma
previsão pode ser afinada à luz de um run).

ACHADO C16 (supervisor, EXECUTADO contra a v0.7.2): DIVIDIR O ATAQUE
PELOS DOIS CANAIS À NOITE. A onda (D-FLEET-SHUTDOWN-WAVE) conta só
shutdowns SEM WO (5 < k=6); a massa (D-MASS-SHUTDOWN-WITH-WO) conta
só shutdowns COM WO válida (5 < 6 e 25,68% < 30%); NENHUMA regra soma
os dois canais. À noite a capacity é cega (div=0 físico). Resultado
medido pelo supervisor: 200×10, SÓ WARN s/WO ×5, ZERO CRIT; depois
BLACKOUT → 10/12 casas às escuras (só devs 4 e 11 com luz). De DIA o
mesmo ataque → D-CAPACITY-DIVERGENCE CRIT (arming s/WO) + o WARN.

Bateria (7 previsões pré-registradas ANTES do RUN 1):
  P-R9-01  C16-split-NOITE  (GO, medição do supervisor — o cenário exato)
  P-R9-02  C16-split-DIA    (GO, a versão diurna do mesmo ataque)
  P-R9-03  C16-split-CAPACIDADE (BUILDER: variante que mostra que a
           lacuna NÃO é só o split exato do GO — 2 com WO + 4 s/WO,
           cada canal abaixo dos seus gatilhos, a UNIÃO acima)
  P-R9-04  C16-residuo      (BUILDER: medição do resíduo total < k E
           < 30% somando os dois canais — o que o GO manda medir)
  P-R9-05  C16-NEG-MNT3     (BUILDER: NEG — manutenção legítima de
           POUCOS dispositivos com WO de âmbito correto → 0 CRIT)
  P-R9-06  C16-NEG-frota-MNT1 (BUILDER: NEG — manutenção legítima da
           FROTA INTEIRA com MNT1 → o CRIT de massa DISPARA e fica
           DECLARADO aceitável, GO da v0.7.2)
  P-R9-07  C16-estatica     (BUILDER: prova estática de que NENHUM ramo
           do detetor soma os dois canais na v0.7.2)

Números pré-calculados (KWP_LAYOUT, Σ=88,8 kWp):
  5 menores [10,2,6,5,1]  = 22,8 kWp = 25,68%  (canal COM WO do split)
  5 seguintes [9,7,3,8,0] = 42,6 kWp = 47,97% (canal SEM WO do split)
  restantes ON [4,11]     = 23,4 kWp = 26,35% (2/12 casas com luz)
  P-R9-03: com WO [11,0]=21,9 (24,66%) + s/WO [8,3,7,9]=32,1 (36,15%)
  P-R9-04: com WO [10,2,6] + s/WO [5,1] = 5 devs, 22,8 kWp = 25,68%

CHANGEDLOG
  v0.2 (13-11-2026, pós-fix, ANTES de qualquer corrida contra a
      v0.7.3): ESTE ficheiro — alvo DUAL. A lista GATEFALL_V072 fica
      CONGELADA (a do GATEFALL OFICIAL run 1 + errata E-R9-1 do run
      1b, 6/7 com P-R9-05 ERRADA registrada — D-AUTH-DEFAULT é CRIT,
      não WARN); a lista GATEFALL_V073 é pré-registada ANTES do
      RUN 2 contra a v0.7.3 (de7f5766…): F-C16 (a massa conta a
      UNIÃO dos shutdowns remotos executados, com ou sem WO, por
      distintos ≥ k OU perda Σkwp ≥ 30%, dia e noite). RESÍDUO
      DECLARADO por medição (mandato do GO): P-R9-04 (5 distintos,
      25,68% < 30 somando os dois canais) continua 0 CRIT — fica
      DECLARADO para a v0.8. As previsões V073 incorporam
      HONESTAMENTE as lições REGISTRADAS dos runs contra a v0.7.2
      (E-R9-1: telemetria natural sem emit do probe; E-R9-2:
      D-AUTH-DEFAULT é CRIT).
  v0.1 (13-11-2026, GO à v0.7.3 ~21:00, via supervisor): bateria
      ORIGINAL da ronda, alvo ÚNICO V072 (1c433df1…). 7 previsões
      pré-registadas ANTES do RUN 1: 2 do GO (split NOITE + split
      DIA) + 5 propostas do BUILDER. RUN 1 = GATEFALL OFICIAL.
  v0.1.1 (13-11-2026, ERRATA DE CONSTRUÇÃO datada — E-R9-1; run 1
      PRESERVADO em sunstrike_probes_v072_r9_run1.txt, publicado no
      repo privado ANTES desta errata): DOIS defeitos de construção
      do probe, NENHUMA previsão muda (precedente E-R8-1; o GATEFALL
      OFICIAL continua a ser o RUN 1). (1) CRASH: strings de
      evidência dos P-R9-04 e P-R9-06 com '%' literal não escapado
      em strings formatadas (TypeError no P-R9-04; P-R9-04..07 NÃO
      executadas no run 1) — corrigido mecanicamente ('30%%',
      '100%%'). (2) INJEÇÃO DE TELEMETRIA PELO PRÓPRIO PROBE: os
      cenários P-R9-02 e P-R9-06 chamavam emit_capacity_snapshot
      auxiliar — o snapshot EXTRA do harness fez a previsão
      'count 5' do P-R9-02 sair ERRADA no run 1 (count 6 medido;
      a causa foi o PRÓPRIO probe, como o D-AUTH-DEFAULT esquecido
      no E-R8-2; a substância confirmou: CRIT capacity + WARN ×5,
      sem massa/onda). O emit NÃO faz parte do ataque do GO — é
      REMOVIDO (a previsão refere a telemetria NATURAL do cenário;
      os handlers de shutdown já emitem os seus snapshots). O
      P-R9-02 fica ERRADA no RUN 1 REGISTADA; o re-run completo é
      o RUN 1B, PRESERVADO e CITADO, NÃO oficial.
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

EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                             "0ac38c6e717fd7b40afbd4")
EXPECTED_LAB_SHA256_V073 = ("de7f5766321299cd2fd8b7d98e7c73e1e2439c9df"
                             "d72ca7eb7f659c59750e301")
# v0.7.4 (14-11-2026, GO a v0.7.4, ronda R10): alvo NOVO V074 —
# previsoes V074 = copia datada da V073: os fixes R10 nao tocam os
# cenarios r9 (splits SEM resumes — a massa F-05b conta OFF EM
# SIMULTANEO e as contagens sao AS MESMAS; sem setpoints <= 25%% em
# >= k dispositivos — D-MASS-CURTAILMENT intocado; sem drains
# acumulados >= 50 pp — D-BATTERY-PARKED-DRAIN intocado; a onda
# AUD-08 por DISTINTOS e a slow ancorada no 1.º evento dao as
# MESMAS contagens nos cenarios de shutdowns em dispositivos
# distintos).
EXPECTED_LAB_SHA256_V074 = ("c039ab6174e309ddfd4158f6a865abda22471518"
                            "a6f2119358a772b1069c62c1")
# v0.7.5 (14-11-2026, GO a v0.7.5, ronda R11): alvo NOVO V075 —
# previsoes V075 = copia datada da V074 (analise: os fixes R11 nao
# tocam os cenarios r9 — splits SEM resumes: o F-01 reporta o estado
# de maior kWp e os estados r9 sao os mesmos; a slow deslizante F-06
# da as MESMAS contagens; sem setpoints <= 25% em >= k distintos nem
# drains acumulados >= 50 pp).
EXPECTED_LAB_SHA256_V075 = ("cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d"
                            "788ae2fb723320b091cb86f8")
if lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "V072"
elif lab_sha == EXPECTED_LAB_SHA256_V073:
    TARGET = "V073"
elif lab_sha == EXPECTED_LAB_SHA256_V074:
    TARGET = "V074"
elif lab_sha == EXPECTED_LAB_SHA256_V075:
    TARGET = "V075"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe (v0.2) só corre contra a v0.7.2 INTOCADA (%s…)\n"
          "  ou a v0.7.3 (%s…).\n  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V072[:16],
             EXPECTED_LAB_SHA256_V073[:16]))
    raise SystemExit(2)

IS_V073 = TARGET in ("V073", "V074", "V075")
# v0.7.5/R11: criterios da V074 aplicam-se a V075 (copia datada).
IS_V074 = TARGET in ("V074", "V075")

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R9 v0.2 (dual-target V072/V073; previsões V073 "
      "pré-registadas ANTES de qualquer corrida contra a v0.7.3; achado "
      "C16 do supervisor, GO à v0.7.3 13-11 ~21:00) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)"
      % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL V072 — previsões PRÉ-REGISTADAS antes do RUN 1 (a v0.7.2 é o
# ANTES; o GATEFALL OFICIAL é o RUN 1 com estas previsões, congeladas).
# P-R9-01/02: MEDIÇÕES EXECUTADAS do supervisor contra a v0.7.2 (GO);
# P-R9-03..07: propostas do BUILDER por análise de design.
# ---------------------------------------------------------------------------
GATEFALL_V072 = [
    {"id": "P-R9-01", "expected": "CONFIRMADO",
     "finding": "C16-split-NOITE",
     "prev": ("CONFIRMADO — SPLIT PELOS DOIS CANAIS À NOITE (GO): NOITE "
              "em NORMAL; devs [10,2,6,5,1] (5 menores, 25,68%) com WO "
              "WO-20261112-MNT1 válida → 200×5; devs [9,7,3,8,0] SEM "
              "work_order → 200×5; alertas do cenário: SÓ "
              "D-REMOTE-SHUTDOWN-NO-WO (WARN, count 5), ZERO CRIT (onda "
              "5 < k=6 na janela; slow 5 < 8; massa 5 distintos < 6 E "
              "25,68% < 30; capacity CEGA à noite div=0); depois "
              "BLACKOUT → 10/12 casas às escuras (só devs 4 e 11 com "
              "luz) — 73,65% da frota no chão SEM um CRIT")},
    {"id": "P-R9-02", "expected": "CONFIRMADO",
     "finding": "C16-split-DIA",
     "prev": ("CONFIRMADO — O MESMO SPLIT DE DIA (GO): idem em DIA/"
              "NORMAL → 200×10; alertas: WARN D-REMOTE-SHUTDOWN-NO-WO "
              "count 5 + D-CAPACITY-DIVERGENCE CRIT (o arming vem dos "
              "shutdowns s/WO; a div cruza 30% ao 1.º shutdown s/WO "
              "(33,33%) e chega a 73,65%) count 5; ZERO outros CRIT "
              "(onda 5 < 6; slow 5 < 8; massa 5 < 6 E 25,68% < 30) — "
              "de DIA a capacity VÊ, mas a MASSA continua cega ao "
              "split: o CRIT de frota não dispara com 10/12 no chão")},
    {"id": "P-R9-03", "expected": "CONFIRMADO",
     "finding": "C16-split-CAPACIDADE",
     "prev": ("CONFIRMADO — VARIANTE DE CAPACIDADE À NOITE (BUILDER): "
              "devs [11,0] com MNT1 (2 distintos, 24,66% < 30) + devs "
              "[8,3,7,9] SEM WO (4 eventos, 36,15% < k em contagem) à "
              "NOITE → 200×6; alertas: SÓ WARN s/WO count 4, ZERO CRIT "
              "(onda 4 < 6; slow 4 < 8; massa 2 < 6 E 24,66% < 30; "
              "capacity cega à noite) — a UNIÃO (6 distintos ≥ k E "
              "60,86% ≥ 30) é INVISÍVEL: a lacuna não é só o split "
              "exato do GO")},
    {"id": "P-R9-04", "expected": "CONFIRMADO",
     "finding": "C16-residuo",
     "prev": ("CONFIRMADO — RESÍDUO SOMADO (BUILDER, medição): devs "
              "[10,2,6] com MNT1 + devs [5,1] SEM WO à NOITE → 200×5; "
              "alertas: SÓ WARN s/WO count 2, ZERO CRIT (5 distintos < "
              "k E 25,68% < 30 SOMANDO os dois canais) — este é o "
              "resíduo que QUALQUER regra de escala continua a ter: "
              "total < k E < 30% escapa; fica para DECLARAÇÃO")},
    {"id": "P-R9-05", "expected": "CONFIRMADO",
     "finding": "C16-NEG-MNT3",
     "prev": ("CONFIRMADO — NEG MANUTENÇÃO LEGÍTIMA (BUILDER): login "
              "default no gate + /fleet/bulk_shutdown com MNT3 (âmbito "
              "{0,2}) → 200 com 2 shutdowns COM WO (dispatch só aos "
              "in-scope, 10 bulk_scope_skip), D-AUTH-DEFAULT WARN ×1 "
              "(login default — lição E-R8-02 REGISTADA), ZERO CRIT "
              "(2 < k E 22,9% < 30), frota 10/12 ON — o caso legítimo "
              "de POUCOS dispositivos com WO de âmbito correto NÃO "
              "dispara massa")},
    {"id": "P-R9-06", "expected": "CONFIRMADO",
     "finding": "C16-NEG-frota-MNT1",
     "prev": ("CONFIRMADO — NEG FROTA INTEIRA LEGÍTIMA (BUILDER): 12 "
              "shutdowns per-device COM MNT1 (âmbito frota, 12 usos) "
              "em DIA → 200×12, D-MASS-SHUTDOWN-WITH-WO CRIT count 12 "
              "(12 ≥ k E 100% ≥ 30 — o FP DECLARADO aceitável do GO "
              "da v0.7.2), SEM onda/slow/WARN/capacity (com WO não "
              "arma; snapshots com div ≥ 30 saem SEM alerta) — o "
              "comportamento da v0.7.2 mantém-se como baseline")},
    {"id": "P-R9-07", "expected": "CONFIRMADO",
     "finding": "C16-estatica",
     "prev": ("CONFIRMADO — PROVA ESTÁTICA (BUILDER): no scan() da "
              "v0.7.2 os shutdowns remotos s/WO vão para a lista "
              "'shutdowns' (onda + slow) e os com WO válida para a "
              "'wo_shutdowns' (massa); NENHUMA regra lê a UNIÃO dos "
              "dois canais; a D-CAPACITY-DIVERGENCE arma só com "
              "eventos s/WO (ou export s/WO) — por construção, o "
              "split de canais deixará sempre cada gatilho abaixo do "
              "seu limiar")},
]

# ---------------------------------------------------------------------------
# GATEFALL V073 — previsões PRÉ-REGISTADAS NESTE FICHEIRO (v0.2) ANTES
# de qualquer corrida contra a v0.7.3 (de7f5766…). Fix F-C16 do GO:
# EXTENSÃO da D-MASS-SHUTDOWN-WITH-WO à UNIÃO dos dois canais. As
# previsões V073 incorporam HONESTAMENTE as lições REGISTRADAS dos runs
# contra a v0.7.2 (precedente r7/r8: a previsão do DEPOIS é informada
# pela MEDIÇÃO do ANTES): E-R9-1 (o P-R9-02 conta a telemetria NATURAL
# — sem emit do probe) e E-R9-2 (D-AUTH-DEFAULT é CRIT, não WARN).
# ---------------------------------------------------------------------------
GATEFALL_V073 = [
    {"id": "P-R9-01", "expected": "RESOLVIDO", "finding": "C16-split-NOITE",
     "prev": ("RESOLVIDO — F-C16: o mesmo split à NOITE → 200×10 e a UNIÃO "
              "acende: D-MASS-SHUTDOWN-WITH-WO CRIT count 10 (10 "
              "distintos ≥ k E 73,65% ≥ 30; with_wo 5/without_wo 5) + "
              "WARN s/WO count 5; SEM onda (5 s/WO < 6 na janela) e SEM "
              "capacity (noite, div=0); no blackout DEPOIS: 10/12 casas "
              "às escuras — mas o CRIT de frota chega ANTES do apagão")},
    {"id": "P-R9-02", "expected": "RESOLVIDO", "finding": "C16-split-DIA",
     "prev": ("RESOLVIDO — F-C16: o mesmo split DE DIA → 200×10; UNIÃO: "
              "D-MASS-SHUTDOWN-WITH-WO CRIT count 10 + WARN s/WO count "
              "5 + D-CAPACITY-DIVERGENCE CRIT count 5 (arming s/WO — a "
              "telemetria NATURAL, sem emit do probe — lição E-R9-1); "
              "SEM onda (5 < 6): de dia a massa VÊ o split somado")},
    {"id": "P-R9-03", "expected": "RESOLVIDO",
     "finding": "C16-split-CAPACIDADE",
     "prev": ("RESOLVIDO — F-C16: a variante 2 com WO + 4 s/WO à NOITE → "
              "200×6; D-MASS-SHUTDOWN-WITH-WO CRIT count 6 (6 distintos "
              "≥ k; 60,86% ≥ 30; with_wo 2/without_wo 4) + WARN s/WO "
              "count 4; SEM onda (4 < 6) e SEM capacity (noite) — a "
              "UNIÃO é o que a extensão conta")},
    {"id": "P-R9-04", "expected": "DECLARADO", "finding": "C16-residuo",
     "prev": ("DECLARADO — RESÍDUO MEDIDO (mandato do GO): 3 com WO + 2 "
              "s/WO à NOITE → 200×5; SÓ WARN s/WO count 2, ZERO CRIT "
              "(5 distintos < k E 25,68% < 30 SOMANDO os dois canais) — "
              "o resíduo do F-C16 é o MESMO da v0.7.2 e fica DECLARADO "
              "para a v0.8")},
    {"id": "P-R9-05", "expected": "RESOLVIDO", "finding": "C16-NEG-MNT3",
     "prev": ("RESOLVIDO — F-C16 FP: bulk MNT3 {0,2} → 200, 2 shutdowns "
              "COM WO, 10 bulk_scope_skip; D-AUTH-DEFAULT CRIT ×1 do "
              "login default (lição E-R9-2 REGISTADA do run 1b: é CRIT, "
              "não WARN) e ZERO outros alertas — a UNIÃO não dispara "
              "com 2 < k E 22,9% < 30; frota 10/12 ON")},
    {"id": "P-R9-06", "expected": "RESOLVIDO",
     "finding": "C16-NEG-frota-MNT1",
     "prev": ("RESOLVIDO — F-C16 baseline mantém: 12 shutdowns COM MNT1 "
              "→ 200×12, D-MASS-SHUTDOWN-WITH-WO CRIT count 12 "
              "(with_wo 12/without_wo 0 — o FP DECLARADO aceitável do GO "
              "da v0.7.2), SEM onda/slow/WARN/capacity — a extensão não "
              "muda o caso legítimo de frota inteira")},
    {"id": "P-R9-07", "expected": "RESOLVIDO", "finding": "C16-estatica",
     "prev": ("RESOLVIDO — F-C16: o scan() da v0.7.3 coleciona TODOS os "
              "shutdowns remotos EXECUTADOS na UNIÃO mass_shutdowns "
              "(o ramo s/WO E o ramo wo_valid alimentam a MESMA lista "
              "por cenário) e a D-MASS-SHUTDOWN-WITH-WO lê a UNIÃO — "
              "a prova estática do canal único fechada")},
]

GATEFALL_V074 = [dict(e) for e in GATEFALL_V073]
# v0.7.5/R11 (14-11, pre-registado ANTES do run de nao-regressao):
# previsoes V075 = copia datada da V074 (nota datada no hash V075).
GATEFALL_V075 = [dict(e) for e in GATEFALL_V074]
GATEFALL = (GATEFALL_V075 if TARGET == "V075"
            else GATEFALL_V074 if IS_V074
            else GATEFALL_V073 if IS_V073 else GATEFALL_V072)

if IS_V073:
    print("\nGATEFALL V073 — PREVISÕES PRÉ-REGISTADAS NESTE FICHEIRO (v0.2) "
          "ANTES de qualquer corrida contra a v0.7.3 (de7f5766…): fix "
          "F-C16 do GO (extensão da D-MASS-SHUTDOWN-WITH-WO à UNIÃO dos "
          "dois canais); resíduo P-R9-04 medido e DECLARADO por mandato "
          "do GO")
else:
    print("\nGATEFALL V072 — PREVISÕES PRÉ-REGISTADAS NESTE FICHEIRO (v0.1) "
          "ANTES de qualquer corrida contra a v0.7.2 INTOCADA (1c433df1…)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))

# ---------------------------------------------------------------------------
# Helpers (padrão das probes R5–R8 — re-implementação INDEPENDENTE)
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


def night_normal(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("NOITE")
    time.sleep(0.4)


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


def alert_set(alerts):
    return sorted((a["rule"], a["severity"], a["count"]) for a in alerts)


# ---------------------------------------------------------------------------
# Execução — RUN 1 (vs v0.7.2 INTOCADA; GATEFALL OFICIAL)
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("\nlab v%s em memória (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))
    try:
        # ============ P-R9-01 — C16: split dois canais (NOITE) ==========
        print("[P-R9-01] C16 — split 5 com WO + 5 s/WO à NOITE (NORMAL)")
        scen = "P-R9-01"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        night_normal(lab)
        wo_devs = [10, 2, 6, 5, 1]
        nowo_devs = [9, 7, 3, 8, 0]
        sts01 = []
        for i in wo_devs:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts01.append(st)
        for i in nowo_devs:
            st, resp = remote_shutdown(lab, i, None)
            sts01.append(st)
        time.sleep(0.6)
        alerts01 = scan_scenario(lab, scen)
        crits01 = [a for a in alerts01 if a["severity"] == "CRIT"]
        warns01 = [a for a in alerts01 if a["severity"] == "WARN"]
        off01 = sum(1 for d in lab.devices if not d.inverter_on)
        blackout(lab)
        served01 = served_count(lab)
        warn_only_nowo = (len(warns01) == 1
                          and warns01[0]["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"
                          and warns01[0]["count"] == 5)
        mass01 = {a["rule"]: a for a in crits01}.get(
            "D-MASS-SHUTDOWN-WITH-WO")
        if IS_V073:
            cond_01 = (all(s == 200 for s in sts01) and off01 == 10
                       and mass01 is not None and mass01["count"] == 10
                       and mass01["distinct_devices"] == 10
                       and abs(mass01["capacity_loss_pct"] - 73.65) < 0.05
                       and mass01["with_wo"] == 5
                       and mass01["without_wo"] == 5
                       and warn_only_nowo and len(crits01) == 1
                       and served01 == 2)
            word_01 = "RESOLVIDO"
            ev_01 = [
                "com WO MNT1 devs %s → %s; s/WO devs %s → %s; frota "
                "OFF: %d/12" % (wo_devs,
                               "200×5" if all(s == 200 for s in sts01[:5])
                               else sts01[:5],
                               nowo_devs,
                               "200×5" if all(s == 200 for s in sts01[5:])
                               else sts01[5:], off01),
                "alertas: %s — a UNIÃO acende: CRIT de massa count 10 "
                "(10 distintos ≥ k E 73,65%% ≥ 30; com/s WO 5/5) + "
                "WARN ×5; SEM onda (5 < 6) e SEM capacity (noite)"
                % alert_set(alerts01),
                "blackout DEPOIS: %d/12 casas com luz — 10/12 às escuras, "
                "MAS o CRIT de frota chegou ANTES do apagão" % served01,
                "F-C16: o split de canais deixa de deixar cada gatilho "
                "abaixo do seu limiar — a massa conta a UNIÃO"]
        else:
            cond_01 = (all(s == 200 for s in sts01) and off01 == 10
                       and len(crits01) == 0 and warn_only_nowo
                       and served01 == 2)
            word_01 = "CONFIRMADO"
            ev_01 = [
                "com WO MNT1 devs %s → %s; s/WO devs %s → %s; frota OFF: "
                "%d/12" % (wo_devs,
                           "200×5" if all(s == 200 for s in sts01[:5]) else sts01[:5],
                           nowo_devs,
                           "200×5" if all(s == 200 for s in sts01[5:]) else sts01[5:],
                           off01),
                "alertas: %s — ZERO CRIT (onda 5<k; slow 5<8; massa 5<6 E "
                "25,68%%<30; capacity cega div=0)"
                % (alert_set(alerts01) or "ZERO"),
                "blackout DEPOIS: %d/12 casas com luz — 10/12 às escuras "
                "(só devs 4 e 11)" % served01,
                "CONSEQUÊNCIA: 65,4/88,8 kWp = 73,65% da frota no chão à "
                "noite com ZERO CRIT — a defesa de escala não soma os dois "
                "canais"]
        expect("P-R9-01", GATEFALL[0]["prev"], cond_01,
               word_01, "PREVISÃO ERRADA (ver detalhe acima)", ev_01)

        # ============ P-R9-02 — C16: o mesmo split DE DIA ===============
        print("\n[P-R9-02] C16 — split 5 com WO + 5 s/Wo DE DIA (NORMAL)")
        scen = "P-R9-02"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts02 = []
        for i in wo_devs:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts02.append(st)
        for i in nowo_devs:
            st, resp = remote_shutdown(lab, i, None)
            sts02.append(st)
        time.sleep(0.6)
        alerts02 = scan_scenario(lab, scen)
        crits02 = {a["rule"]: a for a in alerts02 if a["severity"] == "CRIT"}
        warns02 = [a for a in alerts02 if a["severity"] == "WARN"]
        off02 = sum(1 for d in lab.devices if not d.inverter_on)
        exp02, act02, div02 = L.capacity_divergence_pct(lab.devices)
        cap_ok = ("D-CAPACITY-DIVERGENCE" in crits02
                  and crits02["D-CAPACITY-DIVERGENCE"]["count"] == 5)
        no_wave = ("D-FLEET-SHUTDOWN-WAVE" not in crits02
                   and "D-SLOW-WAVE" not in crits02)
        warn_ok = (len(warns02) == 1
                   and warns02[0]["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"
                   and warns02[0]["count"] == 5)
        if IS_V073:
            mass02 = crits02.get("D-MASS-SHUTDOWN-WITH-WO")
            cond_02 = (all(s == 200 for s in sts02) and off02 == 10
                       and mass02 is not None and mass02["count"] == 10
                       and cap_ok and no_wave and warn_ok)
            word_02 = "RESOLVIDO"
            ev_02 = [
                "200×10, frota OFF %d/12; div final %.2f%% (esperado "
                "%.2f vs real %.2f kW)" % (off02, div02, exp02, act02),
                "alertas: %s — a UNIÃO acende de DIA: massa count 10 + "
                "capacity count 5 (arming s/WO, telemetria NATURAL — "
                "lição E-R9-1) + WARN ×5; SEM onda (5 < 6)"
                % alert_set(alerts02),
                "F-C16: de dia a massa VÊ o split somado (10 distintos "
                "≥ k E 73,65% ≥ 30) — o CRIT de frota já não depende "
                "só da física do sol"]
        else:
            no_mass_no_wave = ("D-MASS-SHUTDOWN-WITH-WO" not in crits02
                               and no_wave)
            cond_02 = (all(s == 200 for s in sts02) and off02 == 10
                       and cap_ok and no_mass_no_wave and warn_ok)
            word_02 = "CONFIRMADO"
            ev_02 = [
                "200×10, frota OFF %d/12; div final %.2f%% (esperado %.2f "
                "vs real %.2f kW)" % (off02, div02, exp02, act02),
                "alertas: %s" % alert_set(alerts02),
                "o CRIT é SÓ o da capacity (arming s/WO, count 5 — a div "
                "cruza 30% ao 1.º shutdown s/WO, 33,33%); a MASSA segue "
                "CEGA ao split de dia (5 com WO < 6 E < 30%)",
                "CONSEQUÊNCIA: de dia a física salva a deteção (C12), mas "
                "nenhuma regra de ESCALA vê os 10 shutdowns somados"]
        expect("P-R9-02", GATEFALL[1]["prev"], cond_02,
               word_02, "PREVISÃO ERRADA (ver detalhe acima)", ev_02)

        # ============ P-R9-03 — C16: variante de capacidade (NOITE) ====
        print("\n[P-R9-03] C16 — 2 com WO + 4 s/WO à NOITE (variante)")
        scen = "P-R9-03"
        lab.scenario(scen)
        reset_all(lab)
        night_normal(lab)
        wo_devs03 = [11, 0]
        nowo_devs03 = [8, 3, 7, 9]
        sts03 = []
        for i in wo_devs03:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts03.append(st)
        for i in nowo_devs03:
            st, resp = remote_shutdown(lab, i, None)
            sts03.append(st)
        time.sleep(0.6)
        alerts03 = scan_scenario(lab, scen)
        crits03 = [a for a in alerts03 if a["severity"] == "CRIT"]
        warns03 = [a for a in alerts03 if a["severity"] == "WARN"]
        off03 = sum(1 for d in lab.devices if not d.inverter_on)
        warn_ok03 = (len(warns03) == 1
                     and warns03[0]["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"
                     and warns03[0]["count"] == 4)
        mass03 = {a["rule"]: a for a in crits03}.get(
            "D-MASS-SHUTDOWN-WITH-WO")
        if IS_V073:
            cond_03 = (all(s == 200 for s in sts03) and off03 == 6
                       and mass03 is not None and mass03["count"] == 6
                       and mass03["distinct_devices"] == 6
                       and mass03["with_wo"] == 2
                       and mass03["without_wo"] == 4
                       and warn_ok03)
            word_03 = "RESOLVIDO"
            ev_03 = [
                "com WO devs %s (21,9 kWp = 24,66%%) + s/WO devs %s (32,1 "
                "kWp = 36,15%%) → %s; frota OFF %d/12"
                % (wo_devs03, nowo_devs03,
                   "200×6" if all(s == 200 for s in sts03) else sts03, off03),
                "alertas: %s — a UNIÃO acende: CRIT de massa count 6 "
                "(6 distintos ≥ k; 60,86%% ≥ 30; com/s WO 2/4) + WARN ×4"
                % alert_set(alerts03),
                "F-C16: a variante que na v0.7.2 era invisível MESMO com "
                "a união acima dos dois gatilhos agora dispara"]
        else:
            cond_03 = (all(s == 200 for s in sts03) and off03 == 6
                       and len(crits03) == 0 and warn_ok03)
            word_03 = "CONFIRMADO"
            ev_03 = [
                "com WO devs %s (21,9 kWp = 24,66%%) + s/WO devs %s (32,1 "
                "kWp = 36,15%%) → %s; frota OFF %d/12"
                % (wo_devs03, nowo_devs03,
                   "200×6" if all(s == 200 for s in sts03) else sts03, off03),
                "alertas: %s — ZERO CRIT" % (alert_set(alerts03) or "ZERO"),
                "a UNIÃO (6 distintos ≥ k E 60,86% ≥ 30) é INVISÍVEL: a "
                "lacuna é ESTRUTURAL (canais separados), não um acaso do "
                "split do GO"]
        expect("P-R9-03", GATEFALL[2]["prev"], cond_03,
               word_03, "PREVISÃO ERRADA (ver detalhe acima)", ev_03)

        # ============ P-R9-04 — C16: resíduo somado (NOITE) ============
        print("\n[P-R9-04] C16 — resíduo: 3 com WO + 2 s/WO (5 < k, "
              "25,68% < 30)")
        scen = "P-R9-04"
        lab.scenario(scen)
        reset_all(lab)
        night_normal(lab)
        wo_devs04 = [10, 2, 6]
        nowo_devs04 = [5, 1]
        sts04 = []
        for i in wo_devs04:
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts04.append(st)
        for i in nowo_devs04:
            st, resp = remote_shutdown(lab, i, None)
            sts04.append(st)
        time.sleep(0.6)
        alerts04 = scan_scenario(lab, scen)
        crits04 = [a for a in alerts04 if a["severity"] == "CRIT"]
        warns04 = [a for a in alerts04 if a["severity"] == "WARN"]
        off04 = sum(1 for d in lab.devices if not d.inverter_on)
        warn_ok04 = (len(warns04) == 1
                     and warns04[0]["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"
                     and warns04[0]["count"] == 2)
        cond_04 = (all(s == 200 for s in sts04) and off04 == 5
                   and len(crits04) == 0 and warn_ok04)
        ev_04 = [
            "com WO devs %s + s/WO devs %s → %s; frota OFF %d/12 "
            "(22,8 kWp = 25,68%% somando os dois canais)"
            % (wo_devs04, nowo_devs04,
               "200×5" if all(s == 200 for s in sts04) else sts04, off04),
            "alertas: %s — ZERO CRIT: total 5 < k E < 30%% SOMADO"
            % (alert_set(alerts04) or "ZERO"),
            "RESÍDUO MEDIDO: qualquer regra de escala deixa escapar "
            "total < k E < 30% — fica DECLARADO (mandato do GO)"]
        expect("P-R9-04", GATEFALL[3]["prev"], cond_04,
               "DECLARADO" if IS_V073 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)", ev_04)

        # ============ P-R9-05 — C16: NEG manutenção MNT3 (bulk) ========
        print("\n[P-R9-05] C16 — NEG: bulk do gate com MNT3 (âmbito {0,2})")
        scen = "P-R9-05"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st_login, resp_login = hj(L.PORT_GATE, "POST", "/fleet/login",
                                  {"user": L.DEFAULT_USER,
                                   "pass": L.DEFAULT_PASS})
        sid = resp_login.get("session")
        st_bulk, resp_bulk = hj(L.PORT_GATE, "POST", "/fleet/bulk_shutdown",
                                 {"work_order_id": "WO-20261113-MNT3"},
                                 token=sid)
        time.sleep(0.6)
        alerts05 = scan_scenario(lab, scen)
        crits05 = [a for a in alerts05 if a["severity"] == "CRIT"]
        warns05 = [a for a in alerts05 if a["severity"] == "WARN"]
        skip05 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "bulk_scope_skip"]
        shut05 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        off05 = sum(1 for d in lab.devices if not d.inverter_on)
        auth_alert = [a for a in alerts05 if a["rule"] == "D-AUTH-DEFAULT"]
        if IS_V073:
            other05 = [a for a in alerts05
                       if a["rule"] != "D-AUTH-DEFAULT"]
            cond_05 = (st_login == 200 and st_bulk == 200 and off05 == 2
                       and len(shut05) == 2 and len(skip05) == 10
                       and len(auth_alert) == 1
                       and auth_alert[0]["severity"] == "CRIT"
                       and not other05)
            word_05 = "RESOLVIDO"
            ev_05 = [
                "login default → %s (D-AUTH-DEFAULT CRIT ×1 — lição "
                "E-R9-2 REGISTRADA do run 1b: a severidade é CRIT, "
                "não WARN); bulk MNT3 → %s: 2 shutdowns COM WO, %d "
                "bulk_scope_skip" % (st_login, st_bulk, len(skip05)),
                "frota OFF %d/12 (só devs 0 e 2); alertas: %s — ZERO "
                "outros: a UNIÃO não dispara com 2 < k E 22,9%% < 30"
                % (off05, alert_set(alerts05)),
                "NEG MANTÉM: manutenção legítima de POUCOS dispositivos "
                "com WO de âmbito correto fica ABAIXO dos gatilhos de "
                "escala somados"]
        else:
            auth_warn = any(a["rule"] == "D-AUTH-DEFAULT" for a in warns05)
            cond_05 = (st_login == 200 and st_bulk == 200 and off05 == 2
                       and len(shut05) == 2 and len(skip05) == 10
                       and len(crits05) == 0 and auth_warn
                       and not any(a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"
                                   for a in alerts05))
            word_05 = "CONFIRMADO"
            ev_05 = [
                "login default → %s (D-AUTH-DEFAULT WARN ×1 — lição "
                "E-R8-02); bulk MNT3 → %s: 2 shutdowns COM WO, %d "
                "bulk_scope_skip" % (st_login, st_bulk, len(skip05)),
                "frota OFF %d/12 (só devs 0 e 2); alertas: %s — ZERO CRIT"
                % (off05, alert_set(alerts05)),
                "NEG MANTÉM: manutenção legítima de POUCOS dispositivos "
                "com WO de âmbito correto fica ABAIXO dos gatilhos de "
                "escala (2 < k E 22,9% < 30)"]
        expect("P-R9-05", GATEFALL[4]["prev"], cond_05,
               word_05, "PREVISÃO ERRADA (ver detalhe acima)", ev_05)

        # ============ P-R9-06 — C16: NEG frota inteira com MNT1 =========
        print("\n[P-R9-06] C16 — NEG: 12 shutdowns COM MNT1 (baseline "
              "v0.7.2)")
        scen = "P-R9-06"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts06 = []
        for i in range(len(lab.devices)):
            st, resp = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts06.append(st)
        time.sleep(0.6)
        alerts06 = scan_scenario(lab, scen)
        crits06 = {a["rule"]: a for a in alerts06 if a["severity"] == "CRIT"}
        warns06 = [a for a in alerts06 if a["severity"] == "WARN"]
        off06 = sum(1 for d in lab.devices if not d.inverter_on)
        mass06 = crits06.get("D-MASS-SHUTDOWN-WITH-WO")
        if IS_V073:
            cond_06 = (all(s == 200 for s in sts06) and off06 == 12
                       and mass06 is not None and mass06["count"] == 12
                       and mass06["with_wo"] == 12
                       and mass06["without_wo"] == 0
                       and len(warns06) == 0
                       and "D-CAPACITY-DIVERGENCE" not in crits06
                       and "D-FLEET-SHUTDOWN-WAVE" not in crits06)
            word_06 = "RESOLVIDO"
            ev_06 = [
                "12 shutdowns COM MNT1 → %s; frota OFF %d/12"
                % ("200×12" if all(s == 200 for s in sts06) else sts06, off06),
                "alertas: %s — o CRIT de massa count 12 (com_wo 12, "
                "without_wo 0) é o FP DECLARADO aceitável do GO da "
                "v0.7.2, MANTIDO pela extensão"
                % alert_set(alerts06),
                "SEM onda/WARN/capacity (com WO válida não arma) — a "
                "extensão não muda o caso legítimo de frota inteira"]
        else:
            cond_06 = (all(s == 200 for s in sts06) and off06 == 12
                       and mass06 is not None and mass06["count"] == 12
                       and len(warns06) == 0
                       and "D-CAPACITY-DIVERGENCE" not in crits06
                       and "D-FLEET-SHUTDOWN-WAVE" not in crits06)
            word_06 = "CONFIRMADO"
            ev_06 = [
                "12 shutdowns COM MNT1 → %s; frota OFF %d/12"
                % ("200×12" if all(s == 200 for s in sts06) else sts06, off06),
                "alertas: %s — o CRIT de massa count 12 é o FP DECLARADO "
                "aceitável do GO da v0.7.2 (12 ≥ k E 100%% ≥ 30)"
                % alert_set(alerts06),
                "SEM onda/WARN/capacity (com WO válida não arma) — baseline "
                "da v0.7.2 MANTÉM neste cenário"]
        expect("P-R9-06", GATEFALL[5]["prev"], cond_06,
               word_06, "PREVISÃO ERRADA (ver detalhe acima)", ev_06)

        # ============ P-R9-07 — C16: prova estática ======================
        print("\n[P-R9-07] C16 — prova estática: nenhum ramo soma os "
              "dois canais")
        src = LAB_BYTES.decode("utf-8")
        scan_zone = src[src.index("def scan(self, events)"):]
        scan_zone = scan_zone[:scan_zone.index("def rule_liveness_check")]
        if IS_V073:
            union_fed = (scan_zone.count(
                "mass_shutdowns[ev.get(\"scenario\"") >= 2)
            wave_reads_shutdowns = ("for scen, evs in shutdowns.items()"
                                    in scan_zone)
            mass_reads_union = ("for scen, evs in "
                                "mass_shutdowns.items()" in scan_zone)
            cond_07 = (union_fed and wave_reads_shutdowns
                       and mass_reads_union)
            word_07 = "RESOLVIDO"
            ev_07 = [
                "scan() da v0.7.3: os ramos s/WO E wo_valid alimentam a "
                "MESMA lista mass_shutdowns por cenário (UNIÃO)",
                "a massa lê mass_shutdowns.items() — a UNIÃO dos dois "
                "canais (com ou sem WO); a onda lê shutdowns (s/WO) "
                "INTACTA; o WARN por evento INTACTO",
                "F-C16: a prova estática do canal único fechada — "
                "nenhum split deixa cada gatilho abaixo do limiar"]
        else:
            has_shutdowns_list = "shutdowns[ev.get(\"scenario\"" in scan_zone
            has_wo_list = "wo_shutdowns[ev.get(\"scenario\"" in scan_zone
            wave_reads_shutdowns = ("for scen, evs in shutdowns.items()"
                                    in scan_zone)
            mass_reads_wo = ("for scen, evs in wo_shutdowns.items()"
                             in scan_zone)
            union_absent = ("mass_all" not in scan_zone
                            and "all_shutdowns" not in scan_zone
                            and "union" not in scan_zone)
            cond_07 = (has_shutdowns_list and has_wo_list
                       and wave_reads_shutdowns
                       and mass_reads_wo and union_absent)
            word_07 = "CONFIRMADO"
            ev_07 = [
                "scan() da v0.7.2: s/WO → 'shutdowns' (onda+slow); com WO "
                "válida → 'wo_shutdowns' (massa); listas SEPARADAS",
                "a onda lê só shutdowns; a massa lê só wo_shutdowns; "
                "NENHUMA regra lê a UNIÃO (sem mass_all/all_shutdowns/union)",
                "a capacity arma só com eventos s/WO (shutdown ou export) "
                "— com WO não arma (C12); à noite div=0 (cegueira física "
                "declarada)",
                "CONSEQUÊNCIA: por CONSTRUÇÃO, dividir pelos dois canais "
                "deixa cada gatilho abaixo do seu limiar — é o C16"]
        expect("P-R9-07", GATEFALL[6]["prev"], cond_07,
               word_07, "PREVISÃO ERRADA (ver detalhe acima)", ev_07)

    finally:
        lab.stop()

    # ---------------- sumário ----------------
    match_words = ("CONFIRMADO", "RESOLVIDO", "DECLARADO")
    match_n = sum(1 for v in VEREDICTOS if v["veredicto"] in match_words)
    print("\nSUMÁRIO — GATEFALL R9 vs alvo %s (run %s)" % (TARGET, RUN_ID))
    for v in VEREDICTOS:
        print("  [%s] %s" % (v["id"], v["veredicto"]))
    print("RESULTADO: %d/%d previsões confirmadas (lab v%s)"
          % (match_n, len(GATEFALL), L.LAB_VERSION))
    if match_n == len(GATEFALL):
        if IS_V073:
            print("RC=0 — RUN 2 vs v0.7.3 (de7f5766…): F-C16 RESOLVIDO "
                  "(com o resíduo P-R9-04 medido e DECLARADO por "
                  "mandato do GO; o CRIT de frota agora soma os dois "
                  "canais, dia e noite).")
        else:
            print("RC=0 — GATEFALL R9 RUN 1 vs v0.7.2 INTOCADA "
                  "(1c433df1…): C16 CONFIRMADO (a lacuna dos dois "
                  "canais existe e foi medida; o fix F-C16 vem "
                  "DEPOIS, por ordem do GO).")
        return 0
    print("RC=1 — há previsões erradas REGISTADAS (método: nunca se "
          "ajusta o probe para bater).")
    return 1


if __name__ == "__main__":
    sys.exit(main())

# EOF:sunstrike_probes_r9.py
