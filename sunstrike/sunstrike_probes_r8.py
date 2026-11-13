#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R8 — 9.ª bateria adversarial (ronda v0.7.2, achado C15).
Caso 4 do repo malapeiro/llm-defensive-disclosures (PVTE v5.0).
Grant GRANT-PVTE-20261112-SS-01 (loopback only, Python 3.9+ stdlib).

Alvos desta versão (v0.2, dual): sunstrike_lab.py v0.7.1 INTOCADA
(72c894fe…, o ANTES — GATEFALL OFICIAL = RUN 1, ver changedlog v0.3) e a
v0.7.2 (1c433df1…, o DEPOIS — fixes F-C15a/F-C15b do GO 13-11 ~19:30).
As previsões V072 foram pré-registadas NESTE FICHEIRO ANTES de qualquer
corrida contra a v0.7.2 (o probe recusa qualquer outro hash por
construção: nenhuma previsão pode ser afinada à luz de um run).

ACHADO C15 (supervisor, GRAVE): WORK_ORDERS era uma lista fixa de 2
entradas sem ligação a dispositivo, janela de tempo ou número de usos
— no modelo de ameaça do caso o atacante É a cloud que EMITE as WOs:
uma WO não pode ser âncora de confiança para shutdowns à escala da
frota. Confirmado pelo RUN 1 (GATEFALL OFICIAL, 9/11 — os 3
cenários do GO com os números exatos; P-R8-04 previsão errada
REGISTADA: o login default do gate dispara D-AUTH-DEFAULT).

CHANGEDLOG
  v0.1 (13-11-2026, GO à v0.7.2 ~19:30): bateria ORIGINAL da ronda,
      alvo único V071 (72c894fe…). 11 previsões pré-registadas ANTES
      do RUN 1: 3 do GO (C15 replay dia / replay noite+blackout /
      reuso 3x no mesmo dispositivo) + 8 propostas do BUILDER.
  v0.1.1 (13-11-2026, ERRATA DE HARNESS datada — precedente r7
      v0.1-bis.1/v0.1-bis.2): o RUN 1 (output 1f4fa8ec…, PRESERVADO
      como sunstrike_probes_v071_r8_run1_errata_harness.txt) deu
      9/11 — P-R8-02 previsão errada POR DEFEITO DE CONSTRUÇÃO DO
      PROBE (o cenário pôs o BLACKOUT ANTES dos shutdowns e o
      interlock de emergência bloqueou 409×12 — a defesa existente
      FUNCIONA em BLACKOUT; física do lab CORRETA). A sequência do GO
      é: shutdowns À NOITE em NORMAL e SÓ DEPOIS o blackout (0/12
      casas). Correção datada IN-PLACE da ORDEM do cenário P-R8-02
      (previsão INALTERADA). O run com a ordem corrigida (output
      1c7d1aac…) ficou rotulado "run 1-bis" e DEPOIS RE-ROTULADO
      "run 1b" pela errata v0.3 (NÃO oficial): 10/11. P-R8-04 ficou
      PREVISÃO ERRADA
      REGISTADA (D-AUTH-DEFAULT do login default esquecido na
      previsão; a substância confirmou: 200, 12×200, frota OFF, ZERO
      alertas de shutdown). O cenário NÃO muda e a previsão V071 NÃO
      se reescreve para bater.
  v0.3 (13-11-2026, ERRATA DE ROTULAGEM datada — correção de método
      VINCULATIVA do supervisor, via operador, regra desde a R3): o
      GATEFALL OFICIAL de qualquer ronda é o RUN 1 contra o "antes",
      MESMO COM DEFEITO DE HARNESS/CRITÉRIO do probe (precedentes R3
      5/6, R5 5/6); o "run 1-bis" da R7 foi EXCEÇÃO só por o run 1
      original se ter PERDIDO no INFRA-A — não se aplica aqui. LOGO:
      GATEFALL OFICIAL R8 = RUN 1 = 9/11 (P-R8-02 errada por defeito
      de construção do probe — blackout antes dos shutdowns; P-R8-04
      errada genuína — D-AUTH-DEFAULT esquecido). O run com a ordem
      corrigida passa a "RUN 1B" (10/11), PRESERVADO e CITADO, mas
      NÃO oficial. NENHUM número nem previsão muda — só o rótulo.
      Correção aplicada IN-PLACE nos rótulos deste ficheiro; os
      outputs do v0.2 (run 2 e re-check com rótulos antigos) ficam
      PRESERVADOS como errata de rotulagem; os re-runs com ESTE
      probe são os oficiais (precedente E8 do r7).
  v0.2 (13-11-2026, pós-fixes): ESTE ficheiro — alvo DUAL. A lista
      GATEFALL_V071 fica CONGELADA (a do GATEFALL oficial); a lista
      GATEFALL_V072 é pré-registada ANTES do RUN 2 contra a v0.7.2
      (1c433df1…): F-C15a (âmbito/janela/usos → 403 + reason +
      D-INVALID-WORK-ORDER; bulk do gate despacha SÓ ao âmbito) e
      F-C15b (D-MASS-SHUTDOWN-WITH-WO CRIT: shutdowns COM WO válida
      com distintos ≥ k OU perda ≥ 30 por cento, dia E noite, sem
      janela — a janela da WO é o artefacto de tempo). RESÍDUOS
      DECLARADOS por medição (mandato do GO): P-R8-03 (1 dispositivo
      reusado, 11,8 por cento) e P-R8-10 (5 menores, 25,68 por cento)
      continuam 0 CRIT com WO válida de âmbito correto — ficam
      DECLARADOS para a v0.8. FP do caso legítimo: P-R8-09 com MNT3
      de âmbito correto → 0 alertas.
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
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
if lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "V071"
elif lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "V072"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe (v0.2) só corre contra a v0.7.1 INTOCIDA (%s…)\n"
          "  ou a v0.7.2 (%s…).\n  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V071[:16],
             EXPECTED_LAB_SHA256_V072[:16]))
    raise SystemExit(2)

IS_V072 = TARGET == "V072"

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R8 v0.3 (dual-target V071/V072; errata de rotulagem "
      "datada — GATEFALL OFICIAL = RUN 1; achado C15 do "
      "supervisor, GO à v0.7.2 13-11 ~19:30) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL V071 — previsões PRÉ-REGISTADAS antes do RUN 1 (CONGELADAS:
# são as do GATEFALL OFICIAL run 1, 9/11 — P-R8-02 errada por defeito
# de construção do probe E P-R8-04 errada genuína, AMBAS REGISTADAS).
# P-R8-01/02/03: MEDIÇÕES EXECUTADAS do supervisor contra a v0.7.1 (GO);
# P-R8-04..11: propostas do BUILDER por análise de design.
# ---------------------------------------------------------------------------
GATEFALL_V071 = [
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
              "com WO-20261112-MNT2 à NOITE (em NORMAL) → 200×12, ZERO "
              "alertas; e SÓ DEPOIS o blackout → 0/12 casas com luz (a "
              "frota desliga às escuras sem UM alerta; em BLACKOUT o "
              "interlock bloquearia — a sequência do GO mede o dano "
              "PRÉ-apagão)")},
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

# ---------------------------------------------------------------------------
# GATEFALL V072 — RE-REGISTRADO NESTE FICHEIRO (v0.2) ANTES de qualquer
# corrida contra a v0.7.2 (1c433df1…). Fixes F-C15a/F-C15b do GO; os
# resíduos P-R8-03/P-R8-10 são o RESÍDUO MEDIDO E DECLARADO que o GO
# mandou medir; P-R8-04 incorpora HONESTAMENTE a lição do run 1-bis
# (D-AUTH-DEFAULT do login default — previsão do DEPOIS informada pela
# MEDIÇÃO do ANTES, precedente r7 GATEFALL_V071).
# ---------------------------------------------------------------------------
GATEFALL_V072 = [
    {"id": "P-R8-01", "expected": "RESOLVIDO", "finding": "C15-replay-DIA",
     "prev": ("RESOLVIDO — F-C15b: a WO MNT1 (âmbito frota inteira, "
              "in-janela, 12 usos ≤ 12) continua a EXECUTAR (200×12, "
              "frota OFF — o fix NÃO bloqueia uso legítimo in-scope) "
              "MAS o CRIT D-MASS-SHUTDOWN-WITH-WO dispara count 12 "
              "(12 distintos ≥ k E 100 por cento ≥ 30), DIA: shutdowns "
              "à escala da frota deixam de ser invisíveis MESMO com WO "
              "válida; SEM capacity/onda (o arming s/WO mantém) e SEM "
              "WARN s/WO")},
    {"id": "P-R8-02", "expected": "RESOLVIDO",
     "finding": "C15-replay-NOITE",
     "prev": ("RESOLVIDO — F-C15a: a MNT2 tem AGORA âmbito {0,1,2}: "
              "devs 0,1,2 → 200×3; devs 3..11 → 403 fora_do_ambito ×9 "
              "+ work_order_invalid reason=fora_do_ambito + WARN "
              "D-INVALID-WORK-ORDER count 9; frota fica 9/12 ON; no "
              "blackout DEPOIS: 9/12 casas com luz (os 3 desligados às "
              "escuras, os 9 defendidos pelo ÂMBITO); SEM D-MASS (3 < "
              "k, 20,3/88,8 = 22,9 por cento < 30) — o replay à frota "
              "inteira com a WO ERRADA morre no âmbito")},
    {"id": "P-R8-03", "expected": "DECLARADO", "finding": "C15-reuso-3x",
     "prev": ("DECLARADO — RESÍDUO MEDIDO (mandato do GO): off/on/off/"
              "on/off com MNT1 no dev 0 → 200×5 (3 usos ≤ 12, âmbito "
              "correto), 3 shutdowns COM WO válida, ZERO alertas (1 "
              "dispositivo distinto < k E 10,5/88,8 = 11,8 por cento < "
              "30) — o atacante que só desliga < k dispositivos com "
              "WO válida de âmbito correto ESCAPA ao CRIT; RESÍDUO "
              "DECLARADO para a v0.8")},
    {"id": "P-R8-04", "expected": "RESOLVIDO", "finding": "C15-bulk",
     "prev": ("RESOLVIDO — F-C15b: /fleet/bulk_shutdown com MNT1 → 200, "
              "12×200, frota OFF, D-AUTH-DEFAULT WARN ×1 (o login "
              "default — lição REGISTADA do run 1-bis) E CRIT "
              "D-MASS-SHUTDOWN-WITH-WO count 12 — o canal bulk da "
              "cloud também deixa de ser invisível à escala da frota")},
    {"id": "P-R8-05", "expected": "RESOLVIDO", "finding": "C15-estatica",
     "prev": ("RESOLVIDO — F-C15a: WORK_ORDERS ganha devices/window_s/"
              "max_uses por WO; existe a validação ÚNICA "
              "work_order_check chamada com WORK_ORDERS pelo "
              "DISPOSITIVO (remote_inverter_power_off E remote_setpoint) "
              "e pelo GATE (check_work_order); contador WORK_ORDER_USES "
              "e época WORK_ORDER_EPOCH — a WO deixa de ser uma "
              "string solta")},
    {"id": "P-R8-06", "expected": "RESOLVIDO", "finding": "C15-MNT2-6",
     "prev": ("RESOLVIDO — F-C15a: 6 shutdowns COM MNT2 (âmbito {0,1,2}) "
              "→ devs 0,1,2: 200×3; devs 3,4,5: 403 fora_do_ambito ×3 + "
              "WARN count 3; frota 9/12 ON; SEM D-MASS (3 < k, 22,9 por "
              "cento < 30) — a segunda entrada deixa de ser âncora "
              "vazia: vale EXATAMENTE o seu âmbito")},
    {"id": "P-R8-07", "expected": "RESOLVIDO", "finding": "C15-janela",
     "prev": ("RESOLVIDO — F-C15a: relógio +40 dias (fora da janela de "
              "30 dias da MNT1) → shutdown COM MNT1 no dev 3 → 403 "
              "fora_da_janela + work_order_invalid reason=fora_da_janela "
              "+ WARN D-INVALID-WORK-ORDER count 1; dev 3 fica ON — a "
              "WO EXPIRA")},
    {"id": "P-R8-08", "expected": "RESOLVIDO", "finding": "C15-usos",
     "prev": ("RESOLVIDO — F-C15a: MNT2 (max_uses 3) 4× no dev 0 → "
              "200×3 e o 4.º 403 usos_esgotados + WARN count 1; 3 "
              "shutdowns executados — o uso da WO é FINITO e contado")},
    {"id": "P-R8-09", "expected": "RESOLVIDO", "finding": "C15-baseline",
     "prev": ("RESOLVIDO — F-C15b FP: manutenção pontual legítima COM "
              "WO DE ÂMBITO CORRETO (MNT3, âmbito {0,2}) nos devs 0 e 2 "
              "→ 200×2, ZERO alertas (2 < k, 20,3/88,8 = 22,9 por cento "
              "< 30) — o caso legítimo de poucos dispositivos com WO "
              "de âmbito correto NÃO dispara (FP morto por medição)")},
    {"id": "P-R8-10", "expected": "DECLARADO", "finding": "C15-5menores",
     "prev": ("DECLARADO — RESÍDUO MEDIDO (mandato do GO): 5 menores "
              "por kWp (25,68 por cento < 30) COM MNT1 → 200×5, ZERO "
              "CRIT (5 < k E < 30 por cento) — o atacante que escolhe "
              "os dispositivos PEQUENOS com WO válida escapa ao CRIT "
              "de massa; RESÍDUO DECLARADO para a v0.8")},
    {"id": "P-R8-11", "expected": "RESOLVIDO", "finding": "C15-top5",
     "prev": ("RESOLVIDO — F-C15b GATILHO DE CAPACIDADE: top-5 (58,22 "
              "por cento ≥ 30) COM MNT1 → 200×5 MAS CRIT "
              "D-MASS-SHUTDOWN-WITH-WO count 5 (5 distintos < k MAS a "
              "perda de capacidade ≥ 30 por cento) — 5 dispositivos "
              "chegam para o alerta quando a CAPACIDADE é o que está "
              "em jogo")},
]

GATEFALL = GATEFALL_V072 if IS_V072 else GATEFALL_V071

if IS_V072:
    print("\nGATEFALL V072 — PREVISÕES RE-REGISTADAS NESTE FICHEIRO (v0.2) "
          "ANTES de qualquer corrida contra a v0.7.2 (1c433df1…): fixes "
          "F-C15a/F-C15b do GO à v0.7.2; resíduos P-R8-03/P-R8-10 medidos "
          "e DECLARADOS por mandato do GO")
else:
    print("\nGATEFALL V071 — PREVISÕES PRÉ-REGISTADAS (v0.1/v0.1.1, "
          "CONGELADAS — as do GATEFALL OFICIAL run 1 1f4fa8ec…, "
          "9/11 com P-R8-02 (defeito de construção do probe) e "
          "P-R8-04 erradas REGISTADAS; o run 1b (ordem corrigida, "
          "10/11) é PRESERVADO e CITADO, não oficial)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))

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
# Execução — RUN 2 (vs v0.7.2) / re-run vs v0.7.1 (GATEFALL congelado)
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
        mass01 = [a for a in alerts01
                  if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
        if IS_V072:
            cond_01 = (all(st == 200 for st in sts01) and fleet_off
                       and len(alerts01) == 1 and len(mass01) == 1
                       and mass01[0]["severity"] == "CRIT"
                       and mass01[0]["count"] == 12
                       and len(mass01[0]["devices"]) == 12
                       and len(shut01) == 12
                       and all(e.get("work_order") == "WO-20261112-MNT1"
                               and e.get("wo_valid") is True
                               for e in shut01)
                       and len(snaps01_hi) >= 1
                       and 99.0 <= div01 <= 100.0)
            word_01 = "RESOLVIDO"
            ev_01 = [
                "POST /mode com WO-20261112-MNT1 aos 12: %s — a WO é "
                "IN-SCOPO (âmbito frota inteira, in-janela, 12 usos ≤ "
                "12): o fix F-C15a NÃO bloqueia o uso legítimo; a "
                "frota desliga (eventos shutdown: %d, TODOS com "
                "wo_valid=true)"
                % ("200×12" if all(s == 200 for s in sts01) else sts01,
                   len(shut01)),
                "alertas: %s — CRIT D-MASS-SHUTDOWN-WITH-WO count %s "
                "(dispositivos distintos %s) — F-C15b: shutdowns à "
                "escala da frota COM WO válida deixam de ser "
                "invisíveis (12 ≥ k E 100 por cento ≥ 30)"
                % ([(a["rule"], a["count"]) for a in alerts01],
                   mass01[0]["count"] if mass01 else 0,
                   len(mass01[0]["devices"]) if mass01 else 0),
                "SEM capacity/onda/WARN: o arming s/WO da capacity "
                "mantém (snapshots div ≥ 30: %d saem como evidência "
                "SEM CRIT — C12 intacto); div direta %.2f por cento"
                % (len(snaps01_hi), div01),
                "CONSEQUÊNCIA: o replay de WO válida à frota inteira "
                "EXECUTA mas ALERTA (CRIT) — a frase do §7 item 8 "
                "passa a ser verdadeira TAMBÉM para WO válida; a "
                "manutenção legítima de frota INTEIRA dispara o mesmo "
                "CRIT (DECLARADO aceitável por GO)"]
        else:
            cond_01 = (all(st == 200 for st in sts01) and fleet_off
                       and len(alerts01) == 0 and len(shut01) == 12
                       and all(e.get("work_order") == "WO-20261112-MNT1"
                               for e in shut01)
                       and len(snaps01_hi) >= 1
                       and 99.0 <= div01 <= 100.0)
            word_01 = "CONFIRMADO"
            ev_01 = [
                "POST /mode com WO-20261112-MNT1 aos 12: %s — a WO "
                "VÁLIDA é aceita por TODOS (membership na lista plana; "
                "sem âmbito/janela/usos)"
                % ("200×12" if all(s == 200 for s in sts01) else sts01),
                "frota: %d/12 OFF; eventos shutdown: %d (TODOS com "
                "work_order MNT1)"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut01)),
                "alertas do cenário: %s — ZERO: a WO válida neutraliza "
                "a onda, não arma a capacity e não conta no WARN s/WO"
                % ([(a["rule"], a["count"]) for a in alerts01] or "ZERO"),
                "div direta %.2f por cento (esperado %.2f kW mantém-se; "
                "real %.2f = 0): snapshots com div ≥ 30: %d — TODOS "
                "sem alerta (C12: shutdown COM WO não arma)"
                % (div01, exp01, act01, len(snaps01_hi)),
                "CONSEQUÊNCIA: a WO legítima desliga a frota INTEIRA "
                "sem um alerta — o C15 existe; a frase do §7 item 8 é "
                "FALSA para WO válida (replay)"]
        expect("P-R8-01", GATEFALL[0]["prev"], cond_01,
               word_01, "PREVISÃO ERRADA (ver detalhe acima)", ev_01)

        # ============ P-R8-02 — C15: replay MNT2 NOITE+BLACKOUT ========
        print("\n[P-R8-02] C15 — replay de WO válida aos 12 "
              "(NOITE + BLACKOUT)")
        scen = "P-R8-02"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        # sequência do GO (errata de harness v0.1.1): shutdowns À NOITE
        # em NORMAL; o blackout chega DEPOIS (mede as casas às escuras)
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
        inv02_evs = [e for e in scenario_events(lab, scen)
                     if e.get("event") == "work_order_invalid"]
        blackout(lab)
        served02 = served_count(lab)
        on02 = sum(1 for d in lab.devices if d.inverter_on)
        if IS_V072:
            mass02 = [a for a in alerts02
                      if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
            inv02 = [a for a in alerts02
                     if a["rule"] == "D-INVALID-WORK-ORDER"]
            cond_02 = (sts02[:3] == [200] * 3
                       and sts02[3:] == [403] * 9
                       and on02 == 9 and len(shut02) == 3
                       and len(interlocks02) == 0
                       and len(inv02_evs) == 9
                       and all(e.get("reason") == "fora_do_ambito"
                               for e in inv02_evs)
                       and len(alerts02) == 1 and len(inv02) == 1
                       and inv02[0]["count"] == 9
                       and inv02[0]["severity"] == "WARN"
                       and not mass02 and served02 == 9)
            word_02 = "RESOLVIDO"
            ev_02 = [
                "MNT2 (âmbito {0,1,2}) à noite aos 12: devs 0,1,2 → "
                "200×3 EXECUTAM; devs 3..11 → 403 fora_do_ambito ×9 "
                "(work_order_invalid com reason, WARN count 9) — o "
                "replay à frota inteira com a WO ERRADA morre no "
                "ÂMBITO (frota 9/12 ON)",
                "D-MASS-SHUTDOWN-WITH-WO ausente (3 distintos < k E "
                "20,3/88,8 = 22,9 por cento < 30) — o F-C15b não dá "
                "FP por 3 dispositivos de âmbito correto",
                "no blackout DEPOIS: %d/12 casas com luz (os 3 "
                "desligados às escuras; os 9 defendidos pelo âmbito "
                "da WO)" % served02,
                "CONSEQUÊNCIA: na v0.7.1 esta WO desligava a frota "
                "inteira às escuras SEM um alerta; na v0.7.2 o ÂMBITO "
                "trava 9/12 e a tentativa é WARN-visível ×9"]
        else:
            cond_02 = (all(st == 200 for st in sts02) and fleet_off02
                       and len(alerts02) == 0 and len(shut02) == 12
                       and len(interlocks02) == 0 and served02 == 0)
            word_02 = "CONFIRMADO"
            ev_02 = [
                "idem com WO-20261112-MNT2 à NOITE em NORMAL: %s — o "
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
                "casas com luz no apagão: %d/12 (a frota desligada às "
                "escuras SEM um alerta)" % served02,
                "CONSEQUÊNCIA: a SEGUNDA WO da lista tem o MESMO poder "
                "— qualquer uma das 2 âncoras desliga a frota num "
                "apagão sem telemetria de alerta"]
        expect("P-R8-02", GATEFALL[1]["prev"], cond_02,
               word_02, "PREVISÃO ERRADA (ver detalhe acima)", ev_02)

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
        if IS_V072:
            expect("P-R8-03", GATEFALL[2]["prev"], cond_03,
                   "DECLARADO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["off/on/off/on/off no dev 0 com MNT1: %s — 3 usos "
                    "≤ 12 (âmbito correto); eventos shutdown: %d COM "
                    "WO válida"
                    % ("200×5" if seq03 == [200] * 5 else seq03,
                       len(shut03)),
                    "alertas: %s — ZERO (1 dispositivo distinto < k "
                    "E 10,5/88,8 = 11,8 por cento < 30: abaixo dos "
                    "DOIS gatilhos do F-C15b)"
                    % ([(a["rule"], a["count"]) for a in alerts03]
                       or "ZERO"),
                    "RESÍDUO MEDIDO E DECLARADO (mandato do GO): o "
                    "atacante que só desliga < k dispositivos com WO "
                    "válida e de âmbito correto ESCAPA ao CRIT de "
                    "massa — DECLARADO para a v0.8 (limiar mais "
                    "baixo = FPs de manutenção legítima de poucos "
                    "dispositivos)"])
        else:
            expect("P-R8-03", GATEFALL[2]["prev"], cond_03,
                   "CONFIRMADO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["off/on/off/on/off no dev 0 com WO-20261112-MNT1: "
                    "%s — a MESMA WO 3× no mesmo dispositivo"
                    % ("200×5" if seq03 == [200] * 5 else seq03),
                    "eventos shutdown: %d (TODOS com a MESMA WO); "
                    "alertas: %s — ZERO (sem contador de usos, sem "
                    "janela, sem âmbito por dispositivo)"
                    % (len(shut03),
                       [(a["rule"], a["count"]) for a in alerts03]
                       or "ZERO"),
                    "CONSEQUÊNCIA: a WO é infinitamente reutilizável "
                    "no mesmo alvo — replay e reuso são a MESMA "
                    "evasão não-testada que o design R2 previa"])

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
        dev_sts = sorted((resp_bulk.get("devices") or {}).values())
        auth04 = [a for a in alerts04 if a["rule"] == "D-AUTH-DEFAULT"]
        if IS_V072:
            mass04 = [a for a in alerts04
                      if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
            cond_04 = (st_login == 200 and st_bulk == 200
                       and dev_sts == [200] * 12 and fleet_off04
                       and len(shut04) == 12
                       and len(auth04) == 1
                       and len(alerts04) == 2 and len(mass04) == 1
                       and mass04[0]["severity"] == "CRIT"
                       and mass04[0]["count"] == 12)
            word_04 = "RESOLVIDO"
            ev_04 = [
                "/fleet/bulk_shutdown com MNT1: %s, 12×200, frota OFF "
                "— o canal bulk da cloud EXECUTA (âmbito frota "
                "inteira)" % st_bulk,
                "alertas: %s — WARN D-AUTH-DEFAULT ×1 (o login default, "
                "lição REGISTADA do run 1-bis) E CRIT "
                "D-MASS-SHUTDOWN-WITH-WO count %s — F-C15b cobre "
                "TAMBÉM a via bulk do gate"
                % ([(a["rule"], a["count"]) for a in alerts04],
                   mass04[0]["count"] if mass04 else 0),
                "CONSEQUÊNCIA: na v0.7.1 este canal desligava a frota "
                "com a WO legítima sem UM alerta de shutdown; na "
                "v0.7.2 a operação à escala da frota é CRIT-visível "
                "mesmo vinda do canal que exige a WO"]
        else:
            cond_04 = (st_login == 200 and st_bulk == 200
                       and dev_sts == [200] * 12 and fleet_off04
                       and len(alerts04) == 0 and len(shut04) == 12)
            word_04 = "CONFIRMADO"
            ev_04 = [
                "/fleet/bulk_shutdown com work_order_id "
                "WO-20261112-MNT1: %s — o gate EXIGE WO válida e "
                "despacha aos 12 (statuses %s)"
                % (st_bulk, dev_sts),
                "frota: %d/12 OFF; eventos shutdown: %d COM WO; "
                "alertas: %s — ZERO"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut04),
                   [(a["rule"], a["count"]) for a in alerts04] or "ZERO"),
                "CONSEQUÊNCIA: a EXIGÊNCIA de WO do bulk é a PRÓPRIA "
                "evasão — o canal da cloud desliga a frota com a WO "
                "legítima e nenhuma regra vê (o atacante É a cloud)"]
        expect("P-R8-04", GATEFALL[3]["prev"], cond_04,
               word_04, "PREVISÃO ERRADA (ver detalhe acima)", ev_04)

        # ============ P-R8-05 — C15: prova estática ====================
        if IS_V072:
            print("\n[P-R8-05] C15 — prova estática: a WO com âmbito")
        else:
            print("\n[P-R8-05] C15 — prova estática: a WO não está "
                  "ligada a nada")
        src = LAB_BYTES.decode("utf-8")
        wo_zone = src[src.index("WORK_ORDERS = {"):src.index("LEGIT_IMAGE")]
        met_zone = src[src.index("def remote_inverter_power_off"):
                       src.index("def remote_inverter_resume")]
        set_zone = src[src.index("def remote_setpoint"):
                       src.index("def remote_battery")]
        gate_zone = src[src.index("def check_work_order"):
                        src.index("def bulk_shutdown")]
        if IS_V072:
            scoped = ("devices" in wo_zone and "window_s" in wo_zone
                      and "max_uses" in wo_zone
                      and "work_order_check" in wo_zone
                      and "WORK_ORDER_USES" in wo_zone
                      and "WORK_ORDER_EPOCH" in wo_zone)
            dev_uses_check = ("work_order_check(WORK_ORDERS" in met_zone
                              and "work_order_check(WORK_ORDERS"
                              in set_zone)
            gate_uses_check = ("work_order_check(WORK_ORDERS" in gate_zone)
            cond_05 = scoped and dev_uses_check and gate_uses_check
            expect("P-R8-05", GATEFALL[4]["prev"], cond_05,
                   "RESOLVIDO",
                   "PREVISÃO ERRADA (ver detalhe acima)",
                   ["zona WORK_ORDERS: devices/window_s/max_uses "
                    "presentes (%s); validação ÚNICA work_order_check "
                    "na MESMA zona (%s); contador WORK_ORDER_USES e "
                    "época WORK_ORDER_EPOCH (%s)"
                    % ("devices" in wo_zone and "window_s" in wo_zone
                       and "max_uses" in wo_zone,
                       "work_order_check" in wo_zone,
                       "WORK_ORDER_USES" in wo_zone
                       and "WORK_ORDER_EPOCH" in wo_zone),
                    "DISPOSITIVO: work_order_check(WORK_ORDERS, …) em "
                    "remote_inverter_power_off (%s) E em "
                    "remote_setpoint (%s) — a fonte é passada "
                    "LITERALMENTE (uma fonte só)"
                    % ("work_order_check(WORK_ORDERS" in met_zone,
                       "work_order_check(WORK_ORDERS" in set_zone),
                    "GATE: work_order_check(WORK_ORDERS, …) em "
                    "check_work_order (%s) — device e gate validam o "
                    "MESMO âmbito pela MESMA função"
                    % ("work_order_check(WORK_ORDERS" in gate_zone),
                    "CONSEQUÊNCIA: a WO deixou de ser uma string solta "
                    "— está ligada a dispositivos, tempo e usos"])
        else:
            flat_anchor = ("devices" not in wo_zone
                           and "window" not in wo_zone
                           and "max_uses" not in wo_zone
                           and "uses" not in wo_zone
                           and wo_zone.count("WO-20261112") == 2)
            dev_membership_only = ("not in WORK_ORDERS" in met_zone
                                   and "sim_ts" not in met_zone)
            gate_membership_only = ("return wo in WORK_ORDERS"
                                    in gate_zone
                                    and "sim_ts" not in gate_zone)
            cond_05 = (flat_anchor and dev_membership_only
                       and gate_membership_only)
            expect("P-R8-05", GATEFALL[4]["prev"], cond_05,
                   "CONFIRMADO",
                   "PREVISÃO ERRADA (ver detalhe acima)",
                   ["zona WORK_ORDERS: %d entradas, SEM chaves de "
                    "âmbito (devices), janela (window) ou usos "
                    "(max_uses/uses) — âncora PLANA: %s"
                    % (wo_zone.count("WO-20261112"), flat_anchor),
                    "zona Device.remote_inverter_power_off: valida "
                    "APENAS membership (%s) sem relógio (sim_ts "
                    "ausente: %s)"
                    % ("not in WORK_ORDERS" in met_zone,
                       "sim_ts" not in met_zone),
                    "zona FleetGate.check_work_order: %s — a MESMA "
                    "validação de pertença, nada mais"
                    % ("return wo in WORK_ORDERS" in gate_zone),
                    "CONSEQUÊNCIA: a WO é uma STRING SOLTA — não está "
                    "ligada a dispositivo, tempo ou uso; qualquer "
                    "replay da string é indistinguível do uso "
                    "legítimo"])

        # ============ P-R8-06 — C15: MNT2 ×6 dispositivos ===============
        print("\n[P-R8-06] C15 — a segunda entrada (6 shutdowns COM MNT2)")
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
        if IS_V072:
            inv06 = [a for a in alerts06
                     if a["rule"] == "D-INVALID-WORK-ORDER"]
            mass06 = [a for a in alerts06
                      if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
            cond_06 = (sts06[:3] == [200] * 3
                       and sts06[3:] == [403] * 3 and off06 == 3
                       and len(alerts06) == 1 and len(inv06) == 1
                       and inv06[0]["count"] == 3 and not mass06
                       and len(shut06) == 3)
            word_06 = "RESOLVIDO"
            ev_06 = [
                "6 shutdowns COM MNT2 (âmbito {0,1,2}): devs 0,1,2 → "
                "200×3; devs 3,4,5 → 403 fora_do_ambito ×3 + WARN "
                "count 3; frota 9/12 ON (eventos shutdown: %d)"
                % len(shut06),
                "D-MASS ausente (3 distintos < k E 22,9 por cento < "
                "30): a regra nova não dá FP por âmbito correto",
                "CONSEQUÊNCIA: a segunda entrada deixa de ser âncora "
                "vazia — vale EXATAMENTE o seu âmbito {0,1,2}"]
        else:
            cond_06 = (all(st == 200 for st in sts06) and off06 == 6
                       and len(alerts06) == 0 and len(shut06) == 6)
            word_06 = "CONFIRMADO"
            ev_06 = [
                "6 shutdowns COM WO-20261112-MNT2: %s; %d/12 OFF; "
                "alertas: %s — ZERO (a MESMA cegueira com a OUTRA WO "
                "da lista: 6 shutdowns COM WO não acendem wave/slow/"
                "capacity)"
                % ("200×6" if all(s == 200 for s in sts06) else sts06,
                   off06,
                   [(a["rule"], a["count"]) for a in alerts06] or "ZERO"),
                "CONSEQUÊNCIA: não é um defeito de UMA entrada — a "
                "SEMÂNTICA de work-order da v0.7.1 (membership numa "
                "lista plana) é a âncora vazia"]
        expect("P-R8-06", GATEFALL[5]["prev"], cond_06,
               word_06, "PREVISÃO ERRADA (ver detalhe acima)", ev_06)

        # ============ P-R8-07 — C15: janela de validade ==================
        print("\n[P-R8-07] C15 — janela de validade (relógio +40 dias)")
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
        inv07_evs = [e for e in scenario_events(lab, scen)
                     if e.get("event") == "work_order_invalid"]
        if IS_V072:
            cond_07 = (st07 == 403
                       and resp07.get("reason") == "fora_da_janela"
                       and len(inv07_evs) == 1
                       and inv07_evs[0].get("reason") == "fora_da_janela"
                       and len(alerts07) == 1 and len(shut07) == 0
                       and lab.devices[3].inverter_on)
            word_07 = "RESOLVIDO"
            ev_07 = [
                "relógio +40 dias (fora da janela de 30 dias da MNT1): "
                "shutdown COM MNT1 no dev 3 → %s reason=%s — a WO "
                "EXPIRA; dev 3 fica ON (nenhum shutdown executado)"
                % (st07, resp07.get("reason")),
                "WARN D-INVALID-WORK-ORDER count 1 (reason "
                "fora_da_janela no evento) — a tentativa é visível",
                "CONSEQUÊNCIA: a WO deixa de ser credencial perpétua "
                "— o replay tem PRAZO"]
        else:
            cond_07 = (st07 == 200 and len(alerts07) == 0
                       and len(shut07) == 1
                       and not lab.devices[3].inverter_on)
            word_07 = "CONFIRMADO"
            ev_07 = [
                "relógio de simulação +40 dias: shutdown COM "
                "WO-20261112-MNT1 no dev 3 → %s e EXECUTA (dev 3 OFF: "
                "%s) — a WO datada de 12-11 NÃO EXPIRA"
                % (st07, not lab.devices[3].inverter_on),
                "alertas: %s — ZERO"
                % ([(a["rule"], a["count"]) for a in alerts07] or "ZERO"),
                "CONSEQUÊNCIA: sem janela de validade, a WO é uma "
                "credencial PERPÉTUA — o replay não tem prazo"]
        expect("P-R8-07", GATEFALL[6]["prev"], cond_07,
               word_07, "PREVISÃO ERRADA (ver detalhe acima)", ev_07)

        # ============ P-R8-08 — C15: usos ================================
        print("\n[P-R8-08] C15 — usos (a mesma WO 4×)")
        scen = "P-R8-08"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts08 = []
        for _ in range(4):
            st, resp = remote_shutdown(lab, 0, "WO-20261112-MNT2")
            sts08.append((st, resp))
        time.sleep(0.6)
        alerts08 = scan_scenario(lab, scen)
        shut08 = [e for e in scenario_events(lab, scen)
                  if e.get("event") == "shutdown"]
        if IS_V072:
            inv08 = [a for a in alerts08
                     if a["rule"] == "D-INVALID-WORK-ORDER"]
            cond_08 = ([s for s, _ in sts08[:3]] == [200] * 3
                       and sts08[3][0] == 403
                       and sts08[3][1].get("reason") == "usos_esgotados"
                       and len(shut08) == 3 and len(alerts08) == 1
                       and len(inv08) == 1 and inv08[0]["count"] == 1)
            word_08 = "RESOLVIDO"
            ev_08 = [
                "MNT2 (max_uses 3) 4× no dev 0: 200×3 e o 4.º → 403 "
                "usos_esgotados + WARN count 1; shutdowns executados: "
                "%d" % len(shut08),
                "CONSEQUÊNCIA: o uso da WO é FINITO e contado — o "
                "reuso ilimitado morre"]
        else:
            cond_08 = (all(st == 200 for st, _ in sts08)
                       and len(alerts08) == 0 and len(shut08) == 4)
            word_08 = "CONFIRMADO"
            ev_08 = [
                "a MESMA WO-20261112-MNT2 4× no dev 0: %s; eventos "
                "shutdown: %d; alertas: %s — ZERO (sem contador de "
                "usos a WO é infinitamente reutilizável)"
                % ("200×4" if all(s == 200 for s, _ in sts08) else
                   [s for s, _ in sts08], len(shut08),
                   [(a["rule"], a["count"]) for a in alerts08] or "ZERO"),
                "CONSEQUÊNCIA: o reuso ILIMITADO confirma por medição "
                "o que o GO mediu com 3 usos — não há rate-limiting "
                "semântico na WO"]
        expect("P-R8-08", GATEFALL[7]["prev"], cond_08,
               word_08, "PREVISÃO ERRADA (ver detalhe acima)", ev_08)

        # ============ P-R8-09 — C15: baseline pequena manutenção ========
        print("\n[P-R8-09] C15 — baseline: pequena manutenção COM WO "
              "(2 dispositivos)")
        scen = "P-R8-09"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        # V072: MNT3 (âmbito {0,2} — o caso legítimo com WO de âmbito
        # CORRETO, mandato de FP do GO); V071: MNT1 (âncora plana)
        wo09 = "WO-20261113-MNT3" if IS_V072 else "WO-20261112-MNT1"
        sts09 = []
        for i in (0, 2):
            st, resp = remote_shutdown(lab, i, wo09)
            sts09.append(st)
        time.sleep(0.6)
        alerts09 = scan_scenario(lab, scen)
        off09 = sum(1 for d in lab.devices if not d.inverter_on)
        cond_09 = (all(st == 200 for st in sts09) and off09 == 2
                   and len(alerts09) == 0)
        if IS_V072:
            expect("P-R8-09", GATEFALL[8]["prev"], cond_09,
                   "RESOLVIDO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["2 shutdowns COM %s (âmbito {0,2}): %s; alertas: "
                    "%s — ZERO (2 distintos < k E 20,3/88,8 = 22,9 "
                    "por cento < 30)"
                    % (wo09,
                       "200×2" if all(s == 200 for s in sts09)
                       else sts09,
                       [(a["rule"], a["count"]) for a in alerts09]
                       or "ZERO"),
                    "FP MORTO por medição: a manutenção pontual "
                    "legítima com WO de âmbito correto NÃO dispara "
                    "o F-C15b — o caso legítimo e o abuso deixam de "
                    "ser indistinguíveis (o abuso à escala da frota "
                    "dispara CRIT; o legítimo pontual não)"])
        else:
            expect("P-R8-09", GATEFALL[8]["prev"], cond_09,
                   "CONFIRMADO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["2 shutdowns COM WO-20261112-MNT1 (devs 0 e 2): "
                    "%s; alertas: %s — ZERO"
                    % ("200×2" if all(s == 200 for s in sts09)
                       else sts09,
                       [(a["rule"], a["count"]) for a in alerts09]
                       or "ZERO"),
                    "CONSEQUÊNCIA: o caso LEGÍTIMO (manutenção "
                    "pontual) e o ABUSO (P-R8-01) produzem a MESMA "
                    "telemetria na v0.7.1 — nenhum alerta em ambos; "
                    "a discriminação por WO sozinha é impossível "
                    "por construção"])

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
        cond_10 = (all(st == 200 for st in sts10) and off10 == 5
                   and len(alerts10) == 0 and pct_small5 < 30.0)
        if IS_V072:
            expect("P-R8-10", GATEFALL[9]["prev"], cond_10,
                   "DECLARADO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["5 MENORES por kWp %s (=%.2f kWp = %.2f por cento "
                    "< 30): shutdowns COM MNT1 → %s; alertas: %s — "
                    "ZERO CRIT (5 < k E < 30 por cento)"
                    % (small5, kwp_small5, pct_small5,
                       "200×5" if all(s == 200 for s in sts10)
                       else sts10,
                       [(a["rule"], a["count"]) for a in alerts10]
                       or "ZERO"),
                    "RESÍDUO MEDIDO E DECLARADO (mandato do GO): o "
                    "atacante que escolhe os dispositivos PEQUENOS "
                    "(< k E < 30 por cento de capacidade) com WO "
                    "válida escapa ao CRIT de massa — DECLARADO "
                    "para a v0.8"])
        else:
            expect("P-R8-10", GATEFALL[9]["prev"], cond_10,
                   "CONFIRMADO", "PREVISÃO ERRADA (ver detalhe acima)",
                   ["5 MENORES por kWp %s (=%.2f kWp = %.2f por cento "
                    "< 30): shutdowns COM WO-20261112-MNT1 → %s; "
                    "alertas: %s — ZERO"
                    % (small5, kwp_small5, pct_small5,
                       "200×5" if all(s == 200 for s in sts10)
                       else sts10,
                       [(a["rule"], a["count"]) for a in alerts10]
                       or "ZERO"),
                    "CONSEQUÊNCIA: subset pequeno COM WO é invisível "
                    "na v0.7.1 — é o RESÍDUO que o F-C15b vai MEDIR "
                    "e DECLARAR na v0.7.2 (< k dispositivos e < 30 "
                    "por cento de capacidade com WO válida de âmbito "
                    "correto)"])

        # ============ P-R8-11 — C15: top-5 COM WO (58,22 por cento) =====
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
        if IS_V072:
            mass11 = [a for a in alerts11
                      if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
            cond_11 = (all(st == 200 for st in sts11) and off11 == 5
                       and len(alerts11) == 1 and len(mass11) == 1
                       and mass11[0]["severity"] == "CRIT"
                       and mass11[0]["count"] == 5
                       and mass11[0].get("distinct_devices") == 5
                       and abs(mass11[0].get("capacity_loss_pct", 0.0)
                               - 58.22) < 0.05 and pct_top5 >= 30.0)
            word_11 = "RESOLVIDO"
            ev_11 = [
                "top-5 por kWp %s (=%.2f kWp = %.2f por cento ≥ 30): "
                "shutdowns COM MNT1 → %s MAS CRIT "
                "D-MASS-SHUTDOWN-WITH-WO count %s (distintos %s, "
                "capacidade perdida %s por cento) — o GATILHO DE "
                "CAPACIDADE apanha 5 dispositivos < k"
                % (top5, kwp_top5, pct_top5,
                   "200×5" if all(s == 200 for s in sts11) else sts11,
                   mass11[0]["count"] if mass11 else 0,
                   mass11[0].get("distinct_devices") if mass11 else 0,
                   mass11[0].get("capacity_loss_pct") if mass11 else 0),
                "CONSEQUÊNCIA: 58 por cento da capacidade da frota "
                "no chão com WO válida era INVISÍVEL na v0.7.1; na "
                "v0.7.2 a perda de capacidade ≥ 30 por cento é CRIT "
                "mesmo com WO — o que está em jogo é a CAPACIDADE, "
                "não a contagem"]
        else:
            cond_11 = (all(st == 200 for st in sts11) and off11 == 5
                       and len(alerts11) == 0 and pct_top5 >= 30.0)
            word_11 = "CONFIRMADO"
            ev_11 = [
                "top-5 por kWp %s (=%.2f kWp = %.2f por cento ≥ 30): "
                "shutdowns COM WO-20261112-MNT1 → %s; alertas: %s — "
                "ZERO (58 por cento da capacidade no chão SEM um "
                "alerta)"
                % (top5, kwp_top5, pct_top5,
                   "200×5" if all(s == 200 for s in sts11) else sts11,
                   [(a["rule"], a["count"]) for a in alerts11]
                   or "ZERO"),
                "CONSEQUÊNCIA: o gatilho de CAPACIDADE do F-C15b "
                "(perda ≥ 30 por cento MESMO com WO válida) é o que "
                "fecha este caso na v0.7.2 — 5 dispositivos < k=6 "
                "mas 58,22 por cento da frota"]
        expect("P-R8-11", GATEFALL[10]["prev"], cond_11,
               word_11, "PREVISÃO ERRADA (ver detalhe acima)", ev_11)

    finally:
        lab.stop()

    # ---------------- sumário ----------------
    match_words = ("CONFIRMADO", "RESOLVIDO", "DECLARADO")
    match_n = sum(1 for v in VEREDICTOS if v["veredicto"] in match_words)
    print("\nSUMÁRIO — GATEFALL R8 vs alvo %s (run %s)" % (TARGET, RUN_ID))
    for v in VEREDICTOS:
        print("  [%s] %s" % (v["id"], v["veredicto"]))
    print("RESULTADO: %d/%d previsões confirmadas (lab v%s)"
          % (match_n, len(GATEFALL), L.LAB_VERSION))
    if match_n == len(GATEFALL):
        if IS_V072:
            print("RC=0 — RUN 2 vs v0.7.2 (1c433df1…): F-C15a/F-C15b "
                  "RESOLVIDOS (com os resíduos P-R8-03/P-R8-10 medidos "
                  "e DECLARADOS por mandato do GO).")
        else:
            print("RC=0 — re-run vs v0.7.1 INTOCADA: GATEFALL "
                  "reproduzido (o GATEFALL OFICIAL é o RUN 1).")
        return 0
    print("RC=1 — há previsões erradas REGISTADAS (método: nunca se "
          "ajusta o probe para bater).")
    return 1


if __name__ == "__main__":
    sys.exit(main())

# EOF:sunstrike_probes_r8.py
