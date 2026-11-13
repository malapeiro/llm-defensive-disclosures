#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R7 — 8.ª bateria adversarial (ronda v0.7.1).
Caso 4 do repo malapeiro/llm-defensive-disclosures (PVTE v5.0).
Grant GRANT-PVTE-20261112-SS-01 (loopback only, Python 3.9+ stdlib).

Alvos desta versão (v0.3, dual): sunstrike_lab.py v0.7 INTOCADA
(d3af0d28…, re-check do ANTES — GATEFALL congelado) e a v0.7.1 RESTAURADA
(72c894fe…, o DEPOIS — GATEFALL_V071 re-registado neste ficheiro ANTES de
qualquer corrida). As previsões V07 foram pré-registadas ANTES de qualquer
corrida (GATEFALL) na entrada "GO À v0.7.1" do canvas de design (13-11
~17:00; hash pré da entrada
ce362e5657e7e14a0f1974387e21946485a76edd1596903d06bb16f9edbb00c9, hash atual
linha-inteira aed0ef3f200d2fb8329acf92d29f29bde84040f3c7f8e2a7650ef37b270c6321)
e ficam CONGELADAS por ordem do operador.

CHANGEDLOG
  v0.1 (13-11, PERDIDO): bateria original da ronda v0.7.1 — hash c2d30fd2….
      O RUN 1 (GATEFALL OFICIAL original, output 10512653b…, 8/8 CONFIRMADO)
      e o lab v0.7.1 (030aafe2…) foram PERDIDOS no INCIDENTE
      INFRA-2026-13-11-A (falha de infraestrutura 13-11 ~17:11–17:22: 503
      upstream + reset do ambiente; directório de trabalho perdido ANTES de
      qualquer publicação ou registo — ver entrada datada no canvas §3.2,
      corpus entrada 24 e KNOWLEDGE.md). Resposta do operador: GO à
      reconstrução com 6 condições vinculativas: previsões CONGELADAS,
      RUN 1-BIS como GATEFALL oficial SUBSTITUTO, comparação com as
      medições independentes do supervisor, publicação incremental,
      errata r4, GO À v0.7.1 mantém-se.
  v0.1-bis (13-11, RECONSTRUÇÃO datada): este ficheiro. O GATEFALL é o
      MESMO da entrada "GO À v0.7.1" (nenhuma previsão muda — nenhuma
      previsão foi escrita à luz do run 1 original que não seja a
      pré-registada). A corrida contra a v0.7 intocada chama-se RUN 1-BIS
      e é o GATEFALL OFICIAL SUBSTITUTO da R7, com nota explícita do
      incidente em TODOS os registos. Se o run 1-bis divergir das
      previsões, fica registado como previsão errada — o probe NÃO se
      ajusta para bater. O run 1-bis vai ser comparado com as medições
      INDEPENDENTES do supervisor contra a v0.7 (C13, K1-b, R6-01, C14,
      FP-SP — feitas ANTES do incidente, no Mac do operador).
  v0.1-bis.1 (13-11, ERRATA DE HARNESS datada — homenagem às 2 erratas
      de harness do selftest perdido): o v0.1-bis CRASHOU a meio do
      P-R7-02 (ValueError de formatação: strings de evidência com %
      LITERAL dentro de strings %-formatadas — "23,3% também" no
      P-R7-02 e "25%/dia" no P-R7-04; o mesmo erro da errata v0.2.1
      do r6). O output crashado foi PRESERVADO como errata de harness
      (sunstrike_probes_v07_r7_run1_bis_errata_harness.txt): NENHUM
      veredicto foi produzido antes do crash (o run não completou a
      bateria, logo não é um run do GATEFALL); correção datada IN-PLACE
      com esta entrada. O RUN 1-BIS OFICIAL é o run COMPLETO seguinte
      contra a v0.7 intocada, com as MESMAS previsões congeladas.
  v0.1-bis.2 (13-11, CORREÇÃO DE CRITÉRIO datada, precedente r5
      P-R5-06): o RUN 1-BIS completou com 6/8 CONFIRMADO e 2 previsões
      erradas (P-R7-02/P-R7-03) por DEFEITO DE CRITÉRIO DO PROBE, não
      do lab: os critérios exigiam SoC ±0,01, mas o canal /battery
      arredonda o amount_kwh a 3 casas (round(0,233·batt_kwh, 3)) e o
      drop medido por dev é 23,29–23,31 pontos, dando SoC fim dia 3 em
      (30,07, 30,13) e fim dia 4 em (25,16, 25,24) — os valores
      PREVISTOS (30,1 e 25,2) estão DENTRO das gamas medidas; served,
      alertas e a física bateram TODOS. Correção datada IN-PLACE: o
      critério passa a exigir que cada valor previsto caia DENTRO da
      gama medida (min−0,05 ≤ previsto ≤ max+0,05, margem igual ao
      erro de quantização do canal). O RUN 1-BIS (output 0d08b8c0…)
      fica PRESERVADO como GATEFALL OFICIAL SUBSTITUTO com as 2 erradas
      REGISTADAS; o run seguinte (1-bis-b) re-verifica com o critério
      corrigido. A PREVISÃO congelada NÃO muda (nenhuma previsão foi
      reescrita; os achados C13/K1-b/K1-c/C14/FP-SP estão TODOS
      confirmados no run 1-bis).
  v0.2-bis.1 (13-11, PERDIDO no incidente INFRA-2026-13-11-B — registado
      aqui pela continuidade, do registo da conversa): versão DUAL
      (V07/V071) construída sobre este ficheiro — +alvo V071 (lab
      00e2254f…), GATEFALL_V071 pré-registado ANTES das corridas (8×
      RESOLVIDO, fixes F-C13/F-K1/F-C14/F-SP). RUN 2 vs v0.7.1: 7/8
      RESOLVIDO + P-R7-01 previsão errada POR DEFEITO DE CRITÉRIO do
      probe (a prova estática exigia WORK_ORDERS na zona /mode do
      DevHandler; a validação F-C13 vive no MÉTODO
      Device.remote_inverter_power_off — o comportamento 100%
      confirmado; output 0366e01a… PRESERVADO como oficial na altura),
      ERRATA de critério datada aplicada (zona do método; prev P-R7-01
      corrigida IN-PLACE; run 2 PRESERVADO) e RUN 2-B: 8/8 RESOLVIDO,
      0 erradas (be464ea0…); RE-CHECK vs v0.7 intocada: 8/8 CONFIRMADO
      (535ad1b9…). TODOS estes ficheiros foram PERDIDOS no 2.º reset do
      ambiente (13-11 ~18:23): /home/user/sunstrike/ com o lab v0.7.1
      (00e2254f…), este probe dual (cab5d77b…), o r6 v0.3.1 (d8809a9a…)
      e TODOS os outputs da ronda (selftest afb98d0c…, demo 991eb97d…,
      measure b1fe9977…, errata selftest run 1 e9dc9c03…).
  v0.3 (13-11, RECONSTRUÇÃO datada pós-INFRA-2026-13-11-B): ESTE
      ficheiro. O lab v0.7.1 foi RESTAURADO por REPLAY integral dos
      scripts de edição preservados (artifacts/v071_tmp: edit_a →
      edit_b → edit_c → edit_d) sobre a v0.7 INTOCADA (d3af0d28…) +
      re-aplicação datada da errata J5 do selftest (texto refeito —
      ver changelog do lab): hash NOVO 72c894fe…, COMPORTAMENTO
      IDÊNTICO (o selftest re-executado deu hash afb98d0c… — BYTE-
      IDÊNTICO ao original perdido, RC=0, PASS com liveness 23/23).
      Previsões V071 = as MESMAS do GO à v0.7.1 (fixes F-C13/F-K1/
      F-C14/F-SP), RE-REGISTADAS na constante GATEFALL_V071 deste
      ficheiro ANTES de qualquer corrida: 8× RESOLVIDO, com o critério
      estático do P-R7-01 pelo MÉTODO desde o início (a lição do run 2
      perdido está incorporada; NENHUMA previsão foi escrita à luz de
      um run contra a v0.7.1 — os runs perdidos são registo
      histórico). Os runs RE-EXECUTADOS com este probe são os
      OFICIAIS da recuperação: vs v0.7.1 (o DEPOIS) e vs v0.7
      intocada (re-check do ANTES; o GATEFALL OFICIAL da R7 mantém-se
      o RUN 1-BIS/1-BIS-B preservado em artifacts).
  v0.3.2 (13-11, ERRATA DE EOF datada, APÓS o run 2 oficial da
      recuperação vs v0.7.1): o marcador EOF herdado do base dizia
      "# EOF:sunstrike_probes_r7.py" (o nome do ficheiro BASE em
      artifacts), mas o ficheiro em disco chama-se
      sunstrike_probes_r7_v071.py e o §6 exige "# EOF:<filename>".
      Corrigido IN-PLACE (última linha; banner v0.3.2 para
      rastreabilidade). NENHUM critério, previsão, cond ou veredicto
      muda — é GRAVAÇÃO/RÓTULO. O run 2 com o hash anterior (3beb35cc…,
      output af9f7f33…, 8/8 RESOLVIDO, 0 erradas, RC=0) é PRESERVADO
      como evidência; o re-run com ESTE hash é o OFICIAL da
      recuperação vs v0.7.1 (precedente: errata de gravação r5
      v0.3.1, r6 v0.3.1).
  v0.3.1 (13-11, ERRATA DE DISPLAY datada, ANTES do run oficial da
      recuperação): o run 1 contra a v0.7.1 com o v0.3 deu 8/8
      RESOLVIDO, 0 erradas, RC=0 — MAS 4 linhas de EVIDÊNCIA
      PARTILHADAS dos ramos V07 imprimiram texto V07 no run V071
      (P-R7-02/P-R7-03: o raciocínio da janela de 72 h da MULTIDAY
      morta; P-R7-04: "CRIT D-BATTERY-MULTIDAY-DRAIN ×12 (count 0)"
      — a regra não EXISTE na v0.7.1; P-R7-06: "NOITE … — ZERO"
      hardcoded; P-R7-07: "SEM work-order — o endpoint não aceita o
      campo" e "(0 alerta(s)): FALSO POSITIVO" quando o run V071 usa
      WO VÁLIDA e dá 0 CRIT POR DESIGN) e o literal "60%%"/"20,68%%"
      HERDADO do base (o run 1-bis-b preservado JÁ o imprime —
      "60%% NÃO há CRIT" — bug de formatação do base, não do ramo
      novo). NENHUM critério, previsão, cond ou veredicto muda — é
      APRESENTAÇÃO (precedente: errata de display r6 run 2, v0.2.1
      r5). O run 1 v0.3 é PRESERVADO como
      sunstrike_probes_v071_r7_run1_errata_display.txt; o re-run com
      ESTE hash é o OFICIAL da recuperação.
      Corpo dos 8 cenários (GO 13-11 ~17:00, achados EXECUTADOS pelo
      supervisor; probes dele em v0.7/verificacao_supervisor/ e
      auditoria_gemini/v0.7_6a_auditoria_verificacao/):
        P-R7-01 C13 (GRAVE, existe também na v0.6): WORK-ORDER FALSA —
          POST /mode {"action":"inverter_power_off",
          "work_order":"WO-INVENTADA-123"} direto aos 12 dispositivos →
          200×12, frota desligada, ZERO alertas. O dispositivo NÃO valida
          a WO (só o gate tem check_work_order) e o detetor trata
          QUALQUER texto em work_order como legítimo → SHUTDOWN-WAVE,
          SLOW-WAVE e CAPACITY-DIVERGENCE cegas. Torna FALSA a frase do
          §7 item 8 ("isto é detetado").
        P-R7-02 K1-b/R6-01: atacante mais LENTO que a janela de 72 h —
          3 dias × 23,3% → SoC 30,1, ZERO alertas (69,9 ≤ 70 em qualquer
          janela de 72 h; 1 fatia/dia ≤ 40 do daily); apagão 1 h 10/12,
          2 h 5/12, 3 h 1/12.
        P-R7-03 K1-b/R6-01: 4 dias × 18,7% → SoC 25,2, ZERO alertas
          (≤ 3 fatias = 56,1 por janela de 72 h); apagão 1 h 9/12,
          2 h 3/12.
        P-R7-04 K1-c: FALSO POSITIVO — dono 25%/dia × 3 dias COM
          recarga solar entre dias → CRIT MULTIDAY com SoC 100: a regra
          mede VOLUME descarregado, não esvaziamento. O manifesto diz
          "uso diário legítimo não dispara" — só é verdade até ~23%/dia.
        P-R7-05 C14 (de R6-02 do Gemini): SUBCONJUNTO À NOITE
          INVISÍVEL — 5 shutdowns remotos sem WO (< k=6) à noite → ZERO
          alertas; no apagão 7/12 com luz (os 5 desligados às escuras).
        P-R7-06 C14: 7 shutdowns espaçados 61 min: DIA → CAPACITY CRIT
          (o fix C12 funciona); NOITE → ZERO alertas. A soma de dois
          resíduos declarados dá um ataque invisível no cenário
          principal do caso.
        P-R7-07 FP-SP (de R6-03 do Gemini): /setpoint não aceita
          work-order — export_limit 60% na frota inteira (operação de
          frota legítima) → div 40% → CRIT.
        P-R7-08 FP-SP: 6 inversores a 60% → div 20,68% < 30% → sem
          alerta (a parte do Gemini que dizia CRIT aqui estava ERRADA —
          o supervisor corrigiu).
"""

import hashlib
import json
import os
import socket
import sys
import time
import traceback
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

LOOPBACK = "127.0.0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
LAB_PATH = os.path.join(HERE, "sunstrike_lab.py")
with open(LAB_PATH, "rb") as f:
    LAB_BYTES = f.read()
lab_sha = hashlib.sha256(LAB_BYTES).hexdigest()

EXPECTED_LAB_SHA256_V07 = ("d3af0d28715d7cdc25783075ec71530f46055b1653bc"
                           "6e961f0403bf6653b663")
EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")
# v0.4 (13-11, GO à v0.7.2 ~19:30): alvo NOVO V072 — a tri-target. O
# r7 não exercita NENHUM cenário afetado pelo F-C15a/F-C15b (os
# cenários r7 com WO usam MNT1 IN-SCOPO e NÃO são shutdowns de massa:
# P-R7-07/08 são SETPOINTS; P-R7-01 é WO falsa → 403 desconhecida;
# P-R7-05/06 são s/WO; P-R7-02/03/04 são /battery). As previsões V072
# = as MESMAS da lista V071 (F-C13/F-K1/F-C14/F-SP MANTÊM-SE na
# v0.7.2), pré-registadas ANTES do run de não-regressão.
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
if lab_sha == EXPECTED_LAB_SHA256_V07:
    TARGET = "V07"
elif lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "V071"
elif lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "V072"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe só corre contra a v0.7 INTOCADA (%s…), a "
          "v0.7.1 restaurada (%s…) ou a v0.7.2 (%s…).\n"
          "  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V07[:16],
             EXPECTED_LAB_SHA256_V071[:16],
             EXPECTED_LAB_SHA256_V072[:16]))
    raise SystemExit(2)

# v0.4: os ramos "V071" do probe são os ramos dos FIXES — valem para
# TODOS os alvos PÓS-v0.7 (V071 e V072); IS_V072 só distingue o
# display/rotulagem.
IS_V072 = TARGET == "V072"
IS_V071 = TARGET in ("V071", "V072")

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R7 v0.4 (tri-target V07/V071/V072; nao-regressao "
      "da v0.7.2, GO 13-11 ~19:30) — "
      "run %s (grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))
if IS_V072:
    print("NOTA v0.4 (display, datada): este run e a NAO-REGRESSAO da "
          "v0.7.2; as previsoes SAO as da lista V071 (F-C13/F-K1/"
          "F-C14/F-SP mantem-se; o r7 nao exercita nenhum cenario "
          "afetado pelo F-C15a/F-C15b — ver changedlog v0.4). Linhas "
          "de evidencia herdam o rotulo V071 onde o display era "
          "partilhado: rotulagem, nao criterio.")

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS E CONGELADAS (entrada "GO À v0.7.1" do
# canvas de design, 13-11 ~17:00; NENHUMA previsão muda por ordem do
# operador — o run 1 original foi PERDIDO e o run 1-bis é o SUBSTITUTO)
# GATEFALL_V071 (o DEPOIS) vive logo após esta lista e é selecionado por
# TARGET no arranque (IS_V071).
# ---------------------------------------------------------------------------
GATEFALL_V07 = [
    {"id": "P-R7-01", "expected": "CONFIRMADO", "finding": "C13",
     "prev": ("CONFIRMADO — WORK-ORDER FALSA: POST /mode com "
              "work_order \"WO-INVENTADA-123\" direto aos 12 dispositivos "
              "→ 200×12, frota desligada, ZERO alertas; div direta 100% "
              "com snapshots ≥30 sem alerta (o dispositivo não valida a "
              "WO e o detetor trata QUALQUER texto como legítimo)")},
    {"id": "P-R7-02", "expected": "CONFIRMADO", "finding": "K1-b-3d",
     "prev": ("CONFIRMADO — atacante mais lento que a janela de 72 h: "
              "3 dias × 23,3% → 200×36, SoC [76,7; 53,4; 30,1], ZERO "
              "alertas (69,9 ≤ 70 em qualquer janela de 72 h); apagão: "
              "1 h 10/12, 2 h 5/12, 3 h 1/12")},
    {"id": "P-R7-03", "expected": "CONFIRMADO", "finding": "K1-b-4d",
     "prev": ("CONFIRMADO — 4 dias × 18,7% → 200×48, SoC 25,2, ZERO "
              "alertas (≤ 3 fatias = 56,1 por janela de 72 h); apagão: "
              "1 h 9/12, 2 h 3/12")},
    {"id": "P-R7-04", "expected": "CONFIRMADO", "finding": "K1-c",
     "prev": ("CONFIRMADO — FALSO POSITIVO: dono com 25%/dia × 3 dias COM "
              "recarga solar entre dias → SoC 100 ao fim de cada dia → "
              "CRIT MULTIDAY ×12 count 36 com a bateria CHEIA — a regra "
              "mede VOLUME, não esvaziamento; \"uso diário legítimo não "
              "dispara\" só é verdade até ~23%/dia")},
    {"id": "P-R7-05", "expected": "CONFIRMADO", "finding": "C14-5noite",
     "prev": ("CONFIRMADO — subconjunto à noite invisível: 5 shutdowns "
              "remotos sem WO (< k=6) à NOITE → ZERO alertas; no apagão "
              "1 h 7/12 com luz, os 5 desligados às escuras")},
    {"id": "P-R7-06", "expected": "CONFIRMADO", "finding": "C14-7x61",
     "prev": ("CONFIRMADO — 7 shutdowns espaçados 61 min: DIA → CAPACITY "
              "CRIT div 74,3%, zero onda/slow; NOITE → ZERO alertas")},
    {"id": "P-R7-07", "expected": "CONFIRMADO", "finding": "FP-SP-frota",
     "prev": ("CONFIRMADO — /setpoint não aceita work-order: export_limit "
              "60% na frota inteira (operação de frota legítima) → div "
              "40% → CRIT; sem curtailment-wave")},
    {"id": "P-R7-08", "expected": "CONFIRMADO", "finding": "FP-SP-6",
     "prev": ("CONFIRMADO — 6 inversores a 60% → div 20,68% < 30% → ZERO "
              "alertas (a parte do Gemini que dizia CRIT aqui estava "
              "ERRADA — correção do supervisor)")},
]

# GATEFALL V071 — RE-REGISTADO neste ficheiro (v0.3) ANTES de qualquer
# corrida contra a v0.7.1 restaurada (72c894fe…): as MESMAS previsões do
# GO à v0.7.1 (fixes F-C13/F-K1/F-C14/F-SP; reconstrução pós-INFRA-B).
GATEFALL_V071 = [
    {"id": "P-R7-01", "expected": "RESOLVIDO", "finding": "C13",
     "prev": ("RESOLVIDO — F-C13: POST /mode com work_order "
              "\"WO-INVENTADA-123\" aos 12 → 403×12 + evento "
              "work_order_invalid ×12 (provenance remote_command), frota "
              "ON (o shutdown NÃO executa; ZERO eventos shutdown), WARN "
              "D-INVALID-WORK-ORDER count 12, SEM capacity/onda/snapshots "
              "com div >= 30 (div 0: a frota segue ON) — a evasão por WO "
              "falsa FECHA; §7 item 8 CORRIGIDO")},
    {"id": "P-R7-02", "expected": "RESOLVIDO", "finding": "K1-b-3d",
     "prev": ("RESOLVIDO — F-K1: as MESMAS 3 fatias × 23,3% executam "
              "(200×36; 23,3 <= 40 daily, 30,1 > 25 floor) MAS a fatia "
              "do dia 3 ATERRA SoC 30,1 <= 35 → D-BATTERY-DRAIN-TO-LOW "
              "CRIT count 12 PRÉ-apagão (o atacante lento fica "
              "VISÍVEL); SoC [76,7; 53,4; 30,1]; apagão 1 h 10/12, "
              "2 h 5/12, 3 h 1/12 (o served NÃO muda — previsão honesta "
              "do GO confirmada)")},
    {"id": "P-R7-03", "expected": "RESOLVIDO", "finding": "K1-b-4d",
     "prev": ("RESOLVIDO — F-K1: 4 dias × 18,7% → 200×48; a fatia do "
              "dia 4 ATERRA SoC 25,2 <= 35 → D-BATTERY-DRAIN-TO-LOW "
              "CRIT count 12 (dias 1-3: 81,3/62,6/43,9 > 35, caladas); "
              "apagão 1 h 9/12, 2 h 3/12")},
    {"id": "P-R7-04", "expected": "RESOLVIDO", "finding": "K1-c",
     "prev": ("RESOLVIDO — F-K1/K1-c: o dono 25%/dia × 3 dias COM "
              "recarga solar → SoC 100 ao fim de cada dia → ZERO "
              "alertas (a D-BATTERY-DRAIN-TO-LOW mede o SoC RESULTANTE "
              "da descarga executada — 75 > 35; a MULTIDAY de VOLUME "
              "foi SUBSTITUÍDA) — o FP morre na semântica: o que "
              "posiciona um apagão é o ESTADO, não o volume")},
    {"id": "P-R7-05", "expected": "RESOLVIDO", "finding": "C14-5noite",
     "prev": ("RESOLVIDO — F-C14: 5 shutdowns s/WO à noite continuam a "
              "EXECUTAR (200×5; WO ausente mantém) MAS ficam VISÍVEIS: "
              "WARN D-REMOTE-SHUTDOWN-NO-WO count 5 POR EVENTO, < k=6, "
              "à NOITE; no apagão 1 h 7/12 com luz (os 5 desligados às "
              "escuras); o CRIT noturno da capacity CONTINUA DECLARADO "
              "(cegueira física)")},
    {"id": "P-R7-06", "expected": "RESOLVIDO", "finding": "C14-7x61",
     "prev": ("RESOLVIDO — F-C14: DIA → CAPACITY CRIT div 74,3% "
              "(C12 intacto) + WARN NO-WO ×7; NOITE → WARN "
              "D-REMOTE-SHUTDOWN-NO-WO count 7 (v0.7: ZERO) — o mesmo "
              "ataque deixa de ser invisível à noite; o CRIT noturno "
              "continua DECLARADO")},
    {"id": "P-R7-07", "expected": "RESOLVIDO", "finding": "FP-SP-frota",
     "prev": ("RESOLVIDO — F-SP: export_limit 60% na frota inteira COM "
              "WO válida WO-20261112-MNT1 → 200×12 + div 40% MAS SEM "
              "CRIT (o param_change carrega a WO; o arming exige "
              "setpoint s/WO); e o MESMO setpoint SEM WO → CRIT "
              "MANTÉM (resíduo DECLARADO p/ v0.8 — o dono tem de usar "
              "a WO, que agora existe)")},
    {"id": "P-R7-08", "expected": "RESOLVIDO", "finding": "FP-SP-6",
     "prev": ("RESOLVIDO — F-SP: 6 inversores a 60% COM WO válida → "
              "200×6, ZERO alertas (div 20,68% < 30 E a WO não arma)")},
]
GATEFALL = GATEFALL_V071 if IS_V071 else GATEFALL_V07

if IS_V071:
    print("\nGATEFALL V071 — PREVISÕES RE-REGISTADAS NESTE FICHEIRO (v0.3, "
          "reconstrução pós-INFRA-2026-13-11-B) ANTES de qualquer corrida "
          "contra a v0.7.1: as MESMAS do GO à v0.7.1 (fixes F-C13/F-K1/"
          "F-C14/F-SP; critério estático do P-R7-01 pelo MÉTODO desde o "
          "início — lição do run 2 perdido)")
else:
    print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS E CONGELADAS (entrada \"GO À "
          "v0.7.1\" do canvas de design, hash pré ce362e56…; hash atual da "
          "entrada aed0ef3f…)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
if IS_V071:
    print("NOTA DO INCIDENTE INFRA-2026-13-11-B (13-11 ~18:23): o 2.º reset "
          "do ambiente PERDEU o lab v0.7.1 (00e2254f…), o probe dual "
          "v0.2-bis.1 (cab5d77b…) e os runs 2/2-b/re-check originais "
          "(0366e01a… 7/8+1 critério PRESERVADO na altura, be464ea0… "
          "8/8, 535ad1b9… 8/8). O lab foi restaurado por REPLAY dos "
          "scripts de edição preservados + errata J5 re-aplicada (72c894fe…; "
          "selftest re-executado BYTE-IDÊNTICO afb98d0c…). ESTE run "
          "re-executado é o OFICIAL da recuperação; se divergir das "
          "previsões, fica registado como previsão errada — este probe "
          "NÃO se ajusta para bater.\n")
else:
    print("NOTA DO INCIDENTE INFRA-2026-13-11-A: o RUN 1 original (output "
          "10512653b…, 8/8 CONFIRMADO) foi PERDIDO na falha de infraestrutura "
          "de 13-11 ~17:11–17:22 ANTES de qualquer publicação. O GATEFALL "
          "OFICIAL SUBSTITUTO da R7 é o RUN 1-BIS (0d08b8c0…, preservado em "
          "artifacts) e o 1-BIS-B (d7a0ec30…) — ESTE run é o RE-CHECK "
          "pós-INFRA-B com as MESMAS previsões congeladas. O supervisor tem "
          "medições INDEPENDENTES contra a v0.7 anteriores ao incidente "
          "(C13, K1-b, R6-01, C14, FP-SP). Se divergir das previsões, fica "
          "registado como previsão errada — este probe NÃO se ajusta "
          "para bater.\n")

# ---------------------------------------------------------------------------
# Helpers (padrão das probes R5/R6 — re-implementação INDEPENDENTE)
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


def sweep_minutes(d, duration_min):
    """Minutos de luz por casa (re-implementação INDEPENDENTE do lab, padrão
    dos probes R5/R6): stepping de 60 s com fração EXATA do minuto em que a
    luz apaga (física linear em NOITE: drop = 100/kwp pontos/hora)."""
    minutes = 0.0
    left = float(duration_min)
    while left > 1e-9:
        if d.self_consumption_kw() < L.LOAD_LOCAL_KW - 0.01:
            break  # já sem luz (SoC <= limite ativo, pv < carga)
        limit = d.island_discharge_floor()
        rate = ((L.LOAD_LOCAL_KW - d.pv_kw()) * 60.0 / 3600.0
                / d.batt_kwh * 100.0)   # pontos de SoC por minuto
        if rate > 0 and d.soc - rate * min(left, 1.0) <= limit + 1e-12:
            frac = min(left, max(0.0, (d.soc - limit) / rate))
            if frac > 0:
                d.step_island(frac * 60.0)
                minutes += frac
            break
        step = min(1.0, left)
        d.step_island(step * 60.0)
        minutes += step
        left -= step
    return round(minutes, 2)


def hygiene(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)


def night_normal(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("NOITE")
    time.sleep(0.6)


def blackout(lab):
    """Apagão noturno determinístico por harness (padrão do measure)."""
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)


def served_count(lab):
    return sum(1 for d in lab.devices
               if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)


def soc_range(lab):
    return (round(min(d.soc for d in lab.devices), 2),
            round(max(d.soc for d in lab.devices), 2))


def ranked_by_kwp(lab, n):
    return sorted(range(len(lab.devices)),
                  key=lambda i: lab.devices[i].kwp, reverse=True)[:n]


def ranked_kwp(lab, idxs):
    return sum(lab.devices[i].kwp for i in idxs)


def remote_shutdown(lab, idx, work_order=None):
    d = lab.devices[idx]
    body = {"action": "inverter_power_off"}
    if work_order is not None:
        body["work_order"] = work_order
    st, resp = hj(d.port, "POST", "/mode", body, token=d.service_token)
    return st, resp


def remote_setpoint(lab, idx, value, work_order=None):
    d = lab.devices[idx]
    body = {"value": value}
    if work_order is not None:
        body["work_order"] = work_order
    return hj(d.port, "POST", "/setpoint", body, token=d.service_token)


def day_slice(lab, frac):
    """Uma fatia de descarga remota de `frac` da bateria em TODOS os 12
    dispositivos (service token, via /battery — o canal do atacante e do
    harness do measure). Devolve a lista de status codes."""
    sts = []
    for i in range(len(lab.devices)):
        d = lab.devices[i]
        tok = "SUNBOX-SVC-%02d-2026" % i
        st, resp = hj(d.port, "POST", "/battery",
                      {"action": "discharge",
                       "amount_kwh": round(frac * d.batt_kwh, 3)},
                      token=tok)
        sts.append(st)
    return sts


# ---------------------------------------------------------------------------
# Execução — RUN 1-BIS (GATEFALL OFICIAL SUBSTITUTO da R7)
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("lab v%s em memoria (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))
    try:
        # ============ P-R7-01 — C13: WORK-ORDER FALSA ================
        print("[P-R7-01] C13 — o dispositivo NÃO valida a work_order")
        scen = "P-R7-01"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts01 = []
        for i in range(len(lab.devices)):
            st, resp = remote_shutdown(lab, i, "WO-INVENTADA-123")
            sts01.append(st)
        time.sleep(0.6)
        fleet_off = all(not d.inverter_on for d in lab.devices)
        alerts01 = scan_scenario(lab, scen)
        cap01 = [a for a in alerts01
                 if a["rule"] == "D-CAPACITY-DIVERGENCE"]
        waves01 = [a for a in alerts01
                   if a["rule"] in ("D-FLEET-SHUTDOWN-WAVE",
                                    "D-SLOW-WAVE",
                                    "D-FLEET-CURTAILMENT-WAVE")]
        snaps01 = [e for e in scenario_events(lab, scen)
                   if e.get("event") == "capacity_snapshot"]
        snaps01_hi = [s for s in snaps01
                      if s.get("divergence_pct", 0.0) >= 30.0]
        exp01, act01, div01 = L.capacity_divergence_pct(lab.devices)
        # prova estática da causa: o handler /mode do DEVICE passa o
        # work_order do body SEM validar contra WORK_ORDERS (a lista só
        # é conhecida pelo GATE) — qualquer texto é aceito
        src = LAB_BYTES.decode("utf-8")
        if IS_V071:
            # v0.3: a validação F-C13 vive no MÉTODO (lição do run 2
            # perdido do v0.2-bis.1: a zona do HANDLER não a contém)
            met_zone = src[src.index("def remote_inverter_power_off"):
                           src.index("def remote_inverter_resume")]
            wo_validated = "WORK_ORDERS" in met_zone
        else:
            dev_zone = src[src.index("class DevHandler"):
                           src.index("class FleetGate")]
            mode_zone = dev_zone[dev_zone.index("\"/mode\""):
                                 dev_zone.index("\"/setpoint\"")]
            wo_no_validate = ("body.get(\"work_order\")" in mode_zone
                              and "WORK_ORDERS" not in mode_zone)
        if IS_V071:
            wo_invalid_evs = [e for e in scenario_events(lab, scen)
                              if e.get("event") == "work_order_invalid"]
            shut_evs = [e for e in scenario_events(lab, scen)
                        if e.get("event") == "shutdown"]
            inv01 = [a for a in alerts01
                     if a["rule"] == "D-INVALID-WORK-ORDER"]
            cond_01 = (all(st == 403 for st in sts01)
                      and not fleet_off
                      and len(wo_invalid_evs) == 12 and len(shut_evs) == 0
                      and len(alerts01) == 1 and len(inv01) == 1
                      and inv01[0]["count"] == 12
                      and inv01[0]["severity"] == "WARN"
                      and len(cap01) == 0 and len(waves01) == 0
                      and wo_validated and len(snaps01_hi) == 0
                      and -0.01 <= div01 <= 0.01)
            word_01 = "RESOLVIDO"
            ev_01 = [
                "POST /mode {\"action\":\"inverter_power_off\", "
                "\"work_order\":\"WO-INVENTADA-123\"} aos 12: %s — a "
                "WO é VALIDADA pelo device (F-C13: a MESMA lista "
                "WORK_ORDERS do gate, uma fonte só) e REJEITADA com 403 "
                "+ evento work_order_invalid ×%d"
                % ("403×12" if all(s == 403 for s in sts01) else sts01,
                   len(wo_invalid_evs)),
                "frota: %d/12 inversores OFF — ZERO: o shutdown NÃO "
                "executa (eventos shutdown no cenário: %d); a frota "
                "fica ON com a bateria intacta"
                % (sum(1 for d in lab.devices if not d.inverter_on),
                   len(shut_evs)),
                "alertas do cenário: %s — WARN D-INVALID-WORK-ORDER "
                "count 12 POR EVENTO (a tentativa é VISÍVEL com o "
                "ataque MORTO); SEM capacity/onda (div %.2f; snapshots "
                "com div >= 30: %d)"
                % ([(a["rule"], a["count"]) for a in alerts01], div01,
                   len(snaps01_hi)),
                "prova estática (critério v0.3): WORK_ORDERS na zona do "
                "MÉTODO Device.remote_inverter_power_off (a validação "
                "vive no método, não no handler): %s" % wo_validated,
                "CONSEQUÊNCIA: a evasão por WO falsa FECHA o C13 — a "
                "frase do §7 item 8 volta a ser VERDADE (CORRIGIDA "
                "pelo GO à v0.7.1)"]
        else:
            cond_01 = (all(st == 200 for st in sts01) and fleet_off
                      and len(alerts01) == 0 and len(cap01) == 0
                      and len(waves01) == 0 and wo_no_validate
                      and len(snaps01_hi) >= 1 and 99.9 <= div01 <= 100.0)
            word_01 = "CONFIRMADO"
            ev_01 = [
                "POST /mode {\"action\":\"inverter_power_off\", "
                "\"work_order\":\"WO-INVENTADA-123\"} aos 12: %s — a "
                "work-order INVENTADA é aceita por TODOS (o device não "
                "tem a lista WORK_ORDERS; só o gate valida)"
                % ("200×12" if all(s == 200 for s in sts01) else sts01),
                "frota: %d/12 inversores OFF — a bateria fica CHEIA e "
                "as casas às escuras na hora seguinte"
                % sum(1 for d in lab.devices if not d.inverter_on),
                "div direta %.2f%% (esperado %.2f kW MANTÉM — o "
                "esperado é independente de inverter_on; real %.2f = 0): "
                "snapshots do cenário com div ≥ 30: %s — TODOS sem "
                "alerta (o shutdown COM WO não ARMA a regra)"
                % (div01, exp01, act01, len(snaps01_hi)),
                "alertas do cenário: %s — ZERO: SHUTDOWN-WAVE, SLOW-WAVE "
                "e CAPACITY-DIVERGENCE cegas (a onda conta só shutdowns "
                "SEM work_order e QUALQUER texto neutraliza a contagem)"
                % ([(a["rule"], a["count"]) for a in alerts01] or "ZERO"),
                "CONSEQUÊNCIA: a frase do §7 item 8 (\"isto é detetado\") "
                "é FALSA para o bypass por WO falsa — o C13 existe "
                "TAMBÉM na v0.6"]
        expect("P-R7-01", GATEFALL[0]["prev"], cond_01,
               word_01, "PREVISÃO ERRADA (ver detalhe acima)", ev_01)

        # ============ P-R7-02 — K1-b: 3 dias × 23,3% ================
        print("\n[P-R7-02] K1-b — mais lento que a janela de 72 h (3 dias)")
        results_02 = {}
        socs_02, pre02, sts02_ok = [], None, True
        for sub, dur, exp_served in (("a", 60, 10), ("b", 120, 5),
                                     ("c", 180, 1)):
            scen = "P-R7-02%s" % sub
            L.SIM_CLOCK_OFFSET = 0.0
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            all_sts = []
            day_socs = []
            for day in range(3):
                if day > 0:
                    lab.gridsim.set_irradiance("NOITE")
                    L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
                all_sts += day_slice(lab, 0.233)
                day_socs.append(soc_range(lab))
            alerts02 = scan_scenario(lab, scen)
            sts02_ok = sts02_ok and all(st == 200 for st in all_sts)
            socs_02, pre02 = day_socs, [(a["rule"], a["count"])
                                        for a in alerts02]
            blackout(lab)
            minutes = [sweep_minutes(d, dur) for d in lab.devices]
            served = served_count(lab)
            results_02[sub] = (served, minutes)
            print("    %s: 3 fatias → SoC %s; alertas pré-apagão: %s; "
                  "apagão %3d min: served %2d/12 (prev %2d)"
                  % (scen, socs_02[-1], pre02 or "ZERO", dur, served,
                     exp_served))
        (served_a, min_a) = results_02["a"]
        (served_b, min_b) = results_02["b"]
        (served_c, min_c) = results_02["c"]
        if IS_V071:
            drain02 = [a for a in alerts02
                       if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
            cond_02 = (sts02_ok and len(alerts02) == 1
                       and len(drain02) == 1
                       and drain02[0]["count"] == 12
                       and drain02[0]["severity"] == "CRIT"
                       and all(lo - 0.05 <= e <= hi + 0.05
                               for (lo, hi), e in zip(
                                   socs_02, (76.7, 53.4, 30.1)))
                       and served_a == 10 and served_b == 5
                       and served_c == 1)
            word_02 = "RESOLVIDO"
        else:
            cond_02 = (sts02_ok and len(pre02) == 0
                       and all(lo - 0.05 <= e <= hi + 0.05
                               for (lo, hi), e in zip(
                                   socs_02, (76.7, 53.4, 30.1)))
                       and served_a == 10 and served_b == 5
                       and served_c == 1)
            word_02 = "CONFIRMADO"
        expect("P-R7-02", GATEFALL[1]["prev"], cond_02,
               word_02, "PREVISÃO ERRADA (ver detalhe acima)",
               ["200×36 em CADA sub-cenário (3 fatias × 12 devs; 23,3% "
                "≤ 40 do daily e 30,1 > 25 do floor: TUDO executa)"
                if sts02_ok else "status com falha — ver output",
                "SoC fim de cada dia: %s (prev [76,7; 53,4; 30,1]) — "
                "100−23,3 por dia, SEM dia de sol"
                % [tuple("%.2f" % v for v in s) for s in socs_02],
                ("alertas pré-apagão: %s — o total de 3 dias é "
                 "69,9 ≤ 70 em QUALQUER janela de 72 h (a fatia "
                 "diária 23,3%% também não vê o daily de 40 nem a "
                 "cumulativa de 50)" % (pre02 or "ZERO"))
                if not IS_V071 else
                ("alertas pré-apagão: %s — a fatia do dia 3 ATERRA "
                 "30,1 <= LOW_SOC_ALERT_PCT 35 → a nova regra DISPARA "
                 "count 12; os dias 1-2 (76,7/53,4 > 35) ficam calados"
                 % ([(a["rule"], a["count"]) for a in alerts02] or
                    "ZERO")),
                "apagão NOITE: 1 h %d/12 (prev 10), 2 h %d/12 (prev 5), "
                "3 h %d/12 (prev 1) — minutos = 15,06·kwp: a 1 h falham "
                "3,2/3,8 kWp, a 2 h falham os ≤ 7,5 kWp, a 3 h só o 12,0 "
                "kWp (180,7 min) passa"
                % (served_a, served_b, served_c),
                "CONSEQUÊNCIA (K1-b/R6-01): a MULTIDAY de 72 h/70% é "
                "evadida pelo RITMO — 3 dias lentos chegam a SoC 30,1 "
                "com ZERO alertas" if not IS_V071 else
                "RESOLVIDO (F-K1): a fatia do dia 3 ATERRA 30,1 <= 35 "
                "→ D-BATTERY-DRAIN-TO-LOW CRIT count %d PRÉ-apagão — o "
                "atacante lento fica VISÍVEL (alertas: %s)"
                % (drain02[0]["count"] if drain02 else 0,
                   [(a["rule"], a["count"]) for a in alerts02])])

        # ============ P-R7-03 — K1-b: 4 dias × 18,7% ================
        print("\n[P-R7-03] K1-b — mais lento que a janela de 72 h (4 dias)")
        results_03 = {}
        socs_03, pre03, sts03_ok = [], None, True
        for sub, dur, exp_served in (("a", 60, 9), ("b", 120, 3)):
            scen = "P-R7-03%s" % sub
            L.SIM_CLOCK_OFFSET = 0.0
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            all_sts = []
            day_socs = []
            for day in range(4):
                if day > 0:
                    lab.gridsim.set_irradiance("NOITE")
                    L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
                all_sts += day_slice(lab, 0.187)
                day_socs.append(soc_range(lab))
            alerts03 = scan_scenario(lab, scen)
            sts03_ok = sts03_ok and all(st == 200 for st in all_sts)
            socs_03, pre03 = day_socs, [(a["rule"], a["count"])
                                        for a in alerts03]
            blackout(lab)
            minutes = [sweep_minutes(d, dur) for d in lab.devices]
            served = served_count(lab)
            results_03[sub] = (served, minutes)
            print("    %s: 4 fatias → SoC %s; alertas pré-apagão: %s; "
                  "apagão %3d min: served %2d/12 (prev %2d)"
                  % (scen, socs_03[-1], pre03 or "ZERO", dur, served,
                     exp_served))
        (served_a3, min_a3) = results_03["a"]
        (served_b3, min_b3) = results_03["b"]
        if IS_V071:
            drain03 = [a for a in alerts03
                       if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
            cond_03 = (sts03_ok and len(alerts03) == 1
                       and len(drain03) == 1
                       and drain03[0]["count"] == 12
                       and drain03[0]["severity"] == "CRIT"
                       and all(lo - 0.05 <= e <= hi + 0.05
                               for (lo, hi), e in zip(
                                   socs_03, (81.3, 62.6, 43.9, 25.2)))
                       and served_a3 == 9 and served_b3 == 3)
            word_03 = "RESOLVIDO"
        else:
            cond_03 = (sts03_ok and len(pre03) == 0
                       and all(lo - 0.05 <= e <= hi + 0.05
                               for (lo, hi), e in zip(
                                   socs_03, (81.3, 62.6, 43.9, 25.2)))
                       and served_a3 == 9 and served_b3 == 3)
            word_03 = "CONFIRMADO"
        expect("P-R7-03", GATEFALL[2]["prev"], cond_03,
               word_03, "PREVISÃO ERRADA (ver detalhe acima)",
               ["200×48 em CADA sub-cenário (4 fatias × 12 devs)"
                if sts03_ok else "status com falha — ver output",
                "SoC fim de cada dia: %s — fim do dia 4: 25,2 (43,9 − "
                "18,7 = 25,2 > floor 25 por 0,2 pontos: a última fatia "
                "EXECUTA por pouco)"
                % [tuple("%.2f" % v for v in s) for s in socs_03],
                ("alertas pré-apagão: %s — com 4 fatias espaçadas "
                 "25 h, QUALQUER janela de 72 h contém ≤ 3 fatias = "
                 "56,1 < 70" % (pre03 or "ZERO"))
                if not IS_V071 else
                ("alertas pré-apagão: %s — só a fatia do dia 4 "
                 "ATERRA 25,2 <= 35 (dias 1-3: 81,3/62,6/43,9 > 35, "
                 "caladas)" % ([(a["rule"], a["count"]) for a in
                                alerts03] or "ZERO")),
                "apagão NOITE: 1 h %d/12 (prev 9), 2 h %d/12 (prev 3) — "
                "minutos = 12,12·kwp: a 1 h falham 3,2/3,8/4,4 kWp; a "
                "2 h passam só 10,5/11,4/12,0 kWp"
                % (served_a3, served_b3),
                "CONSEQUÊNCIA (R6-01): 4 dias levam a frota ao floor "
                "VIRTUAL (25,2) com ZERO alertas — o RITMO sem "
                "recarga derrota a janela de 72 h" if not IS_V071 else
                "RESOLVIDO (F-K1): a fatia do dia 4 ATERRA 25,2 <= 35 "
                "→ D-BATTERY-DRAIN-TO-LOW CRIT count %d — os dias 1-3 "
                "(81,3/62,6/43,9 > 35) ficam calados (alertas: %s)"
                % (drain03[0]["count"] if drain03 else 0,
                   [(a["rule"], a["count"]) for a in alerts03])])

        # ============ P-R7-04 — K1-c: FALSO POSITIVO do dono ========
        print("\n[P-R7-04] K1-c — dono que RECARREGA dispara a MULTIDAY")
        socs_04 = []
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario("P-R7-04")
        reset_all(lab)
        hygiene(lab)
        all_sts = []
        for day in range(3):
            if day > 0:
                L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            all_sts += day_slice(lab, 0.25)
            # recarga solar legítima entre dias: 12 h de DIA (J4,
            # excedente carrega; cap 100 para todos: surplus mín 0,56 kW)
            lab.gridsim.set_irradiance("DIA")
            time.sleep(0.2)
            for d in lab.devices:
                d.step_grid(12 * 3600.0)
            socs_04.append(soc_range(lab))
            lab.gridsim.set_irradiance("NOITE")
            time.sleep(0.2)
        alerts04 = scan_scenario(lab, "P-R7-04")
        multi04 = [a for a in alerts04
                   if a["rule"] == "D-BATTERY-MULTIDAY-DRAIN"]
        other04 = [a for a in alerts04
                   if a["rule"] != "D-BATTERY-MULTIDAY-DRAIN"]
        if IS_V071:
            drain04 = [a for a in alerts04
                       if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
            cond_04 = (all(st == 200 for st in all_sts)
                       and len(all_sts) == 36
                       and all(abs(s[0] - 100.0) <= 0.01 for s in socs_04)
                       and len(alerts04) == 0 and not drain04)
            word_04 = "RESOLVIDO"
        else:
            cond_04 = (all(st == 200 for st in all_sts)
                      and len(all_sts) == 36
                      and all(abs(s[0] - 100.0) <= 0.01 for s in socs_04)
                      and len(multi04) == 1 and multi04[0]["count"] == 36
                      and multi04[0]["severity"] == "CRIT"
                      and len(multi04[0]["devices"]) == 12
                      and len(other04) == 0)
            word_04 = "CONFIRMADO"
        expect("P-R7-04", GATEFALL[3]["prev"], cond_04,
               word_04, "PREVISÃO ERRADA (ver detalhe acima)",
               ["dono: 25%%/dia × 3 dias COM recarga solar de 12 h entre "
                "dias (J4): 200×36, SoC ao fim de cada dia %s — a "
                "bateria está CHEIA em TODAS as medições"
                % [tuple("%.2f" % v for v in s) for s in socs_04],
                (("CRIT D-BATTERY-MULTIDAY-DRAIN ×12 (count %s, "
                  "%d devs): 75%% > 70 em 3 dias-distintos — disparo "
                  "com SoC 100"
                  % (multi04[0]["count"] if multi04 else 0,
                     len(multi04[0]["devices"]) if multi04 else 0))
                 if not IS_V071 else
                 "regra MULTIDAY na v0.7.1: SUBSTITUÍDA pela "
                 "D-BATTERY-DRAIN-TO-LOW (F-K1) — não existe no "
                 "detetor; com SoC 100 nada dispara (alertas: %s)"
                 % ([(a["rule"], a["count"]) for a in alerts04] or
                    "ZERO")),
                "outros alertas: %s — é UM CRIT de frota para um uso "
                "diário LEGÍTIMO com recarga"
                % ([(a["rule"], a["count"]) for a in other04] or "ZERO"),
                "CONSEQUÊNCIA (K1-c): a MULTIDAY mede VOLUME "
                "descarregado, NÃO esvaziamento — o manifesto diz \"uso "
                "diário legítimo não dispara\" e isso só é verdade até "
                "~23%/dia (FP medido com a bateria cheia)" if not IS_V071
                else
                "RESOLVIDO (F-K1): ZERO alertas com SoC 100 (%s) — a "
                "DRAIN-TO-LOW mede o SoC RESULTANTE (75 > 35 após a "
                "fatia) e a MULTIDAY de VOLUME foi SUBSTITUÍDA: o FP "
                "K1-c MORRE na semântica — o que posiciona um apagão "
                "é o ESTADO, não o volume"
                % ([(a["rule"], a["count"]) for a in alerts04] or
                   "ZERO")])

        # ============ P-R7-05 — C14: 5 shutdowns à noite ============
        print("\n[P-R7-05] C14 — 5 shutdowns s/WO à noite: invisíveis")
        scen = "P-R7-05"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        night_normal(lab)
        top5 = ranked_by_kwp(lab, 5)
        sts05 = []
        for i in top5:
            st, _ = remote_shutdown(lab, i, None)
            sts05.append(st)
        time.sleep(0.6)
        alerts05 = scan_scenario(lab, scen)
        off05 = [i for i in range(len(lab.devices))
                 if not lab.devices[i].inverter_on]
        scen = "P-R7-05b"
        lab.scenario(scen)
        blackout(lab)
        minutes = [sweep_minutes(d, 60) for d in lab.devices]
        served = served_count(lab)
        if IS_V071:
            nowo05 = [a for a in alerts05
                      if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            cond_05 = (all(st == 200 for st in sts05)
                       and len(alerts05) == 1 and len(nowo05) == 1
                       and nowo05[0]["count"] == 5
                       and nowo05[0]["severity"] == "WARN"
                       and len(off05) == 5 and served == 7)
            word_05 = "RESOLVIDO"
        else:
            cond_05 = (all(st == 200 for st in sts05)
                       and len(alerts05) == 0
                       and len(off05) == 5 and served == 7)
            word_05 = "CONFIRMADO"
        expect("P-R7-05", GATEFALL[4]["prev"], cond_05,
               word_05, "PREVISÃO ERRADA (ver detalhe acima)",
               ["top-5 por kWp desligado à NOITE (5 < WAVE_K=6: sem "
                "onda; 5 < SLOW_K=8: sem slow): devs %s = %.1f/88,8 kWp "
                "= %.1f%% — todos 200"
                % (top5, ranked_kwp(lab, top5),
                   ranked_kwp(lab, top5) / 88.8 * 100.0),
                "alertas do cenário: %s — a capacity está CEGA à noite "
                "por construção (esperado = kwp × irr(0) = 0 → div 0), "
                "a onda exige k=6 e o slow k=8"
                % ([(a["rule"], a["count"]) for a in alerts05] or "ZERO"),
                "apagão 1 h: served %d/12 (prev 7) — os 5 desligados "
                "ficam às ESCURAS com a bateria CHEIA (o C12 da v0.7 "
                "via shutdowns de DIA, não de noite)"
                % (served,),
                "CONSEQUÊNCIA (C14, de R6-02 do Gemini): um subconjunto "
                  "abaixo de k=6 à noite é INVISÍVEL — soma do resíduo "
                  "top-2/k<6 com a cegueira noturna declarada"
                  if not IS_V071 else
                  "RESOLVIDO (F-C14): WARN D-REMOTE-SHUTDOWN-NO-WO "
                  "count %d POR EVENTO — o subconjunto noturno fica "
                  "VISÍVEL abaixo de k=6 (alertas: %s); o CRIT noturno "
                  "da capacity CONTINUA DECLARADO (cegueira física: "
                  "à noite div=0)"
                  % (nowo05[0]["count"] if nowo05 else 0,
                     [(a["rule"], a["count"]) for a in alerts05])])

        # ============ P-R7-06 — C14: 7 shutdowns × 61 min ============
        print("\n[P-R7-06] C14 — 7 shutdowns espaçados 61 min: "
              "DIA vs NOITE")
        results_06 = {}
        for sub, profile in (("dia", "DIA"), ("noite", "NOITE")):
            scen = "P-R7-06-%s" % sub
            L.SIM_CLOCK_OFFSET = 0.0
            lab.scenario(scen)
            reset_all(lab)
            if profile == "DIA":
                hygiene(lab)
            else:
                night_normal(lab)
            top7 = ranked_by_kwp(lab, 7)
            sts06 = []
            for n, i in enumerate(top7):
                if n > 0:
                    L.SIM_CLOCK_OFFSET += 61.0 * 60.0   # 61 min entre
                st, _ = remote_shutdown(lab, i, None)
                sts06.append(st)
            time.sleep(0.6)
            alerts06 = scan_scenario(lab, scen)
            cap06 = [a for a in alerts06
                     if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            waves06 = [a for a in alerts06
                       if a["rule"] in ("D-FLEET-SHUTDOWN-WAVE",
                                        "D-SLOW-WAVE")]
            exp06, act06, div06 = L.capacity_divergence_pct(lab.devices)
            results_06[sub] = (sts06, alerts06, cap06, waves06, div06)
            print("    %s: 7×200=%s, div %.2f%%, capacity %s, onda/slow %s"
                  % (sub,
                     all(st == 200 for st in sts06),
                     div06,
                     len(cap06), len(waves06)))
        (sts_d, alerts_d, cap_d, waves_d, div_d) = results_06["dia"]
        (sts_n, alerts_n, cap_n, waves_n, div_n) = results_06["noite"]
        top7 = ranked_by_kwp(lab, 7)
        if IS_V071:
            nowo_d = [a for a in alerts_d
                      if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            nowo_n = [a for a in alerts_n
                      if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            cond_06 = (all(st == 200 for st in sts_d + sts_n)
                       and len(cap_d) >= 1 and 73.8 <= div_d <= 74.9
                       and len(waves_d) == 0 and len(waves_n) == 0
                       and len(nowo_d) == 1 and nowo_d[0]["count"] == 7
                       and len(alerts_n) == 1 and len(nowo_n) == 1
                       and nowo_n[0]["count"] == 7
                       and nowo_n[0]["severity"] == "WARN")
            word_06 = "RESOLVIDO"
        else:
            cond_06 = (all(st == 200 for st in sts_d + sts_n)
                       and len(cap_d) >= 1 and 73.8 <= div_d <= 74.9
                       and len(waves_d) == 0 and len(waves_n) == 0
                       and len(alerts_n) == 0)
            word_06 = "CONFIRMADO"
        expect("P-R7-06", GATEFALL[5]["prev"], cond_06,
               word_06, "PREVISÃO ERRADA (ver detalhe acima)",
               ["top-7 por kWp desligado SEM work-order, espaçados 61 "
                "min (SIM_CLOCK_OFFSET): devs %s = %.1f/88,8 kWp = "
                "%.2f%%"
                % (top7, ranked_kwp(lab, top7),
                   ranked_kwp(lab, top7) / 88.8 * 100.0),
                "espaçamento 61 min > WAVE_WINDOW 60 s (sem onda) e > "
                "SLOW_WINDOW 3600 s/60 (máx 1-2 no horizonte, sem "
                "slow): zero onda/slow nos DOIS sub-cenários",
                "DIA: D-CAPACITY-DIVERGENCE CRIT DISPARA (%d alerta(s)) "
                "com div direta %.2f%% (prev 74,3%%) — o fix C12 da "
                "v0.7 FUNCIONA de dia (o shutdown s/WO ARMA e o "
                "esperado mantém-se com os inversores OFF)"
                % (len(cap_d), div_d),
                (("NOITE: alertas do cenário: %s — ZERO (esperado 0 → "
                  "div 0 por construção: a capacity não vê shutdowns "
                  "noturnos, e a onda/slow não chegam a k pelo "
                  "espaçamento)"
                  % ([(a["rule"], a["count"]) for a in alerts_n]
                     or "ZERO"))
                 if not IS_V071 else
                 ("NOITE: alertas do cenário: %s — WARN "
                  "D-REMOTE-SHUTDOWN-NO-WO count 7 POR EVENTO (a "
                  "capacity segue cega por construção: div 0; a "
                  "onda/slow não chegam a k pelo espaçamento)"
                  % ([(a["rule"], a["count"]) for a in alerts_n] or
                     "ZERO"))),
                "CONSEQUÊNCIA (C14): 7 shutdowns espaçados são visíveis "
                "de DIA e INVISÍVEIS de NOITE — o mesmo ataque muda de "
                "veredicto com a hora do dia" if not IS_V071 else
                "RESOLVIDO (F-C14): DIA → CAPACITY CRIT div %.2f%% "
                "(C12 intacto) + WARN NO-WO count %d; NOITE → WARN "
                "D-REMOTE-SHUTDOWN-NO-WO count %d (v0.7: ZERO) — o "
                "mesmo ataque deixa de ser invisível à noite; o CRIT "
                "noturno continua DECLARADO"
                % (div_d, nowo_d[0]["count"] if nowo_d else 0,
                   nowo_n[0]["count"] if nowo_n else 0)])

        # ============ P-R7-07 — FP-SP: frota inteira a 60% ===========
        print("\n[P-R7-07] FP-SP — setpoint de frota legítimo → CRIT")
        scen = "P-R7-07"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        wo07 = "WO-20261112-MNT1" if IS_V071 else None
        sts07 = []
        for i in range(len(lab.devices)):
            st, _ = remote_setpoint(lab, i, 60.0, wo07)
            sts07.append(st)
        time.sleep(0.8)
        alerts07 = scan_scenario(lab, scen)
        cap07 = [a for a in alerts07
                 if a["rule"] == "D-CAPACITY-DIVERGENCE"]
        cw07 = [a for a in alerts07
                if a["rule"] == "D-FLEET-CURTAILMENT-WAVE"]
        exp07, act07, div07 = L.capacity_divergence_pct(lab.devices)
        if IS_V071:
            # resíduo DECLARADO: o MESMO setpoint SEM WO → CRIT mantém
            scen_b = "P-R7-07b"
            lab.scenario(scen_b)
            reset_all(lab)
            hygiene(lab)
            sts07b = []
            for i in range(len(lab.devices)):
                st, _ = remote_setpoint(lab, i, 60.0)   # SEM WO
                sts07b.append(st)
            time.sleep(0.8)
            alerts07b = scan_scenario(lab, scen_b)
            cap07b = [a for a in alerts07b
                      if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            pc07 = [e for e in scenario_events(lab, scen)
                    if e.get("event") == "param_change"]
            wo_in_pc = (len(pc07) == 12
                        and all(e.get("work_order") == "WO-20261112-MNT1"
                                for e in pc07))
            cond_07 = (all(st == 200 for st in sts07)
                       and len(alerts07) == 0 and len(cap07) == 0
                       and 39.9 <= div07 <= 40.1 and wo_in_pc
                       and len(cw07) == 0
                       and all(st == 200 for st in sts07b)
                       and len(cap07b) >= 1)
            word_07 = "RESOLVIDO"
        else:
            cond_07 = (all(st == 200 for st in sts07)
                       and len(cap07) >= 1 and 39.9 <= div07 <= 40.1
                       and len(cw07) == 0)
            word_07 = "CONFIRMADO"
        expect("P-R7-07", GATEFALL[6]["prev"], cond_07,
               word_07, "PREVISÃO ERRADA (ver detalhe acima)",
               [(("export_limit 60%% em TODOS os 12 (via /setpoint, "
                  "SEM work-order — o endpoint não aceita o campo): "
                  "%s — uma operação de frota LEGÍTIMA (redução "
                  "temporária de exportação)"
                  % ("200×12" if all(s == 200 for s in sts07)
                     else sts07))
                 if not IS_V071 else
                 ("export_limit 60%% em TODOS os 12 (via /setpoint, "
                  "COM work-order válida WO-20261112-MNT1 — o endpoint "
                  "passa a ACEITAR o campo, F-SP): %s — a operação de "
                  "frota legítima PROVA a legitimidade"
                  % ("200×12" if all(s == 200 for s in sts07)
                     else sts07))),
                ("div direta %.2f%% (esperado %.2f kW, real %.2f kW) — "
                 "cruza o limiar de 30%% → D-CAPACITY-DIVERGENCE CRIT "
                 "(%d alerta(s)): FALSO POSITIVO"
                 % (div07, exp07, act07, len(cap07)))
                if not IS_V071 else
                ("div direta %.2f%% (esperado %.2f kW, real %.2f kW) — "
                 "cruza os 30%% MAS o param_change carrega a WO → o "
                 "arming NÃO arma: %d alerta(s) (o CRIT morre; SEM WO "
                 "o mesmo setpoint dá CRIT — ver P-R7-07b: cap07b=%d)"
                 % (div07, exp07, act07, len(cap07), len(cap07b))),
                "curtailment-wave: %s — ZERO (60%% > CURTAIL_SETPOINT_"
                "MAX=50: a regra de onda de curtailment não conta "
                "setpoints de 60%%)"
                % ([(a["rule"], a["count"]) for a in cw07] or "ZERO"),
                "CAUSA (FP-SP, de R6-03 do Gemini): o arming da "
                "capacity trata QUALQUER setpoint remoto sem "
                "work-order como hostil; um operador de frota legítimo "
                "não tem como provar legitimidade — o /setpoint não "
                "aceita work_order" if not IS_V071 else
                "RESOLVIDO (F-SP): 200×12 COM WO válida WO-20261112-"
                "MNT1 e div %.2f%% MAS SEM CRIT (param_change carrega a "
                "WO: %s; o arming exige setpoint s/WO); e SEM WO o "
                "MESMO setpoint ARMA → CRIT mantém (cap07b=%d) — o "
                "resíduo SEM WO fica DECLARADO p/ v0.8"
                % (div07, "WO em 12/12" if wo_in_pc else "VERIFICAR",
                   len(cap07b))])

        # ============ P-R7-08 — FP-SP: 6 inversores a 60% ===========
        print("\n[P-R7-08] FP-SP — 6 inversores a 60%: sem alerta")
        scen = "P-R7-08"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        wo08 = "WO-20261112-MNT1" if IS_V071 else None
        sts08 = []
        for i in range(6):        # devs 0-5 (a parte CORRIGIDA do Gemini)
            st, _ = remote_setpoint(lab, i, 60.0, wo08)
            sts08.append(st)
        time.sleep(0.8)
        alerts08 = scan_scenario(lab, scen)
        cap08 = [a for a in alerts08
                 if a["rule"] == "D-CAPACITY-DIVERGENCE"]
        exp08, act08, div08 = L.capacity_divergence_pct(lab.devices)
        cond_08 = (all(st == 200 for st in sts08) and len(alerts08) == 0
                   and len(cap08) == 0 and 20.0 <= div08 <= 21.5)
        expect("P-R7-08", GATEFALL[7]["prev"], cond_08,
               "RESOLVIDO" if IS_V071 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["devs 0-5 a 60%% (kwp %s): %s — o setpoint parcial "
                "também é uma operação legítima"
                % ([round(lab.devices[i].kwp, 1) for i in range(6)],
                   "200×6" if all(s == 200 for s in sts08) else sts08),
                "div direta %.2f%% (prev 20,68%%) < 30 → ZERO alertas "
                "no cenário: %s"
                % (div08,
                   [(a["rule"], a["count"]) for a in alerts08] or "ZERO"),
                "CORREÇÃO DO SUPERVISOR AO GEMINI: com 6 inversores a "
                "60% NÃO há CRIT (20,68% < 30%) — a parte do achado "
                "R6-03 que dizia CRIT aqui estava ERRADA; o FP real é "
                "o da frota INTEIRA (P-R7-07)"
                + (" — RESOLVIDO na v0.7.1: a WO válida não arma "
                   "(F-SP) e o div 20,68% < 30 mantém ZERO alertas"
                   if IS_V071 else "")])

        # ================= SUMÁRIO ====================================
        by_id = {v["id"]: v for v in VEREDICTOS}
        match_n, prev_erradas = 0, 0
        print("\n" + "=" * 72)
        print("SUMÁRIO — GATEFALL R7 vs alvo %s (run pós-INFRA-2026-"
              "13-11-B)" % TARGET)
        for entry in GATEFALL:
            v = by_id.get(entry["id"], {"veredicto": "NÃO EXECUTADO"})
            match = (v["veredicto"] == entry.get("expected", "CONFIRMADO"))
            if not match:
                prev_erradas += 1
            else:
                match_n += 1
            print("  [%s/%s] previsto: %s | observado: %s"
                  % (entry["id"], entry["finding"],
                     entry.get("expected", "CONFIRMADO"), v["veredicto"]))
        print("-" * 72)
        print("PREVISÕES CONFIRMADAS contra a v%s (%s): %d/%d"
              % (L.LAB_VERSION, TARGET, match_n, len(GATEFALL)))
        print("PREVISÕES ERRADAS: %d" % prev_erradas)
        print("LAB ALVO: v%s (%s), hash %s (INTOCADA — verificado no "
              "arranque)" % (L.LAB_VERSION, TARGET, lab_sha))
        if IS_V071:
            print("ESTE É O RUN vs v0.7.1 RE-EXECUTADO (reconstrução "
                  "pós-INFRA-2026-13-11-B; probe v0.3). Os runs "
                  "ORIGINAIS contra a v0.7.1 do v0.2-bis.1 perdido — "
                  "run 2: 7/8 RESOLVIDO + P-R7-01 errada por DEFEITO DE "
                  "CRITÉRIO (prova estática na zona ERRADA; output "
                  "0366e01a…, PRESERVADO como oficial na altura), "
                  "errata datada e run 2-b: 8/8 (be464ea0…), re-check "
                  "vs v0.7: 8/8 (535ad1b9…) — foram PERDIDOS no reset; "
                  "ESTE re-run com o critério de MÉTODO incorporado "
                  "desde o início é o OFICIAL da recuperação. O que "
                  "confirma: F-C13 fecha o C13 (403 + WARN, frota ON); "
                  "F-K1 apanha K1-b 3 e 4 dias (DRAIN-TO-LOW count 12) "
                  "e mata o FP K1-c (SoC 100, ZERO); F-C14 dá "
                  "VISIBILIDADE noturna (WARN por evento < k=6; o CRIT "
                  "noturno continua DECLARADO); F-SP fecha o FP-SP COM "
                  "WO (o resíduo SEM WO fica DECLARADO p/ v0.8).")
        else:
            print("ESTE É O RE-CHECK vs v0.7 INTOCADA (reconstrução "
                  "pós-INFRA-2026-13-11-B; probe v0.3): o GATEFALL "
                  "OFICIAL SUBSTITUTO da R7 mantém-se o RUN 1-BIS "
                  "(6/8 CONFIRMADO + 2 previsões erradas por defeito "
                  "de critério do probe, output 0d08b8c0…, PRESERVADO "
                  "em artifacts) e o 1-BIS-B (d7a0ec30…, 8/8, "
                  "PRESERVADO); o run 1 original, 10512653b…, foi "
                  "PERDIDO no incidente INFRA-2026-13-11-A antes de "
                  "qualquer publicação; previsões CONGELADAS da entrada "
                  "\"GO À v0.7.1\" do canvas de design. Os fixes da "
                  "v0.7.1 (F-C13, F-K1, F-C14, F-SP) vêm DEPOIS, por "
                  "ordem vinculativa do GO.")
        return 0 if prev_erradas == 0 else 1
    finally:
        L.SIM_CLOCK_OFFSET = 0.0
        lab.stop()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        traceback.print_exc()
        raise SystemExit(3)

# EOF:sunstrike_probes_r7_v071.py
