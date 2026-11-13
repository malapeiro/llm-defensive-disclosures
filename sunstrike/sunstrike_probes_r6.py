#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# SUNSTRIKE — bateria de probes R6 (M2, ronda 6 — achados K1/C12 + GO à v0.7)
# Grant: GRANT-PVTE-20261112-SS-01 (lab sintético, loopback apenas)
# Alvo:  sunstrike_lab.py v0.6 (698b8cff…, VERIFICADA por execução pelo
#        supervisor em Python 3.13: 22/22 ficheiros batem com o manifesto,
#        selftest PASS, demo 9/9, measure PASS, probes r2–r5 com 0 previsões
#        erradas). Nada corre contra um lab que não seja este hash.
# Corpus R6 (GO do operador 13-11 15:30, via supervisor; 5.ª auditoria às
#        cegas do Gemini, 12 achados AUD-01..12, verificados por EXECUÇÃO):
#   K1  (AUD-01) O limite diário trava o RITMO, não o TOTAL. Atacante
#        paciente SEM dia de sol: dia 1 fatia 40% (200) → +25 h → dia 2
#        fatia 34,9% (200 — o máximo que passa o floor a partir de 60) →
#        SoC 25,1 nos 12, ZERO alertas antes do apagão. Apagão NOITE:
#        1 h = 9/12, 2 h = 3/12 (= v0.5). Com dia NUVEM intermédio:
#        1 h 9/12, 2 h 7/12. O floor aguenta (3.ª fatia → 409). Os
#        "12/12 a 1 h" e "60% → 11/12" só valem com dia de sol.
#   C12 (AUD-07.3) D-CAPACITY-DIVERGENCE é cega a shutdowns por
#        construção. Top-5 por kWp desligado via service token: ZERO
#        alertas, divergência 0,0%. Causas: (1) o esperado usa
#        pv_gross_kw() que devolve 0 com o inversor OFF (esperado e real
#        descem juntos); (2) a regra só arma com param_change export_limit
#        remote_command sem work-order; (3) o snapshot contínuo só sai em
#        transição de banda, que um shutdown nunca provoca. O design
#        §4.4/R3 prometia apanhar subset targeting com esta regra.
# Papel: probes "antes" contra a v0.6 INTOCADA (padrão R1-R5): o output é
#        a evidência do ANTES; os fixes são o DEPOIS (v0.7). Protocolo
#        GATEFALL — previsões PRÉ-REGISTADAS por construção (constantes
#        deste script, hash-verificáveis), impressas ANTES da execução.
#        Veredicto observado != previsto é reportado como PREVISÃO
#        ERRADA. GATEFALL OFICIAL desta ronda = RUN 1 desta bateria
#        contra a v0.6 (ordem vinculativa do GO; nunca o run seguinte).
# O atacante (d) é o padrão K1 em FATIAS PURAS (40% dia 1, 34,9% dia 2,
#        SEM a direta 999 — correção datada do pré-registo, canvas §3.2):
#        fatias acima do floor e ≤ 40%/dia nunca tocam no floor remoto
#        nem no limite diário — o ANTES mostra o padrão invisível.
# Portabilidade: Python 3.9+, 100% stdlib, 127.0.0.1 apenas.
#
# CHANGELOG DE PROBES (o LAB alvo NUNCA é editado):
#   v0.1 (13-11): primeira versão, alvo v0.6. GATEFALL contra a v0.6
#        PRÉ-REGISTADO nesta entrada, ANTES de qualquer corrida (as
#        mesmas previsões foram registadas no canvas design §3.2 na
#        entrada "GO À v0.7" e no corpus entrada 22, com correção datada
#        do LEGACY-D do measure — irrelevante para estes probes, que
#        correm todos em config DEFENDED v0.6):
#          P-R6-01 CONFIRMADO (K1, atacante (d)): dia 1 fatia 40% →
#            200×12 (SoC 60,00), +25 h SEM dia de sol, dia 2 fatia
#            34,9% → 200×12 (SoC ~25,10 nos 12), ZERO alertas antes do
#            apagão; apagão NOITE: 1 h → 9/12, 2 h → 3/12;
#          P-R6-02 CONFIRMADO (K1, curva do atacante (d)): served
#            [30: 12, 60: 9, 90: 6, 120: 3, 180: 0], SoC min
#            [9,47; 5,00; 5,00; 5,00; 5,00] (tol 0,05), minutos de luz
#            por casa = 12,06·kwp com clamp na duração (3,2 kWp →
#            38,59 min; 3,8 → 45,83; 4,4 → 53,06 — os que falham na 1 h);
#          P-R6-03 CONFIRMADO (K1, dia NUVEM intermédio): dia 1 40% →
#            200×12 (SoC 60); NUVEM 12 h de step_grid — só kwp ≥ 6,8 tem
#            excedente (6,8 → 83,53; ≥ 7,5 → 100 por cap; ≤ 6,0 ficam
#            60); +25 h; dia 2 34,9% → 200×12 (SoC [25,1 nos ≤ 6,0;
#            48,63 no 6,8; 65,1 nos ≥ 7,5]); apagão: 1 h → 9/12,
#            2 h → 7/12 (números do supervisor, confirmados pela física);
#          P-R6-04 CONFIRMADO (C12): top-5 por kWp [devs 4, 11, 0, 8, 3
#            = 12,0 + 11,4 + 10,5 + 9,6 + 8,2 = 51,7/88,8 kWp = 58,2%]
#            desligados por service token (5 < WAVE_K, sem onda) →
#            ZERO alertas D-CAPACITY-DIVERGENCE, divergência 0,0%
#            (esperado ~20,41 kW = real ~20,41 kW), NENHUM
#            capacity_snapshot do cenário com div > 0 (o supervisor
#            mediu 55,7% na cópia dele — subconjunto ligeiramente
#            diferente, o ACHADO é o mesmo);
#          P-R6-05 CONFIRMADO (C12, as 3 causas): (1) DINÂMICA —
#            pv_gross_kw() = 0,0 com inverter OFF e export_kw() = 0,0
#            (esperado e real descem JUNTOS → div 0,0); (2) ESTÁTICA —
#            o armar da regra (scan) só tem remote_export_change
#            (param_change export_limit remote sem work-order), NENHUMA
#            condição de shutdown; (3) ESTÁTICA — o snapshot contínuo do
#            GridSim.publish só emite em TRANSIÇÃO de banda
#            (band != _cap_band), que um shutdown nunca provoca;
#          P-R6-06 CONFIRMADO (o floor aguenta, controlo): 3.ª fatia de
#            20% a partir de SoC 25,1 → 409 min_emergency_soc_floor (o
#            floor é verificado ANTES do daily — P-R4-04) +
#            D-BATTERY-DRAIN-BELOW-FLOOR ×12, SoC intacto ~25,10 — a
#            3.ª fatia NÃO passa nem conta no ledger.
#   v0.2 (13-11): DUAL-TARGET (V06/V07, deteção por hash). ERRATA
#        DATADA DE DISPLAY (precedente r5 v0.2.1): a linha de evidência
#        do P-R6-06 mostrava "40%%+34,9%%" LITERAL (string SEM operador
#        de formatação — o %% só se renderiza como % quando há um
#        operador % na string); corrigido para "40%+34,9%". O run 1
#        oficial (v0.1, contra a v0.6 INTOCADA, hash 3853d46b…) NÃO é
#        afectado: a gralha era de DISPLAY, o critério estava certo.
#        GATEFALL V07 (run 2, o DEPOIS) PRÉ-REGISTADO NESTA ENTRADA,
#        ANTES de qualquer corrida contra a v0.7 (hash d3af0d28…):
#          P-R6-01 RESOLVIDO-VISIBILIDADE: a FÍSICA NÃO MUDA (200×12
#            nos 2 dias, SoC ~25,10, 1 h 9/12, 2 h 3/12) mas o scan
#            pré-apagão passa de ZERO alertas para D-BATTERY-MULTIDAY-
#            DRAIN ×12 (count 24) em CADA sub-cenário — a v0.7 DETETA,
#            não previne (o served é o mesmo; muda a VISIBILIDADE);
#          P-R6-02 RESOLVIDO-VISIBILIDADE: curva IGUAL (served
#            [12,9,6,3,0], SoC min [9,47;5,00;5,00;5,00;5,00], minutos
#            12,06·kwp) + multiday ×12 count 24 pré-apagão nas 5
#            durações;
#          P-R6-03 RESOLVIDO-VISIBILIDADE: NUVEM igual (6,8→83,53,
#            ≥7,5→cap, ≤6,0 ficam 60; 1 h 9/12, 2 h 7/12) + multiday
#            ×12 count 24 pré-apagão (74,9 > 70 em 2 dias em TODOS);
#          P-R6-04 RESOLVIDO: top-5 (58,2% kWp) → D-CAPACITY-DIVERGENCE
#            DISPARA (div 58,2% ≥ 30; esperado 48,84 kW MANTÉM, real
#            cai a 20,44 kW); resíduo top-2 (23,4/88,8 = 26,35% < 30)
#            ESCAPA — vai para o what-cannot-be-claimed;
#          P-R6-05 RESOLVIDO: as 3 causas ENDEREÇADAS: (1) esperado
#            INDEPENDENTE de inverter_on (com 1 OFF: esperado mantém
#            48,84, div ~13,5% em vez de 0,0); (2) a regra arma também
#            por shutdown remote s/WO (remote_shutdown_change); (3)
#            snapshot contínuo pós-shutdown/resume com dedupe
#            determinístico (partilhado com a transição de banda);
#          P-R6-06 CONFIRMADO: o floor AGUENTA IGUAL (3.ª fatia 20% →
#            409 min_emergency_soc_floor + BELOW-FLOOR ×12, SoC
#            intacto) E o cenário tem o multiday ×12 count 24 (o
#            padrão (d) já tinha disparado antes da 3.ª fatia);
#          P-R6-07 RESOLVIDO (NOVO, só V07): NEG intacto — shutdown
#            COM work-order → 0 CRIT capacity (snapshots saem como
#            EVIDÊNCIA neutra, o armar é que discrimina); P(f) autónomo
#            de frota inteira → 0 CRIT (esperado desconta o P(f)).
#   v0.2.1 (13-11, ERRATA DE DISPLAY, correção datada): a linha de
#        evidência V07 do P-R6-06 (nova nesta versão) repetia a MESMA
#        gralha da v0.2 — "40%%+34,9%% somados > 70%%" LITERAL numa
#        string SEM operador de formatação. Corrigido para
#        "40%+34,9% somados > 70%". O run 2 v0.2 contra a v0.7 deu
#        7/7 com 0 previsões erradas e o critério estava CERTO (a
#        gralha era só de display); o output foi PRESERVADO como
#        sunstrike_probes_v07_r6_run2_errata.txt e a corrida foi
#        refeita com a correção. GATEFALL OFICIAL (run 1 contra a
#        v0.6, hash 3853d46b…/e8739d2a…) NÃO é afectado.
#   v0.3.1 (13-11, PERDIDO no incidente INFRA-2026-13-11-B ~18:23 —
#        registado aqui pela continuidade, do registo da conversa):
#        TRI-TARGET (V06/V07/V071, deteção por hash) construído sobre
#        a v0.2.1 — +alvo V071 (lab 00e2254f…), GATEFALL_V071
#        pré-registado ANTES da corrida: P-R6-01/02/03 RESOLVIDO-
#        VISIBILIDADE com D-BATTERY-DRAIN-TO-LOW count 12/12/5 (a
#        fatia do dia 2 ATERRA 25,1 <= 35; no NUVEM só os 5 devs que
#        ficam a 60 aterram <= 35), P-R6-04 RESOLVIDO CRIT capacity +
#        WARN D-REMOTE-SHUTDOWN-NO-WO count 5 (resíduo top-2: 0 CRIT +
#        WARN count 2), P-R6-05 RESOLVIDO, P-R6-06 CONFIRMADO 409 +
#        BELOW-FLOOR + DRAIN-TO-LOW count 12, P-R6-07 RESOLVIDO com a
#        WO VÁLIDA WO-20261112-MNT1 (a WO-20261113-R7 inventada da
#        v0.2.1 daria 403 com o F-C13 — no NEG o shutdown tem de
#        EXECUTAR) → 200×5, 0 CRIT, 0 WARN. RUN vs v0.7.1: 7/7, 0
#        erradas, RC=0. O ficheiro (d8809a9a…) e o output foram
#        PERDIDOS no reset.
#   v0.4 (13-11, RECONSTRUÇÃO datada pós-INFRA-2026-13-11-B): ESTE
#        ficheiro. O lab v0.7.1 foi RESTAURADO por REPLAY dos scripts
#        de edição preservados + errata J5 re-aplicada (hash NOVO
#        72c894fe…, comportamento IDÊNTICO — selftest re-executado
#        BYTE-IDÊNTICO afb98d0c…). Previsões V071 = as MESMAS do
#        v0.3.1 perdido (do GO à v0.7.1), RE-REGISTADAS na constante
#        GATEFALL_V071 deste ficheiro ANTES de qualquer corrida. O run
#        RE-EXECUTADO com este probe é o OFICIAL da recuperação
#        (não-regressão R6 vs v0.7.1).
# ---------------------------------------------------------------------------

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

EXPECTED_LAB_SHA256_V06 = ("698b8cff89cb87c57ef7cbe46254af960346025a2"
                           "0f7eb4823334cc3d04b3464")
EXPECTED_LAB_SHA256_V07 = ("d3af0d28715d7cdc25783075ec71530f46055b1653bc"
                           "6e961f0403bf6653b663")
# v0.5 (13-11, GO à v0.7.2 ~19:30): alvo NOVO V072 — quad-target. A
# lista V072 é pré-registada ANTES do run de não-regressão: cópia da
# V071 EXCETO P-R6-07 — o top-5 COM MNT1 (58,22% ≥ 30) ganha o CRIT
# D-MASS-SHUTDOWN-WITH-WO (F-C15b) POR DESIGN do GO à v0.7.2: o
# cenário deixa de ser NEG silencioso e fica DECLARADO (capacity
# segue 0: o arming s/WO mantém; WARN s/WO segue 0: WO válida).
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")
if lab_sha == EXPECTED_LAB_SHA256_V06:
    TARGET = "V06"
elif lab_sha == EXPECTED_LAB_SHA256_V07:
    TARGET = "V07"
elif lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "V071"
elif lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "V072"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe só corre contra a v0.6 (%s…), a v0.7 (%s…), "
          "a v0.7.1 restaurada (%s…) ou a v0.7.2 (%s…).\n"
          "  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V06[:16],
             EXPECTED_LAB_SHA256_V07[:16],
             EXPECTED_LAB_SHA256_V071[:16],
             EXPECTED_LAB_SHA256_V072[:16]))
    raise SystemExit(2)
IS_V07 = TARGET in ("V07", "V071", "V072")
IS_V071 = TARGET in ("V071", "V072")
IS_V072 = TARGET == "V072"

# regra de VISIBILIDADE do atacante (d) pré-apagão, por alvo: na v0.7 é
# a MULTIDAY de VOLUME (count 24: 12 devs × 2 fatias-contadas); na
# v0.7.1 a regra foi SUBSTITUÍDA pela DRAIN-TO-LOW (SoC RESULTANTE) —
# só a fatia do dia 2 ATERRA 25,1 <= 35 → count 12 (no NUVEM, só os
# 5 devs que ficam a 60 aterram <= 35 → count 5)
VIS_DRAIN = ("D-BATTERY-MULTIDAY-DRAIN", 24) if not IS_V071 \
    else ("D-BATTERY-DRAIN-TO-LOW", 12)
VIS_DRAIN_NUVEM = VIS_DRAIN if not IS_V071 \
    else ("D-BATTERY-DRAIN-TO-LOW", 5)

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R6 v0.4 (tri-target V06/V07/V071; reconstrucao "
      "pos-incidente INFRA-2026-13-11-B) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS (constantes hash-verificáveis)
# ---------------------------------------------------------------------------
GATEFALL_V06 = [
    {"id": "P-R6-01", "expected": "CONFIRMADO", "finding": "K1",
     "prev": ("CONFIRMADO — o limite diário trava o RITMO, não o TOTAL: "
              "atacante paciente SEM dia de sol (fatias 40% + 34,9%, +25 h "
              "de relógio) → 200×12 nos dois dias, SoC ~25,10 nos 12, ZERO "
              "alertas antes do apagão; apagão NOITE: 1 h 9/12, 2 h 3/12")},
    {"id": "P-R6-02", "expected": "CONFIRMADO", "finding": "K1-curva",
     "prev": ("CONFIRMADO — curva do atacante (d) na v0.6: served "
              "[30: 12, 60: 9, 90: 6, 120: 3, 180: 0], SoC min [9,47; "
              "5,00; 5,00; 5,00; 5,00], minutos de luz = 12,06·kwp com "
              "clamp (3,2/3,8/4,4 kWp = 38,59/45,83/53,06 min)")},
    {"id": "P-R6-03", "expected": "CONFIRMADO", "finding": "K1-nuvem",
     "prev": ("CONFIRMADO — com dia NUVEM intermédio (12 h step_grid a "
              "NUVEM: só kwp ≥ 6,8 recarrega; 6,8 → 83,53, ≥ 7,5 → cap "
              "100): dia 2 34,9% executa em todos (SoC [25,1; 48,63; "
              "65,1]); apagão: 1 h 9/12, 2 h 7/12")},
    {"id": "P-R6-04", "expected": "CONFIRMADO", "finding": "C12",
     "prev": ("CONFIRMADO — top-5 por kWp (devs 4, 11, 0, 8, 3 = 58,2% da "
              "potência) desligado via service token → ZERO alertas, "
              "divergência 0,0%, nenhum snapshot com div > 0: a regra é "
              "CEGA a shutdowns")},
    {"id": "P-R6-05", "expected": "CONFIRMADO", "finding": "C12-causas",
     "prev": ("CONFIRMADO — as 3 causas: (1) pv_gross_kw() = 0 com o "
              "inversor OFF (esperado e real descem juntos); (2) o armar "
              "da regra só conhece param_change export_limit remote sem "
              "work-order; (3) o snapshot contínuo só sai em transição "
              "de banda")},
    {"id": "P-R6-06", "expected": "CONFIRMADO", "finding": "floor",
     "prev": ("CONFIRMADO — o floor aguenta: 3.ª fatia de 20% a partir de "
              "SoC 25,1 → 409 min_emergency_soc_floor + BELOW-FLOOR ×12, "
              "SoC intacto (floor verificado ANTES do daily)")},
]
GATEFALL_V07 = [
    {"id": "P-R6-01", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1",
     "prev": ("RESOLVIDO-VISIBILIDADE — a física NÃO muda (200×12 nos "
              "dois dias, SoC ~25,10, ZERO 409) e o served é o mesmo "
              "(1 h 9/12, 2 h 3/12), mas o scan pré-apagão passa de ZERO "
              "alertas para D-BATTERY-MULTIDAY-DRAIN ×12 (count 24) em "
              "cada sub-cenário: a v0.7 DETETA, não previne")},
    {"id": "P-R6-02", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1-curva",
     "prev": ("RESOLVIDO-VISIBILIDADE — curva IGUAL (served [12, 9, 6, "
              "3, 0], SoC min [9,47; 5,00; 5,00; 5,00; 5,00], minutos "
              "12,06·kwp) + multiday ×12 count 24 pré-apagão nas 5 "
              "durações")},
    {"id": "P-R6-03", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1-nuvem",
     "prev": ("RESOLVIDO-VISIBILIDADE — NUVEM igual (6,8→83,53, ≥7,5→"
              "cap 100, ≤6,0 ficam 60; 1 h 9/12, 2 h 7/12) + multiday "
              "×12 count 24 pré-apagão (74,9 > 70 em 2 dias em TODOS)")},
    {"id": "P-R6-04", "expected": "RESOLVIDO", "finding": "C12",
     "prev": ("RESOLVIDO — top-5 (58,2% kWp) desligado → D-CAPACITY-"
              "DIVERGENCE DISPARA (div 58,2% ≥ 30: o esperado 48,84 kW "
              "MANTÉM com os inversores OFF, o real cai a 20,44 kW); "
              "resíduo top-2 (26,35% < 30) ESCAPA (declarado)")},
    {"id": "P-R6-05", "expected": "RESOLVIDO", "finding": "C12-causas",
     "prev": ("RESOLVIDO — as 3 causas endereçadas: (1) esperado "
              "INDEPENDENTE de inverter_on (1 OFF: esperado mantém "
              "48,84 kW, div ~13,5% em vez de 0,0); (2) armar também "
              "por shutdown remote s/WO; (3) snapshot contínuo pós-"
              "shutdown/resume com dedupe determinístico")},
    {"id": "P-R6-06", "expected": "CONFIRMADO", "finding": "floor",
     "prev": ("CONFIRMADO — o floor aguenta IGUAL (3.ª fatia de 20% → "
              "409 min_emergency_soc_floor + BELOW-FLOOR ×12, SoC "
              "intacto) E o cenário tem o multiday ×12 count 24 (o "
              "padrão (d) disparou antes da 3.ª fatia)")},
    {"id": "P-R6-07", "expected": "RESOLVIDO", "finding": "C12-NEG",
     "prev": ("RESOLVIDO — NEG intacto: shutdown COM work-order → 0 "
              "CRIT capacity (snapshots saem como EVIDÊNCIA neutra; o "
              "ARMAR é que discrimina por work-order); P(f) autónomo "
              "de frota inteira → 0 CRIT (o esperado desconta o P(f))")},
]

# GATEFALL V071 — RE-REGISTADO neste ficheiro (v0.4) ANTES de qualquer
# corrida contra a v0.7.1 restaurada (72c894fe…): as MESMAS previsões
# do v0.3.1 perdido (GO à v0.7.1; reconstrução pós-INFRA-B).
GATEFALL_V071 = [
    {"id": "P-R6-01", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1",
     "prev": ("RESOLVIDO-VISIBILIDADE — a física NÃO muda (200×12 nos "
              "dois dias, SoC ~25,10, ZERO 409) e o served é o mesmo "
              "(1 h 9/12, 2 h 3/12), mas o scan pré-apagão passa de "
              "ZERO alertas para D-BATTERY-DRAIN-TO-LOW ×12 (count 12: "
              "a fatia do dia 2 ATERRA 25,1 <= 35) em cada "
              "sub-cenário: a v0.7.1 DETETA o ESTADO resultante")},
    {"id": "P-R6-02", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1-curva",
     "prev": ("RESOLVIDO-VISIBILIDADE — curva IGUAL (served [12, 9, 6, "
              "3, 0], SoC min [9,47; 5,00; 5,00; 5,00; 5,00], minutos "
              "12,06·kwp) + DRAIN-TO-LOW ×12 (count 12) pré-apagão "
              "nas 5 durações")},
    {"id": "P-R6-03", "expected": "RESOLVIDO-VISIBILIDADE",
     "finding": "K1-nuvem",
     "prev": ("RESOLVIDO-VISIBILIDADE — NUVEM igual (6,8→83,53, ≥7,5→"
              "cap 100, ≤6,0 ficam 60; 1 h 9/12, 2 h 7/12) + "
              "DRAIN-TO-LOW count 5 pré-apagão (só os 5 devs ≤ 6,0 "
              "kwp FICAM a 60 e a fatia de 34,9% os ATERRA a 25,1 <= "
              "35; os recarregados aterram 48,63/65,1 > 35)")},
    {"id": "P-R6-04", "expected": "RESOLVIDO", "finding": "C12",
     "prev": ("RESOLVIDO — top-5 (58,2% kWp) desligado → "
              "D-CAPACITY-DIVERGENCE CRIT (div 58,2% >= 30; esperado "
              "48,84 kW MANTÉM, real cai a 20,44 kW) + WARN "
              "D-REMOTE-SHUTDOWN-NO-WO count 5 (F-C14: visível < k=6); "
              "resíduo top-2 (26,35% < 30) ESCAPA ao CRIT MAS ganha "
              "WARN count 2 (declarado)")},
    {"id": "P-R6-05", "expected": "RESOLVIDO", "finding": "C12-causas",
     "prev": ("RESOLVIDO — as 3 causas continuam ENDEREÇADAS na "
              "v0.7.1 (o código do F-C12 é INALTERADO pelo F-C13/F-K1/"
              "F-C14/F-SP): (1) esperado INDEPENDENTE de inverter_on "
              "(1 OFF: esperado mantém 48,84 kW, div ~13,5%); (2) "
              "armar também por shutdown remote s/WO; (3) snapshot "
              "contínuo pós-shutdown/resume com dedupe "
              "determinístico")},
    {"id": "P-R6-06", "expected": "CONFIRMADO", "finding": "floor",
     "prev": ("CONFIRMADO — o floor aguenta IGUAL (3.ª fatia de 20% → "
              "409 min_emergency_soc_floor + BELOW-FLOOR ×12, SoC "
              "intacto) E o cenário tem o D-BATTERY-DRAIN-TO-LOW "
              "×12 (count 12: a fatia do dia 2 ATERRA 25,1 <= 35 "
              "antes da 3.ª fatia)")},
    {"id": "P-R6-07", "expected": "RESOLVIDO", "finding": "C12-NEG",
     "prev": ("RESOLVIDO — NEG intacto COM WO VÁLIDA WO-20261112-MNT1 "
              "(a WO inventada da v0.2.1 daria 403 com o F-C13: no NEG "
              "o shutdown tem de EXECUTAR): shutdown COM WO válida → "
              "200×5, 0 CRIT capacity, 0 WARN D-REMOTE-SHUTDOWN-NO-WO "
              "(a regra não conta shutdowns COM WO válida); P(f) "
              "autónomo de frota inteira → 0 CRIT")},
]
GATEFALL_V072 = [dict(e) for e in GATEFALL_V071]
for e in GATEFALL_V072:
    if e["id"] == "P-R6-07":
        e["prev"] = ("RESOLVIDO-DECLARADO — v0.7.2/F-C15b (pré-registado "
                     "v0.5 ANTES do run): o top-5 COM WO VÁLIDA "
                     "WO-20261112-MNT1 continua a EXECUTAR (200×5; "
                     "âmbito frota inteira) com 0 CRIT capacity e 0 "
                     "WARN s/WO (mecanismos C12/C14 intactos), MAS ganha "
                     "o CRIT D-MASS-SHUTDOWN-WITH-WO count 5 (5 < k MAS "
                     "58,22% ≥ 30) POR DESIGN do GO à v0.7.2 — o "
                     "cenário que na v0.7.1 era NEG silencioso passa a "
                     "alertar e fica DECLARADO (manutenção legítima de "
                     "alta capacidade com WO de âmbito correto é o "
                     "trade-off declarado); P(f) autônomo de frota "
                     "inteira → 0 CRIT mantém")
GATEFALL = (GATEFALL_V072 if IS_V072
            else (GATEFALL_V071 if TARGET == "V071"
                  else (GATEFALL_V07 if IS_V07 else GATEFALL_V06)))

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS (antes de qualquer execução)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
if IS_V071:
    print("ESTE É O RUN de NÃO-REGRESSÃO contra a v0.7.1 RESTAURADA "
          "(reconstrução pós-INFRA-2026-13-11-B; probe v0.4): o lab "
          "foi restaurado por REPLAY dos edit scripts preservados + "
          "errata J5 (72c894fe…; selftest BYTE-IDÊNTICO afb98d0c…). "
          "GATEFALL V071 pré-registado acima. O que verifica: o "
          "F-K1 SUBSTITUI a MULTIDAY pela DRAIN-TO-LOW (SoC "
          "RESULTANTE <= 35: o atacante (d) fica VISÍVEL count 12, "
          "no NUVEM count 5), o F-C14 dá WARN por shutdown s/WO "
          "(top-5 count 5; top-2 count 2), o F-C12 mantém-se "
          "(C12 intacto), o floor mantém-se e o NEG exige WO VÁLIDA "
          "(F-C13). O GATEFALL OFICIAL da R6 mantém-se o RUN 1 contra "
          "a v0.6 INTOCADA (6/6 CONFIRMADO, output preservado).\n")
elif IS_V07:
    print("ESTE É O RUN 2 (o DEPOIS): verificação da v0.7 (F-C12: "
          "esperado independente de inverter_on + armar por shutdown + "
          "snapshot pós-shutdown/resume; F-K1: D-BATTERY-MULTIDAY-DRAIN, "
          "21.ª regra, visibilidade do padrão multi-dia SEM prevenção "
          "nova; F-LIMP: docstrings, SIM_CLOCK_OFFSET por braço, banner "
          "SUNBOX/0.7, liveness 21/21). O GATEFALL OFICIAL da R6 foi o "
          "RUN 1 contra a v0.6 INTOCADA (6/6 CONFIRMADO, output "
          "preservado). C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a "
          "v0.8.\n")
else:
    print("ORDEM VINCULATIVA DO GO (13-11 15:30): o GATEFALL OFICIAL "
          "da R6 é o RUN 1 desta bateria contra a v0.6 INTOCADA (com "
          "as previsões erradas que saírem, sejam defeitos do probe ou "
          "achados reais), NUNCA o run seguinte. A v0.7 (F-C12: "
          "esperado independente de inverter_on + armar por shutdown + "
          "snapshot pós-shutdown/resume; F-K1: D-BATTERY-MULTIDAY-DRAIN, "
          "21.ª regra, visibilidade do padrão multi-dia SEM prevenção "
          "nova; F-LIMP: docstrings, SIM_CLOCK_OFFSET por braço, banner "
          "SUNBOX/0.7, liveness 21/21) é o DEPOIS; o run 2 contra a "
          "v0.7 verifica o DEPOIS. C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam "
          "para a v0.8.\n")

# ---------------------------------------------------------------------------
# Helpers
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
    dos probes R5): stepping de 60 s com fração EXATA do minuto em que a luz
    apaga (física linear em NOITE: drop = 100/kwp pontos/hora)."""
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


def blackout(lab):
    """Apagão noturno determinístico por harness (padrão do measure)."""
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)


def attack_d(lab, scen, nuvem_mid=False):
    """Atacante (d) — K1 (GO 13-11 15:30): paciente, SEM dia de sol, FATIAS
    PURAS (a direta 999 NÃO faz parte — padrão do supervisor). Dia 1:
    fatia 40% (executa: 100→60, ledger 40). +25 h de relógio de simulação
    (janela diária INCLUSIVA de 24 h expira; SEM step_grid). Dia 2:
    fatia 34,9% (o máximo que passa o floor a partir de 60: 60−34,9 = 25,1
    ≥ 25; e ≤ 40 do limite diário com o ledger expirado) → SoC ~25,1.
    nuvem_mid=True: 12 h de step_grid a NUVEM entre os dias (só kwp ≥ 6,8
    recarrega; o resto fica a 60). Devolve contagens e o scan dos alertas
    ANTES do apagão."""
    L.SIM_CLOCK_OFFSET = 0.0        # cada corrida começa um "dia 1" novo
    slices_d1, slices_d2 = [], []

    def day(frac):
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
    slices_d1 = day(0.40)
    soc_d1 = (round(min(d.soc for d in lab.devices), 2),
              round(max(d.soc for d in lab.devices), 2))
    if nuvem_mid:
        lab.gridsim.set_irradiance("NUVEM")
        time.sleep(0.2)
        for d in lab.devices:
            d.step_grid(12 * 3600.0)
    # SEM dia de sol: nada entre os dias; noite cartoon + avanço do relógio
    lab.gridsim.set_irradiance("NOITE")
    L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
    slices_d2 = day(0.349)
    soc_d2 = (round(min(d.soc for d in lab.devices), 2),
              round(max(d.soc for d in lab.devices), 2))
    pre = scan_scenario(lab, scen)
    return {"slices_d1": slices_d1, "slices_d2": slices_d2,
            "soc_d1": soc_d1, "soc_d2": soc_d2, "pre_alerts": pre}


def served_count(lab):
    return sum(1 for d in lab.devices
               if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("lab v%s em memoria (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))
    try:
        # ================= P-R6-01 — K1: ritmo vs total ================
        print("[P-R6-01] K1 — o limite diário trava o RITMO, não o TOTAL")
        results_01 = {}
        for sub, dur, exp_served in (("a", 60, 9), ("b", 120, 3)):
            scen = "P-R6-01%s" % sub
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            atk = attack_d(lab, scen)
            zero_alerts = len(atk["pre_alerts"]) == 0
            pre01 = [(a["rule"], a["count"]) for a in atk["pre_alerts"]]
            vis_ok = (zero_alerts if not IS_V07
                      else (len(pre01) == 1 and pre01[0] == VIS_DRAIN))
            blackout(lab)
            minutes = [sweep_minutes(d, dur) for d in lab.devices]
            served = served_count(lab)
            soc_min = round(min(d.soc for d in lab.devices), 2)
            results_01[sub] = (atk, vis_ok, served, soc_min, minutes)
            print("    %s: d1 40%% → %s (SoC %s); +25 h SEM sol; d2 34,9%% "
                  "→ %s (SoC %s); alertas pré-apagão: %s; apagão %d min: "
                  "served %d/12, SoC min %.2f"
                  % (scen,
                     "200×12" if all(s == 200 for s in atk["slices_d1"])
                     else atk["slices_d1"], atk["soc_d1"],
                     "200×12" if all(s == 200 for s in atk["slices_d2"])
                     else atk["slices_d2"], atk["soc_d2"],
                     [(a["rule"], a["count"]) for a in atk["pre_alerts"]]
                     or "ZERO", dur, served, soc_min))
        atk_a, vis_a, served_a, soc_min_a, minutes_a = results_01["a"]
        atk_b, vis_b, served_b, soc_min_b, minutes_b = results_01["b"]
        cond_01 = (all(s == 200 for s in atk_a["slices_d1"]
                       + atk_a["slices_d2"] + atk_b["slices_d1"]
                       + atk_b["slices_d2"])
                  and 59.99 <= atk_a["soc_d1"][0]
                  and atk_a["soc_d1"][1] <= 60.01
                  and 25.05 <= atk_a["soc_d2"][0]
                  and atk_a["soc_d2"][1] <= 25.15
                  and vis_a and vis_b
                  and served_a == 9 and served_b == 3)
        expect("P-R6-01", GATEFALL[0]["prev"], cond_01,
               "RESOLVIDO-VISIBILIDADE" if IS_V07 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["dia 1 fatia 40%%: 200 em todos, SoC %s (ledger 40%%/disp); "
                "+25 h de SIM_CLOCK_OFFSET (janela INCLUSIVA de 24 h "
                "expira — o ledger diário NÃO trava o dia 2)"
                % (atk_a["soc_d1"],),
                "dia 2 fatia 34,9%% (máximo que passa o floor a partir "
                "de 60: 60−34,9 = 25,1 ≥ 25): 200 em todos, SoC %s — o "
                "atacante paciente chega ao floor SEM recarga e SEM "
                "alerta nenhum" % (atk_a["soc_d2"],),
                ("alertas ANTES do apagão: %s ×12 (count %d) em CADA "
                 "sub-cenário — %s"
                 % (VIS_DRAIN[0], VIS_DRAIN[1],
                    ("a v0.7.1 (F-K1) DETETA o ESTADO resultante: SoC "
                     "RESULTANTE <= 35 após a fatia do dia 2 (a do dia 1 "
                     "ATERRA 60 > 35 e NÃO conta); a física é a mesma; "
                     "a cumulativa continua evadida pelo espaçamento de "
                     "25 h — C11 ABERTO"
                     if IS_V071 else
                     "a v0.7 dá VISIBILIDADE ao padrão multi-dia; a "
                     "física é a mesma (a cumulativa continua evadida "
                     "pelo espaçamento de 25 h — C11 ABERTO)"))
                 if IS_V07 else
                 ("alertas ANTES do apagão: %s e %s — a cumulativa "
                  "(janela 3600 s) é evadida pelo espaçamento de 25 h "
                  "(C11 ABERTO), a large não vê fatias <50%% e o daily "
                  "só vê >40%%/24 h"
                  % ("ZERO" if vis_a else "HÁ",
                     "ZERO" if vis_b else "HÁ"))),
                "apagão NOITE 1 h: served %d/12 (prev 9) — as casas "
                "3,2/3,8/4,4 kWp apagam dentro da hora (SoC min %.2f, "
                "clamp 5,0); minutos das 3: %s"
                % (served_a, soc_min_a,
                   [round(m, 1) for m in minutes_a
                    if m < 60.0]),
                "apagão NOITE 2 h: served %d/12 (prev 3) — só "
                "10,5/11,4/12,0 kWp passam os 120 min (= o v0.5 SEM "
                "defesa nenhuma: o limite diário NÃO muda este resultado, "
                "só o ritmo)" % (served_b,)])

        # ================= P-R6-02 — K1: curva do (d) =================
        print("\n[P-R6-02] K1 — curva de durações do atacante (d)")
        durs = [30, 60, 90, 120, 180]
        exp_served = [12, 9, 6, 3, 0]
        exp_socmin = [9.47, 5.00, 5.00, 5.00, 5.00]
        kwp_order = [d.kwp for d in lab.devices]
        full = [round(12.06 * k, 2) for k in kwp_order]  # 12,06 = (25,1−5)·0,6
        exp_minutes = {d: [min(m, float(d)) for m in full] for d in durs}
        curve_ok, curve_lines = True, []
        for dur, es, emin in zip(durs, exp_served, exp_socmin):
            scen = "P-R6-02-%03d" % dur
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            atk = attack_d(lab, scen)
            zero_alerts = len(atk["pre_alerts"]) == 0
            pre02 = [(a["rule"], a["count"]) for a in atk["pre_alerts"]]
            vis_ok = (zero_alerts if not IS_V07
                      else (len(pre02) == 1 and pre02[0] == VIS_DRAIN))
            blackout(lab)
            minutes = [sweep_minutes(d, dur) for d in lab.devices]
            served = served_count(lab)
            soc_min = round(min(d.soc for d in lab.devices), 2)
            mins_ok = all(abs(m - e) <= 0.2
                          for m, e in zip(minutes, exp_minutes[dur]))
            run_ok = (all(s == 200 for s in atk["slices_d1"]
                          + atk["slices_d2"])
                      and 25.05 <= atk["soc_d2"][0]
                      and atk["soc_d2"][1] <= 25.15
                      and vis_ok and served == es
                      and abs(soc_min - emin) <= 0.05 and mins_ok)
            curve_ok = curve_ok and run_ok
            curve_lines.append(
                "    %3d min: served %2d/12 (prev %2d), SoC min %6.2f "
                "(prev %6.2f), minutos/casa %s"
                % (dur, served, es, soc_min, emin,
                   [round(m, 1) for m in minutes]))
        print("\n".join(curve_lines))
        expect("P-R6-02", GATEFALL[1]["prev"], curve_ok,
               "RESOLVIDO-VISIBILIDADE" if IS_V07 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver tabela acima)",
               ["curva medida: served %s (prev [12, 9, 6, 3, 0])"
                % exp_served,
                "SoC min %s (prev [9,47; 5,00; 5,00; 5,00; 5,00])"
                % exp_socmin,
                "minutos = 12,06·kwp (o mesmo perfil do braço v0.5 da "
                "curva (b): a partir de 25,1 com ilha até 5,0 a luz dura "
                "(25,1−5)·0,6·kwp; a 1 h falham 3,2/3,8/4,4 kWp = "
                "38,59/45,83/53,06 min — os 40/48/55 do J2)",
                "consequência (K1): os \"12/12 a 1 h\" e \"11/12 a 2 h\" "
                "da v0.6 com dia de sol NÃO valem aqui — sem recarga, o "
                "atacante paciente reproduz a curva do v0.5"])

        # ================= P-R6-03 — K1: dia NUVEM intermédio =========
        print("\n[P-R6-03] K1 — dia NUVEM intermédio (recarga parcial)")
        results_03 = {}
        for sub, dur, exp_served in (("a", 60, 9), ("b", 120, 7)):
            scen = "P-R6-03%s" % sub
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            atk = attack_d(lab, scen, nuvem_mid=True)
            soc_after_sun = (round(min(d.soc for d in lab.devices), 2),
                             round(max(d.soc for d in lab.devices), 2))
            zero_alerts = len(atk["pre_alerts"]) == 0
            pre03 = [(a["rule"], a["count"]) for a in atk["pre_alerts"]]
            vis_ok = (zero_alerts if not IS_V07
                      else (len(pre03) == 1
                            and pre03[0] == VIS_DRAIN_NUVEM))
            blackout(lab)
            minutes = [sweep_minutes(d, dur) for d in lab.devices]
            served = served_count(lab)
            results_03[sub] = (atk, soc_after_sun, vis_ok, served,
                               minutes)
            print("    %s: d1 40%% → SoC %s; NUVEM 12 h → SoC %s; +25 h; "
                  "d2 34,9%% → %s (SoC %s); apagão %d min: served %d/12"
                  % (scen, atk["soc_d1"], soc_after_sun,
                     "200×12" if all(s == 200 for s in atk["slices_d2"])
                     else atk["slices_d2"], atk["soc_d2"], dur, served))
        atk_a, sun_a, vis_a3, served_a3, minutes_a3 = results_03["a"]
        atk_b, sun_b, vis_b3, served_b3, minutes_b3 = results_03["b"]
        cond_03 = (all(s == 200 for s in atk_a["slices_d1"]
                       + atk_a["slices_d2"] + atk_b["slices_d1"]
                       + atk_b["slices_d2"])
                  and vis_a3 and vis_b3
                  and served_a3 == 9 and served_b3 == 7)
        expect("P-R6-03", GATEFALL[2]["prev"], cond_03,
               "RESOLVIDO-VISIBILIDADE" if IS_V07 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["NUVEM (irr 0,20): só kwp ≥ 6,8 tem excedente "
                "(kwp·0,2 > 1,2): o 6,8 recarrega 60→83,53; os ≥ 7,5 "
                "fazem cap 100; os ≤ 6,0 FICAM a 60 (sem carga)"
                % (),
                "dia 2 fatia 34,9%%: executa em TODOS (60−34,9 = 25,1 ≥ "
                "floor; 83,53−34,9 = 48,63; 100−34,9 = 65,1) → SoC fim "
                "dia 2 %s" % (atk_a["soc_d2"],),
                "apagão 1 h: served %d/12 (prev 9) — passam 5,4 (65,12 "
                "min), 6,0 (72,36), 6,8 (178,0) e os seis ≥ 7,5; 2 h: "
                "served %d/12 (prev 7) — passam 6,8 (178,0) e os seis "
                "≥ 7,5 (≥ 270 min)" % (served_a3, served_b3),
                "números do supervisor (9/12 a 1 h, 7/12 a 2 h) "
                "confirmados pela física: o dia NUVEM recarrega SÓ os "
                "grandes, e o 6,8 kWp é a casa que muda de lado"])

        # ================= P-R6-04 — C12: top-5 shutdown ==============
        print("\n[P-R6-04] C12 — D-CAPACITY-DIVERGENCE cega a shutdowns")
        scen = "P-R6-04"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        ranked = sorted(range(len(lab.devices)),
                        key=lambda i: lab.devices[i].kwp, reverse=True)[:5]
        kwp_top5 = sum(lab.devices[i].kwp for i in ranked)
        kwp_total = sum(d.kwp for d in lab.devices)
        sts = []
        for i in ranked:
            d = lab.devices[i]
            st, resp = hj(d.port, "POST", "/mode",
                          {"action": "inverter_power_off"},
                          token=d.service_token)
            sts.append((i, st))
        time.sleep(0.6)     # o publish loop recalcula a divergência
        alerts = scan_scenario(lab, scen)
        capdiv = [a for a in alerts if a["rule"] == "D-CAPACITY-DIVERGENCE"]
        waves = [a for a in alerts
                 if a["rule"] in ("D-FLEET-SHUTDOWN-WAVE", "D-SLOW-WAVE")]
        snaps = [e for e in scenario_events(lab, scen)
                 if e.get("event") == "capacity_snapshot"]
        divs = [s.get("divergence_pct", 0.0) for s in snaps]
        exp_kw, act_kw, div_direct = L.capacity_divergence_pct(lab.devices)
        if IS_V07:
            # v0.7/F-C12: o esperado MANTÉM com os inversores OFF → a
            # regra VÊ os kWp desligados (58,2% ≥ 30: DISPARA)
            cond_04 = (all(st == 200 for _, st in sts)
                       and len(capdiv) >= 1 and len(waves) == 0
                       and len(snaps) >= 1
                       and max(divs) >= 30.0
                       and 55.0 <= div_direct <= 60.0)
            ev_04 = ["top-5 por kWp desligado por service token (5 < "
                     "WAVE_K: sem onda, sem slow-wave): devs %s = "
                     "%.1f/%.1f kWp = %.1f%% da potência — todos 200"
                     % (ranked, kwp_top5, kwp_total,
                        kwp_top5 / kwp_total * 100.0),
                     "divergência DIRETA: esperado %.2f kW MANTÉM "
                     "(independente de inverter_on), real %.2f kW → div "
                     "%.2f%% ≥ 30: a regra VÊ os kWp desligados "
                     "(F-C12 a: kwp × irr × (1 − curtail_aut/100))"
                     % (exp_kw, act_kw, div_direct),
                     "snapshots do cenário: %s (div máx %.2f%%) — "
                     "contínuos após CADA shutdown remoto (F-C12 c, "
                     "dedupe determinístico; nunca só por transição de "
                     "banda)"
                     % (len(snaps), max(divs) if divs else 0.0),
                     "alertas do cenário: %s — D-CAPACITY-DIVERGENCE "
                     "DISPARA: o design §4.4/R3 cumpre agora o subset "
                     "targeting (C12 endereçado)"
                     % ([(a["rule"], a["count"]) for a in alerts]
                        or "ZERO")]
            # sub-cenário R: o resíduo top-2 (26,35% < 30) ESCAPA
            scen = "P-R6-04R"
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            res_ranked = sorted(range(len(lab.devices)),
                               key=lambda i: lab.devices[i].kwp,
                               reverse=True)[:2]
            kwp_top2 = sum(lab.devices[i].kwp for i in res_ranked)
            res_sts = []
            for i in res_ranked:
                d = lab.devices[i]
                st, _ = hj(d.port, "POST", "/mode",
                           {"action": "inverter_power_off"},
                           token=d.service_token)
                res_sts.append(st)
            time.sleep(0.6)
            res_alerts = scan_scenario(lab, scen)
            res_capdiv = [a for a in res_alerts
                          if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            res_snaps = [e for e in scenario_events(lab, scen)
                         if e.get("event") == "capacity_snapshot"]
            res_divs = [sn.get("divergence_pct", 0.0) for sn in res_snaps]
            exp_r, act_r, div_r = L.capacity_divergence_pct(lab.devices)
            res_max = max(res_divs) if res_divs else 0.0
            nowo04 = [a for a in alerts
                      if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            res_nowo = [a for a in res_alerts
                        if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            cond_04 = (cond_04
                       and all(st == 200 for st in res_sts)
                       and len(res_capdiv) == 0
                       and 25.5 <= res_max <= 27.5
                       and 25.5 <= div_r <= 27.5
                       # v0.7.1/F-C14: WARN por shutdown remoto s/WO
                       and (not IS_V071
                            or (len(nowo04) == 1
                                and nowo04[0]["count"] == 5
                                and nowo04[0]["severity"] == "WARN"
                                and len(res_nowo) == 1
                                and res_nowo[0]["count"] == 2)))
            ev_04.append(
                "RESÍDUO (P-R6-04R): top-2 devs %s = %.1f kWp = "
                "%.2f%% < 30%% e 2 devs < k=6 → 0 D-CAPACITY-"
                "DIVERGENCE, snapshots %s div máx %.2f%% — ESCAPA e "
                "fica DECLARADO no what-cannot-be-claimed (o maior "
                "subconjunto que ainda escapa)"
                % (res_ranked, kwp_top2, kwp_top2 / kwp_total * 100.0,
                   len(res_snaps), res_max))
            if IS_V071:
                ev_04.append(
                    "v0.7.1/F-C14: os 5 shutdowns s/WO ganham WARN "
                    "D-REMOTE-SHUTDOWN-NO-WO count %d (POR EVENTO, "
                    "abaixo de k=6) e o resíduo top-2 ganha WARN count "
                    "%d — o CRIT continua a ESCAPAR ao subconjunto "
                    "< 30%% (DECLARADO), mas o WARN já VÊ"
                    % (nowo04[0]["count"] if nowo04 else 0,
                       res_nowo[0]["count"] if res_nowo else 0))
        else:
            cond_04 = (all(st == 200 for _, st in sts)
                       and len(capdiv) == 0 and len(waves) == 0
                       and not any(dv > 0.0 for dv in divs)
                       and abs(div_direct) < 0.01)
            ev_04 = ["top-5 por kWp desligado por service token (5 < "
                     "WAVE_K: sem onda, sem slow-wave): devs %s = "
                     "%.1f/%.1f kWp = %.1f%% da potência — todos 200"
                     % (ranked, kwp_top5, kwp_total,
                        kwp_top5 / kwp_total * 100.0),
                     "divergência DIRETA (capacity_divergence_pct): "
                     "esperado %.2f kW, real %.2f kW → div %.2f%% — o "
                     "esperado DESCE JUNTO com o real (pv_gross_kw() = "
                     "0 com o inversor OFF)"
                     % (exp_kw, act_kw, div_direct),
                     "snapshots do cenário: %s (divs %s) — nenhum com "
                     "div > 0; um shutdown NÃO provoca transição de "
                     "banda"
                     % (len(snaps), divs or "nenhum"),
                     "alertas do cenário: %s — ZERO D-CAPACITY-"
                     "DIVERGENCE: a regra que o design §4.4/R3 prometia "
                     "para subset targeting é CEGA a shutdowns (C12 do "
                     "supervisor, de AUD-07.3)"
                     % ([(a["rule"], a["count"]) for a in alerts]
                        or "ZERO")]
        expect("P-R6-04", GATEFALL[3]["prev"], cond_04,
               "RESOLVIDO" if IS_V07 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)", ev_04)

        # ================= P-R6-05 — C12: as 3 causas =================
        print("\n[P-R6-05] C12 — as 3 causas (1 dinâmica + 2 estáticas)")
        scen = "P-R6-05"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d4 = lab.devices[4]           # 12,0 kWp: o maior
        off_gross = d4.pv_gross_kw()  # com o inversor ON (pré-shutdown)
        st_off, _ = hj(d4.port, "POST", "/mode",
                       {"action": "inverter_power_off"},
                       token=d4.service_token)
        time.sleep(0.3)
        dyn1 = (off_gross > 0.0 and d4.pv_gross_kw() == 0.0
                and d4.export_kw() == 0.0)
        exp_all, act_all, div_all = L.capacity_divergence_pct(lab.devices)
        if IS_V07:
            # v0.7/F-C12 (a): com 1 OFF o esperado MANTÉM ~48,84 kW
            # (kwp × irr × (1 − curtail_aut/100)) → div ~13,5% > 0
            dyn2 = (47.5 <= exp_all <= 50.0 and 12.5 <= div_all <= 14.5)
        else:
            dyn2 = abs(div_all) < 0.01    # 1 OFF: esperado e real caem juntos
        src = LAB_BYTES.decode("utf-8")
        cap_fn = src[src.index("def capacity_divergence_pct"):
                     src.index("# GRIDSIM")]
        if IS_V07:
            # v0.7/F-C12 (a): o código do esperado NÃO usa pv_gross_kw()
            # (só o docstring refere o histórico da v0.6)
            cause1 = ("expected += d.pv_gross_kw()" not in cap_fn
                      and "d.irr_factor" in cap_fn
                      and "d.curtail_autonomous" in cap_fn
                      and dyn1 and dyn2)
        else:
            cause1 = ("pv_gross_kw" in cap_fn and dyn1 and dyn2)
        scan_src = src[src.index("class Detector"):src.index("def run_")]
        cap_rule_zone = scan_src[scan_src.index("capacity_snapshot"):
                                 scan_src.index("elif e == \"login_fail\"")]
        if IS_V07:
            # v0.7/F-C12 (b): o shutdown remoto s/WO ARMA a regra
            cause2 = "remote_shutdown_change" in cap_rule_zone
        else:
            cause2 = ("remote_export_change" in cap_rule_zone
                      and "shutdown" not in cap_rule_zone)
        pub_src = src[src.index("def publish"):src.index("def loop")]
        if IS_V07:
            # v0.7/F-C12 (c): snapshot partilhado + hooks pós
            # shutdown/resume remoto (dedupe determinístico)
            hook_src = src[src.index("def remote_inverter_power_off"):]
            cause3 = ("emit_capacity_snapshot" in pub_src
                      and "emit_capacity_snapshot" in hook_src
                      and "snapshot continuo apos shutdown remoto"
                      in hook_src)
        else:
            cause3 = "band != self._cap_band" in pub_src
        cond_05 = cause1 and cause2 and cause3 and st_off == 200
        expect("P-R6-05", GATEFALL[4]["prev"], cond_05,
               "RESOLVIDO" if IS_V07 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               [("CAUSA 1 ENDEREÇADA (dinâmica): dev 12,0 kWp OFF → "
                 "pv_gross %.2f, export %.2f (física INALTERADA), MAS "
                 "o esperado MANTÉM %.2f kW, independente de "
                 "inverter_on (kwp × irr × (1 − curtail_aut/100)) → "
                 "div %.2f%% > 0 (na v0.6 seria 0,0: os dois desciam "
                 "JUNTOS)"
                 % (d4.pv_gross_kw(), d4.export_kw(), exp_all, div_all)
                 if IS_V07 else
                 ("CAUSA 1 (dinâmica): dev 12,0 kWp ON → pv_gross "
                  "%.2f kW; OFF → pv_gross %.2f, export %.2f — o "
                  "esperado usa pv_gross_kw() que devolve 0 com o "
                  "inversor OFF; com 1 OFF: esperado %.2f = real "
                  "%.2f → div %.2f%% (os dois descem JUNTOS)"
                  % (off_gross, d4.pv_gross_kw(), d4.export_kw(),
                     exp_all, act_all, div_all))),
                ("CAUSA 2 ENDEREÇADA (estática): o armar tem AGORA "
                 "remote_shutdown_change — um shutdown remoto SEM "
                 "work-order ARMA a D-CAPACITY-DIVERGENCE (além do "
                 "param_change export_limit)"
                 if IS_V07 else
                 ("CAUSA 2 (estática): o armar da regra no scan só tem "
                  "remote_export_change (param_change export_limit "
                  "remote sem work-order) — NENHUMA condição de "
                  "shutdown arma a regra (o evento shutdown só conta "
                  "para as ondas)")),
                ("CAUSA 3 ENDEREÇADA (estática): snapshot contínuo "
                 "também APÓS shutdown/resume remoto via "
                 "emit_capacity_snapshot PARTILHADO com dedupe "
                 "determinístico (banda+div+nº OFF) — nunca só em "
                 "transição de banda"
                 if IS_V07 else
                 ("CAUSA 3 (estática): o snapshot contínuo do publish() "
                  "só emite em TRANSIÇÃO de banda (band != _cap_band) — "
                  "um shutdown mantém div 0 → banda 0 → transição "
                  "NENHUMA")),
                ("v0.7: as 3 causas ENDEREÇADAS = C12 fechado por "
                 "CONSTRUÇÃO e por EXECUÇÃO (ver P-R6-04)"
                 if IS_V07 else
                 "as 3 causas confirmadas = C12 por CONSTRUÇÃO (AUD-07.3 "
                 "do Gemini, executado pelo supervisor)")])

        # ================= P-R6-06 — o floor aguenta (controlo) =======
        print("\n[P-R6-06] o floor aguenta: 3.ª fatia → 409 (controlo)")
        scen = "P-R6-06"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        atk = attack_d(lab, scen)     # 2 dias → SoC ~25,1
        soc_pre3 = round(min(d.soc for d in lab.devices), 2)
        sts3, resps3 = [], []
        for i in range(len(lab.devices)):
            d = lab.devices[i]
            tok = "SUNBOX-SVC-%02d-2026" % i
            st, resp = hj(d.port, "POST", "/battery",
                          {"action": "discharge",
                           "amount_kwh": round(0.20 * d.batt_kwh, 3)},
                          token=tok)
            sts3.append(st)
            resps3.append(resp.get("error"))
        alerts = scan_scenario(lab, scen)
        below = [a for a in alerts
                 if a["rule"] == "D-BATTERY-DRAIN-BELOW-FLOOR"]
        soc_post3 = round(min(d.soc for d in lab.devices), 2)
        pre06 = [(a["rule"], a["count"]) for a in atk["pre_alerts"]]
        cond_06 = (all(s == 200 for s in atk["slices_d1"]
                       + atk["slices_d2"])
                  and all(st == 409 and e == "min_emergency_soc_floor"
                          for st, e in zip(sts3, resps3))
                  and below and below[0]["count"] == 12
                  and abs(soc_post3 - soc_pre3) < 0.01
                  and ((len(pre06) == 0) if not IS_V07
                       else (len(pre06) == 1 and pre06[0] == VIS_DRAIN)))
        ev_06 = ["3.ª fatia de 20%% a partir de SoC %.2f: 409 "
                 "min_emergency_soc_floor em TODOS (25,1−20 = 5,1 < floor "
                 "25 — verificado ANTES do daily, P-R4-04)" % (soc_pre3,),
                 "D-BATTERY-DRAIN-BELOW-FLOOR ×12 (count %s) — deteção POR "
                 "EVENTO do bloqueio; SoC intacto %.2f"
                 % (below[0]["count"] if below else 0, soc_post3)]
        if IS_V071:
            ev_06.append(
                "v0.7.1: o cenário JÁ tinha D-BATTERY-DRAIN-TO-LOW ×12 "
                "(count 12) PRÉ-apagão (a fatia do dia 2 ATERRA 25,1 "
                "<= 35 — o ESTADO resultante, F-K1; a MULTIDAY de "
                "volume foi SUBSTITUÍDA)")
        elif IS_V07:
            ev_06.append(
                "v0.7: o cenário JÁ tinha D-BATTERY-MULTIDAY-DRAIN ×12 "
                "(count 24) PRÉ-apagão (o padrão (d) disparou antes da "
                "3.ª fatia: 40%+34,9% somados > 70% em 2 dias-distintos)")
        ev_06.append(
            "consequência (K1): o atacante paciente fica PRESO no "
            "floor — o padrão 40%+34,9% é o MÁXIMO de 2 dias sem "
            "sol; a 3.ª fatia não executa nem conta no ledger")
        expect("P-R6-06", GATEFALL[5]["prev"], cond_06,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)", ev_06)

        if IS_V07:
            # ================= P-R6-07 — C12 NEG intacto ============
            print("\n[P-R6-07] C12 — NEG intacto (WO + P(f) autónomo)")
            # (a) shutdown top-5 COM work-order → 0 CRIT capacity,
            #     snapshots como EVIDÊNCIA neutra (o ARMAR discrimina)
            scen = "P-R6-07a"
            lab.scenario(scen)
            reset_all(lab)
            hygiene(lab)
            ranked7 = sorted(range(len(lab.devices)),
                             key=lambda i: lab.devices[i].kwp,
                             reverse=True)[:5]
            sts7a = []
            for i in ranked7:
                d = lab.devices[i]
                st, _ = hj(d.port, "POST", "/mode",
                           {"action": "inverter_power_off",
                            "work_order": ("WO-20261112-MNT1"
                                           if IS_V071
                                           else "WO-20261113-R7")},
                           token=d.service_token)
                sts7a.append(st)
            time.sleep(0.6)
            alerts7a = scan_scenario(lab, scen)
            crit7a = [a for a in alerts7a if a["severity"] == "CRIT"]
            cap7a = [a for a in alerts7a
                     if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            snaps7a = [e for e in scenario_events(lab, scen)
                       if e.get("event") == "capacity_snapshot"]
            for i in range(len(lab.devices)):
                lab.devices[i].harness_reset()
            time.sleep(0.3)
            # (b) P(f) autónomo de frota inteira (STRESS) → 0 CRIT
            lab.gridsim.set_state("STRESS")
            time.sleep(0.6)
            lab.gridsim.set_state("NORMAL")
            time.sleep(0.3)
            scen = "P-R6-07b"
            lab.scenario(scen)
            lab.gridsim.set_state("STRESS")
            time.sleep(0.6)
            alerts7b = scan_scenario(lab, scen)
            crit7b = [a for a in alerts7b if a["severity"] == "CRIT"]
            cap7b = [a for a in alerts7b
                     if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            snaps7b = [e for e in scenario_events(lab, scen)
                       if e.get("event") == "capacity_snapshot"]
            div7b_max = max((sn.get("divergence_pct", 0.0)
                            for sn in snaps7b), default=0.0)
            lab.gridsim.set_state("NORMAL")
            time.sleep(0.3)
            nowo7a = [a for a in alerts7a
                      if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
            mass7a = [a for a in alerts7a
                      if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
            if IS_V072:
                # v0.5 (pré-registado ANTES do run): o F-C15b faz o
                # top-5 COM WO válida ALERTAR (58,22% >= 30) — o CRIT
                # do cenário é EXATAMENTE a regra nova (capacity
                # segue ausente: o arming s/WO mantém)
                cond_07 = (all(st == 200 for st in sts7a)
                           and len(crit7a) == 1 and len(mass7a) == 1
                           and mass7a[0]["severity"] == "CRIT"
                           and mass7a[0]["count"] == 5
                           and len(cap7a) == 0
                           and len(snaps7a) >= 1
                           and len(crit7b) == 0 and len(cap7b) == 0
                           and div7b_max < 30.0
                           and len(nowo7a) == 0)
            else:
                cond_07 = (all(st == 200 for st in sts7a)
                           and len(crit7a) == 0 and len(cap7a) == 0
                           and len(snaps7a) >= 1
                           and len(crit7b) == 0 and len(cap7b) == 0
                           and div7b_max < 30.0
                           and (not IS_V071 or len(nowo7a) == 0))
            expect("P-R6-07", GATEFALL[6]["prev"], cond_07,
                   "RESOLVIDO",
                   "PREVISÃO ERRADA (ver detalhe acima)",
                   ["(a) shutdown top-5 COM work-order %s: "
                    % ("WO-20261112-MNT1 (VÁLIDA — o F-C13 exige: "
                       "a WO inventada da v0.2.1 daria 403 e o NEG "
                       "exige que o shutdown EXECUTE)"
                       if IS_V071 else "WO-20261113-R7") +
                    "todos 200; CRIT do cenário: %s (o ARMAR discrimina "
                    "por work-order); snapshots %s saem como EVIDÊNCIA "
                    "neutra (F-C12 c: também em shutdown COM WO)"
                    % ([a["rule"] for a in crit7a] or "ZERO",
                       len(snaps7a)),
                    "(b) P(f) autónomo de frota inteira (STRESS 0,6 s): "
                    "CRIT do cenário: %s; 0 D-CAPACITY-DIVERGENCE, div "
                    "máx %.2f%% < 30 — o esperado DESCONTA o curtail "
                    "autónomo (NEG intacto)"
                    % ([a["rule"] for a in crit7b] or "ZERO", div7b_max),
                    "à NOITE o esperado é 0 → a regra NÃO vê shutdowns "
                    "noturnos: DECLARADO no what-cannot-be-claimed, não "
                    "escondido"])

        # ================= SUMÁRIO ====================================
        by_id = {v["id"]: v for v in VEREDICTOS}
        match_n, prev_erradas = 0, 0
        print("\n" + "=" * 72)
        print("SUMÁRIO — GATEFALL R6 vs alvo %s" % TARGET)
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
            print("GATEFALL OFICIAL da R6 = RUN 1 contra a v0.6 INTOCADA "
                  "(6/6 CONFIRMADO, output preservado). ESTE é o RUN de "
                  "NÃO-REGRESSÃO da recuperação (v0.7.1: F-C13 + F-K1 "
                  "DRAIN-TO-LOW + F-C14 + F-SP sobre o F-C12). C5/C6/C9/"
                  "H7/I2/I3/I6/C11/J3 ficam para a v0.8; o resíduo "
                  "setpoint SEM WO fica DECLARADO.")
        elif IS_V07:
            print("GATEFALL OFICIAL da R6 = RUN 1 contra a v0.6 INTOCADA "
                  "(6/6 CONFIRMADO, output preservado). ESTE é o RUN 2 "
                  "de verificação do DEPOIS (v0.7: F-C12 + F-K1 "
                  "D-BATTERY-MULTIDAY-DRAIN + F-LIMP). C5/C6/C9/H7/"
                  "I2/I3/I6/C11/J3 ficam para a v0.8.")
        else:
            print("GATEFALL OFICIAL da R6 = ESTE RUN 1 contra a v0.6 "
                  "(ordem vinculativa do GO 13-11 15:30: probes ANTES "
                  "dos fixes). A v0.7 (F-C12 + F-K1 D-BATTERY-"
                  "MULTIDAY-DRAIN + F-LIMP) é o DEPOIS; o run 2 contra "
                  "a v0.7 verifica o DEPOIS. C5/C6/C9/H7/I2/I3/I6/C11/"
                  "J3 ficam para a v0.8.")
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

# EOF:sunstrike_probes_r6.py
