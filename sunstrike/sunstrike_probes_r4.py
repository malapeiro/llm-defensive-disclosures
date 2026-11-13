#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# SUNSTRIKE — bateria de probes R4 (M2, ronda 4 — achado C10 + GO à v0.5)
# Grant: GRANT-PVTE-20261112-SS-01 (lab sintético, loopback apenas)
# Alvo:  sunstrike_lab.py v0.4 (cca99757…, VERIFICADA pelo supervisor em
#        Python 3.13: selftest PASS +6, demo 9/9, measure 12/12 vs 0/12,
#        R3 6/6 CONFIRMADO + 6/6 RESOLVIDO, R2 sem regressão; C7/I1/C8/
#        I4/I5 confirmados). Nada corre contra um lab que não seja este
#        hash verificado.
# Corpus R4 (registo oficial do operador, GO à v0.5 de 13-11):
#   C10 ACHADO (EXECUTADO pelo supervisor): a headline não aguenta o H5
#        do design §5 — o measure só ataca DURANTE o apagão (o interlock
#        trava por construção). Com H5 pré-posicionado — rede NORMAL,
#        cada bateria descida a 26% em 2 fatias permitidas (40% + 34%) —
#        e depois apagão 1h NOITE: braço DEFENDIDO v0.4 = 0/12 casas,
#        SoC 25.00, ZERO alertas. Igual ao LEGACY.
#        Causa 1: o measure não inclui o atacante pré-posicionado.
#        Causa 2: step_island pára NO floor — a reserva de 25% nunca
#        pode ser usada pela casa.
#   DECISÃO DO OPERADOR (design): o floor bloqueia apenas descarga
#        REMOTA; em modo ilha a carga local usa a reserva até um mínimo
#        técnico ISLAND_MIN_SOC = 5%. Regra selada §4.7.2 mantém-se:
#        nenhum comando remoto desce abaixo do floor.
#   GO v0.5: (1) step_island desce até ISLAND_MIN_SOC; (2) measure com
#        DOIS atacantes em ambos os braços ((a) durante o apagão; (b) H5
#        pré-posicionado em NORMAL com fatias permitidas), reportados
#        separadamente, previsões pré-registadas ANTES da corrida —
#        espera-se que (b) DEFENDIDO fique abaixo de 100% (estimativa do
#        supervisor ~9/12, NÃO medida; vale o que for medido); (3) linha
#        de comparação "opção B" (v0.4, reserva trancada) para o ataque
#        (b) — o ANTES do C10; (4) regra nova de descarga remota
#        CUMULATIVA numa janela (fecha o C4 e faz o ataque (b) gerar
#        alerta ANTES do apagão).
# Papel: probes "antes" contra a v0.4 INTOCADA (padrão R1/R2/R3): o
#        output VERMELHO é a evidência do ANTES; os fixes são o DEPOIS
#        (v0.5). Protocolo GATEFALL — previsões PRÉ-REGISTADAS por
#        construção (constantes deste script, hash-verificáveis),
#        impressas ANTES da execução. Veredicto observado != previsto é
#        reportado como PREVISÃO ERRADA. CORREÇÃO DE MÉTODO do operador
#        (13-11, vinculativa): o GATEFALL oficial desta ronda é o RUN 1
#        desta bateria contra a v0.4, NUNCA o run seguinte.
# Portabilidade: Python 3.9+, 100% stdlib, 127.0.0.1 apenas.
#
# CHANGELOG DE PROBES (o LAB alvo NUNCA é editado):
#   v0.1 (13-11): primeira versão, alvo v0.4. GATEFALL contra a v0.4
#        PRÉ-REGISTADO nesta entrada, ANTES de qualquer corrida:
#          P-R4-01 CONFIRMADO (C10 outcome): H5 pré-posicionado em 2
#            fatias permitidas (40% + 34% → SoC ~26) com rede NORMAL,
#            SEM alarme; depois apagão 1h NOITE: carga servida 0/12,
#            SoC min 25.00 (clamp NO floor), ZERO alertas no cenário —
#            a defesa da v0.4 iguala o LEGACY exatamente no cenário que
#            a headline devia cobrir (H5 do design §5);
#          P-R4-02 CONFIRMADO (C10 causa 1): o run_measure da v0.4 não
#            inclui o atacante pré-posicionado — leitura estática: o
#            PRIMEIRO pedido /battery do measure aparece DEPOIS de
#            set_state("BLACKOUT"); o atacante só existe DENTRO do
#            apagão (o interlock trava por construção e a métrica nunca
#            mede o pré-posicionamento);
#          P-R4-03 CONFIRMADO (C10 causa 2): a reserva é INUTILIZÁVEL
#            pela casa — ilha + deficit (NOITE): step_island desce ATÉ
#            AO floor (25.0) e PÁRA; a carga local cai para pv (0.0) com
#            SoC 25 ainda na bateria (evento island_battery_at_floor);
#          P-R4-04 OK (guarda de regressão, VERDE esperado em QUALQUER
#            versão): a invariante selada §4.7.2 — descarga remota 999
#            SEM /local_confirm → 409 floor_block; fatia que cruzaria o
#            floor → 409; SoC intacto; D-BATTERY-DRAIN-BELOW-FLOOR no
#            scan. A v0.5 (floor só para descarga REMOTA) NÃO pode
#            regressar esta invariante;
#          P-R4-05 CONFIRMADO (C4 aberto): descarga fatiada (2 fatias
#            40%+34%, cada <50%) → ZERO alertas — D-BATTERY-DRAIN-LARGE
#            só vê a operação ÚNICA >=50% (a de 60% dispara); regra
#            cumulativa INEXISTENTE no RULE_ATTACK_MAP (19 regras);
#          P-R4-06 CONFIRMADO (FP pendente): operações LEGÍTIMAS
#            silenciosas (export acima do floor 43.86% numa operação +
#            abaixo do floor COM /local_confirm) — mas na v0.4 o
#            silêncio existe POR CEGUEIRA (sem regra cumulativa, o
#            legítimo e o ataque fatiado são indistinguíveis).
#        Calibração de desenvolvimento ANTES do pré-registo (leitura
#        estática do código v0.4 + física das fatias, documentada):
#        (a) step_island deficit: new_soc = max(FLOOR_SOC, soc - drop)
#            — clamp no floor, nunca abaixo;
#        (b) run_measure: reset → NOITE → BLACKOUT → atacante →
#            step_island(3600) — nenhum passo remoto antes do BLACKOUT;
#        (c) RULE_ATTACK_MAP: 19 regras, nenhuma cumulativa de SoC;
#        (d) física das fatias: 40%+34% → SoC 26.0 (25.99 nas casas
#            pequenas por arredondamento do amount a 3 decimais); drop
#            de 1h em NOITE = 100/kwp pontos (pior casa 3.2 kWp →
#            31.25) → TODAS as casas clamp ao floor 25.0 na v0.4;
#        (e) NEG-style: 2.0 kWh na casa 3.8 kWp (batt 4.56) → 43.86%
#            numa operação (<50%, silencioso).
#        A calibração não alterou nenhuma previsão: formou-as.
#   v0.2 (13-11): DUAL-TARGET. O lab alvo é DETETADO pelo hash no arranque:
#        v0.4 (cca99757…, evidência do ANTES colhida no run 1, que é o
#        GATEFALL OFICIAL da R4 por correção de método) ou v0.5
#        (052688ee…, entregue neste turno: semântica do floor opção A +
#        ISLAND_MIN_SOC 5% + RESERVE_LOCKED_MODE [contrafactual opção B]
#        + measure com dois atacantes + linha OPTION-B + regra
#        D-BATTERY-CUMULATIVE-DRAIN que fecha o C4). GATEFALL v0.5
#        PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.5 (protocolo GATEFALL):
#          P-R4-01 RESOLVIDO (C10): as mesmas 2 fatias permitidas (40%+
#            34% → ~26) agora geram D-BATTERY-CUMULATIVE-DRAIN ANTES do
#            apagão (o ataque deixa de ser invisível); apagão 1h NOITE:
#            carga servida 9/12 (retido 75%), SoC min 5.00 — a reserva é
#            usada pela casa até ao mínimo técnico ISLAND_MIN_SOC (as
#            casas 3.2/3.8/4.4 kWp clampam no mínimo e ficam escuras ao
#            fim da hora); NÃO 0/12: a defesa corrigida deixa de igualar
#            o LEGACY;
#          P-R4-02 RESOLVIDO (C10 causa 1): o run_measure da v0.5 INCLUI o
#            atacante pré-posicionado — o PRIMEIRO pedido /battery do
#            measure aparece ANTES de set_state("BLACKOUT") (atacante
#            (b) em NORMAL, reportado separadamente do (a));
#          P-R4-03 RESOLVIDO (C10 causa 2): ilha + deficit: step_island
#            desce ATRAVÉS do floor (28.0 → 24.9136, ABAIXO de 25) até
#            ao mínimo técnico; a carga local CONTINUA servida (1.2 kW)
#            — a reserva é USÁVEL pela casa;
#          P-R4-04 OK (guarda de regressão, critério IDÊNTICO ao v0.1):
#            a invariante selada §4.7.2 tem de continuar VERDE na v0.5
#            (descarga remota 999 → 409; fatia que cruza o floor → 409;
#            SoC intacto; regra no scan);
#          P-R4-05 RESOLVIDO (C4 fechado): D-BATTERY-CUMULATIVE-DRAIN
#            EXISTE no RULE_ATTACK_MAP (20 regras); as 2 fatias de
#            40%+34% disparam a cumulativa (count 2) SEM a por-operação;
#            a operação única de 60% continua só na por-operação (sem
#            dupla-disparo);
#          P-R4-06 RESOLVIDO (FP guardado): os legítimos continuam
#            silenciosos (43.86% numa operação < limiar; abaixo do floor
#            COM /local_confirm, provenance local_confirm fora da regra)
#            — agora POR DISCRIMINAÇÃO (regra existe E não dispara),
#            não por cegueira.
#        NENHUMA previsão v0.4 alterada (o alvo v0.4 mantém o GATEFALL
#        original do run 1).
#   v0.3 (13-11; ERRATA de data, ver ERRATA_v06_datas.md 4f012123…):
#        TRI-TARGET (não-regressão da v0.6, GO 13-11 13:23).
#        O lab v0.6 (698b8cff…) é detetado pelo hash e corre os ramos
#        V06 com GATEFALL próprio PRÉ-REGISTADO NESTA ENTRADA, ANTES
#        de qualquer corrida contra a v0.6 (protocolo GATEFALL):
#          P-R4-01 RESOLVIDO (limite diário): as MESMAS 2 fatias
#            permitidas: a de 40% EXECUTA (100→60, 200) e a de 34%
#            apanha o LIMITE DIÁRIO (used 40+34 > 40 → 409
#            remote_discharge_daily_limit ×12); SEM alerta cumulativo
#            (superssenção datada: com o limite ativo, fatias por
#            remote_command não acumulam para além de 40%/dia);
#            apagão 1h NOITE: 12/12 servidas, SoC min ~28.75 (a casa
#            3.2 kWp: 60 − 100/3.2), ZERO eventos de clamp (a frota
#            nem chega ao mínimo técnico) — o outcome do C10 fica
#            RESOLVIDO COM MARGEM: nenhuma casa às escuras;
#          P-R4-02 RESOLVIDO (critério espelhado ao V05): o
#            run_measure da v0.6 mantém o atacante pré-posicionado —
#            o PRIMEIRO /battery vem ANTES de set_state("BLACKOUT")
#            (agora em CURVA de durações com minutos por casa + o
#            atacante (c) de 2 dias);
#          P-R4-03 RESOLVIDO (critério IDÊNTICO ao V05): a semântica
#            do step_island NÃO mudou na v0.6 — ilha + deficit desce
#            ATRAVÉS do floor (28.0 → 24.9136) com carga servida;
#          P-R4-04 OK (guarda de regressão, critério IDÊNTICO): 999
#            → 409 min_emergency_soc_floor; fatia 20% de 30 → 10 <
#            floor → 409 floor (o floor é verificado ANTES do limite
#            diário); SoC intacto 30.0; D-BATTERY-DRAIN-BELOW-FLOOR
#            no scan — a invariante selada §4.7.2 continua VERDE;
#          P-R4-05 RESOLVIDO (limite diário apanha as fatias): a
#            fatia de 40% executa (200, SoC 100→60) e a de 34% dá
#            409 daily; a operação única de 60% dá 409 daily TAMBÉM
#            (60 > 40, NEM EXECUTA — DRAIN-LARGE fica inatingível);
#            cumulativa e por-operação AUSENTES dos alertas (2
#            eventos remote_daily_limit_block) — a deteção por regra
#            cede à PREVENÇÃO por bloqueio (declaração datada no lab);
#          P-R4-06 DECLARADO (custo declarado da opção 1): o
#            legítimo de 2.0 kWh (43.86% da casa 3.8 kWp) agora dá
#            409 daily (43.86 > 40) + evento — legítimos >40%/dia
#            passam a exigir /local_confirm (consequência declarada
#            no GO); o fluxo abaixo do floor COM /local_confirm
#            mantém-se 200/200 (exceção exclusiva §4.7.2 intacta);
#            ZERO alertas de regra no cenário.
#        Sumário esperado V06: RESOLVIDO ×4 + OK ×1 + DECLARADO ×1.
#        NENHUMA previsão v0.4/v0.5 alterada.
#   v0.3.1 (13-11, ERRATA de data, ver ERRATA_v06_datas.md; correção
#        de CRITÉRIO datada, antes do run oficial
#        da não-regressão): o primeiro run contra a v0.6 (preservado em
#        sunstrike_probes_v06_r4_run1.txt, hash f8ca701e…) deu 5/6 com
#        P-R4-02 PREVISÃO ERRADA por DEFEITO DE CRITÉRIO DO PROBE, não
#        por achado: o measure v0.6 encapsulou o blackout no helper
#        blackout_set() cuja DEFINIÇÃO vem textualmente antes do
#        attack_b, e o critério textual do P-R4-02 cortava na definição
#        em vez de olhar a ordem de EXECUÇÃO (atk = attack_b(label) é
#        chamado ANTES de blackout_set() nos dois sítios — braço (b) e
#        dia 2 do (c); verificado no texto do lab e impresso no run 1).
#        Corrigido: o ramo V06 passa a comparar os índices das
#        CHAMADAS. A PREVISÃO de P-R4-02 MANTÉM-SE (RESOLVIDO); nada
#        mais mudou. Este run NÃO é o GATEFALL oficial (o da R4 é o
#        RUN 1 contra a v0.4); os dois runs ficam preservados.
#   v0.4 (13-11, GO v0.7 do operador 15:30): QUAD-TARGET — acrescentado
#        o alvo V07 (hash d3af0d28…, lab INTOCADO). GATEFALL V07
#        pré-registado NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.7: critérios = CÓPIA dos V06 (a v0.7 F-C12/F-K1/F-LIMP
#        NÃO mexe no limite diário, na ordem floor→daily, na semântica
#        do step_island nem no fluxo /local_confirm; as fatias destes
#        cenários ficam DENTRO de 1 dia: o novo D-BATTERY-MULTIDAY-
#        DRAIN exige ≥2 dias-distintos e NÃO dispara aqui). Sumário
#        esperado V07: 4 RESOLVIDO + 1 OK + 1 DECLARADO (6/6).
#        ERRATA DE DATAS (ERRATA_v06_datas.md, 4f012123…): as entradas
#        v0.3 e v0.3.1 diziam "14-11" — o dia correto é 13-11-2026;
#        corrigido (ocorrências :133 e :176). ERRATA DE GRAVAGEM
#        (mesma gralha apontada pelo supervisor no design §7/corpus,
#        varrida no lab v0.7): a grafia errada de "apagão" corrigida
#        em TODO o ficheiro (comentários e strings de evidência —
#        NENHUM critério numérico muda; 23 ocorrências).
#   v0.5.1 (13-11, RECONSTRUÇÃO datada pós-incidente INFRA-2026-13-11-B
#        ~18:23): acrescentado o alvo V071 (hash 72c894fe…, lab v0.7.1
#        RESTAURADO por REPLAY dos edit scripts preservados + errata
#        J5; selftest re-executado BYTE-IDÊNTICO afb98d0c…).
#        GATEFALL V071 pré-registado NESTA ENTRADA, ANTES de qualquer
#        corrida contra a v0.7.1: critérios = CÓPIA dos V07 (o
#        F-C13/F-K1/F-C14/F-SP NÃO mexe no limite diário, na ordem
#        floor→daily, na semântica do step_island nem no fluxo
#        /local_confirm; a D-BATTERY-DRAIN-TO-LOW fica CALADA em
#        TODOS os cenários r4: as fatias EXECUTADAS aterram SoC
#        60/100 > 35, as BLOQUEADAS (409) não emitem param_change, e
#        o consumo LOCAL em ilha é provenance ≠ remote_command).
#        Sumário esperado V071: 4 RESOLVIDO + 1 OK + 1 DECLARADO (6/6).
#        ERRATA DE DISPLAY datada (v0.5.1): a mensagem "ALVO
#        REJEITADO" dizia "só corre contra a v0.4/v0.5/v0.6" mas a
#        v0.4 do probe JÁ aceitava a v0.7 — incluída a v0.7 e a
#        v0.7.1 na mensagem. NENHUM critério muda.
# ---------------------------------------------------------------------------
# Probes:
#   P-R4-01  C10  H5 pré-posicionado (2 fatias permitidas, NORMAL) +
#                apagão 1h NOITE: DEFENDIDO v0.4 = 0/12, SoC 25.00,
#                ZERO alertas — igual ao LEGACY
#   P-R4-02  C10  causa 1: o measure não inclui o atacante
#                pré-posicionado (primeiro /battery sempre DEPOIS do
#                BLACKOUT)
#   P-R4-03  C10  causa 2: step_island pára NO floor — a reserva de
#                25% nunca pode ser usada pela casa em deficit
#   P-R4-04  §4.7.2  guarda de regressão: floor REMOTO intocado (409 +
#                floor_block + CRIT) — tem de ser VERDE em qualquer
#                versão, incl. a v0.5
#   P-R4-05  C4   descarga fatiada (cada <50%) é invisível: zero
#                alertas; regra cumulativa inexistente (19 regras)
#   P-R4-06  FP   legítimos (export acima do floor; abaixo do floor
#                COM local_confirm) silenciosos — por CEGUEIRA na v0.4
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

EXPECTED_LAB_SHA256_V04 = ("cca997578e1f1b108a0d98e151104eec90ceae78"
                           "22e8900cb2ed002b6aa654a4")
EXPECTED_LAB_SHA256_V05 = ("052688ee7ee45c55691242c42f2b3ada223eaddf"
                           "a3f4401e0aa562da224ed209")
EXPECTED_LAB_SHA256_V06 = ("698b8cff89cb87c57ef7cbe46254af960346025a2"
                           "0f7eb4823334cc3d04b3464")
EXPECTED_LAB_SHA256_V07 = ("d3af0d28715d7cdc25783075ec71530f46055b16"
                           "53bc6e961f0403bf6653b663")
# v0.6 (13-11, GO à v0.7.2 ~19:30): alvo NOVO V072 — hexa-target.
# Previsões V072 = cópia da V071 (o r4 não exercita WO em shutdown:
# os cenários são /battery e interlocks; a semântica do step_island
# e do limite diário são INALTERADOS pelo F-C15a/F-C15b).
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")
if lab_sha == EXPECTED_LAB_SHA256_V04:
    TARGET = "V04"
elif lab_sha == EXPECTED_LAB_SHA256_V05:
    TARGET = "V05"
elif lab_sha == EXPECTED_LAB_SHA256_V06:
    TARGET = "V06"
elif lab_sha == EXPECTED_LAB_SHA256_V07:
    TARGET = "V07"
elif lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "V071"
elif lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "V072"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe só corre contra a v0.4 (%s…), a v0.5 (%s…), "
          "a v0.6 (%s…), a v0.7 (%s…) ou a v0.7.1 restaurada "
          "(%s…), labs INTOCADOS.\n  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V04[:16],
             EXPECTED_LAB_SHA256_V05[:16],
             EXPECTED_LAB_SHA256_V06[:16],
             EXPECTED_LAB_SHA256_V07[:16],
             EXPECTED_LAB_SHA256_V071[:16]))
    raise SystemExit(2)

IS_V07 = TARGET in ("V07", "V071", "V072")
IS_V071 = TARGET in ("V071", "V072")
IS_V072 = TARGET == "V072"

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R4 v0.5.1 (penta-target V04/V05/V06/V07/V071; "
      "reconstrucao pos-incidente INFRA-2026-13-11-B) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS (constantes hash-verificáveis)
# ---------------------------------------------------------------------------
GATEFALL_V04 = [
    {"id": "P-R4-01", "finding": "C10",
     "prev": ("CONFIRMADO — H5 pré-posicionado em 2 fatias permitidas "
              "(40%+34% → ~26%) em NORMAL, SEM alarme; apagão 1h NOITE: "
              "0/12 casas, SoC min 25.00 (clamp no floor), ZERO alertas")},
    {"id": "P-R4-02", "finding": "C10",
     "prev": ("CONFIRMADO — o measure v0.4 não inclui o atacante "
              "pré-posicionado: o primeiro /battery do run_measure vem "
              "DEPOIS de set_state(\"BLACKOUT\")")},
    {"id": "P-R4-03", "finding": "C10",
     "prev": ("CONFIRMADO — ilha em deficit: step_island desce ATÉ AO "
              "floor (25.0) e PÁRA; carga local cai para pv=0 com SoC 25 "
              "ainda na bateria (island_battery_at_floor)")},
    {"id": "P-R4-04", "finding": "§4.7.2", "expected": "OK",
     "prev": ("OK — guarda de regressão: descarga remota 999 sem "
              "/local_confirm → 409 + floor_block; fatia que cruza o "
              "floor → 409; SoC intacto; D-BATTERY-DRAIN-BELOW-FLOOR no "
              "scan (invariante selada, VERDE em qualquer versão)")},
    {"id": "P-R4-05", "finding": "C4",
     "prev": ("CONFIRMADO — 2 fatias de 40%+34% (cada <50%): ZERO "
              "alertas; D-BATTERY-DRAIN-LARGE só dispara na operação "
              "única de 60%; regra cumulativa INEXISTENTE no "
              "RULE_ATTACK_MAP (19 regras)")},
    {"id": "P-R4-06", "finding": "FP",
     "prev": ("CONFIRMADO — legítimos silenciosos (43.86% acima do floor "
              "+ abaixo do floor COM /local_confirm) — na v0.4 por "
              "CEGUEIRA: sem regra cumulativa, legítimo e ataque fatiado "
              "são indistinguíveis")},
]
GATEFALL_V05 = [
    {"id": "P-R4-01", "finding": "C10",
     "prev": ("RESOLVIDO — as mesmas 2 fatias (40%+34% → ~26%) geram "
              "D-BATTERY-CUMULATIVE-DRAIN ANTES do apagão; apagão 1h "
              "NOITE: 9/12 casas (retido 75%), SoC min 5.00 (reserva "
              "usada até ISLAND_MIN_SOC; as casas 3.2/3.8/4.4 kWp "
              "clampam no mínimo técnico)")},
    {"id": "P-R4-02", "finding": "C10",
     "prev": ("RESOLVIDO — o measure v0.5 INCLUI o atacante "
              "pré-posicionado: o primeiro /battery do run_measure vem "
              "ANTES de set_state(\"BLACKOUT\") (atacante (b) em NORMAL, "
              "reportado separadamente)")},
    {"id": "P-R4-03", "finding": "C10",
     "prev": ("RESOLVIDO — ilha em deficit: step_island desce ATRAVÉS "
              "do floor (28.0 → 24.9136) até ao mínimo técnico; a carga "
              "local CONTINUA servida (1.2 kW) — a reserva é USÁVEL")},
    {"id": "P-R4-04", "finding": "§4.7.2", "expected": "OK",
     "prev": ("OK — guarda de regressão (critério idêntico ao v0.1): "
              "descarga remota 999 sem /local_confirm → 409 + "
              "floor_block; fatia que cruza o floor → 409; SoC intacto; "
              "D-BATTERY-DRAIN-BELOW-FLOOR no scan")},
    {"id": "P-R4-05", "finding": "C4",
     "prev": ("RESOLVIDO — D-BATTERY-CUMULATIVE-DRAIN existe (20 "
              "regras); 2 fatias de 40%+34% disparam a CUMULATIVA "
              "(count 2) sem a por-operação; a operação única de 60% "
              "fica só na por-operação (sem dupla-disparo)")},
    {"id": "P-R4-06", "finding": "FP",
     "prev": ("RESOLVIDO — legítimos silenciosos POR DISCRIMINAÇÃO: a "
              "regra existe E não dispara (43.86% < limiar; "
              "local_confirm fora da provenance remote_command)")},
]
GATEFALL_V06 = [
    {"id": "P-R4-01", "finding": "C10+limite",
     "prev": ("RESOLVIDO — com o limite diário: fatia 40% executa "
              "(100→60), fatia 34% → 409 daily ×12 (40+34 > 40); SEM "
              "cumulativa; apagão 1h NOITE: 12/12 servidas, SoC min "
              "~28.75, ZERO eventos de clamp — nenhuma casa às "
              "escuras")},
    {"id": "P-R4-02", "finding": "C10 causa 1",
     "prev": ("RESOLVIDO — o measure v0.6 mantém o atacante "
              "pré-posicionado: o PRIMEIRO /battery vem ANTES de "
              "set_state(\"BLACKOUT\") (em curva de durações com "
              "minutos por casa + atacante (c) de 2 dias)")},
    {"id": "P-R4-03", "finding": "C10 causa 2",
     "prev": ("RESOLVIDO — critério idêntico ao V05 (a semântica do "
              "step_island não mudou): ilha + deficit desce ATRAVÉS "
              "do floor (28.0 → 24.9136) com a carga servida")},
    {"id": "P-R4-04", "finding": "§4.7.2", "expected": "OK",
     "prev": ("OK — guarda de regressão (critério idêntico): 999 → "
              "409 floor; fatia que cruza o floor → 409 floor (veri-"
              "ficado ANTES do limite diário); SoC intacto; regra "
              "BELOW-FLOOR no scan")},
    {"id": "P-R4-05", "finding": "C4+limite",
     "prev": ("RESOLVIDO — a fatia 40% executa (200) e a 34% dá 409 "
              "daily; a única de 60% dá 409 daily TAMBÉM (nem executa); "
              "cumulativa e por-operação ausentes (2 eventos "
              "remote_daily_limit_block): a deteção por regra cede à "
              "prevenção por bloqueio")},
    {"id": "P-R4-06", "finding": "FP", "expected": "DECLARADO",
     "prev": ("DECLARADO — o legítimo de 43.86% agora dá 409 daily "
              "(custo declarado da opção 1: legítimos >40%/dia "
              "exigem /local_confirm); o fluxo /local_confirm abaixo "
              "do floor mantém 200/200; ZERO alertas de regra")},
]
GATEFALL_V07 = [
    {"id": "P-R4-01", "finding": "C10+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6 (limite diário INTACTO na "
              "v0.7): fatia 40% executa (100→60), fatia 34% → 409 "
              "daily ×12 (40+34 > 40); SEM cumulativa; apagão 1h "
              "NOITE: 12/12 servidas, SoC min ~28.75, ZERO eventos "
              "de clamp — nenhuma casa às escuras")},
    {"id": "P-R4-02", "finding": "C10 causa 1",
     "prev": ("RESOLVIDO — o measure v0.7 mantém o atacante "
              "pré-posicionado: o PRIMEIRO /battery vem ANTES de "
              "set_state(\"BLACKOUT\") (braços (b)/(c)/(d) com "
              "minutos por casa)")},
    {"id": "P-R4-03", "finding": "C10 causa 2",
     "prev": ("RESOLVIDO — critério idêntico ao V05/V06 (a semântica "
              "do step_island não mudou na v0.7): ilha + deficit "
              "desce ATRAVÉS do floor (28.0 → 24.9136) com a carga "
              "servida")},
    {"id": "P-R4-04", "finding": "§4.7.2", "expected": "OK",
     "prev": ("OK — guarda de regressão (critério idêntico): 999 → "
              "409 floor; fatia que cruza o floor → 409 floor (veri-"
              "ficado ANTES do limite diário); SoC intacto; regra "
              "BELOW-FLOOR no scan")},
    {"id": "P-R4-05", "finding": "C4+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6: a fatia 40% executa (200) e "
              "a 34% dá 409 daily; a única de 60% dá 409 daily TAMBÉM "
              "(nem executa); cumulativa e por-operação ausentes (2 "
              "eventos remote_daily_limit_block). NOTA v0.7: o "
              "D-BATTERY-MULTIDAY-DRAIN exige ≥2 dias-distintos — "
              "estas fatias ficam DENTRO do mesmo dia: só o daily "
              "dispara")},
    {"id": "P-R4-06", "finding": "FP", "expected": "DECLARADO",
     "prev": ("DECLARADO — IGUAL à v0.6: o legítimo de 43.86% dá 409 "
              "daily (custo declarado da opção 1); o fluxo "
              "/local_confirm abaixo do floor mantém 200/200; ZERO "
              "alertas de regra (43.86% num só dia NÃO arma o "
              "multiday novo)")},
]

# GATEFALL V071 — pré-registado na entrada v0.5.1 do changelog, ANTES
# de qualquer corrida contra a v0.7.1 restaurada (72c894fe…): cópia dos
# V07 com a NOTA de que a DRAIN-TO-LOW fica CALADA (provenance
# remote_command apenas; fatias executadas > 35; bloqueadas sem
# param_change; consumo local em ilha fora do ramo).
GATEFALL_V071 = [
    {"id": "P-R4-01", "finding": "C10+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6/v0.7 (limite diário INTACTO "
              "na v0.7.1): fatia 40% executa (100→60), fatia 34% → "
              "409 daily ×12 (40+34 > 40); SEM cumulativa; apagão 1h "
              "NOITE: 12/12 servidas, SoC min ~28.75, ZERO eventos "
              "de clamp — nenhuma casa às escuras; a DRAIN-TO-LOW "
              "fica CALADA (fatia executada aterra 60 > 35; o "
              "esvaziamento no apagão é consumo LOCAL em ilha)")},
    {"id": "P-R4-02", "finding": "C10 causa 1",
     "prev": ("RESOLVIDO — o measure v0.7.1 mantém o atacante "
              "pré-posicionado: o PRIMEIRO /battery vem ANTES de "
              "set_state(\"BLACKOUT\") (braços (b)/(c)/(d) com "
              "minutos por casa)")},
    {"id": "P-R4-03", "finding": "C10 causa 2",
     "prev": ("RESOLVIDO — critério idêntico ao V05/V06/V07 (a "
              "semântica do step_island não mudou na v0.7.1): ilha "
              "+ deficit desce ATRAVÉS do floor (28.0 → 24.9136) "
              "com a carga servida; consumo LOCAL em ilha NÃO entra "
              "na DRAIN-TO-LOW (provenance ≠ remote_command)")},
    {"id": "P-R4-04", "finding": "§4.7.2", "expected": "OK",
     "prev": ("OK — guarda de regressão (critério idêntico): 999 → "
              "409 floor; fatia que cruza o floor → 409 floor (veri-"
              "ficado ANTES do limite diário); SoC intacto; regra "
              "BELOW-FLOOR no scan")},
    {"id": "P-R4-05", "finding": "C4+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6/v0.7: a fatia 40% executa "
              "(200) e a 34% dá 409 daily; a única de 60% dá 409 "
              "daily TAMBÉM (nem executa); cumulativa e por-operação "
              "ausentes (2 eventos remote_daily_limit_block). NOTA "
              "v0.7.1: a DRAIN-TO-LOW (que SUBSTITUIU a MULTIDAY) "
              "fica CALADA — as fatias executadas aterram SoC "
              "60/100 > 35 e as bloqueadas não emitem param_change")},
    {"id": "P-R4-06", "finding": "FP", "expected": "DECLARADO",
     "prev": ("DECLARADO — IGUAL à v0.6/v0.7: o legítimo de 43.86% "
              "dá 409 daily (custo declarado da opção 1); o fluxo "
              "/local_confirm abaixo do floor mantém 200/200; ZERO "
              "alertas de regra (43.86% num só dia NÃO arma nada; "
              "/local_confirm é provenance local_confirm: FORA do "
              "ramo da DRAIN-TO-LOW)")},
]
GATEFALL_V072 = [dict(e) for e in GATEFALL_V071]
GATEFALL = (GATEFALL_V04 if TARGET == "V04"
            else GATEFALL_V05 if TARGET == "V05"
            else GATEFALL_V072 if IS_V072
            else GATEFALL_V071 if TARGET == "V071"
            else GATEFALL_V07 if TARGET == "V07" else GATEFALL_V06)

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS (antes de qualquer execução)")
print("contra sunstrike_lab.py %s (hash %s…)"
      % ("v0.4 (o ANTES)" if TARGET == "V04" else
         "v0.5 (o DEPOIS da R4)" if TARGET == "V05"
         else "v0.7.1 (NÃO-REGRESSÃO da recuperação pós-INFRA-B)"
         if TARGET == "V071"
         else "v0.7 (NÃO-REGRESSÃO da R7)" if TARGET == "V07"
         else "v0.6 (o DEPOIS da R5)",
         lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
if TARGET == "V071":
    print("GATEFALL v0.7.1 pré-registado na entrada v0.5.1 do changelog "
          "do probe, ANTES desta corrida (NÃO-REGRESSÃO da recuperação "
          "pós-INFRA-2026-13-11-B, reconstrução datada; regras novas "
          "F-C13/F-K1/F-C14/F-SP CALADAS nos cenários r4). O GATEFALL "
          "OFICIAL da R4 continua a ser o RUN 1 contra a v0.4 (6/6 "
          "CONFIRMADO, preservado).")
elif TARGET == "V07":
    print("GATEFALL v0.7 pré-registado na entrada v0.4 do changelog do "
          "probe, ANTES desta corrida (NÃO-REGRESSÃO da R7). O GATEFALL "
          "OFICIAL da R4 continua a ser o RUN 1 contra a v0.4 (6/6 "
          "CONFIRMADO, preservado).")
if TARGET == "V04":
    print("DECISÃO DO OPERADOR 13-11: o GATEFALL OFICIAL da R4 é o RUN 1 "
          "desta\nbateria contra a v0.4 (com as previsões erradas que "
          "saírem, sejam\ndefeitos do probe ou achados reais), NUNCA o "
          "run seguinte. C5/C6/C9/\nH7/I2/I3/I6 ficam para a ronda "
          "seguinte.\n")
elif TARGET == "V05":
    print("GATEFALL v0.5 pré-registado na entrada v0.2 do changelog do "
          "probe, ANTES\ndesta corrida. O GATEFALL OFICIAL da R4 é o RUN "
          "1 contra a v0.4 (6/6\nCONFIRMADO, preservado em "
          "sunstrike_probes_v04_r4_run1.txt); esta corrida é a evidência "
          "do DEPOIS.\nC5/C6/C9/H7/I2/I3/I6 ficam para a ronda "
          "seguinte.\n")
else:
    print("GATEFALL v0.6 pré-registado na entrada v0.3 do changelog do "
          "probe, ANTES\ndesta corrida (não-regressão da v0.6 + guardas "
          "§4.7.2/C10/C4). O GATEFALL\nOFICIAL da R4 é o RUN 1 contra a "
          "v0.4; esta corrida é a NÃO-REGRESSÃO da\nv0.6 (cada fix da R5 "
          "tem de manter os veredictos da R4 no V05). "
          "C5/C6/C9/H7/I2/I3/I6/C11/J3\nficam para a ronda seguinte.\n")

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


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("lab v%s em memoria (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))

    # ================= P-R4-01 — C10: o outcome ==========================
    print("[P-R4-01] C10 — H5 pré-posicionado: a headline não aguenta")
    lab.scenario("P-R4-01")
    reset_all(lab)
    # ATAQUE (b) do supervisor: 2 fatias PERMITIDAS (40% + 34%), rede
    # NORMAL, por service token (autenticado, in-band, acima do floor).
    # v0.3: fatias separadas por estado (na v0.6 a de 34% apanha o
    # limite diário; na v0.4/v0.5 ambas executam 200).
    st40, st34, soc_pre = [], [], []
    for d in lab.devices:
        st, _ = hj(d.port, "POST", "/battery",
                   {"action": "discharge",
                    "amount_kwh": round(0.40 * d.batt_kwh, 3)},
                   token=d.service_token)
        st40.append(st)
        st, _ = hj(d.port, "POST", "/battery",
                   {"action": "discharge",
                    "amount_kwh": round(0.34 * d.batt_kwh, 3)},
                   token=d.service_token)
        st34.append(st)
        soc_pre.append(d.soc)
    st_slices = st40 + st34
    pre_alerts = scan_scenario(lab, "P-R4-01")   # ANTES do apagão
    # noite + apagão 1h (integração determinística por harness, como o
    # measure oficial: relés abrem pelo anti-islanding, latch arma)
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)
    for d in lab.devices:
        d.step_island(3600.0)
    served = sum(1 for d in lab.devices
                 if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)
    soc_min = round(min(d.soc for d in lab.devices), 2)
    floor_evs = [e for e in scenario_events(lab, "P-R4-01")
                 if e.get("event") == "island_battery_at_floor"]
    alerts = scan_scenario(lab, "P-R4-01")
    all_ok = all(s == 200 for s in st_slices)
    cum_pre = any(a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
                  for a in pre_alerts)
    min_evs = [e for e in scenario_events(lab, "P-R4-01")
               if e.get("event") == "island_battery_at_island_min"]
    if TARGET == "V04":
        cond = (all_ok and served == 0 and soc_min == L.FLOOR_SOC
                and not pre_alerts and not alerts)
        expect("P-R4-01", GATEFALL[0]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias 200=%s (24 pedidos, 2 por casa); SoC pós-fatiar: "
                "min=%.2f max=%.2f (~26%% em TODAS)"
                % (all_ok, min(soc_pre), max(soc_pre)),
                "alertas ANTES do apagão: %s — as fatias são invisíveis"
                % [(a["rule"], a["count"]) for a in pre_alerts],
                "apagão 1h NOITE: carga servida %d/12, SoC min %.2f "
                "(clamp NO floor %.1f; eventos island_battery_at_floor=%d)"
                % (served, soc_min, L.FLOOR_SOC, len(floor_evs)),
                "alertas do cenário: %s — ZERO alertas"
                % [(a["rule"], a["count"]) for a in alerts],
                "consequência: o braço DEFENDIDO da v0.4 IGUALA o LEGACY "
                "exatamente no cenário H5 que a headline devia cobrir"])
    elif TARGET == "V05":
        cond = (all_ok and 25.99 <= min(soc_pre) and max(soc_pre) <= 26.01
                and cum_pre and served == 9
                and abs(soc_min - L.ISLAND_MIN_SOC) < 0.005
                and min_evs)
        expect("P-R4-01", GATEFALL[0]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias 200=%s (24 pedidos, 2 por casa); SoC pós-fatiar: "
                "min=%.2f max=%.2f (~26%% em TODAS)"
                % (all_ok, min(soc_pre), max(soc_pre)),
                "alertas ANTES do apagão: %s — a regra cumulativa (C4) "
                " flagra as fatias em NORMAL, ANTES do apagão"
                % [(a["rule"], a["count"]) for a in pre_alerts],
                "apagão 1h NOITE: carga servida %d/12 (retido %.0f%%), "
                "SoC min %.2f — a reserva é USADA até ISLAND_MIN_SOC %.1f "
                "(eventos island_battery_at_island_min=%d; as casas "
                "3.2/3.8/4.4 kWp clampam no mínimo técnico e ficam "
                "escuras ao fim da hora)"
                % (served, served / 12.0 * 100.0, soc_min,
                   L.ISLAND_MIN_SOC, len(min_evs)),
                "alertas do cenário: %s"
                % [(a["rule"], a["count"]) for a in alerts],
                "C10 RESOLVIDO: o braço DEFENDIDO da v0.5 DEIXA de "
                "igualar o LEGACY (9/12 vs 0/12) E o ataque deixa de ser "
                "invisível (cumulativa dispara em NORMAL)"])
    else:
        cond = (all(s == 200 for s in st40)
                and all(s == 409 for s in st34)
                and 59.99 <= min(soc_pre) and max(soc_pre) <= 60.01
                and not cum_pre and served == 12
                and abs(soc_min - 28.75) < 0.05
                and not min_evs and not floor_evs)
        expect("P-R4-01", GATEFALL[0]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias: 40%% → 200 ×12 (SoC 100→60, ledger 40); "
                "34%% → 409 remote_discharge_daily_limit ×12 (used "
                "40+34 > 40) — o limite diário ENCERRA a evasão "
                "fatiada que sobreviveu ao C4/C10",
                "SoC pós-ataque: min=%.2f max=%.2f (~60%% em TODAS, "
                "não ~26%%)" % (min(soc_pre), max(soc_pre)),
                "alertas ANTES do apagão: %s — SEM cumulativa "
                "(superssenção datada: com o limite ativo, DRAIN-LARGE "
                "e CUMULATIVE são inatingíveis por remote_command; o "
                "bloqueio diário é PREVENÇÃO, o evento é a deteção)"
                % [(a["rule"], a["count"]) for a in pre_alerts],
                "apagão 1h NOITE: carga servida %d/12, SoC min %.2f "
                "(a casa 3.2 kWp: 60 − 100/3.2 = 28.75; NENHUMA casa "
                "chega ao mínimo técnico %.1f — eventos de clamp=0)"
                % (served, soc_min, L.ISLAND_MIN_SOC),
                "alertas do cenário: %s" % [(a["rule"], a["count"])
                                            for a in alerts],
                "o outcome do C10 fica RESOLVIDO COM MARGEM: com o "
                "limite diário + reserva usável até 5%%, o apagão de "
                "1 h deixa de pôr QUALQUER casa às escuras neste "
                "cenário"])
    # higiene: repor rede/perfil e limpar o latch para os probes seguintes
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)

    # ================= P-R4-02 — C10 causa 1: measure cego ================
    print("\n[P-R4-02] C10 causa 1 — o measure não inclui o atacante "
          "pré-posicionado (leitura estática)")
    lab.scenario("P-R4-02")
    src = open(L.__file__, encoding="utf-8").read()
    sect = src[src.index("def run_measure"):src.index("def run_serve")]
    pre = sect[:sect.index('set_state("BLACKOUT")')]
    blind = ("/battery" not in pre)
    if TARGET == "V04":
        cond = blind
        expect("P-R4-02", GATEFALL[1]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["run_measure: o PRIMEIRO pedido /battery aparece DEPOIS "
                "de set_state(\"BLACKOUT\") — sem atacante "
                "pré-posicionado: %s" % (not blind),
                "o atacante do measure só existe DENTRO do apagão (o "
                "interlock trava por construção e a métrica nunca mede "
                "o pré-posicionamento em NORMAL)",
                "MEASURE_EXPECTED da v0.4: braços DEFENDED/LEGACY sem "
                "qualquer variante de ataque pré-posicionado"])
    elif TARGET == "V05":
        cond = (not blind)
        expect("P-R4-02", GATEFALL[1]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["run_measure: o PRIMEIRO pedido /battery aparece ANTES "
                "de set_state(\"BLACKOUT\") — atacante (b) "
                "pré-posicionado PRESENTE no measure: %s" % (not blind),
                "o measure v0.5 mede os DOIS atacantes em ambos os "
                "braços: (a) durante o apagão e (b) H5 pré-posicionado "
                "em NORMAL com fatias permitidas, reportados "
                "separadamente",
                "C10 causa 1 RESOLVIDA: a métrica agora mede o "
                "pré-posicionamento que a headline devia cobrir"])
    else:
        # v0.3.1 (correção de critério datada): o measure v0.6 extraiu o
        # blackout para o HELPER blackout_set(), cuja DEFINIÇÃO vem
        # textualmente antes do attack_b — o critério textual do
        # P-R4-02 (primeiro "/battery" antes da primeira ocorrência de
        # set_state("BLACKOUT")) corta na DEFINIÇÃO e dava cego. O
        # critério passa a comparar a ORDEM DE EXECUÇÃO das CHAMADAS:
        # attack_b(label) tem de ser chamado ANTES de blackout_set()
        # nos dois sítios (braço (b) e dia 2 do atacante (c)).
        i_atk = sect.index("atk = attack_b(label)")
        i_blk = sect.index("blackout_set()", i_atk)
        i_day2 = sect.index("day2 = attack_b(label)")
        i_blk2 = sect.index("blackout_set()", i_day2)
        cond = ("/battery" in sect and i_atk < i_blk and i_day2 < i_blk2)
        expect("P-R4-02", GATEFALL[1]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["run_measure: ORDEM DE EXECUÇÃO — atk = attack_b(label) "
                "é chamado ANTES de blackout_set() nos DOIS sítios "
                "(braço (b) de cada duração e dia 2 do atacante (c)); "
                "o helper blackout_set() apenas encapsula o set_state"
                "(\"BLACKOUT\") que a v0.5 tinha inline",
                "o measure v0.6 mede a CURVA de durações (30 min…3 h) "
                "com MINUTOS de luz por casa (J1/J2) em 4 braços, "
                "com o atacante (b) pré-posicionado em TODOS, e o "
                "atacante (c) de 2 dias (40%%/dia com dia de sol "
                "entre eles, recarga grid-tied J4 contando a favor da "
                "defesa)",
                "não-regressão: a causa 1 do C10 (measure cego) "
                "continua RESOLVIDA na v%s"
                % ("0.7.1" if IS_V071
                   else ("0.7" if IS_V07 else "0.6"))])

    # ================= P-R4-03 — C10 causa 2: reserva inútil =============
    print("\n[P-R4-03] C10 causa 2 — a reserva de 25% nunca pode ser usada "
          "pela casa")
    lab.scenario("P-R4-03")
    reset_all(lab)
    lab.gridsim.set_irradiance("NOITE")
    d5 = lab.devices[5]
    d5.soc = 28.0                 # acima do floor: reserva "disponível"
    d5.relay_closed = False       # modo ilha (relé aberto)
    d5.inverter_on = True
    d5.step_island(600.0)         # 600 s de deficit de 1.2 kW (NOITE)
    sc = d5.self_consumption_kw()
    floor_ev = [e for e in scenario_events(lab, "P-R4-03")
                if e.get("event") == "island_battery_at_floor"]
    min_ev = [e for e in scenario_events(lab, "P-R4-03")
              if e.get("event") == "island_battery_at_island_min"]
    if TARGET == "V04":
        cond = (d5.soc == L.FLOOR_SOC and sc == 0.0 and floor_ev)
        expect("P-R4-03", GATEFALL[2]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["ilha + deficit (NOITE, 600 s): SoC 28.0 → %.2f — desce "
                "ATÉ AO floor %.1f e PÁRA (clamp)"
                % (d5.soc, L.FLOOR_SOC),
                "carga local servida: %.2f kW (CAIU para pv=0) com SoC "
                "%.1f ainda NA bateria; island_battery_at_floor=%d"
                % (sc, d5.soc, len(floor_ev)),
                "consequência: a reserva de emergência é INTOCÁVEL "
                "também para a casa — o floor da v0.4 tranca a reserva "
                "em vez de a reservar à CARGA LOCAL (causa 2 do C10)"])
    elif TARGET == "V05":
        cond = (abs(d5.soc - 24.9136) < 0.0005
                and d5.soc < L.FLOOR_SOC
                and sc == L.LOAD_LOCAL_KW
                and not floor_ev and not min_ev)
        expect("P-R4-03", GATEFALL[2]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["ilha + deficit (NOITE, 600 s): SoC 28.0 → %.4f — desce "
                "ATRAVÉS do floor %.1f (abaixo dele) SEM clamp"
                % (d5.soc, L.FLOOR_SOC),
                "carga local servida: %.2f kW (= LOAD_LOCAL) — a reserva "
                "CONTINUA a alimentar a casa ABAIXO do floor"
                % sc,
                "eventos clamp: island_battery_at_floor=%d, "
                "island_battery_at_island_min=%d (nenhum — o floor de "
                "ilha só pára em ISLAND_MIN_SOC=%.1f)"
                % (len(floor_ev), len(min_ev), L.ISLAND_MIN_SOC),
                "C10 causa 2 RESOLVIDA: o floor da v0.5 bloqueia apenas "
                "a descarga REMOTA; a carga LOCAL usa a reserva até ao "
                "mínimo técnico (opção A do operador)"])
    else:
        cond = (abs(d5.soc - 24.9136) < 0.0005
                and d5.soc < L.FLOOR_SOC
                and sc == L.LOAD_LOCAL_KW
                and not floor_ev and not min_ev)
        expect("P-R4-03", GATEFALL[2]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["ilha + deficit (NOITE, 600 s): SoC 28.0 → %.4f — a "
                "semântica do step_island NÃO mudou na v0.%s (critério "
                "IDÊNTICO ao V05)" % (d5.soc,
                                      "7.1" if IS_V071
                                      else ("7" if IS_V07
                                            else "6")),
                "carga local servida: %.2f kW (= LOAD_LOCAL); eventos "
                "clamp: floor=%d, island_min=%d — a reserva continua "
                "USÁVEL pela casa até ISLAND_MIN_SOC %.1f"
                % (sc, len(floor_ev), len(min_ev), L.ISLAND_MIN_SOC),
                "o limite diário da v0.6 conta apenas provenance "
                "remote_command: o consumo da CASA em ilha (este "
                "teste) NÃO entra no ledger diário por construção",
                "não-regressão: a causa 2 do C10 continua RESOLVIDA"])
    lab.gridsim.set_irradiance("DIA")

    # ================= P-R4-04 — §4.7.2: guarda de regressão ==============
    print("\n[P-R4-04] §4.7.2 — invariante do floor REMOTO (guarda de "
          "regressão)")
    lab.scenario("P-R4-04")
    reset_all(lab)
    time.sleep(0.3)
    d0 = lab.devices[0]
    st1, resp1 = hj(d0.port, "POST", "/battery",
                    {"action": "force_export", "amount_kwh": 999.0},
                    token=d0.service_token)
    d0.soc = 30.0                 # reserva parcial por harness
    st2, resp2 = hj(d0.port, "POST", "/battery",
                    {"action": "discharge",
                     "amount_kwh": round(0.2 * d0.batt_kwh, 3)},
                    token=d0.service_token)
    fb = [e for e in scenario_events(lab, "P-R4-04")
          if e.get("event") == "floor_block"]
    alerts = scan_scenario(lab, "P-R4-04")
    cond = (st1 == 409 and st2 == 409
            and resp1.get("error") == "min_emergency_soc_floor"
            and d0.soc == 30.0 and len(fb) >= 2
            and any(a["rule"] == "D-BATTERY-DRAIN-BELOW-FLOOR"
                    for a in alerts))
    expect("P-R4-04", GATEFALL[3]["prev"], cond,
           "OK",
           "FALHOU (ver detalhe acima)",
           ["force_export 999 sem /local_confirm → %d (%s); fatia que "
            "cruzaria o floor (30→10) → %d; SoC intacto %.2f"
            % (st1, resp1.get("error"), st2, d0.soc),
            "floor_block auditados: %d; scan: %s"
            % (len(fb), [(a["rule"], a["count"]) for a in alerts]),
            ("invariante selada §4.7.2 SEGURA na v0.4 — a v0.5 (floor "
             "só para descarga REMOTA) tem de manter este veredicto OK"
             if TARGET == "V04" else
             "invariante selada §4.7.2 SEGURA na v0.5: a nova semântica "
             "(floor bloqueia apenas descarga REMOTA; carga local até "
             "ISLAND_MIN_SOC em ilha) NÃO tocou no floor remoto — "
             "descida remota abaixo do floor continua IMPOSSÍVEL sem "
             "/local_confirm"
             if TARGET == "V05" else
             ("invariante selada §4.7.2 SEGURA na v0.7.1: o limite "
              "diário continua verificado DEPOIS do floor (999 → 409 "
              "floor com BELOW-FLOOR preservado) — o F-C13/F-K1/F-C14/"
              "F-SP NÃO mexeu na ordem floor→daily"
              if IS_V071 else
              ("invariante selada §4.7.2 SEGURA na v0.7: o limite "
              "diário continua verificado DEPOIS do floor (999 → 409 "
              "floor com BELOW-FLOOR preservado) — o F-C12/F-K1/F-LIMP "
              "NÃO mexeu na ordem floor→daily"
              if IS_V07 else
              "invariante selada §4.7.2 SEGURA na v0.6: o limite diário "
              "é verificado DEPOIS do floor (999 → 409 floor com "
              "BELOW-FLOOR preservado; fatia que cruza o floor → 409 "
              "floor, não daily) — a ordem floor→daily preserva as "
              "contagens do demo e a invariante selada")))])

    # ================= P-R4-05 — C4: fatias invisíveis ====================
    print("\n[P-R4-05] C4 — descarga fatiada (cada <50%) evade TODAS as "
          "regras")
    lab.scenario("P-R4-05")
    reset_all(lab)
    time.sleep(0.3)
    d3 = lab.devices[3]
    socs3 = [d3.soc]
    st_a, _ = hj(d3.port, "POST", "/battery",
                 {"action": "discharge",
                  "amount_kwh": round(0.40 * d3.batt_kwh, 3)},
                 token=d3.service_token)
    socs3.append(d3.soc)
    st_b, _ = hj(d3.port, "POST", "/battery",
                 {"action": "discharge",
                  "amount_kwh": round(0.34 * d3.batt_kwh, 3)},
                 token=d3.service_token)
    socs3.append(d3.soc)
    d4 = lab.devices[4]
    st_c, _ = hj(d4.port, "POST", "/battery",
                 {"action": "discharge",
                  "amount_kwh": round(0.60 * d4.batt_kwh, 3)},
                 token=d4.service_token)
    alerts = scan_scenario(lab, "P-R4-05")
    rules = {a["rule"]: (a["count"], sorted(a["devices"])) for a in alerts}
    cum_in_map = "D-BATTERY-CUMULATIVE-DRAIN" in L.RULE_ATTACK_MAP
    if TARGET == "V04":
        cond = (st_a == 200 and st_b == 200 and st_c == 200
                and not cum_in_map
                and "D-BATTERY-CUMULATIVE-DRAIN" not in rules
                and rules.get("D-BATTERY-DRAIN-LARGE", (0, None))[0] == 1)
        expect("P-R4-05", GATEFALL[4]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias na casa %s: SoC %s (74%% em 2 operações, cada "
                "<50%%)" % (d3.name, socs3),
                "operação única de 60%% na casa %s: %d — D-BATTERY-"
                "DRAIN-LARGE (G7) SÓ vê a operação ÚNICA >=50%%"
                % (d4.name, st_c),
                "alertas do cenário: %s — as FATIAS não geram NADA"
                % sorted(rules.items()),
                "RULE_ATTACK_MAP: %d regras — regra cumulativa "
                "INEXISTENTE (C4 aberto por decisão do operador; a v0.5 "
                "fecha-o)" % len(L.RULE_ATTACK_MAP)])
    elif TARGET == "V05":
        cum = rules.get("D-BATTERY-CUMULATIVE-DRAIN", (0, None))
        cond = (st_a == 200 and st_b == 200 and st_c == 200
                and cum_in_map
                and cum[0] == 2
                and rules.get("D-BATTERY-DRAIN-LARGE", (0, None))[0] == 1)
        expect("P-R4-05", GATEFALL[4]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias na casa %s: SoC %s (74%% em 2 operações, cada "
                "<50%%)" % (d3.name, socs3),
                "operação única de 60%% na casa %s: %d — continua SÓ na "
                "por-operação D-BATTERY-DRAIN-LARGE (a per-op >=50%% é "
                "EXCLUÍDA da cumulativa: sem dupla-disparo)"
                % (d4.name, st_c),
                "alertas do cenário: %s — a CUMULATIVA flagra as fatias"
                % sorted(rules.items()),
                "RULE_ATTACK_MAP: %d regras — D-BATTERY-CUMULATIVE-"
                "DRAIN PRESENTE; janela %.0f s, limiar %.0f%%, só "
                "remote_command (C4 FECHADO)"
                % (len(L.RULE_ATTACK_MAP), L.CUMULATIVE_DRAIN_WINDOW,
                   L.CUMULATIVE_DRAIN_PCT)])
    else:
        daily_evs = [e for e in scenario_events(lab, "P-R4-05")
                     if e.get("event") == "remote_daily_limit_block"]
        cond = (st_a == 200 and st_b == 409 and st_c == 409
                and cum_in_map
                and "D-BATTERY-CUMULATIVE-DRAIN" not in rules
                and "D-BATTERY-DRAIN-LARGE" not in rules
                and len(daily_evs) == 2)
        expect("P-R4-05", GATEFALL[4]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias na casa %s: SoC %s — a de 40%% executa (200) e "
                "a de 34%% dá 409 remote_discharge_daily_limit (used "
                "40+34 = 74 > 40)"
                % (d3.name, socs3),
                "operação única de 60%% na casa %s: %d daily TAMBÉM "
                "(60 > 40 — NEM EXECUTA: DRAIN-LARGE fica INATINGÍVEL "
                "por remote_command com o limite ativo)"
                % (d4.name, st_c),
                "alertas do cenário: %s — cumulativa e por-operação "
                "AUSENTES (superssenção datada no lab; o bloqueio "
                "diário é PREVENÇÃO, os 2 eventos "
                "remote_daily_limit_block são a deteção)"
                % sorted(rules.items()),
                "RULE_ATTACK_MAP: %d regras (regra cumulativa PRESENTE "
                "mas inatingível neste cenário); limite diário %.0f%% "
                "/%.0f s por remote_command"
                % (len(L.RULE_ATTACK_MAP), L.REMOTE_DISCHARGE_DAILY_PCT,
                   L.REMOTE_DISCHARGE_DAILY_WINDOW)])

    # ================= P-R4-06 — FP: legítimos silenciosos ===============
    print("\n[P-R4-06] FP — operações legítimas: silêncio por cegueira na "
          "v0.4")
    lab.scenario("P-R4-06")
    reset_all(lab)
    time.sleep(0.3)
    d2 = lab.devices[2]
    st1, _ = hj(d2.port, "POST", "/battery",
                {"action": "discharge", "amount_kwh": 2.0},
                token=d2.service_token)          # 43.86% — acima do floor
    stc, respc = hj(d2.port, "POST", "/local_confirm",
                    {"pin": d2.local_pin})       # exceção exclusiva §4.7.2
    st2, _ = hj(d2.port, "POST", "/battery",
                {"action": "discharge", "amount_kwh": 999.0,
                 "confirm_token": respc.get("confirm_token")},
                token=d2.service_token)
    alerts = scan_scenario(lab, "P-R4-06")
    cum_in_map = "D-BATTERY-CUMULATIVE-DRAIN" in L.RULE_ATTACK_MAP
    if TARGET == "V04":
        cond = (st1 == 200 and stc == 200 and st2 == 200
                and not alerts and not cum_in_map)
        expect("P-R4-06", GATEFALL[5]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["export legítimo acima do floor (2.0 kWh = %.2f%%): %d; "
                "abaixo do floor COM /local_confirm: %d → %d"
                % (2.0 / d2.batt_kwh * 100.0, st1, stc, st2),
                "alertas do cenário: %s — silêncio TOTAL"
                % [(a["rule"], a["count"]) for a in alerts],
                "MAS o silêncio é POR CEGUEIRA: sem regra cumulativa "
                "(%d regras), o legítimo e o ataque fatiado do P-R4-05 "
                "são INDISTINGUÍVEIS — a regra nova da v0.5 tem de "
                "manter estes legítimos silenciosos E alertar nas "
                "fatias" % len(L.RULE_ATTACK_MAP)])
    elif TARGET == "V05":
        cond = (st1 == 200 and stc == 200 and st2 == 200
                and not alerts and cum_in_map)
        expect("P-R4-06", GATEFALL[5]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["export legítimo acima do floor (2.0 kWh = %.2f%%): %d; "
                "abaixo do floor COM /local_confirm: %d → %d"
                % (2.0 / d2.batt_kwh * 100.0, st1, stc, st2),
                "alertas do cenário: %s — silêncio MANTIDO"
                % [(a["rule"], a["count"]) for a in alerts],
                "agora POR DISCRIMINAÇÃO: a regra cumulativa EXISTE "
                "(%d regras) e NÃO dispara nos legítimos (43.86%% < "
                "limiar por janela; /local_confirm é provenance "
                "local_confirm, FORA de remote_command) — discrimina o "
                "ataque fatiado do P-R4-05 sem falsos positivos"
                % len(L.RULE_ATTACK_MAP)])
    else:
        daily_evs = [e for e in scenario_events(lab, "P-R4-06")
                     if e.get("event") == "remote_daily_limit_block"]
        cond = (st1 == 409 and stc == 200 and st2 == 200
                and not alerts and cum_in_map and len(daily_evs) == 1)
        expect("P-R4-06", GATEFALL[5]["prev"], cond,
               "DECLARADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["export legítimo (2.0 kWh = %.2f%%): %d daily — "
                "43.86 > 40: o limite diário ATINGE também os "
                "legítimos (custo DECLARADO da opção 1)"
                % (2.0 / d2.batt_kwh * 100.0, st1),
                "o fluxo abaixo do floor COM /local_confirm mantém-se "
                "%d → %d — a exceção exclusiva §4.7.2 está INTACTA "
                "(provenance local_confirm, fora do ledger diário)"
                % (stc, st2),
                "alertas do cenário: %s — ZERO alertas de REGRA (o "
                "evento remote_daily_limit_block é deteção do bloqueio, "
                "não regra; nenhuma regra nova por escopo do GO)"
                % [(a["rule"], a["count"]) for a in alerts],
                "consequência declarada no GO: operações legítimas "
                ">40%%/dia passam a exigir /local_confirm — o J3 (FP "
                "WARN) morre por saturação mas nasce o atrito da "
                "confirmação física; fica DECLARADO"])

    # ---------------------------------------------------------------------
    # SUMÁRIO — previsão vs observado (GATEFALL fechado; alinhado por ID)
    # ---------------------------------------------------------------------
    by_id = {v["id"]: v for v in VEREDICTOS}
    print("\n" + "=" * 72)
    print("SUMÁRIO GATEFALL — previsão PRÉ-registada vs veredicto OBSERVADO")
    print("=" * 72)
    prev_erradas = 0
    match_n = 0
    default_word = "CONFIRMADO" if TARGET == "V04" else "RESOLVIDO"
    for entry in GATEFALL:
        v = by_id.get(entry["id"], {"veredicto": "NÃO EXECUTADO"})
        match = (v["veredicto"] == entry.get("expected", default_word))
        if not match:
            prev_erradas += 1
        else:
            match_n += 1
        print("  [%s/%s] previsto: %s | observado: %s"
              % (entry["id"], entry["finding"],
                 entry.get("expected", default_word), v["veredicto"]))
    print("-" * 72)
    print("PREVISÕES CONFIRMADAS contra a v%s (%s): %d/%d"
          % (L.LAB_VERSION, TARGET, match_n, len(GATEFALL)))
    print("PREVISÕES ERRADAS: %d" % prev_erradas)
    print("LAB ALVO: v%s (%s), hash %s (INTOCADA — verificado no arranque)"
          % (L.LAB_VERSION, TARGET, lab_sha))
    if TARGET == "V04":
        print("GATEFALL OFICIAL da R4 = ESTE RUN 1 contra a v0.4 "
              "(correção de método do operador 13-11: nunca o run "
              "seguinte). A v0.5 (semântica do floor opção A + "
              "ISLAND_MIN_SOC + measure com dois atacantes + linha "
              "opção B + regra cumulativa C4) é o DEPOIS; C5/C6/C9/H7/"
              "I2/I3/I6 ficam para a ronda seguinte.")
    elif TARGET == "V05":
        print("GATEFALL OFICIAL da R4 = RUN 1 contra a v0.4 (6/6 "
              "CONFIRMADO, preservado em sunstrike_probes_v04_r4_run1."
              "txt). ESTE run contra a v0.5 é a evidência do DEPOIS "
              "(previsões pré-registadas na entrada v0.2 do changelog "
              "do probe, ANTES desta corrida); C5/C6/C9/H7/I2/I3/I6 "
              "ficam para a ronda seguinte.")
    elif TARGET == "V071":
        print("GATEFALL OFICIAL da R4 = RUN 1 contra a v0.4 (6/6 "
              "CONFIRMADO, preservado). ESTE run contra a v0.7.1 "
              "RESTAURADA é a NÃO-REGRESSÃO da recuperação (reconstrução "
              "pós-INFRA-2026-13-11-B; previsões V071 pré-registadas na "
              "entrada v0.5.1 do changelog, ANTES desta corrida): o "
              "limite diário mantém o C10 resolvido COM MARGEM, as "
              "guardas §4.7.2/C10-causa-2 ficam VERDES, o custo da "
              "opção 1 nos legítimos fica DECLARADO e as regras novas "
              "(F-C13/F-K1/F-C14/F-SP) ficam CALADAS nos cenários r4. "
              "C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a v0.8.")
    else:
        print("GATEFALL OFICIAL da R4 = RUN 1 contra a v0.4. ESTE run "
              "contra a v0.6 é a NÃO-REGRESSÃO da R5 (previsões V06 "
              "pré-registadas na entrada v0.3 do changelog do probe, "
              "ANTES desta corrida): o limite diário mantém o C10 "
              "resolvido COM MARGEM, as guardas §4.7.2/C10-causa-2 "
              "ficam VERDES e o custo da opção 1 nos legítimos fica "
              "DECLARADO; C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a "
              "ronda seguinte.")
    lab.stop()
    return 0 if prev_erradas == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        traceback.print_exc()
        raise SystemExit(3)

# EOF:sunstrike_probes_r4.py
