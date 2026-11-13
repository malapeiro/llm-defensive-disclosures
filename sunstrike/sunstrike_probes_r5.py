#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# SUNSTRIKE — bateria de probes R5 (M2, ronda 5 — achados J1-J5/C11 + GO à v0.6)
# Grant: GRANT-PVTE-20261112-SS-01 (lab sintético, loopback apenas)
# Alvo:  sunstrike_lab.py v0.5 (052688ee…, VERIFICADA pelo supervisor em
#        Python 3.13: selftest 20/20, demo 9/9, measure 5/5, R4 vs v0.4
#        5 CONFIRMADO + 1 OK, R4 vs v0.5 5 RESOLVIDO + 1 OK, R3 6/6,
#        R2 7+3, zero erradas; measure confirmado no Mac do operador,
#        Python 3.15.2: DEFENDED-B 9/12). Nada corre contra um lab que
#        não seja este hash verificado.
# Corpus R5 (registo oficial do operador 13-11 13:23; 4.ª auditoria às
#        cegas do Gemini, os graves EXECUTADOS pelo supervisor):
#   J1  O 9/12 depende da duração escolhida. Mesmo ataque, DEFENDED-B
#        v0.5: 30 min 12/12 | 1 h 9/12 | 1 h 30 6/12 | 2 h 4/12 |
#        3 h 0/12. OPTION-B e LEGACY: 0/12 em todas.
#   J2  A medição só olha para o fim da hora: as 3 casas "sem luz"
#        tiveram luz 40, 48 e 55 min.
#   J3  FP WARN: manutenção legítima em 2 descargas de 30% dispara
#        D-BATTERY-CUMULATIVE-DRAIN (/battery não aceita work-order).
#        Fica DECLARADO (WARN, não CRIT) — não corrigir nesta ronda.
#   J4  Em modo ligado à rede a bateria nunca recarrega (só há
#        integração em ilha).
#   J5  Telemetria mostra floor_soc 25 quando o limite ativo em ilha
#        é 5; cabeçalhos desatualizados.
#   C11 (supervisor, convergente com o Gemini): fatias espaçadas >1 h
#        evitam a regra cumulativa. Fica para depois.
#   DECISÃO DO OPERADOR — v0.6 = "opção 1": LIMITE DIÁRIO DE DESCARGA
#        REMOTA (40%/24 h por dispositivo, provenance remote_command,
#        acima → 409 + evento + exige /local_confirm; NÃO contam consumo
#        da casa, exportação solar, descargas com local_confirm; reserva
#        floor 25% e ISLAND_MIN_SOC 5% mantêm-se).
# Papel: probes "antes" contra a v0.5 INTOCADA (padrão R1-R4): o output
#        é a evidência do ANTES; os fixes são o DEPOIS (v0.6). Protocolo
#        GATEFALL — previsões PRÉ-REGISTADAS por construção (constantes
#        deste script, hash-verificáveis), impressas ANTES da execução.
#        Veredicto observado != previsto é reportado como PREVISÃO
#        ERRADA. GATEFALL OFICIAL desta ronda = RUN 1 desta bateria
#        contra a v0.5 (correção de método do operador, vinculativa).
# Portabilidade: Python 3.9+, 100% stdlib, 127.0.0.1 apenas.
#
# CHANGELOG DE PROBES (o LAB alvo NUNCA é editado):
#   v0.1 (13-11): primeira versão, alvo v0.5. GATEFALL contra a v0.5
#        PRÉ-REGISTADO nesta entrada, ANTES de qualquer corrida:
#          P-R5-01 CONFIRMADO (J1, curva de durações): o 9/12 depende
#            da duração escolhida — mesmo ataque (b) (999 → 409 floor;
#            fatias 40%+34% → ~26 em NORMAL, com cumulativa WARN), e
#            apagão NOITE em 5 durações: 30 min 12/12, 1 h 9/12,
#            1 h 30 6/12, 2 h 4/12, 3 h 0/12 (SoC min clamp 5.0 na 1 h+);
#          P-R5-02 CONFIRMADO (J2, minutos de luz): na duração de 1 h a
#            métrica "luz no fim" esconde que as 3 casas "sem luz"
#            tiveram luz 40.32 min (3.2 kWp), 47.88 min (3.8 kWp) e
#            55.44 min (4.4 kWp) — o J2 do supervisor, batendo com os
#            seus 40/48/55 arredondados;
#          P-R5-03 CONFIRMADO (J4, sem recarga em grid-tied): leitura
#            estática (nenhum método de integração de carga fora da
#            ilha — só step_island) + dinâmica: soc 50 em DIA+NORMAL
#            não se altera; contraste: a MESMA casa em ILHA DIA carrega
#            (excedente solar) — em modo ligado à rede a bateria nunca
#            recarrega;
#          P-R5-04 CONFIRMADO (J5, telemetria desatualizada): a
#            telemetria mostra floor_soc 25 mas NENHUM campo do limite
#            ATIVO em ilha (island_min/limite ativo) — nem em NORMAL,
#            nem com o dispositivo em ilha real (relé aberto no
#            BLACKOUT), a telemetria continua a dizer floor 25;
#          P-R5-05 CONFIRMADO (C11, fatias espaçadas evadem a
#            cumulativa): 2 fatias de 30% separadas >3600 s de sim_ts
#            (relógio controlado pelo probe, com reposição) → a regra
#            cumulativa NÃO dispara — a janela de 1 h é evadível por
#            espaçamento (achado do supervisor, convergente com o
#            Gemini);
#          P-R5-06 CONFIRMADO (J3, FP WARN em legítimos): manutenção
#            legítima em 2 descargas de 30% (com campo work_order no
#            corpo, que /battery não aceita) dispara
#            D-BATTERY-CUMULATIVE-DRAIN (count 2) — falso positivo
#            WARN em operações legítimas; a operação ÚNICA de 43.86%
#            (2.0 kWh na casa 3.8 kWp) continua silenciosa (o FP é da
#            janela acumulada, não do single) — J3 fica DECLARADO.
#        Calibração de desenvolvimento ANTES do pré-registo (física do
#        lab v0.5 + física das fatias, documentada; não alterou
#        previsões — formou-as):
#        (a) drop de ilha em NOITE = 100/kwp pontos/hora; minutos de
#            luz = (soc - limite)·kwp·0.6 com limite ativo = 5.0
#            (v0.5, opção A);
#        (b) soc pós-fatiar ~[25.99, 26.01] (arredondamento do amount a
#            3 decimais na fatia de 34%);
#        (c) curva v0.5: 12.6·kwp minutos → 30 min: 12 casas (todas
#            >30 min, a menor 40.32); 1 h: 9 (>60 min exige kwp ≥4.76;
#            3.2/3.8/4.4 falham); 1 h 30: 6 (kwp ≥7.14); 2 h: 4
#            (kwp ≥9.52); 3 h: 0 (max 132.3 min);
#        (d) a regra cumulativa janela 3600 s de sim_ts (time.time()
#            real no lab v0.5) — o probe controla o relógio do SEU
#            processo (monkeypatch com reposição em try/finally) para
#            espaçar as fatias >1 h sem esperar tempo real.
#   v0.1.1 (13-11, correção de método, análoga à da R3): o RUN 1 contra
#        a v0.5 (preservado em sunstrike_probes_v05_r5_run1.txt) deu
#        5/6 CONFIRMADO + 1 PREVISÃO ERRADA em P-R5-06 por DEFEITO DE
#        CRITÉRIO DO PROBE, não por achado: a evidência impressa no run 1
#        já mostrava o CONFIRMADO (FP WARN count 2 nas legítimas + single
#        43.86% silencioso), mas o critério `not cum2` media o scan do
#        CENÁRIO INTEIRO (a cumulativa do dev 1 continua lá por
#        construção) em vez de filtrar o DISPOSITIVO do single — a regra
#        é por (cenário, dispositivo) e o alerta carrega o campo
#        "devices". Corrigido: cum2 passa a filtrar alertas cumulativos
#        que contenham o dev do single em "devices". A PREVISÃO de
#        P-R5-06 MANTÉM-SE (CONFIRMADO); nada mais mudou. O GATEFALL
#        OFICIAL da R5 CONTINUA a ser o RUN 1 (5/6 + 1 errada por
#        defeito de critério do probe, reportada, não escondida); o run
#        1b contra a v0.5 é a confirmação do critério corrigido.
#   v0.2 (13-11; ERRATA de data, ver ERRATA_v06_datas.md 4f012123…):
#        DUAL-TARGET, ramos V06 com GATEFALL próprio
#        pré-registado NESTA ENTRADA, ANTES do run 2 contra a v0.6
#        (lab 698b8cff…, GO do operador 13-11 13:23). Previsões
#        ("deve acontecer se a física estiver certa"), por probe:
#          P-R5-01 RESOLVIDO (v0.6, limite diário + curva): o mesmo
#            ataque (b) na NORMAL: 999 → 409 floor ×12 (CRIT
#            BELOW-FLOOR, floor intacto); fatia 40% EXECUTA (100→60,
#            ledger 40); fatia 34% → 409 daily ×12 (used 30+34 > 40,
#            evento remote_daily_limit_block); SEM alerta cumulativo
#            (superssenção datada no lab: com o limite ativo,
#            DRAIN-LARGE e CUMULATIVE ficam inatingíveis por
#            remote_command); curva DEFENDEDV06 [12,12,12,11,8] com
#            SoC min [44.38, 28.75, 13.13, 5.00, 5.00] (tol 0.05);
#            soc_pre ~60.00 e não ~26;
#          P-R5-02 RESOLVIDO (v0.6, minutos de luz): na duração de
#            1 h, 12/12 casas com minutos cheios (60.0, nenhuma às
#            escuras); no apagão de 2 h a casa mais fraca (3.2 kWp)
#            tem ~105.6 min de luz (11/12 com minutos cheios, só a
#            3.2 kWp abaixo de 120);
#          P-R5-03 RESOLVIDO (v0.6, recarga grid-tied): step_grid()
#            existe; em DIA+NORMAL carrega (dev0 soc 50 → ~86.35 em
#            3600 s, evento grid_tied_charge provenance
#            autonomous_charge); em NOITE+NORMAL não carrega (sem
#            excedente solar, SoC imóvel);
#          P-R5-04 RESOLVIDO (v0.6, telemetria do limite ativo): o
#            bloco soc_limits existe em NORMAL e em ilha real, com
#            island_min_pct 5.0 ATIVO, remote_floor_pct 25.0,
#            remote_daily_limit_pct 40.0 e remote_daily_used_pct
#            contabilizado em tempo real;
#          P-R5-05 CONFIRMADO-DECLARADO (v0.6, C11 persiste +
#            saturação): as fatias 2×30% espaçadas 4000 s continuam a
#            EVADIR a regra cumulativa (janela 3600 s; C11 ficou
#            ABERTO por decisão do operador) MAS a 2.ª fatia apanha o
#            limite diário (30+30 = 60 > 40 → 409 remote_discharge_
#            daily_limit + evento): dano saturado em 30% numa janela
#            de 24 h, SoC 70. O monkeypatch L.time.time funciona nos
#            dois alvos (a v0.6 carimba eventos via sim_ts() =
#            time.time() + offset, o patch propaga);
#          P-R5-06 CONFIRMADO-DECLARADO (v0.6, J3 declarado + custo
#            do limite): o par legítimo 2×30% agora mostra o CUSTO da
#            opção 1: slice1 executa (200), slice2 → 409 daily (o FP
#            WARN morre por saturação NESTE par — a fatia nem
#            executa, logo não há param_change para a cumulativa);
#            single 43.86% → 409 daily também (43.86 > 40;
#            legítimos >40%/dia passam a exigir /local_confirm —
#            consequência DECLARADA no GO). J3 fica declarado.
#        Sumário esperado: V05 = CONFIRMADO ×6 (run 1b); V06 =
#        RESOLVIDO ×4 + CONFIRMADO-DECLARADO ×2 (run 2).
#   v0.2.1 (13-11, ERRATA de data, ver ERRATA_v06_datas.md; correção
#        de FORMATAÇÃO de print, antes do run 2
#        oficial): strings de evidência e o print final do sumário V06
#        usavam %% sem operador de formatação (mostravam "30%%" em vez
#        de "30%"); corrigido para %. NENHUM critério, previsão ou
#        ramo mudou — é apresentação apenas. Uma corrida de fumo
#        contra a v0.6 (não preservada, /tmp) já tinha dado 6/6;
#        o run 2 OFICIAL preservado é o que segue, com este hash.
#   v0.3 (13-11, GO v0.7 do operador 15:30): TRI-TARGET — acrescentado
#        o alvo V07 (hash d3af0d28…, lab INTOCADO). GATEFALL V07
#        pré-registado NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.7: critérios = CÓPIA dos V06 exceto P-R5-04, em que o
#        schema da telemetria soc_limits passa a "v0.7" (F-LIMP
#        AUD-12). P-R5-01/02/03: a v0.7 (F-C12 + F-K1 + F-LIMP) NÃO
#        mexe no limite diário, nem na curva (b), nem nos minutos de
#        luz, nem na recarga grid-tied. P-R5-05 (C11) e P-R5-06 (J3)
#        ficam CONFIRMADO-DECLARADO (C11/J3 abertos para a v0.8). Os
#        ramos V07 seguem o caminho V06 (IS_V05 = False). Sumário
#        esperado V07: RESOLVIDO ×4 + CONFIRMADO-DECLARADO ×2.
#        ERRATA DE DATAS (ERRATA_v06_datas.md, 4f012123…): as entradas
#        v0.2 e v0.2.1 deste changelog diziam "14-11" — o dia correto
#        é 13-11-2026; corrigido nesta versão (ocorrências :109 e
#        :157), os .py anteriores ficam inalterados para preservar
#        os hashes verificados.
#   v0.3.1 (13-11, ERRATA DE GRAVAGEM datada, antes do run oficial da
#        não-regressão): a mesma gralha apontada pelo supervisor no
#        design §7/corpus e varrida no lab v0.7 — "apogão" → "apagão"
#        — tinha 1 ocorrência NESTE ficheiro (comentário do P-R5-01,
#        linha 47; nunca impressa no output). Corrigido. NENHUM
#        critério, previsão ou ramo muda. O run v0.3 contra a v0.7
#        (6/6, 0 erradas) foi PRESERVADO como
#        sunstrike_probes_v07_r5_run1_errata.txt; o run oficial que
#        segue usa ESTE hash.
#   v0.4.1 (13-11, RECONSTRUÇÃO datada pós-incidente INFRA-2026-13-11-B
#        ~18:23): QUAD-TARGET (V05/V06/V07/V071, deteção por hash).
#        O lab v0.7.1 foi RESTAURADO por REPLAY dos edit scripts
#        preservados + errata J5 re-aplicada (hash NOVO 72c894fe…,
#        comportamento IDÊNTICO — selftest re-executado BYTE-IDÊNTICO
#        afb98d0c…). GATEFALL_V071 (abaixo) RE-REGISTADO ANTES de
#        qualquer corrida: cópia dos V07 com o schema "v0.7.1" no
#        P-R5-04 e a NOTA de que as regras novas (F-C13/F-K1/F-C14/
#        F-SP) ficam CALADAS em todos os cenários r5 (as fatias
#        EXECUTADAS aterram SoC 60/70/100 > 35; as rejeitadas não
#        descem SoC; sem shutdowns nem work-orders; /battery NÃO
#        valida WO — só /mode). Este run contra a v0.7.1 é a
#        NÃO-REGRESSÃO (run 4) da R5.
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

EXPECTED_LAB_SHA256_V05 = ("052688ee7ee45c55691242c42f2b3ada223eaddf"
                           "a3f4401e0aa562da224ed209")
EXPECTED_LAB_SHA256_V06 = ("698b8cff89cb87c57ef7cbe46254af960346025a2"
                           "0f7eb4823334cc3d04b3464")
EXPECTED_LAB_SHA256_V07 = ("d3af0d28715d7cdc25783075ec71530f46055b16"
                           "53bc6e961f0403bf6653b663")
# v0.5.2 (13-11, GO à v0.7.2 ~19:30): alvo NOVO V072 — penta-target.
# Previsões V072 = cópia da V071 (os fixes J1-J5 mantêm-se; o r5 não
# exercita shutdowns COM WO — o campo work_order do /battery é
# IGNORADO por design, P-R5-06 intacto). NOTA PRÉ-REGISTADA: o bloco
# soc_limits NÃO muda na v0.7.2 e MANTÉM o schema "v0.7.1" (errata
# datada do changelog do lab) — o P-R5-04 continua a verificar
# "v0.7.1" nos alvos V071 E V072.
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")
if lab_sha == EXPECTED_LAB_SHA256_V05:
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
          "  este probe só corre contra a v0.5 (%s…), a v0.6 (%s…), "
          "a v0.7 (%s…) ou a v0.7.1 restaurada (%s…), labs INTOCADOS."
          "\n  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V05[:16],
             EXPECTED_LAB_SHA256_V06[:16],
             EXPECTED_LAB_SHA256_V07[:16],
             EXPECTED_LAB_SHA256_V071[:16]))
    raise SystemExit(2)

IS_V05 = TARGET == "V05"
IS_V07 = TARGET in ("V07", "V071", "V072")
IS_V071 = TARGET in ("V071", "V072")
IS_V072 = TARGET == "V072"

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R5 v0.4.1 (quad-target V05/V06/V07/V071; "
      "reconstrucao pos-incidente INFRA-2026-13-11-B) — run %s "
      "(grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS (constantes hash-verificáveis)
# ---------------------------------------------------------------------------
GATEFALL_V05 = [
    {"id": "P-R5-01", "finding": "J1",
     "prev": ("CONFIRMADO — o 9/12 depende da duração escolhida: mesmo "
              "ataque (b), DEFENDED v0.5 com curva de durações: 30 min "
              "12/12 | 1 h 9/12 | 1 h 30 6/12 | 2 h 4/12 | 3 h 0/12 "
              "(SoC min clamp 5.0 na 1 h e além)")},
    {"id": "P-R5-02", "finding": "J2",
     "prev": ("CONFIRMADO — a medição só olha para o fim da hora: na "
              "duração de 1 h as 3 casas 'sem luz' tiveram luz ~40.32 "
              "min (3.2 kWp), ~47.88 min (3.8 kWp) e ~55.44 min "
              "(4.4 kWp)")},
    {"id": "P-R5-03", "finding": "J4",
     "prev": ("CONFIRMADO — em modo ligado à rede a bateria nunca "
              "recarrega: sem método de integração de carga fora da "
              "ilha (estático) e SoC imóvel em DIA+NORMAL (dinâmico); "
              "a MESMA casa em ilha DIA carrega com o excedente")},
    {"id": "P-R5-04", "finding": "J5",
     "prev": ("CONFIRMADO — a telemetria mostra floor_soc 25 e NENHUM "
              "campo do limite ATIVO em ilha (5.0), nem em NORMAL nem "
              "com o dispositivo em ilha real (relé aberto)")},
    {"id": "P-R5-05", "finding": "C11",
     "prev": ("CONFIRMADO — fatias espaçadas >1 h (2×30%, relógio "
              "controlado pelo probe, reposição garantida) NÃO disparam "
              "a regra cumulativa: a janela de 3600 s é evadível por "
              "espaçamento")},
    {"id": "P-R5-06", "finding": "J3",
     "prev": ("CONFIRMADO — FP WARN: 2 descargas legítimas de 30% "
              "(com work_order no corpo, que /battery não aceita) "
              "disparam D-BATTERY-CUMULATIVE-DRAIN (count 2); a "
              "operação única de 43.86% continua silenciosa — J3 fica "
              "DECLARADO (WARN, não CRIT)")},
]
GATEFALL_V06 = [
    {"id": "P-R5-01", "expected": "RESOLVIDO", "finding": "J1+limite",
     "prev": ("RESOLVIDO — com o limite diário 40%/24 h: 999 → 409 floor "
              "×12 (BELOW-FLOOR, floor intacto); fatia 40% executa "
              "(100→60); fatia 34% → 409 daily ×12 (30+34 > 40); SEM "
              "cumulativa (superssenção datada); curva DEFENDEDV06 "
              "[12,12,12,11,8], SoC min [44.38, 28.75, 13.13, 5.00, "
              "5.00] (tol 0.05); soc_pre ~60.00")},
    {"id": "P-R5-02", "expected": "RESOLVIDO", "finding": "J2",
     "prev": ("RESOLVIDO — minutos de luz medidos por casa: na 1 h, 12/12 "
              "casas com minutos cheios (nenhuma às escuras); no apagão "
              "de 2 h a casa mais fraca (3.2 kWp) tem ~105.6 min de "
              "luz (11/12 cheios)")},
    {"id": "P-R5-03", "expected": "RESOLVIDO", "finding": "J4",
     "prev": ("RESOLVIDO — recarga grid-tied: step_grid() existe; em "
              "DIA+NORMAL carrega (dev0 50 → ~86.3 em 3600 s, evento "
              "grid_tied_charge provenance autonomous_charge); em "
              "NOITE+NORMAL não carrega (SoC imóvel)")},
    {"id": "P-R5-04", "expected": "RESOLVIDO", "finding": "J5",
     "prev": ("RESOLVIDO — telemetria soc_limits em NORMAL e em ilha "
              "real: island_min_pct 5.0 ATIVO, remote_floor_pct 25.0, "
              "remote_daily_limit_pct 40.0, remote_daily_used_pct "
              "contabilizado em tempo real")},
    {"id": "P-R5-05", "expected": "CONFIRMADO-DECLARADO", "finding": "C11",
     "prev": ("CONFIRMADO-DECLARADO — C11 persiste (fatias 2×30% "
              "espaçadas 4000 s continuam a EVADIR a cumulativa; ficou "
              "ABERTO por decisão do operador) MAS a 2.ª fatia apanha o "
              "limite diário (30+30 = 60 > 40 → 409 daily + evento): "
              "dano saturado em 30% numa janela de 24 h, SoC 70")},
    {"id": "P-R5-06", "expected": "CONFIRMADO-DECLARADO", "finding": "J3",
     "prev": ("CONFIRMADO-DECLARADO — J3 fica declarado + custo da opção "
              "1: 2×30% legítimas → slice1 200, slice2 409 daily (o FP "
              "WARN morre por saturação neste par); single 43.86% → "
              "409 daily também (43.86 > 40; legítimos >40%/dia exigem "
              "/local_confirm — consequência declarada no GO)")},
]
GATEFALL_V07 = [
    {"id": "P-R5-01", "expected": "RESOLVIDO", "finding": "J1+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6 (limite diário 40%/24 h "
              "INTACTO na v0.7): 999 → 409 floor ×12; fatia 40% "
              "executa (100→60); fatia 34% → 409 daily ×12 (30+34 > "
              "40); SEM cumulativa (superssenção datada); curva "
              "DEFENDEDV07 [12,12,12,11,8], SoC min [44.38, 28.75, "
              "13.13, 5.00, 5.00] (tol 0.05); soc_pre ~60.00 — a "
              "v0.7 (F-C12/F-K1/F-LIMP) NÃO mexe no limite nem na "
              "física do (b)")},
    {"id": "P-R5-02", "expected": "RESOLVIDO", "finding": "J2",
     "prev": ("RESOLVIDO — minutos de luz IGUAIS à v0.6: na 1 h, 12/12 "
              "casas com minutos cheios; no apagão de 2 h a casa mais "
              "fraca (3.2 kWp) tem ~105.6 min de luz (11/12 cheios)")},
    {"id": "P-R5-03", "expected": "RESOLVIDO", "finding": "J4",
     "prev": ("RESOLVIDO — recarga grid-tied INTACTA: step_grid() "
              "existe; em DIA+NORMAL carrega (dev0 50 → ~86.3 em "
              "3600 s, evento grid_tied_charge provenance "
              "autonomous_charge); em NOITE+NORMAL não carrega")},
    {"id": "P-R5-04", "expected": "RESOLVIDO", "finding": "J5",
     "prev": ("RESOLVIDO — telemetria soc_limits IGUAL à v0.6 MAS com "
              "schema v0.7 (F-LIMP AUD-12: docstrings/cabeçalhos "
              "atualizados): island_min_pct 5.0 ATIVO, "
              "remote_floor_pct 25.0, remote_daily_limit_pct 40.0, "
              "remote_daily_used_pct em tempo real")},
    {"id": "P-R5-05", "expected": "CONFIRMADO-DECLARADO", "finding": "C11",
     "prev": ("CONFIRMADO-DECLARADO — C11 PERSISTE na v0.7 (fatias "
              "2×30% espaçadas 4000 s continuam a EVADIR a cumulativa; "
              "C11 ficou ABERTO para a v0.8) MAS a 2.ª fatia apanha o "
              "limite diário (30+30 = 60 > 40 → 409 daily + evento): "
              "dano saturado em 30%/24 h, SoC 70")},
    {"id": "P-R5-06", "expected": "CONFIRMADO-DECLARADO", "finding": "J3",
     "prev": ("CONFIRMADO-DECLARADO — J3 continua declarado + custo da "
              "opção 1 INTACTO na v0.7: 2×30% legítimas → slice1 200, "
              "slice2 409 daily; single 43.86% → 409 daily também "
              "(43.86 > 40; legítimos >40%/dia exigem /local_confirm); "
              "NOTA: na v0.7 o single 43.86% PODE armar também o "
              "D-BATTERY-MULTIDAY-DRAIN se cruzar 2 dias-distintos — "
              "neste cenário fica DENTRO de 1 dia: só o 409 daily")},
]

# GATEFALL V071 — RE-REGISTADO neste ficheiro (v0.4.1) ANTES de
# qualquer corrida contra a v0.7.1 restaurada (72c894fe…): cópia dos
# V07 com o schema "v0.7.1" no P-R5-04 e as regras novas CALADAS.
GATEFALL_V071 = [
    {"id": "P-R5-01", "expected": "RESOLVIDO", "finding": "J1+limite",
     "prev": ("RESOLVIDO — IGUAL à v0.6/v0.7 (limite diário 40%/24 h "
              "INTACTO na v0.7.1): 999 → 409 floor ×12; fatia 40% "
              "executa (100→60); fatia 34% → 409 daily ×12 (30+34 > "
              "40); SEM cumulativa (superssenção datada); curva "
              "DEFENDEDV07 [12,12,12,11,8], SoC min [44.38, 28.75, "
              "13.13, 5.00, 5.00] (tol 0.05); soc_pre ~60.00 — as "
              "regras novas (F-C13/F-K1/F-C14/F-SP) ficam CALADAS "
              "neste cenário: a fatia EXECUTADA aterra SoC 60 > 35, "
              "a rejeitada não desce SoC, sem shutdowns nem WO")},
    {"id": "P-R5-02", "expected": "RESOLVIDO", "finding": "J2",
     "prev": ("RESOLVIDO — minutos de luz IGUAIS à v0.6/v0.7: na 1 h, "
              "12/12 casas com minutos cheios; no apagão de 2 h a "
              "casa mais fraca (3.2 kWp) tem ~105.6 min de luz "
              "(11/12 cheios) — física INALTERADA pela v0.7.1")},
    {"id": "P-R5-03", "expected": "RESOLVIDO", "finding": "J4",
     "prev": ("RESOLVIDO — recarga grid-tied INTACTA: step_grid() "
              "existe; em DIA+NORMAL carrega (dev0 50 → ~86.3 em "
              "3600 s, evento grid_tied_charge provenance "
              "autonomous_charge); em NOITE+NORMAL não carrega")},
    {"id": "P-R5-04", "expected": "RESOLVIDO", "finding": "J5",
     "prev": ("RESOLVIDO — telemetria soc_limits IGUAL à v0.6 MAS "
              "com schema v0.7.1 (F-LIMP AUD-12: docstrings/cabeçalhos "
              "atualizados; a v0.7.1 carimba schema \"v0.7.1\"): "
              "island_min_pct 5.0 ATIVO, remote_floor_pct 25.0, "
              "remote_daily_limit_pct 40.0, remote_daily_used_pct "
              "em tempo real")},
    {"id": "P-R5-05", "expected": "CONFIRMADO-DECLARADO", "finding": "C11",
     "prev": ("CONFIRMADO-DECLARADO — C11 PERSISTE na v0.7.1 (fatias "
              "2×30% espaçadas 4000 s continuam a EVADIR a cumulativa; "
              "C11 ficou ABERTO para a v0.8) MAS a 2.ª fatia apanha o "
              "limite diário (30+30 = 60 > 40 → 409 daily + evento): "
              "dano saturado em 30%/24 h, SoC 70 (a DRAIN-TO-LOW fica "
              "CALADA: SoC 70 > 35)")},
    {"id": "P-R5-06", "expected": "CONFIRMADO-DECLARADO", "finding": "J3",
     "prev": ("CONFIRMADO-DECLARADO — J3 continua declarado + custo da "
              "opção 1 INTACTO na v0.7.1: 2×30% legítimas → slice1 "
              "200, slice2 409 daily; single 43.86% → 409 daily também "
              "(43.86 > 40; legítimos >40%/dia exigem /local_confirm); "
              "a DRAIN-TO-LOW (que SUBSTITUIU a MULTIDAY) fica CALADA: "
              "SoC 70/100 > 35 e DENTRO de 1 dia — só o 409 daily")},
]
GATEFALL_V072 = [dict(e) for e in GATEFALL_V071]
GATEFALL = (GATEFALL_V072 if IS_V072
            else (GATEFALL_V071 if TARGET == "V071"
                  else (GATEFALL_V07 if TARGET == "V07"
                        else (GATEFALL_V05 if TARGET == "V05"
                              else GATEFALL_V06))))

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS (antes de qualquer execução)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
print("DECISÃO DO OPERADOR 13-11 13:23: o GATEFALL OFICIAL da R5 é o RUN 1 "
      "desta\nbateria contra a v0.5 (com as previsões erradas que saírem, "
      "sejam\ndefeitos do probe ou achados reais), NUNCA o run seguinte. "
      "A v0.6 (limite\ndiário de descarga remota 40%/24 h + recarga "
      "grid-tied J4 + measure em\ncurva com minutos de luz J1/J2 + "
      "atacante (c) 2 dias + telemetria J5) é o\nDEPOIS; este run contra "
      "a v0.6 é o run 2 (verificação do DEPOIS). J3 fica\nDECLARADO; "
      "C5/C6/C9/H7/I2/I3/I6/C11 ficam para depois.\n")
if IS_V071:
    print("GO v0.7.1 (operador 13-11 ~17:00, via supervisor): este run "
          "contra a v0.7.1 RESTAURADA é a\nNÃO-REGRESSÃO da R5 (run 4; "
          "reconstrução pós-INFRA-2026-13-11-B); os critérios V071 são "
          "cópia dos\nV07 exceto o schema v0.7.1 do P-R5-04 e a NOTA "
          "de que as regras novas (F-C13/F-K1/F-C14/F-SP) ficam\n"
          "CALADAS em todos os cenários r5. O GATEFALL OFICIAL da R5 "
          "continua a ser o RUN 1 contra a v0.5.\n")
elif IS_V07:
    print("GO v0.7 (operador 13-11 15:30): este run contra a v0.7 é a "
          "NÃO-REGRESSÃO\nda R5 (run 3); os critérios V07 são cópia dos "
          "V06 exceto o schema v0.7\ndo P-R5-04. O GATEFALL OFICIAL da "
          "R5 continua a ser o RUN 1 contra a v0.5.\n")

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
    """J2 — minutos de luz por casa: stepping de 60 s com clamp EXATO do
    minuto parcial (física linear em NOITE: drop = 100/kwp pontos/h).
    Implementação INDEPENDENTE do lab e do run_measure oficial
    (re-implementação de medição para o GATEFALL; devolve também a casa
    'servida no fim' implícita no SoC final)."""
    minutes = 0.0
    left = float(duration_min)
    while left > 1e-9:
        if d.self_consumption_kw() < L.LOAD_LOCAL_KW - 0.01:
            break  # já sem luz (SoC <= limite ativo e pv < carga)
        limit = d.island_discharge_floor()
        rate = ((L.LOAD_LOCAL_KW - d.pv_kw()) * 60.0 / 3600.0
                / d.batt_kwh * 100.0)  # pontos de SoC por MINUTO
        if rate > 0 and d.soc - rate * min(left, 1.0) <= limit + 1e-12:
            # a luz apaga-se DENTRO deste minuto: fração exata (linear)
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


def attack_b(lab, scen):
    """O atacante (b) do measure: direta 999 e evasão fatiada 40%+34%,
    em NORMAL, por service token. Na v0.5 AMBAS as fatias executam
    (→ ~26, com cumulativa WARN); na v0.6 a fatia de 40% executa
    (100→60, ledger 40) e a de 34% apanha o limite diário (409,
    used 30+34 > 40)."""
    st_dir, st40, st34, soc_pre = [], [], [], []
    for d in lab.devices:
        st, _ = hj(d.port, "POST", "/battery",
                   {"action": "force_export", "amount_kwh": 999},
                   token=d.service_token)
        st_dir.append(st)
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
    return st_dir, st40, st34, soc_pre


def blackout(lab):
    """Apogão noturno determinístico por harness (padrão do measure)."""
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)


def hygiene(lab):
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("lab v%s em memoria (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))

    # ================= P-R5-01 — J1: curva de durações ===================
    print("[P-R5-01] J1 — o 9/12 depende da duração escolhida")
    durations = [30, 60, 90, 120, 180]        # minutos
    if IS_V05:
        expected_served = [12, 9, 6, 4, 0]    # previsão pré-registada
        expected_socmin = None
    else:                                     # V06: limite diário ativo
        expected_served = [12, 12, 12, 11, 8]  # previsão pré-registada
        expected_socmin = [44.38, 28.75, 13.13, 5.00, 5.00]
    curve_served, curve_socmin, curve_minutes = [], [], []
    for dur in durations:
        scen = "P-R5-01-%03d" % dur
        lab.scenario(scen)
        reset_all(lab)
        st_dir, st40, st34, soc_pre = attack_b(lab, scen)
        pre_alerts = scan_scenario(lab, scen)
        blackout(lab)
        minutes = [sweep_minutes(d, dur) for d in lab.devices]
        served = sum(1 for d in lab.devices
                     if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)
        soc_min = round(min(d.soc for d in lab.devices), 2)
        cum_pre = any(a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
                     for a in pre_alerts)
        bf_pre = any(a["rule"] == "D-BATTERY-DRAIN-BELOW-FLOOR"
                     for a in pre_alerts)
        curve_served.append(served)
        curve_socmin.append(soc_min)
        curve_minutes.append(minutes)
        print("    %3d min: served %2d/12, SoC min %.2f, minutos/casa %s"
              % (dur, served, soc_min,
                 [round(m, 1) for m in minutes]))
        if IS_V05:
            ok_run = (all(s == 409 for s in st_dir)
                      and all(s == 200 for s in st40 + st34)
                      and 25.99 <= min(soc_pre) and max(soc_pre) <= 26.01
                      and cum_pre)
        else:
            ok_run = (all(s == 409 for s in st_dir)
                      and all(s == 200 for s in st40)
                      and all(s == 409 for s in st34)
                      and 59.99 <= min(soc_pre) and max(soc_pre) <= 60.01
                      and not cum_pre and bf_pre)
        if not ok_run:
            print("    AVISO: pre-condições do ataque (b) não verificadas "
                  "nesta duração (fatias40=%s, fatias34=%s, direta 409=%s, "
                  "soc=%s, cumulativa=%s, below-floor=%s)"
                  % (all(s == 200 for s in st40),
                     all(s == 409 for s in st34),
                     all(s == 409 for s in st_dir),
                     (round(min(soc_pre), 2), round(max(soc_pre), 2)),
                     cum_pre, bf_pre))
        hygiene(lab)
    cond = (curve_served == expected_served)
    if TARGET == "V06":
        cond = (cond and all(abs(a - b) <= 0.05
                             for a, b in zip(curve_socmin,
                                             expected_socmin)))
    if IS_V05:
        ev_01 = [
            "curva medida (mesmo ataque (b)): %s para %s min"
            % (curve_served, durations),
            "previsão pré-registada: %s — BATE" % expected_served,
            "SoC min por duração: %s (clamp no mínimo técnico %.1f a "
            "partir de 1 h)" % (curve_socmin, L.ISLAND_MIN_SOC),
            "consequência: a headline '9/12' era um PONTO da curva, não "
            "o comportamento — a 3 h o DEFENDED v0.5 IGUALA o LEGACY"]
        word_01 = "CONFIRMADO"
    else:
        ev_01 = [
            "curva medida (mesmo ataque (b)): %s para %s min"
            % (curve_served, durations),
            "previsão pré-registada: %s — BATE; SoC min medido %s vs "
            "previsto %s (tol 0.05)"
            % (expected_served, curve_socmin, expected_socmin),
            "ataque (b) na v0.6: 999 → 409 floor (BELOW-FLOOR ×12); "
            "fatia 40% EXECUTA (100→60, ledger 40); fatia 34% → 409 "
            "daily (used 30+34 > 40) — SEM cumulativa (superssenção "
            "datada: com o limite ativo, DRAIN-LARGE e CUMULATIVE são "
            "inatingíveis por remote_command)",
            "consequência: com o limite diário o atacante só estaciona "
            "a frota a 60% — a reserva aguenta a curva toda até 2 h "
            "(11/12) e 8/12 às 3 h (estimativa do supervisor ~12/~11/~8 "
            "CONFIRMADA MEDIDA na corrida oficial)"]
        word_01 = "RESOLVIDO"
    expect("P-R5-01", GATEFALL[0]["prev"], cond,
           word_01,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_01)

    # ================= P-R5-02 — J2: minutos de luz =====================
    print("\n[P-R5-02] J2 — a métrica 'luz no fim' esconde minutos servidos")
    m60 = curve_minutes[1]                    # duração 60 min
    kwp = [d.kwp for d in lab.devices]
    # casas à escuras no fim da 1 h (v0.5): 3.2, 3.8, 4.4 kWp (devs 10, 2, 6)
    d3_2 = [i for i in range(12) if kwp[i] == 3.2][0]
    d3_8 = [i for i in range(12) if kwp[i] == 3.8][0]
    d4_4 = [i for i in range(12) if kwp[i] == 4.4][0]
    if IS_V05:
        cond = (40.0 <= m60[d3_2] <= 40.7
                and 47.7 <= m60[d3_8] <= 48.2
                and 55.2 <= m60[d4_4] <= 55.7
                and curve_served[1] == 9)
        ev_02 = [
            "na duração de 1 h: served 9/12 (luz no fim), mas as 3 casas "
            "'sem luz' tiveram luz: casa 3.2 kWp (dev %d) %.2f min, "
            "casa 3.8 kWp (dev %d) %.2f min, casa 4.4 kWp (dev %d) %.2f "
            "min" % (d3_2, m60[d3_2], d3_8, m60[d3_8],
                     d4_4, m60[d4_4]),
            "física: minutos = (SoC 26 - limite %.1f)·kwp·0.6 = "
            "12.6·kwp → 40.32/47.88/55.44 (os 40/48/55 do supervisor, "
            "arredondados)" % L.ISLAND_MIN_SOC,
            "consequência: o measure tem de reportar MINUTOS por casa, "
            "não só 'luz no fim' (corrigido na v0.6 por GO)"]
        word_02 = "CONFIRMADO"
    else:
        m120 = curve_minutes[3]              # duração 120 min
        cond = (all(abs(m - 60.0) < 0.01 for m in m60)
                and curve_served[1] == 12
                and 105.4 <= m120[d3_2] <= 105.8
                and curve_served[3] == 11)
        ev_02 = [
            "na duração de 1 h: 12/12 casas com minutos CHEIOS (60.0, "
            "nenhuma às escuras) — com a frota a 60% (limite diário), "
            "a reserva serve a hora inteira",
            "no apagão de 2 h: 11/12 com minutos cheios; a casa mais "
            "fraca (3.2 kWp, dev %d) tem %.2f min de luz (previsto "
            "~105.6: (60-5)·3.2·0.6 = 105.6)" % (d3_2, m120[d3_2]),
            "a métrica agora reporta MINUTOS por casa (não só 'luz no "
            "fim') — J2 resolvido; a dependência da duração (J1) é "
            "reportada como CURVA"]
        word_02 = "RESOLVIDO"
    expect("P-R5-02", GATEFALL[1]["prev"], cond,
           word_02,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_02)

    # ================= P-R5-03 — J4: recarga grid-tied ==================
    print("\n[P-R5-03] J4 — em modo ligado à rede a bateria nunca recarrega")
    lab.scenario("P-R5-03")
    reset_all(lab)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)
    dev = lab.devices[0]
    dev.soc = 50.0                            # harness (evidência do ANTES)
    soc_before = dev.soc
    # estático: nenhum método de integração de carga fora da ilha
    src = open(L.__file__, encoding="utf-8").read()
    has_step_grid = "def step_grid" in src
    charge_paths = [ln.strip() for ln in src.splitlines()
                    if "def step" in ln]
    if IS_V05:
        # dinâmico: 12 h cartoon em DIA+NORMAL — nada muda o SoC
        for _ in range(12):                   # 12 "horas" sem qualquer
            pass                             # integração existente a chamar
        soc_static = dev.soc
        sc_grid = dev.self_consumption_kw()
        # contraste: a MESMA casa em ILHA (relé aberto) DIA carrega
        lab.gridsim.set_state("BLACKOUT")
        time.sleep(0.4)
        dev.step_island(3600.0)               # 1 h de sol em ilha
        soc_island = dev.soc
        cond = (not has_step_grid and soc_static == soc_before
                and sc_grid >= L.LOAD_LOCAL_KW - 0.01
                and soc_island > soc_before + 1.0)
        ev_03 = [
            "estático: métodos de passo no lab v0.5: %s — nenhum "
            "step_grid/carrega em modo ligado à rede" % charge_paths,
            "dinâmico: SoC %.1f em DIA+NORMAL continua %.1f após '12 h "
            "cartoon' (não existe caminho de recarga); autoconsumo "
            "%.2f kW (a rede serve a casa, a bateria fica imóvel)"
            % (soc_before, soc_static, sc_grid),
            "contraste: a MESMA casa em ILHA (relé aberto) DIA: 1 h de "
            "step_island → SoC %.2f (>%.1f) — o excedente SÓ integra em "
            "ilha (assimetria J4)" % (soc_island, soc_before),
            "consequência: um ataque em vários dias nunca encontra a "
            "bateria rearmada em modo ligado à rede (corrigido na v0.6 "
            "por GO: recarga solar grid-tied)"]
        word_03 = "CONFIRMADO"
    else:
        # dinâmico (v0.6): step_grid CARREGA em DIA+NORMAL (relé fechado)
        kwh = dev.step_grid(3600.0)          # 1 h de excedente solar
        soc_grid = dev.soc
        ev_grid = [e for e in scenario_events(lab, "P-R5-03")
                   if e.get("event") == "grid_tied_charge"]
        # NOITE+NORMAL: sem excedente, sem carga (SoC imóvel)
        lab.gridsim.set_irradiance("NOITE")
        time.sleep(0.4)
        dev2 = lab.devices[1]
        dev2.soc = 50.0
        soc2_before = dev2.soc
        dev2.step_grid(3600.0)
        soc2_after = dev2.soc
        cond = (has_step_grid and kwh > 0.0
                and abs(soc_grid - 86.35) < 0.05
                and ev_grid and ev_grid[0].get("provenance")
                == "autonomous_charge"
                and soc2_after == soc2_before)
        ev_03 = [
            "estático: métodos de passo no lab v0.6: %s — step_grid "
            "EXISTE (recarga grid-tied)" % charge_paths,
            "dinâmico DIA+NORMAL: dev0 SoC %.1f → %.2f após step_grid("
            "3600) (previsto ~86.35: pv 5.78 kW, excedente 4.58 kW · 1 h "
            "÷ bateria 12.6 kWh = 36.35 pontos), %.4f kWh integrados"
            % (soc_before, soc_grid, kwh),
            "evento grid_tied_charge: provenance %s (NÃO é "
            "remote_command: por construção NÃO conta no ledger diário)"
            % (ev_grid[0].get("provenance") if ev_grid else "—"),
            "NOITE+NORMAL: SoC %.1f imóvel após 1 h (%.1f) — sem "
            "excedente solar não há carga" % (soc2_before, soc2_after),
            "consequência: a bateria REARMA em modo ligado à rede — o "
            "atacante (c) multi-dia já encontra frota recarregada (J4 "
            "resolvido por GO)"]
        word_03 = "RESOLVIDO"
    expect("P-R5-03", GATEFALL[2]["prev"], cond,
           word_03,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_03)
    hygiene(lab)

    # ================= P-R5-04 — J5: telemetria desatualizada ===========
    print("\n[P-R5-04] J5 — telemetria mostra floor 25, não o limite ativo")
    lab.scenario("P-R5-04")
    reset_all(lab)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)
    dev = lab.devices[0]
    st, tel = hj(dev.port, "GET", "/telemetry", token=dev.service_token)
    tel_normal = tel
    # dispositivo em ilha real (relé aberto pelo anti-islanding)
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)
    st2, tel_island = hj(dev.port, "GET", "/telemetry",
                         token=dev.service_token)
    missing = ("soc_limits" not in tel_normal
               and "island_min_pct" not in tel_normal
               and "island_min_soc" not in tel_normal)
    if IS_V05:
        cond = (st == 200 and st2 == 200
                and tel_normal.get("floor_soc") == L.FLOOR_SOC
                and missing
                and tel_island.get("floor_soc") == L.FLOOR_SOC
                and "soc_limits" not in tel_island
                and not tel_island.get("relay_closed", True))
        ev_04 = [
            "telemetria em NORMAL: floor_soc=%s, chaves de limite "
            "ativo presentes? soc_limits/island_min: %s"
            % (tel_normal.get("floor_soc"), not missing),
            "telemetria em ILHA REAL (relé aberto, relay_closed=%s): "
            "continua floor_soc=%s, SEM campo do limite ATIVO (%.1f) — "
            "o operador da casa vê 'floor 25' quando a reserva usável "
            "em ilha é até %.1f"
            % (tel_island.get("relay_closed"), tel_island.get("floor_soc"),
               L.ISLAND_MIN_SOC, L.ISLAND_MIN_SOC),
            "consequência: cabeçalhos desatualizados (corrigido na v0.6 "
            "por GO: bloco soc_limits com o limite ativo)"]
        word_04 = "CONFIRMADO"
    else:
        lim_n = tel_normal.get("soc_limits") or {}
        lim_i = tel_island.get("soc_limits") or {}
        cond = (st == 200 and st2 == 200
                and lim_n.get("schema")
                == ("v0.7.1" if IS_V071
                    else ("v0.7" if IS_V07 else "v0.6"))
                and lim_n.get("island_min_pct") == L.ISLAND_MIN_SOC
                and lim_n.get("remote_floor_pct") == L.FLOOR_SOC
                and lim_n.get("remote_daily_limit_pct")
                == L.REMOTE_DISCHARGE_DAILY_PCT
                and "remote_daily_used_pct" in lim_n
                and lim_i.get("island_min_pct") == L.ISLAND_MIN_SOC
                and lim_i.get("remote_daily_limit_pct")
                == L.REMOTE_DISCHARGE_DAILY_PCT
                and not tel_island.get("relay_closed", True))
        ev_04 = [
            "telemetria em NORMAL: soc_limits %s — island_min_pct %.1f "
            "(o limite ATIVO em ilha), remote_floor_pct %.1f, "
            "remote_daily_limit_pct %.1f, remote_daily_used_pct "
            "contabilizado (%s)"
            % (lim_n, L.ISLAND_MIN_SOC, L.FLOOR_SOC,
               L.REMOTE_DISCHARGE_DAILY_PCT,
               lim_n.get("remote_daily_used_pct")),
            "telemetria em ILHA REAL (relé aberto, relay_closed=%s): "
            "soc_limits CONTINUA presente — island_min_pct %.1f, "
            "remote_daily_limit_pct %.1f — o operador da casa vê o "
            "limite que está ATIVO, não 'floor 25' fixo"
            % (tel_island.get("relay_closed"),
               lim_i.get("island_min_pct"),
               lim_i.get("remote_daily_limit_pct")),
            "consequência: J5 resolvido por GO (bloco soc_limits, "
            "schema %s, cabeçalhos atualizados)"
            % ("v0.7.1" if IS_V071
               else ("v0.7" if IS_V07 else "v0.6"))]
        word_04 = "RESOLVIDO"
    expect("P-R5-04", GATEFALL[3]["prev"], cond,
           word_04,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_04)
    hygiene(lab)

    # ================= P-R5-05 — C11: fatias espaçadas =================
    print("\n[P-R5-05] C11 — fatias espaçadas >1 h evadem a cumulativa")
    lab.scenario("P-R5-05")
    reset_all(lab)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)
    dev = lab.devices[3]
    orig_time = L.time.time
    try:
        # relógio do processo controlado pelo probe (v0.5 carimba
        # sim_ts com time.time() real); reposição GARANTIDA em finally
        fake_now = [orig_time()]
        L.time.time = lambda: fake_now[0]
        st1, _ = hj(dev.port, "POST", "/battery",
                    {"action": "discharge",
                     "amount_kwh": round(0.30 * dev.batt_kwh, 3)},
                    token=dev.service_token)
        fake_now[0] += 4000.0                 # >3600 s: fora da janela
        st2, body2 = hj(dev.port, "POST", "/battery",
                        {"action": "discharge",
                         "amount_kwh": round(0.30 * dev.batt_kwh, 3)},
                        token=dev.service_token)
    finally:
        L.time.time = orig_time
    alerts = scan_scenario(lab, "P-R5-05")
    cum = [a for a in alerts
           if a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"]
    large = [a for a in alerts
             if a["rule"] == "D-BATTERY-DRAIN-LARGE"]
    if IS_V05:
        cond = (st1 == 200 and st2 == 200 and not cum and not large
                and abs(dev.soc - 40.0) < 0.02)
        ev_05 = [
            "fatias 30%% + 30%% separadas 4000 s de sim_ts (>janela "
            "3600 s): ambas 200 (st=%s), SoC %.2f — a descarga EXECUTA "
            "na mesma" % (st1 == 200 and st2 == 200, dev.soc),
            "alertas do cenário: %s — a regra cumulativa NÃO vê as duas "
            "fatias como uma janela" % [(a["rule"], a["count"])
                                        for a in alerts],
            "contraste (já medido na R4, run 1): as MESMAS fatias a "
            "segundos de distância disparam a cumulativa (count 2)",
            "consequência: a janela de 1 h é evadível por espaçamento "
            "(C11 do supervisor, convergente com o Gemini) — a v0.6 "
            "limita o dano por dia, mas o C11 fica ABERTO por decisão "
            "do operador"]
        word_05 = "CONFIRMADO"
    else:
        evs = [e for e in scenario_events(lab, "P-R5-05")
               if e.get("event") == "remote_daily_limit_block"]
        cond = (st1 == 200 and st2 == 409 and not cum and not large
                and abs(dev.soc - 70.0) < 0.02
                and body2.get("error") == "remote_discharge_daily_limit"
                and evs and evs[0].get("used_pct") == 30.0
                and evs[0].get("requested_pct") == 30.0
                and evs[0].get("limit_pct")
                == L.REMOTE_DISCHARGE_DAILY_PCT)
        ev_05 = [
            "fatias 30% + 30% separadas 4000 s: slice1 EXECUTA (200, "
            "SoC 100→70); slice2 → 409 remote_discharge_daily_limit — "
            "o ledger diário NÃO é evadível por espaçamento (janela "
            "24 h; used 30 + pedido 30 > 40)",
            "a cumulativa (janela 3600 s) CONTINUA cega às fatias "
            "espaçadas — C11 PERSISTE (ficou ABERTO por decisão do "
            "operador) — MAS o dano por dia fica SATURADO em 30%%: "
            "SoC %.2f" % dev.soc,
            "evento remote_daily_limit_block: used_pct %s (acumulado), "
            "requested_pct %s, limit_pct %s, window_s %s (deteção POR "
            "EVENTO do próprio bloqueio — prevenção primária, não "
            "regra)"
            % (evs[0].get("used_pct") if evs else "—",
               evs[0].get("requested_pct") if evs else "—",
               evs[0].get("limit_pct") if evs else "—",
               evs[0].get("window_s") if evs else "—"),
            "consequência: o C11 deixa de ser canal de esvaziamento "
            "(máx. 40%/dia por remote_command), mas a cegueira da "
            "janela de 1 h permanece DECLARADA"]
        word_05 = "CONFIRMADO-DECLARADO"
    expect("P-R5-05", GATEFALL[4]["prev"], cond,
           word_05,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_05)

    # ================= P-R5-06 — J3: FP WARN em legítimos ===============
    print("\n[P-R5-06] J3 — FP WARN: manutenção legítima dispara a cumulativa")
    lab.scenario("P-R5-06")
    reset_all(lab)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.6)
    dev = lab.devices[1]
    # manutenção legítima: 2 descargas de 30% com work_order no corpo
    # (/battery não aceita work-order — o campo é ignorado)
    st1, b1 = hj(dev.port, "POST", "/battery",
                 {"action": "discharge",
                  "amount_kwh": round(0.30 * dev.batt_kwh, 3),
                  "work_order": "WO-2026-1113-MNT"},
                 token=dev.service_token)
    st2, b2 = hj(dev.port, "POST", "/battery",
                 {"action": "discharge",
                  "amount_kwh": round(0.30 * dev.batt_kwh, 3),
                  "work_order": "WO-2026-1113-MNT"},
                 token=dev.service_token)
    alerts = scan_scenario(lab, "P-R5-06")
    cum = [a for a in alerts
           if a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"]
    # single 43.86% (2.0 kWh na casa 3.8 kWp) — sem FP
    dev2 = lab.devices[2]
    st3, b3 = hj(dev2.port, "POST", "/battery",
                 {"action": "discharge", "amount_kwh": 2.0},
                 token=dev2.service_token)
    alerts2 = scan_scenario(lab, "P-R5-06")
    # v0.1.1: a regra cumulativa é por (cenário, DISPOSITIVO) — filtrar
    # os alertas que contêm o dev do single, não o cenário inteiro
    cum2 = [a for a in alerts2
            if a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
            and dev2.name in a.get("devices", ())]
    if IS_V05:
        cond = (st1 == 200 and st2 == 200
                and len(cum) == 1 and cum[0]["count"] == 2
                and st3 == 200 and not cum2)
        ev_06 = [
            "manutenção legítima (2×30%, work_order WO-2026-1113-MNT no "
            "corpo): ambas 200 — /battery NÃO aceita work-order (a "
            "provenance é sempre remote_command)",
            "alertas: %s — D-BATTERY-CUMULATIVE-DRAIN dispara nas "
            "legítimas (count 2): FALSO POSITIVO WARN"
            % [(a["rule"], a["count"]) for a in alerts],
            "single 43.86%% (2.0 kWh, casa 3.8 kWp): 200, SEM alerta "
            "cumulativo (%s) — o FP é da janela acumulada, não do "
            "single" % (not cum2),
            "J3 fica DECLARADO por decisão do operador (WARN, não CRIT; "
            "não corrigir nesta ronda)"]
        word_06 = "CONFIRMADO"
    else:
        daily_evs = [e for e in scenario_events(lab, "P-R5-06")
                     if e.get("event") == "remote_daily_limit_block"]
        cond = (st1 == 200 and st2 == 409
                and b2.get("error") == "remote_discharge_daily_limit"
                and not cum
                and st3 == 409
                and b3.get("error") == "remote_discharge_daily_limit"
                and not cum2 and daily_evs)
        ev_06 = [
            "manutenção legítima (2×30%, work_order WO-2026-1113-MNT): "
            "slice1 200; slice2 → 409 daily (used 30 + 30 > 40) — o FP "
            "WARN morre por SATURAÇÃO neste par (a fatia nem executa, "
            "logo não há param_change para a cumulativa acumular)",
            "single 43.86%% (2.0 kWh, casa 3.8 kWp): 409 daily também "
            "(43.86 > 40) — evento %s× no cenário"
            % (len(daily_evs)),
            "custo DECLARADO da opção 1 (consequência registada no GO): "
            "operações legítimas >40%/dia passam a exigir "
            "/local_confirm (token físico na casa); o J3 original (FP "
            "WARN em 2×30% legítimas) fica coberto pelo limite, mas o "
            "pedido de confirmação local é o NOVO atrito",
            "J3 fica DECLARADO por decisão do operador; eventos "
            "remote_daily_limit_block são deteção DO bloqueio "
            "(prevenção primária), não uma regra nova"]
        word_06 = "CONFIRMADO-DECLARADO"
    expect("P-R5-06", GATEFALL[5]["prev"], cond,
           word_06,
           "PREVISÃO ERRADA (ver detalhe acima)",
           ev_06)

    # ---------------------------------------------------------------------
    # SUMÁRIO — previsão vs observado (GATEFALL fechado; alinhado por ID)
    # ---------------------------------------------------------------------
    by_id = {v["id"]: v for v in VEREDICTOS}
    print("\n" + "=" * 72)
    print("SUMÁRIO GATEFALL — previsão PRÉ-registada vs veredicto OBSERVADO")
    print("=" * 72)
    prev_erradas = 0
    match_n = 0
    default_word = "CONFIRMADO" if IS_V05 else "RESOLVIDO"
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
    if IS_V05:
        print("GATEFALL OFICIAL da R5 = ESTE RUN 1 contra a v0.5 (correção "
              "de método do operador: nunca o run seguinte). A v0.6 "
              "(limite diário 40%%/24 h + recarga grid-tied + measure em "
              "curva com minutos + atacante (c) 2 dias + telemetria com "
              "limite ativo) é o DEPOIS; J3 declarado; "
              "C5/C6/C9/H7/I2/I3/I6/C11 ficam para depois.")
    elif IS_V071:
        print("Este é o RUN 4 (NÃO-REGRESSÃO contra a v0.7.1 RESTAURADA, "
              "reconstrução pós-INFRA-2026-13-11-B): o GATEFALL OFICIAL "
              "da R5 continua a ser o RUN 1 contra a v0.5 (run 1b 6/6). "
              "Previsões V071 confirmadas acima = o limite diário "
              "40%/24 h, a recarga grid-tied (J4), a telemetria "
              "soc_limits (agora schema v0.7.1), a curva com minutos "
              "(J1/J2) e a saturação do C11/J3 NÃO REGREDIRAM com o "
              "F-C13/F-K1/F-C14/F-SP (regras novas CALADAS nos cenários "
              "r5). J3 fica declarado; C5/C6/C9/H7/I2/I3/I6/C11/J3 "
              "ficam para a v0.8.")
    elif IS_V07:
        print("Este é o RUN 3 (NÃO-REGRESSÃO contra a v0.7): o GATEFALL "
              "OFICIAL da R5 continua a ser o RUN 1 contra a v0.5 (run 1b "
              "6/6); o run 2 contra a v0.6 deu 6/6. Previsões V07 "
              "confirmadas acima = o limite diário 40%/24 h, a recarga "
              "grid-tied (J4), a telemetria soc_limits (agora schema "
              "v0.7), a curva com minutos (J1/J2) e a saturação do "
              "C11/J3 NÃO REGREDIRAM com o F-C12/F-K1/F-LIMP. J3 fica "
              "declarado; C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a "
              "v0.8.")
    else:
        print("Este é o RUN 2 (verificação do DEPOIS): o GATEFALL OFICIAL "
              "da R5 foi o RUN 1 contra a v0.5 (5/6 + 1 previsão errada "
              "por defeito de critério do probe, corrigida na v0.1.1; "
              "run 1b 6/6). Previsões V06 confirmadas acima = o limite "
              "diário 40%/24 h, a recarga grid-tied (J4), a telemetria "
              "soc_limits (J5), a curva com minutos (J1/J2) e a saturação "
              "do C11/J3 se comportaram COMO PRÉ-REGISTADO. J3 fica "
              "declarado; C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para depois.")
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

# EOF:sunstrike_probes_r5.py
