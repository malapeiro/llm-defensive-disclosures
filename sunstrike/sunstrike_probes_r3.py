#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# SUNSTRIKE — bateria de probes R3 (M2, ronda 3 — pré-requisitos v0.4)
# Grant: GRANT-PVTE-20261112-SS-01 (lab sintético, loopback apenas)
# Alvo:  sunstrike_lab.py — DUAL-TARGET, detetado pelo hash no arranque:
#        v0.3 (fe6f59ca…, verificada pelo supervisor em Python 3.13:
#        selftest 19/19, demo 9/9, R2 idêntica à do builder) ou v0.4
#        (cca99757…, entregue neste turno: C7/I1/C8/I4/I5 + measure
#        contrafactual). Nada corre contra um lab que não seja um dos
#        dois hashes verificados.
# Corpus R3 (registo oficial do operador, GO à v0.4 de 13-11) — PRÉ-REQUISITOS
#        da v0.4 (executados pelo supervisor; sem eles a métrica principal
#        é falsa):
#   C7  irradiância FIXA: pv mínimo 1.76 kW > carga 1.2 kW em TODAS as
#        casas; em ilha a bateria nunca é usada. O measure precisa de
#        perfil de irradiância (dia/nuvem/noite). Rever a frase
#        "bateria integrando" do H4-BLACKOUT (a carga é servida pelo sol).
#   I1  curtail_pct é uma CATRACA: após STRESS fica em 40% para sempre.
#        O curtail autónomo tem de baixar quando f volta ao normal.
#   C8  D-CAPACITY-DIVERGENCE: FP CRIT com 1 setpoint legítimo (90%) +
#        P(f) autónomo. O esperado desconta o curtail autónomo; a
#        condição remote vem de param_change remote_command sem
#        work-order. Snapshot contínuo, não só do harness.
# Corrigir também na v0.4 (pequenos, já provados):
#   I4  canonicalizador: rejeitar < 0x20, 0x7F e segmentos /./ e /../.
#   I5  guard: rejeitar QUALQUER Transfer-Encoding (não só == "chunked").
# Ficam para a R3 seguinte (documentar como abertos): C4, C5, C6, C9, H7,
#        I2 (slow-wave "lavável"), I3 (curtailment em degraus), I6.
# Papel: probes "antes" contra a v0.3 INTOCADA (padrão R1/R2): o output
#        VERMELHO é a evidência do "antes"; os fixes são DEPOIS (v0.4).
# Protocolo: GATEFALL — previsões PRÉ-REGISTADAS por construção (constantes
#        deste script, hash-verificáveis), impressas ANTES da execução.
#        Veredicto observado != previsto é reportado como PREVISÃO ERRADA.
#        CORREÇÃO DE MÉTODO do operador (13-11): o GATEFALL oficial do
#        relatório é o RUN 1 desta bateria contra a v0.3 (com as previsões
#        erradas que saírem), NUNCA o run limpo seguinte.
# Portabilidade: Python 3.9+, 100% stdlib, 127.0.0.1 apenas.
#
# CHANGELOG DE PROBES (o LAB alvo NUNCA é editado):
#   v0.1 (13-11): primeira versão, alvo v0.3. GATEFALL contra a v0.3
#        pré-registado: 6 probes P-R3-01..06, todos CONFIRMADO previstos
#        (vermelho do antes). Calibração de desenvolvimento ANTES do
#        pré-registo (raw sockets + leitura de código, documentada):
#        (a) pv_gross_kw() = kwp*IRRADIANCE_FACTOR com IRRADIANCE_FACTOR
#            constante global 0.55 — sem qualquer perfil/API de
#            irradiância (C7 estático confirmado);
#        (b) sensor_update: curtail_pct = max(curtail_pct, target) — só
#            sobe; a f nominal target=0 mas o max mantém 40 (I1 estático
#            confirmado);
#        (c) emit_capacity_snapshot: expected = pv_gross SEM desconto do
#            curtail P(f); remote_curtail_devices conta export_limit<100
#            (90% legítimo incluído) — FP do C8 estático confirmado; e a
#            ÚNICA emissão é via harness (sem snapshot contínuo);
#        (d) canonical_request_line: sem teste de bytes de controlo
#            (<0x20/0x7F) nem de segmentos /./ e /../ (I4 estático);
#        (e) GuardHandler: só rejeita Transfer-Encoding == "chunked"
#            (I5 estático).
#        A calibração não alterou nenhuma previsão: confirmou a leitura
#        estática do código.
#   v0.1.1 (13-11): RUN 1 (preservado em sunstrike_probes_v03_r3_run1.txt):
#        5/6 CONFIRMADO, 1 PREVISÃO ERRADA (P-R3-02) — DEFEITO DO CRITÉRIO
#        DO PROBE, o LAB não mudou (hash fe6f59ca… verificado no arranque):
#        o critério exigia "SoC SOBE em TODOS" com SoC inicial 100.0 e
#        cap 100.0 — impossível por construção (o cap trava o carregamento
#        ANTES de qualquer variação; a evidência do run 1 mostra o achado
#        C7 real: SoC congelado a 100 no cap, 0 eventos de floor, deficit
#        inalcançável). Corrigido: o harness DESCE o SoC a 60.0 antes do
#        step (reserva parcial), e o critério passa a exigir SoC SOBE em
#        todos (só CARREGA; nunca gasta) + 0 eventos floor. A PREVISÃO não
#        muda (o achado é o mesmo); o GATEFALL OFICIAL do relatório é o
#        RUN 1 com esta previsão errada, por decisão do operador 13-11
#        (correção de método: nunca o run limpo seguinte).
#   v0.2 (13-11): DUAL-TARGET. O lab alvo é DETETADO pelo hash no arranque:
#        v0.3 (fe6f59ca…, evidência do ANTES já colhida nos runs 1-2, o
#        run 1 é o GATEFALL OFICIAL da R3 por correção de método) ou
#        v0.4 (cca99757…, entregue neste turno: C7 perfis de irradiância
#        + I1 release do curtail P(f) + C8 fórmula/condição/snapshot
#        contínuo + I4 control chars/dot segments + I5 TE qualquer +
#        measure contrafactual de dois braços). GATEFALL v0.4
#        PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.4 (protocolo GATEFALL): 6 RESOLVIDO previstos:
#          P-R3-01 RESOLVIDO (C7): perfis DIA/NUVEM/NOITE existem e são
#            publicados pelo GRIDSIM no canal de sensor; set NOITE →
#            pv_gross 0.0 em TODOS; NUVEM → kwp*0.20; DIA repõe kwp*0.55
#            (mínimo 1.76 > carga 1.2 preservado no perfil default);
#          P-R3-02 RESOLVIDO (C7-b): com perfil NOITE o caminho DEFICIT
#            é alcançável: ilha + SoC 60.0 + step_island(3600) → SoC
#            DESCE em todos (drop% = 100/kwp; pior casa 3.2 kWp → 28.75,
#            acima do floor 25), sem eventos island_battery_at_floor —
#            a bateria PASSA a integrar na métrica (measure não-trivial);
#          P-R3-03 RESOLVIDO (I1): STRESS → curtail autónomo 40; NORMAL
#            → RELEASE: curtail_autonomous volta a 0.0 com evento
#            pf_release (catraca morta; o curtail segue a frequência
#            para cima E para baixo);
#          P-R3-04 RESOLVIDO (C8): FP morto — setpoint LEGÍTIMO 90% +
#            P(f) autónomo (STRESS) + snapshot → div ~1.2% < 30 (o
#            esperado DESCONTA o curtail autónomo), SEM alerta
#            D-CAPACITY-DIVERGENCE; e o snapshot CONTÍNUO existe: onda
#            de 6 setpoints a 0 → transição de banda → capacity_snapshot
#            provenance=grid_monitor (fora do harness) → alerta dispara;
#          P-R3-05 RESOLVIDO (I4): os 4 pedidos crus (0x01, 0x7F, /./,
#            /../) → 400 + eventos non_canonical_request com reasons
#            control_char e dot_segment (fail-closed completo);
#          P-R3-06 RESOLVIDO (I5): 'Transfer-Encoding: identity' no
#            guard → 400 + guard_reject (rejeição pela PRESENÇA do
#            header, não pelo valor), SEM forward.
#        NENHUMA previsão v0.3 alterada (o alvo v0.3 mantém o GATEFALL
#        original dos runs 1-2).
#   v0.3 (13-11): TRI-TARGET. Terceiro alvo: v0.5 (052688ee… — semântica
#        do floor opção A + ISLAND_MIN_SOC 5% + RESERVE_LOCKED_MODE
#        [contrafactual opção B] + measure com dois atacantes + linha
#        OPTION-B + regra D-BATTERY-CUMULATIVE-DRAIN). GATEFALL v0.5
#        PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.5 (protocolo GATEFALL): 6× RESOLVIDO, critérios IDÊNTICOS
#        aos do ramo v0.4 — nenhum dos fixes da v0.5 toca nos achados
#        R3 (C7/I1/C8/I4/I5). Verificação de critérios antes de
#        registar:
#          P-R3-02: above_floor exige socs > FLOOR_SOC (25) — no v0.5 a
#            física é a mesma (SoC 60 − 100/kwp; pior casa 3.2 kWp →
#            28.75 > 25, e muito acima de ISLAND_MIN_SOC 5) e o modo
#            default (opção A) NÃO emite island_battery_at_floor: o
#            critério mantém-se;
#          P-R3-03/04/05/06: curtail release, capacity divergence,
#          canonicalizador e guard intocados pela v0.5.
#        NENHUMA previsão v0.3/v0.4 alterada (os alvos históricos
#        mantêm os GATEFALL registados).
#   v0.4 (13-11): QUAD-TARGET. Quarto alvo: v0.6 (698b8cff… — limite
#        diário de descarga remota 40%/24 h + recarga grid-tied J4 +
#        telemetria soc_limits J5 + measure em curva com minutos J1/J2
#        + atacante (c) 2 dias). GATEFALL v0.6 PRÉ-REGISTADO NESTA
#        ENTRADA, ANTES de qualquer corrida contra a v0.6 (protocolo
#        GATEFALL): 6× RESOLVIDO, critérios IDÊNTICOS aos dos ramos
#        v0.4/v0.5 — nenhum fix da v0.6 toca nos achados R3
#        (C7/I1/C8/I4/I5). Verificação de critérios antes de
#        registar:
#          P-R3-02: above_floor exige socs > FLOOR_SOC (25) — no v0.6 a
#            física é a mesma (SoC 60 − 100/kwp; pior casa 3.2 kWp →
#            28.75 > 25); o limite diário conta apenas provenance
#            remote_command e o teste usa CONSUMO DA CASA em ilha
#            (fora do ledger diário): o critério mantém-se;
#          P-R3-03/04/05/06: curtail release, capacity divergence,
#          canonicalizador e guard intocados pela v0.6.
#        NENHUMA previsão v0.3/v0.4/v0.5 alterada.
#   v0.4.1 (13-11, correção de CRITÉRIO datada, antes do run oficial
#        da não-regressão): o primeiro run contra a v0.6 (preservado
#        em sunstrike_probes_v06_r3_run1.txt, hash bc59289c…) deu 5/6
#        com P-R3-02 PREVISÃO ERRADA por DEFEITO DO PROBE, não do
#        lab: o setup do perfil NOITE testava `TARGET in ("V04",
#        "V05")` e não aplicava NOITE na v0.6 — os devices ficavam em
#        DIA (surplus) e a bateria CARREGAVA (60→74.58/97.50) em vez
#        de gastar. Corrigido: `TARGET != "V03"`. A PREVISÃO de
#        P-R3-02 MANTÉM-SE (RESOLVIDO); nada mais mudou. Este run NÃO
#        é o GATEFALL oficial (o da R3 é o RUN 1 contra a v0.3); os
#        preservados.
#   v0.5 (13-11): PENTA-TARGET. Quinto alvo: v0.7 (d3af0d28… — F-C12:
#        esperado da divergência de capacidade = kwp × irr × (1 −
#        curtail_autonomous/100), INDEPENDENTE de inverter_on, fórmula
#        partilhada; a regra arma também por remote_shutdown_change
#        provenance remote_command sem work-order; snapshot contínuo
#        também após shutdown/resume remoto com dedupe determinístico
#        + F-K1: regra 21.ª D-BATTERY-MULTIDAY-DRAIN (soma das
#        descargas remote EXECUTADAS/dev numa janela de 72 h > 70% E
#        ≥ 2 dias-distintos, CRIT, sem prevenção nova) + banner
#        SUNBOX/0.7 + liveness 21/21). GATEFALL v0.7 PRÉ-REGISTADO
#        NESTA ENTRADA, ANTES de qualquer corrida contra a v0.7
#        (protocolo GATEFALL): 6× RESOLVIDO, critérios IDÊNTICOS aos
#        dos ramos v0.4/v0.5/v0.6 — nenhum fix da v0.7 toca nos
#        achados R3 (C7/I1/C8/I4/I5). Verificação de critérios antes
#        de registar:
#          P-R3-02: above_floor exige socs > FLOOR_SOC (25) — na v0.7
#            a física é a mesma (SoC 60 − 100/kwp; pior casa 3.2 kWp →
#            28.75 > 25); o teste usa CONSUMO DA CASA em ilha (fora do
#            ledger diário e da janela multiday de 72 h): o critério
#            mantém-se;
#          P-R3-04: o snapshot é emitido UMA vez via harness e o
#            cenário NÃO tem shutdowns (o novo gatilho remote_shutdown_
#            change e o snapshot pós-shutdown não se exercitam); com a
#            fórmula partilhada da v0.7 o div do setpoint LEGÍTIMO 90%
#            + P(f) autónomo continua < 30 e o alerta AUSENTE (FP
#            morto mantém-se); snap_evs == 1 mantém-se;
#          P-R3-01/03/05/06: perfis de irradiância, curtail release,
#            canonicalizador e guard intocados pela v0.7.
#        NENHUMA previsão v0.3/v0.4/v0.5/v0.6 alterada.
#   v0.5 ERRATAS (13-11, datadas):
#        (a) DATAS — errata registada pelo supervisor em
#            ERRATA_v06_datas.md (4f012123…): as entradas v0.4 e
#            v0.4.1 deste changelog diziam "14-11"; o dia correto é
#            13-11-2026. Corrigido IN-PLACE nesta versão (r3:127 e
#            r3:144); os ficheiros anteriores ficam inalterados para
#            preservar os hashes verificados.
#        (b) GRAVAGEM — varredura "apogão"→"apagão" em TODO o
#            ficheiro: 0 ocorrências neste probe (nada a corrigir; a
#            ficheiro: 0 ocorrências neste probe (nada a corrigir; a
#            varredura fica registada por paridade com o r4/r5).
#   v0.5.2 (13-11, RECONSTRUÇÃO datada pós-incidente INFRA-2026-13-11-B
#        ~18:23): HEXA-TARGET. Sexto alvo: V071 (72c894fe… — lab v0.7.1
#        RESTAURADO por REPLAY dos edit scripts preservados + errata
#        J5; selftest re-executado BYTE-IDÊNTICO afb98d0c…). GATEFALL
#        V071 pré-registado NESTA ENTRADA, ANTES de qualquer corrida
#        contra a v0.7.1 (protocolo GATEFALL): 6× RESOLVIDO, critérios
#        IDÊNTICOS aos dos ramos v0.4/v0.5/v0.6/v0.7 — nenhum fix da
#        v0.7.1 toca nos achados R3 (C7/I1/C8/I4/I5). Verificação de
#        critérios antes de registar:
#          P-R3-02: above_floor exige socs > FLOOR_SOC (25) — a física
#            é a mesma (SoC 60 − 100/kwp; pior casa 28.75 > 25); o
#            teste usa CONSUMO DA CASA em ilha, provenance ≠
#            remote_command: FORA do ramo da D-BATTERY-DRAIN-TO-LOW
#            (F-K1) e do ledger diário — o critério mantém-se;
#          P-R3-04: o snapshot é emitido UMA vez via harness e o
#            cenário NÃO tem shutdowns nem work-orders (o F-C13 e o
#            WARN D-REMOTE-SHUTDOWN-NO-WO do F-C14 não se exercitam);
#            com a fórmula partilhada o div do setpoint LEGÍTIMO 90%
#            + P(f) autónomo continua < 30 e o alerta AUSENTE (FP
#            morto mantém-se; o F-SP só acrescenta a work_order
#            OPCIONAL ao /setpoint — sem WO o setpoint continua a
#            EXECUTAR como antes); snap_evs == 1 mantém-se;
#          P-R3-01/03/05/06: perfis de irradiância, curtail release,
#            canonicalizador e guard intocados pela v0.7.1.
#        NENHUMA previsão v0.3/v0.4/v0.5/v0.6/v0.7 alterada.
# ---------------------------------------------------------------------------
# Probes:
#   P-R3-01  C7  irradiância fixa: pv_gross > carga em TODAS as casas;
#                bateria nunca gasta em condições naturais (sem perfil)
#   P-R3-02  C7  1h de ilha default (sem harness): SoC SOBE em todos,
#                o caminho deficit é inalcançável — measure de retenção
#                trivial 100%, dia/noite indistinguíveis
#   P-R3-03  I1  curtail_pct é catraca: STRESS (f 50.4 → 40%) e NORMAL
#                (f nominal) → curtail CONTINUA 40% para sempre
#   P-R3-04  C8  FP CRIT: 1 setpoint legítimo 90% + P(f) autónomo →
#                D-CAPACITY-DIVERGENCE dispara; snapshot só via harness
#   P-R3-05  I4  canonicalizador fail-OPEN para 0x01/0x7F e /./ /../
#                (rodam sem evento non_canonical_request)
#   P-R3-06  I5  guard aceita Transfer-Encoding: identity (só rejeita
#                == "chunked") e faz FORWARD
# ---------------------------------------------------------------------------

import hashlib
import json
import os
import socket
import sys
import time
import traceback
from datetime import datetime, timezone
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

LAB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "sunstrike_lab.py")

EXPECTED_LAB_SHA256 = {
    "V03": ("fe6f59caae442e239669d13415a38d30f283258"
            "7436212615b9a608cadc44008"),
    "V04": ("cca997578e1f1b108a0d98e151104eec90ceae78"
            "22e8900cb2ed002b6aa654a4"),
    "V05": ("052688ee7ee45c55691242c42f2b3ada223eaddf"
            "a3f4401e0aa562da224ed209"),
    "V06": ("698b8cff89cb87c57ef7cbe46254af960346025a2"
            "0f7eb4823334cc3d04b3464"),
    "V07": ("d3af0d28715d7cdc25783075ec71530f46055b16"
            "53bc6e961f0403bf6653b663"),
    "V071": ("72c894fe579dfc335f9b072995e472d2de943e0b"
             "d51fc657a7e7ff0af23d00f7"),
    # v0.6 (13-11, GO à v0.7.2 ~19:30): alvo NOVO V072 — hepta-target.
    # Previsões V072 = cópia da V071 (C7/I1/C8/I4/I5 são setpoints
    # s/WO, firmware e canonicalização — INALTERADOS pelo F-C15a/b).
    "V072": ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
             "0ac38c6e717fd7b40afbd4"),
}

with open(LAB_PATH, "rb") as f:
    LAB_BYTES = f.read()
lab_sha = hashlib.sha256(LAB_BYTES).hexdigest()
TARGET = None
for tag, h in EXPECTED_LAB_SHA256.items():
    if lab_sha == h:
        TARGET = tag
        break
print("SUNSTRIKE probes R3 v0.5.2 (hexa-target, reconstrucao "
      "pos-incidente INFRA-2026-13-11-B) — grant "
      "GRANT-PVTE-20261112-SS-01")
print("run_id           : %s" %
      (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
       "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]))
print("hashes esperados : %s" %
      {k: v[:16] + "…" for k, v in EXPECTED_LAB_SHA256.items()})
if TARGET is None:
    print("hash OBSERVADO   : %s" % lab_sha)
    print("FALHA: o lab alvo não é a v0.3, a v0.4, a v0.5, a v0.6, a "
          "v0.7 nem a v0.7.1 restaurada verificadas — ABORTADO antes "
          "de qualquer execução (protocolo: nada corre contra alvo "
          "errado).")
    raise SystemExit(2)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))
if TARGET == "V03":
    print("                   [OK — v0.3 intocada; GATEFALL do ANTES]")
elif TARGET == "V04":
    print("                   [OK — v0.4; GATEFALL do DEPOIS]")
elif TARGET == "V05":
    print("                   [OK — v0.5; NÃO-REGRESSÃO R3 — os "
          "achados R3 têm de continuar RESOLVIDOS]")
elif TARGET == "V07":
    print("                   [OK — v0.7; NÃO-REGRESSÃO R3 da R7 — "
          "os achados R3 têm de continuar RESOLVIDOS]")
else:
    print("                   [OK — v0.6; NÃO-REGRESSÃO R3 da R5 — "
          "os achados R3 têm de continuar RESOLVIDOS]")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

LOOPBACK = L.LOOPBACK

# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS (impressas antes de qualquer execução)
# Contra a v0.3: todos CONFIRMADO = o achado existe (VERMELHO do antes).
# Contra a v0.4: todos RESOLVIDO = o fix existe (VERDE do depois).
# ---------------------------------------------------------------------------

GATEFALL_V03 = [
    {"id": "P-R3-01", "finding": "C7",
     "prev": "CONFIRMADO — irradiância FIXA: pv_gross = kwp*0.55 em todas "
             "as casas (mínimo 3.2*0.55 = 1.76 kW) > carga 1.2 kW; não "
             "existe qualquer perfil de irradiância (dia/nuvem/noite) — "
             "o sol nunca se põe no lab",
     "criterio": "min(pv_gross) == 1.76 > 1.2 E IRRADIANCE_FACTOR constante "
                 "global no código (sem API/estado de perfil)"},
    {"id": "P-R3-02", "finding": "C7",
     "prev": "CONFIRMADO — 1h de ilha com tudo default (sem harness/curtail): "
             "SoC SOBE em TODOS os dispositivos; o caminho DEFICIT do "
             "step_island é inalcançável em condições naturais — a bateria "
             "nunca serve carga e o measure de retenção seria trivialmente "
             "100% de dia E de noite",
     "criterio": "step_island(3600) direto: todos soc > soc0 (nenhum "
                 "desce) E nenhum evento island_battery_at_floor"},
    {"id": "P-R3-03", "finding": "I1",
     "prev": "CONFIRMADO — curtail_pct é uma CATRACA: em STRESS (f 50.4) "
             "o P(f) autónomo sobe para 40%; ao voltar a NORMAL (f "
             "nominal) o curtail CONTINUA 40% PARA SEMPRE (max(curtail, "
             "target) só sobe) — a frota perde 40% de capacidade "
             "permanentemente sem qualquer comando remoto",
     "criterio": "STRESS: curtail 40 em todos + pf_curtail; NORMAL >1s: "
                 "curtail CONTINUA 40 E 0 eventos pf_release"},
    {"id": "P-R3-04", "finding": "C8",
     "prev": "CONFIRMADO — FP CRIT: 1 setpoint LEGÍTIMO de 90% (in-band, "
             "200 OK) + P(f) autónomo (STRESS) → snapshot: expected NÃO "
             "desconta o curtail autónomo e remote_curtail conta o 90% "
             "legítimo → D-CAPACITY-DIVERGENCE CRIT com FALSA condição "
             "remota; e o snapshot só existe via harness (não há emissão "
             "contínua)",
     "criterio": "divergence >= 30 E alerta D-CAPACITY-DIVERGENCE no scan E "
                 "setpoint único foi legítimo E 0 emissões de snapshot fora "
                 "do harness"},
    {"id": "P-R3-05", "finding": "I4",
     "prev": "CONFIRMADO — canonicalizador fail-OPEN para bytes de controlo "
             "e dot-segments: request lines com 0x01, 0x7F, /./mode e "
             "/../mode são ACEITES (o routing corre, 404) SEM evento "
             "non_canonical_request — o fail-closed da v0.3 não cobre "
             "control chars nem normalização de segmentos",
     "criterio": "os 4 pedidos crus rodam (404 de routing) E 0 eventos "
                 "non_canonical_request no cenário"},
    {"id": "P-R3-06", "finding": "I5",
     "prev": "CONFIRMADO — guard só rejeita Transfer-Encoding == 'chunked': "
             "um pedido com 'Transfer-Encoding: identity' (codificação "
             "ambígua) é ACEITO e sofre FORWARD ao device — a via gerida "
             "continua a aceitar codificação de transporte não validada",
     "criterio": "GET /device/0/telemetry com TE: identity → 200 do device "
                 "(forward) E evento guard_forward E 0 guard_reject"},
]

# GATEFALL v0.4 — PRÉ-REGISTADO na entrada v0.2 do changelog, ANTES de
# qualquer corrida contra a v0.4 (hash cca99757…): todos RESOLVIDO.
GATEFALL_V04 = [
    {"id": "P-R3-01", "finding": "C7", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — perfis de irradiância DIA/NUVEM/NOITE existem "
             "(IRRADIANCE_PROFILES + set_irradiance no GRIDSIM, canal de "
             "sensor): NOITE → pv_gross 0.0 em TODOS; NUVEM → kwp*0.20; "
             "DIA repõe kwp*0.55 (mínimo 1.76 > carga 1.2 no default)",
     "criterio": "set_irradiance(NOITE) → todos pv_gross==0.0; NUVEM → "
                 "==kwp*0.20; DIA → ==kwp*0.55"},
    {"id": "P-R3-02", "finding": "C7", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — com perfil NOITE o DEFICIT é alcançável: ilha + "
             "SoC 60.0 + step_island(3600) → SoC DESCE em TODOS (drop% = "
             "100/kwp; pior casa 3.2 kWp → 28.75 > floor 25), 0 eventos "
             "island_battery_at_floor — a bateria integra na métrica",
     "criterio": "NOITE + ilha + SoC 60: todos soc < 60 E todos soc > "
                 "FLOOR_SOC E 0 island_battery_at_floor"},
    {"id": "P-R3-03", "finding": "I1", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — o curtail autónomo tem RELEASE: STRESS → 40 em "
             "todos (pf_curtail); NORMAL → curtail_autonomous volta a 0.0 "
             "com evento pf_release (a catraca morre; pv volta ao bruto "
             "sem comando nenhum)",
     "criterio": "STRESS: curtail_autonomous==40; NORMAL: ==0.0 E "
                 "pf_release >= 1 evento"},
    {"id": "P-R3-04", "finding": "C8", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — FP morto: setpoint LEGÍTIMO 90% + P(f) autónomo "
             "(STRESS) + snapshot → div < 30 (o esperado DESCONTA o "
             "autónomo), SEM alerta D-CAPACITY-DIVERGENCE; e o snapshot "
             "CONTÍNUO existe: 6 setpoints a 0 → transição de banda → "
             "capacity_snapshot provenance=grid_monitor → alerta dispara",
     "criterio": "FP: st==200 E div < 30 E 0 alertas; contínuo: snapshot "
                 "grid_monitor >= 1 E alerta D-CAPACITY-DIVERGENCE dispara"},
    {"id": "P-R3-05", "finding": "I4", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — canonicalizador fail-closed COMPLETO: 0x01, "
             "0x7F, /./mode e /../mode → 400 + eventos "
             "non_canonical_request com reasons control_char e "
             "dot_segment (o routing nunca os vê)",
     "criterio": "os 4 pedidos crus → 400 E eventos >= 4 E reasons "
                 "{control_char, dot_segment} presentes"},
    {"id": "P-R3-06", "finding": "I5", "expected": "RESOLVIDO",
     "prev": "RESOLVIDO — o guard rejeita QUALQUER Transfer-Encoding pela "
             "PRESENÇA do header: 'Transfer-Encoding: identity' → 400 + "
             "guard_reject (reason transfer_encoding_not_supported), "
             "SEM forward ao device",
     "criterio": "GET /device/0/telemetry com TE: identity → 400 E "
                 "guard_reject >= 1 E 0 guard_forward"},
]

# GATEFALL v0.5 — PRÉ-REGISTADO na entrada v0.3 do changelog, ANTES de
# qualquer corrida contra a v0.5 (hash 052688ee…): critérios e previsões
# IDÊNTICOS aos da v0.4 (nenhum fix da v0.5 toca em C7/I1/C8/I4/I5).
GATEFALL_V05 = [dict(e) for e in GATEFALL_V04]
# GATEFALL v0.6 — PRÉ-REGISTADO na entrada v0.4 do changelog, ANTES de
# qualquer corrida contra a v0.6 (hash 698b8cff…): critérios e previsões
# IDÊNTICOS aos da v0.4/v0.5 — nenhum fix da v0.6 (limite diário,
# recarga grid-tied J4, telemetria soc_limits J5, measure em curva)
# toca em C7/I1/C8/I4/I5. Verificação de critérios antes de registar:
#   P-R3-02: above_floor exige socs > FLOOR_SOC (25) — no v0.6 a física
#     é a mesma (SoC 60 − 100/kwp; pior casa 3.2 kWp → 28.75 > 25) e o
#     modo default NÃO emite island_battery_at_floor; o limite diário
#     conta apenas provenance remote_command e este teste usa consumo
#     da casa em ILHA (fora do ledger): o critério mantém-se.
GATEFALL_V06 = [dict(e) for e in GATEFALL_V04]
# GATEFALL v0.7 — PRÉ-REGISTADO na entrada v0.5 do changelog, ANTES de
# qualquer corrida contra a v0.7 (hash d3af0d28…): critérios e previsões
# IDÊNTICOS aos da v0.4/v0.5/v0.6 — nenhum fix da v0.7 (F-C12 fórmula
# do esperado + armar por remote_shutdown_change + snapshot contínuo
# pós shutdown/resume com dedupe; F-K1 D-BATTERY-MULTIDAY-DRAIN;
# banner SUNBOX/0.7) toca em C7/I1/C8/I4/I5.
GATEFALL_V07 = [dict(e) for e in GATEFALL_V04]
# v0.5.2: critérios V071 = CÓPIA dos V04 (= V07): nenhum fix da v0.7.1
# (F-C13/F-K1/F-C14/F-SP) toca nos achados R3; o consumo LOCAL em ilha
# (P-R3-02) e o setpoint legítimo sem WO (P-R3-04) ficam FORA das
# regras novas (verificação registada na entrada v0.5.2 do changelog).
GATEFALL_V071 = [dict(e) for e in GATEFALL_V04]
# v0.6: critérios V072 = CÓPIA dos V071 (= V04 = V07): nenhum fix da
# v0.7.2 (F-C15a/F-C15b) toca nos achados R3 (setpoints s/WO,
# firmware, canonicalização; verificação registada na entrada v0.6).
GATEFALL_V072 = [dict(e) for e in GATEFALL_V071]
GATEFALL = (GATEFALL_V03 if TARGET == "V03"
            else GATEFALL_V04 if TARGET == "V04"
            else GATEFALL_V05 if TARGET == "V05"
            else GATEFALL_V06 if TARGET == "V06"
            else GATEFALL_V072 if TARGET == "V072"
            else GATEFALL_V071 if TARGET == "V071" else GATEFALL_V07)

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS (antes de qualquer execução)")
print("contra sunstrike_lab.py %s (hash %s…)"
      % ("v0.3 (o ANTES)" if TARGET == "V03"
         else "v0.4 (o DEPOIS da R3)" if TARGET == "V04"
         else "v0.5 (não-regressão R3)" if TARGET == "V05"
         else "v0.6 (não-regressão R3 da R5)" if TARGET == "V06"
         else "v0.7.1 (não-regressão da recuperação)"
         if TARGET == "V071"
         else "v0.7 (não-regressão R3 da R7)",
         lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
if TARGET == "V03":
    print("DECISÃO DO OPERADOR 13-11: C7/I1/C8 são PRÉ-REQUISITOS da v0.4 "
          "(sem eles a métrica principal é falsa); I4/I5 são pequenos; o "
          "measure contrafactual (dois braços) vem a seguir; C4/C5/C6/C9/H7/"
          "I2/I3/I6 ficam para a ronda seguinte.\n")
elif TARGET == "V04":
    print("GATEFALL v0.4 pré-registado na entrada v0.2 do changelog do "
          "probe, ANTES desta corrida. O GATEFALL OFICIAL da R3 é o RUN 1 "
          "contra a v0.3 (correção de método do operador); esta corrida é "
          "a evidência do DEPOIS. C4/C5/C6/C9/H7/I2/I3/I6 ficam para a "
          "ronda seguinte.\n")
elif TARGET == "V071":
    print("GATEFALL v0.7.1 pré-registado na entrada v0.5.2 do changelog "
          "do probe, ANTES desta corrida (critérios idênticos aos da "
          "v0.4/v0.5/v0.6/v0.7). O GATEFALL OFICIAL da R3 é o RUN 1 "
          "contra a v0.3; esta corrida é a NÃO-REGRESSÃO da "
          "recuperação (reconstrução pós-INFRA-2026-13-11-B): os "
          "fixes da v0.7.1 (F-C13 work-order, F-K1 DRAIN-TO-LOW, "
          "F-C14 WARN s/WO, F-SP setpoint) NÃO podem reabrir "
          "C7/I1/C8/I4/I5 (as regras novas ficam CALADAS nos cenários "
          "R3: consumo LOCAL em ilha é provenance ≠ remote_command; o "
          "setpoint legítimo continua a executar sem WO). "
          "C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a v0.8.\n")
elif TARGET == "V07":
    print("GATEFALL v0.7 pré-registado na entrada v0.5 do changelog do "
          "probe, ANTES desta corrida (critérios idênticos aos da "
          "v0.4/v0.5/v0.6). O GATEFALL OFICIAL da R3 é o RUN 1 contra "
          "a v0.3; esta corrida é a NÃO-REGRESSÃO da R7: os fixes da "
          "v0.7 (F-C12 capacity divergence, F-K1 multiday drain, "
          "banner SUNBOX/0.7) NÃO podem reabrir C7/I1/C8/I4/I5. "
          "C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a ronda seguinte.\n")
else:
    print("GATEFALL v0.5 pré-registado na entrada v0.3 do changelog do "
          "probe, ANTES desta corrida (critérios idênticos aos da v0.4). "
          "O GATEFALL OFICIAL da R3 é o RUN 1 contra a v0.3; esta corrida "
          "é a NÃO-REGRESSÃO da v0.5: os fixes da v0.5 (floor opção A, "
          "ISLAND_MIN_SOC, measure com dois atacantes, regra cumulativa "
          "C4) NÃO podem reabrir C7/I1/C8/I4/I5. C5/C6/C9/H7/I2/I3/I6 "
          "ficam para a ronda seguinte.\n" if TARGET == "V05" else
          "GATEFALL v0.6 pré-registado na entrada v0.4 do changelog do "
          "probe, ANTES desta corrida (critérios idênticos aos da "
          "v0.4/v0.5). O GATEFALL OFICIAL da R3 é o RUN 1 contra a "
          "v0.3; esta corrida é a NÃO-REGRESSÃO da R5: os fixes da "
          "v0.6 (limite diário 40%/24 h, recarga grid-tied, telemetria "
          "soc_limits, measure em curva) NÃO podem reabrir "
          "C7/I1/C8/I4/I5. C5/C6/C9/H7/I2/I3/I6/C11/J3 ficam para a "
          "ronda seguinte.\n")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VEREDICTOS = []


def raw_http(port, request_bytes, read_s=5.0):
    """Envia bytes crus e devolve (status_line, headers_dict, body_bytes)."""
    s = socket.create_connection((LOOPBACK, port), timeout=read_s)
    try:
        s.sendall(request_bytes)
        s.settimeout(read_s)
        data = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data and b"Content-Length" in data:
                    head, _, rest = data.partition(b"\r\n\r\n")
                    cl = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            cl = int(line.split(b":")[1].strip())
                    if len(rest) >= cl:
                        break
        except socket.timeout:
            pass
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode(
                "latin-1").strip()
    return status_line, headers, body


def raw_post(port, target, body, auth=None):
    req = b"POST " + target + b" HTTP/1.1\r\nHost: " + LOOPBACK.encode() + b"\r\n"
    if auth:
        req += b"Authorization: Bearer " + auth.encode() + b"\r\n"
    req += (b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
            % len(body)) + body
    return raw_http(port, req)


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

    # ================= P-R3-01 — C7: irradiância fixa / perfis ==========
    if TARGET == "V03":
        print("[P-R3-01] C7 — irradiância fixa: o sol nunca se põe no lab")
    else:
        print("[P-R3-01] C7 — perfis de irradiância: o sol põe-se no lab")
    lab.scenario("P-R3-01")
    reset_all(lab)
    pv_all = [d.pv_gross_kw() for d in lab.devices]
    src = open(L.__file__, encoding="utf-8").read()
    if TARGET == "V03":
        irr_fixed = ("IRRADIANCE_FACTOR = 0.55" in src
                     and "set_irradiance" not in src
                     and "irradiance_profile" not in src
                     and "IRRADIANCE_PROFILES" not in src)
        cond = (min(pv_all) > L.LOAD_LOCAL_KW and min(pv_all) == 1.76
                and irr_fixed)
        expect("P-R3-01", GATEFALL[0]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["pv_gross por casa: min=%.2f max=%.2f (todos > carga %.2f)"
                % (min(pv_all), max(pv_all), L.LOAD_LOCAL_KW),
                "IRRADIANCE_FACTOR constante global, sem perfil dia/nuvem/"
                "noite nem API: %s" % irr_fixed,
                "consequência: em ilha a bateria nunca SERVE carga (deficit "
                "natural inexistente); o measure v0.4 sem perfil mediria "
                "retenção trivialmente 100%"])
    else:
        # v0.4: perfis publicados pelo GRIDSIM no canal de sensor
        lab.gridsim.set_irradiance("NOITE")
        pv_noite = [d.pv_gross_kw() for d in lab.devices]
        lab.gridsim.set_irradiance("NUVEM")
        pv_nuvem = [d.pv_gross_kw() for d in lab.devices]
        lab.gridsim.set_irradiance("DIA")
        pv_dia = [d.pv_gross_kw() for d in lab.devices]
        exp_nuvem = [round(d.kwp * 0.20, 2) for d in lab.devices]
        exp_dia = [round(d.kwp * 0.55, 2) for d in lab.devices]
        cond = (all(v == 0.0 for v in pv_noite)
                and pv_nuvem == exp_nuvem and pv_dia == exp_dia
                and min(pv_dia) == 1.76)
        expect("P-R3-01", GATEFALL[0]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["NOITE: pv_gross 0.0 em TODOS (%d/%d)"
                % (sum(1 for v in pv_noite if v == 0.0), len(pv_noite)),
                "NUVEM: pv_gross == kwp*0.20 em TODOS (%d/%d); DIA repõe "
                "kwp*0.55 (min=%.2f > carga %.2f)"
                % (sum(1 for a, b in zip(pv_nuvem, exp_nuvem) if a == b),
                   len(pv_nuvem), min(pv_dia), L.LOAD_LOCAL_KW),
                "IRRADIANCE_PROFILES + set_irradiance no GRIDSIM (canal de "
                "sensor, fora da API HTTP): o measure pode exercitar dia E "
                "noite"])

    # ================= P-R3-02 — C7: deficit inalcançável / alcançável ==
    if TARGET == "V03":
        print("\n[P-R3-02] C7 — 1h de ilha default: bateria nunca gasta")
    else:
        print("\n[P-R3-02] C7-b — 1h de ilha em NOITE: bateria gasta "
              "(deficit alcançável)")
    lab.scenario("P-R3-02")
    reset_all(lab)
    # modo ilha por harness (o mesmo estado que o BLACKOUT produz): relé
    # aberto, inversor ON — SEM mexer em curtail.
    # v0.1.1 (V03): SoC desce a 60.0 por harness ANTES (no run 1, com SoC
    # 100 no cap 100, "SoC sobe" era impossível por construção — o achado
    # é o mesmo: o ÚNICO fluxo possível é CARREGAR, nunca GASTAR).
    # v0.4 (V04): SoC 60.0 + perfil NOITE → pv 0 → deficit: SoC DESCE
    # (drop% = 100/kwp; pior casa 3.2 kWp → 28.75 > floor 25).
    # v0.4.1 (correção datada): o setup era `TARGET in ("V04", "V05")`
    # e não aplicava o perfil NOITE na v0.6 — a bateria CARREGAVA em
    # DIA e o critério all_down falhava por DEFEITO DO PROBE, não do
    # lab (run 1 contra a v0.6 preservado em
    # sunstrike_probes_v06_r3_run1.txt). Corrigido: `TARGET != "V03"`.
    if TARGET != "V03":
        lab.gridsim.set_irradiance("NOITE")
    socs0 = []
    for d in lab.devices:
        d.relay_closed = False
        d.soc = 60.0
        socs0.append(d.soc)
        d.step_island(3600.0)   # 1h de ilha
    socs1 = [d.soc for d in lab.devices]
    floor_evs = [e for e in scenario_events(lab, "P-R3-02")
                 if e.get("event") == "island_battery_at_floor"]
    if TARGET == "V03":
        all_up = all(s1 > s0 for s0, s1 in zip(socs0, socs1))
        none_down = all(s1 >= s0 for s0, s1 in zip(socs0, socs1))
        cond = all_up and none_down and not floor_evs
        expect("P-R3-02", GATEFALL[1]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["1h de ilha default (SoC de partida 60.0): SoC → min=%.2f "
                "max=%.2f — todos SOBEM (só CARREGA, nunca GASTA)"
                % (min(socs1), max(socs1)),
                "eventos island_battery_at_floor: %d — o caminho DEFICIT "
                "é inalcançável sem harness/curtail" % len(floor_evs),
                "consequência: o measure de retenção não pode distinguir "
                "dia de noite; a bateria nunca entra na métrica"])
    else:
        all_down = all(s1 < s0 for s0, s1 in zip(socs0, socs1))
        above_floor = all(s1 > L.FLOOR_SOC for s1 in socs1)
        cond = all_down and above_floor and not floor_evs
        lab.gridsim.set_irradiance("DIA")   # repor perfil default
        expect("P-R3-02", GATEFALL[1]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["1h de ilha em NOITE (SoC de partida 60.0): SoC → min=%.2f "
                "max=%.2f — todos DESCEM (a bateria SERVE carga)"
                % (min(socs1), max(socs1)),
                "pior casa (3.2 kWp): 60.0 → %.2f (drop 31.25%% = 100/kwp; "
                "acima do floor %.1f); eventos floor: %d"
                % (min(socs1), L.FLOOR_SOC, len(floor_evs)),
                "consequência: o measure PASSA a distinguir dia de noite — "
                "a bateria integra na métrica (MEASURE/NOITE do lab)"])

    # ================= P-R3-03 — I1: catraca / release do curtail =========
    if TARGET == "V03":
        print("\n[P-R3-03] I1 — curtail_pct é catraca (só sobe)")
    else:
        print("\n[P-R3-03] I1 — curtail autónomo com RELEASE (sobe e desce)")
    lab.scenario("P-R3-03")
    reset_all(lab)
    lab.gridsim.set_state("STRESS")
    time.sleep(0.8)     # publish loop aplica P(f): f 50.4 → target 40
    curt_stress = [d.curtail_pct for d in lab.devices]
    pf_evs = [e for e in scenario_events(lab, "P-R3-03")
              if e.get("event") == "pf_curtail"]
    lab.gridsim.set_state("NORMAL")
    time.sleep(1.2)     # f nominal 50.0 → target 0
    curt_normal = [d.curtail_pct for d in lab.devices]
    release_evs = [e for e in scenario_events(lab, "P-R3-03")
                   if e.get("event") in ("pf_release", "pf_restore",
                                         "curtail_release")]
    pv_expect_normal = round(3.2 * L.IRRADIANCE_FACTOR, 2)
    if TARGET == "V03":
        cond = (all(c == 40.0 for c in curt_stress)
                and all(c == 40.0 for c in curt_normal)
                and pf_evs and not release_evs)
        expect("P-R3-03", GATEFALL[2]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["STRESS (f 50.4): curtail_pct=%s em todos (pf_curtail=%d)"
                % (sorted(set(curt_stress)), len(pf_evs)),
                "NORMAL (f nominal, >1s): curtail_pct=%s — CATRACA, sem "
                "qualquer evento de release (%d)" % (sorted(set(curt_normal)),
                                                     len(release_evs)),
                "consequência: pv_kw fica 60%% do bruto PARA SEME (ex.: casa "
                "3.2 kWp: %.2f vs %.2f) sem comando remoto nenhum — a "
                "divergência de capacidade fica cega para P(f) acumulado"
                % (round(pv_expect_normal * 0.6, 2), pv_expect_normal)])
    else:
        aut_normal = [d.curtail_autonomous for d in lab.devices]
        cond = (all(c == 40.0 for c in curt_stress)
                and all(c == 0.0 for c in aut_normal)
                and all(c == 0.0 for c in curt_normal)
                and pf_evs and release_evs)
        expect("P-R3-03", GATEFALL[2]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["STRESS (f 50.4): curtail_pct=%s em todos (pf_curtail=%d)"
                % (sorted(set(curt_stress)), len(pf_evs)),
                "NORMAL (f nominal, >1s): curtail_autonomous=%s, "
                "curtail_pct=%s — RELEASE (%d eventos pf_release); pv volta "
                "ao bruto (casa 3.2 kWp: %.2f) sem comando nenhum"
                % (sorted(set(aut_normal)), sorted(set(curt_normal)),
                   len(release_evs), pv_expect_normal)])
    reset_all(lab)
    lab.gridsim.set_state("NORMAL")

    # ================= P-R3-04 — C8: FP da divergência / fix ============
    if TARGET == "V03":
        print("\n[P-R3-04] C8 — FP CRIT: setpoint legítimo 90% + P(f) "
              "autónomo")
    else:
        print("\n[P-R3-04] C8 — FP morto + snapshot contínuo por transição "
              "de banda")
    lab.scenario("P-R3-04")
    reset_all(lab)
    dev0 = lab.devices[0]
    # 1 setpoint LEGÍTIMO: 90% está dentro da banda [0,100], 200 OK,
    # param_change auditado — manutenção normal de um operador.
    st, resp = hj(dev0.port, "POST", "/setpoint", {"value": 90.0},
                  token=dev0.service_token)
    lab.gridsim.set_state("STRESS")
    time.sleep(0.8)     # P(f) autónomo: curtail 40% em todos (legítimo)
    L.emit_capacity_snapshot(lab)
    snap_evs = [e for e in scenario_events(lab, "P-R3-04")
                if e.get("event") == "capacity_snapshot"]
    div = snap_evs[0].get("divergence_pct", 0.0) if snap_evs else 0.0
    remote_c = (snap_evs[0].get("remote_curtail_devices", 0)
                if snap_evs else 0)
    alerts = scan_scenario(lab, "P-R3-04")
    capdiv = [a for a in alerts if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    if TARGET == "V03":
        cond = (st == 200 and len(snap_evs) == 1 and div >= 30.0
                and remote_c == 1 and capdiv)
        expect("P-R3-04", GATEFALL[3]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["setpoint 90%% LEGÍTIMO → %s (in-band, param_change remoto "
                "auditado); P(f) autónomo 40%% em STRESS (legítimo)" % st,
                "snapshot (via harness — sem emissão contínua): divergence="
                "%.2f%% >= 30, remote_curtail_devices=%d (O 90%% LEGÍTIMO "
                "CONTA COMO REMOTO)" % (div, remote_c),
                "D-CAPACITY-DIVERGENCE CRIT DISPARA: %s — FALSO POSITIVO: "
                "nenhum atacante curtailou a frota"
                % [(a["rule"], a["count"]) for a in capdiv]])
        reset_all(lab)
        lab.gridsim.set_state("NORMAL")
    else:
        fp_dead = (st == 200 and len(snap_evs) == 1 and div < 30.0
                   and not capdiv)
        # snapshot CONTÍNUO: onda de 6 setpoints a 0 → transição de banda
        for i in range(6):
            hj(lab.devices[i].port, "POST", "/setpoint", {"value": 0.0},
               token=lab.devices[i].service_token)
        time.sleep(0.6)   # o publish loop cruza o limiar → grid_monitor
        cont_evs = [e for e in scenario_events(lab, "P-R3-04")
                    if e.get("event") == "capacity_snapshot"
                    and e.get("provenance") == "grid_monitor"]
        alerts2 = scan_scenario(lab, "P-R3-04")
        capdiv2 = [a for a in alerts2
                   if a["rule"] == "D-CAPACITY-DIVERGENCE"]
        cond = fp_dead and cont_evs and capdiv2
        expect("P-R3-04", GATEFALL[3]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["FP MORTO: setpoint 90%% legítimo → %s + P(f) autónomo → "
                "divergence=%.2f%% < 30 (o esperado DESCONTA o curtail "
                "autónomo) — 0 alertas D-CAPACITY-DIVERGENCE"
                % (st, div),
                "SNAPSHOT CONTÍNUO: 6 setpoints a 0 → transição de banda → "
                "%d capacity_snapshot provenance=grid_monitor (fora do "
                "harness); a regra dispara: %s"
                % (len(cont_evs), [(a["rule"], a["count"])
                                   for a in capdiv2]),
                "o estado já não conta como condição remota: a condição "
                "vem de param_change export_limit remote_command "
                "(setpoint legítimo 90%% NÃO arma sozinho + div < 30)"])
        reset_all(lab)
        lab.gridsim.set_state("NORMAL")

    # ================= P-R3-05 — I4: control chars / dot segments =======
    if TARGET == "V03":
        print("\n[P-R3-05] I4 — canonicalizador fail-open: 0x01/0x7F, "
              "/./, /../")
    else:
        print("\n[P-R3-05] I4 — canonicalizador fail-closed: 0x01/0x7F, "
              "/./, /../ → 400")
    lab.scenario("P-R3-05")
    reset_all(lab)
    dev = lab.devices[5]
    body = b'{"action":"grid_reconnect"}'
    probes_raw = [
        ("0x01",  b"/mo\x01de"),
        ("0x7F",  b"/mo\x7fde"),
        ("/./",   b"/./mode"),
        ("/../",  b"/../mode"),
    ]
    results = []
    for tag, target in probes_raw:
        status, headers, _ = raw_post(dev.port, target, body,
                                      auth=dev.service_token)
        routed = ("404" in status or "200" in status or "409" in status)
        results.append((tag, status.split(" ")[1] if " " in status
                        else status, routed))
    noncanon = [e for e in scenario_events(lab, "P-R3-05")
                if e.get("event") == "non_canonical_request"]
    reasons = {e.get("reason") for e in noncanon}
    if TARGET == "V03":
        routed_all = all(r for _, _, r in results)
        cond = routed_all and not noncanon
        expect("P-R3-05", GATEFALL[4]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["pedidos crus: %s — TODOS rodam no routing" % results,
                "eventos non_canonical_request: %d — o canonicalizador "
                "ACEITA control chars e dot-segments (fail-open)"
                % len(noncanon),
                "consequência: normalização de segmentos e bytes de "
                "controlo ficam a cargo da stdlib (a lição gh-87389 "
                "aplica-se a /./ e /../ em várias versões do Python)"])
    else:
        all_400 = all(r == "400" for _, r, _ in results)
        cond = (all_400 and len(noncanon) >= 4
                and "control_char" in reasons and "dot_segment" in reasons)
        expect("P-R3-05", GATEFALL[4]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["pedidos crus: %s — TODOS 400 antes do routing" % results,
                "eventos non_canonical_request: %d, reasons=%s — o "
                "canonicalizador rejeita <0x20, 0x7F (control_char) e "
                "segmentos . / .. (dot_segment)"
                % (len(noncanon), sorted(reasons)),
                "o routing nunca vê os bytes: fail-closed por construção "
                "(a lição gh-87389 estendida ao canonicalizador próprio)"])

    # ================= P-R3-06 — I5: guard TE ===========================
    if TARGET == "V03":
        print("\n[P-R3-06] I5 — guard só rejeita TE == 'chunked'")
    else:
        print("\n[P-R3-06] I5 — guard rejeita QUALQUER Transfer-Encoding")
    lab.scenario("P-R3-06")
    reset_all(lab)
    req = (b"GET /device/0/telemetry HTTP/1.1\r\nHost: "
           + LOOPBACK.encode()
           + b"\r\nTransfer-Encoding: identity\r\n\r\n")
    status, headers, bodyb = raw_http(L.PORT_GUARD, req)
    fwd = [e for e in scenario_events(lab, "P-R3-06")
           if e.get("event") == "guard_forward"]
    rej = [e for e in scenario_events(lab, "P-R3-06")
           if e.get("event") == "guard_reject"]
    if TARGET == "V03":
        cond = ("200" in status and fwd and not rej)
        expect("P-R3-06", GATEFALL[5]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["GET /device/0/telemetry com 'Transfer-Encoding: "
                "identity' → %s (FORWARD ao device)"
                % status.split(" ")[1],
                "guard_forward=%d, guard_reject=%d — o guard só rejeita "
                "TE == 'chunked'; qualquer OUTRA codificação de transporte "
                "passa" % (len(fwd), len(rej)),
                "consequência: a via gerida aceita codificação ambígua de "
                "transporte (o check é por VALOR, não pela PRESENÇA do "
                "header)"])
    else:
        cond = ("400" in status and rej and not fwd)
        expect("P-R3-06", GATEFALL[5]["prev"], cond,
               "RESOLVIDO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["GET /device/0/telemetry com 'Transfer-Encoding: "
                "identity' → %s (REJEITADO no guard)"
                % status.split(" ")[1],
                "guard_reject=%d, guard_forward=%d — o check é pela "
                "PRESENÇA do header, não pelo valor; nenhuma codificação "
                "de transporte passa na via gerida"
                % (len(rej), len(fwd)),
                "reason do reject: transfer_encoding_not_supported"])

    # ---------------------------------------------------------------------
    # SUMÁRIO — previsão vs observado (GATEFALL fechado; alinhado por ID)
    # ---------------------------------------------------------------------
    by_id = {v["id"]: v for v in VEREDICTOS}
    expected_word = "CONFIRMADO" if TARGET == "V03" else "RESOLVIDO"
    print("\n" + "=" * 72)
    print("SUMÁRIO GATEFALL — previsão PRÉ-registada vs veredicto OBSERVADO")
    print("=" * 72)
    prev_erradas = 0
    match_n = 0
    for entry in GATEFALL:
        v = by_id.get(entry["id"], {"veredicto": "NÃO EXECUTADO"})
        match = (v["veredicto"] == entry.get("expected", "CONFIRMADO"))
        if not match:
            prev_erradas += 1
        else:
            match_n += 1
        print("  [%s/%s] previsto: %s | observado: %s"
              % (entry["id"], entry["finding"], expected_word,
                 v["veredicto"]))
    print("-" * 72)
    if TARGET == "V03":
        print("CONFIRMADOS (vermelho do ANTES contra a v0.3): %d/%d"
              % (match_n, len(GATEFALL)))
    elif TARGET == "V04":
        print("RESOLVIDOS (verde do DEPOIS contra a v0.4): %d/%d"
              % (match_n, len(GATEFALL)))
    elif TARGET == "V05":
        print("RESOLVIDOS (não-regressão contra a v0.5): %d/%d"
              % (match_n, len(GATEFALL)))
    elif TARGET == "V06":
        print("RESOLVIDOS (não-regressão contra a v0.6): %d/%d"
              % (match_n, len(GATEFALL)))
    elif TARGET == "V071":
        print("RESOLVIDOS (não-regressão da recuperação contra a "
              "v0.7.1): %d/%d" % (match_n, len(GATEFALL)))
    else:
        print("RESOLVIDOS (não-regressão contra a v0.7): %d/%d"
              % (match_n, len(GATEFALL)))
    print("PREVISÕES ERRADAS: %d" % prev_erradas)
    print("LAB ALVO: v%s (%s), hash %s (INTOCADA — verificado no arranque)"
          % (L.LAB_VERSION, TARGET, lab_sha))
    if TARGET == "V03":
        print("DECISÃO DO OPERADOR 13-11: v0.4 = pré-requisitos C7 (perfil "
              "de irradiância dia/nuvem/noite), I1 (release do curtail "
              "P(f)), C8 (esperado desconta autónomo + condição remota por "
              "param_change + snapshot contínuo) + I4 (control chars/dot "
              "segments) + I5 (TE qualquer) + measure contrafactual de "
              "dois braços. C4/C5/C6/C9/H7/I2/I3/I6 ficam para a ronda "
              "seguinte.")
    elif TARGET == "V04":
        print("GATEFALL OFICIAL da R3 = RUN 1 contra a v0.3 (5/6 + 1 "
              "previsão errada por defeito de critério do probe, "
              "preservado em sunstrike_probes_v03_r3_run1.txt). Esta "
              "corrida é a evidência do DEPOIS (v0.4). ERRATA do "
              "operador: a frase \"bateria integrando\" do H4-BLACKOUT "
              "foi revista no lab (carga servida pelo SOL em DIA; a "
              "bateria só entra em deficit — MEASURE/NOITE).")
    elif TARGET == "V071":
        print("GATEFALL OFICIAL da R3 = RUN 1 contra a v0.3 (preservado "
              "em sunstrike_probes_v03_r3_run1.txt). Esta corrida é a "
              "NÃO-REGRESSÃO da recuperação (v0.7.1 RESTAURADA, "
              "reconstrução pós-INFRA-2026-13-11-B): o F-C13 "
              "(work-order), o F-K1 (D-BATTERY-DRAIN-TO-LOW), o F-C14 "
              "(WARN shutdown s/WO) e o F-SP (setpoint) não reabriram "
              "nenhum achado R3 (C7/I1/C8/I4/I5 continuam "
              "RESOLVIDOS); a R4/R5/R6/R7 são cobertas pelos probes "
              "r4/r5/r6/r7.")
    elif TARGET == "V07":
        print("GATEFALL OFICIAL da R3 = RUN 1 contra a v0.3 (preservado "
              "em sunstrike_probes_v03_r3_run1.txt). Esta corrida é a "
              "NÃO-REGRESSÃO da R7 (v0.7): o F-C12 (capacity divergence), "
              "o F-K1 (D-BATTERY-MULTIDAY-DRAIN) e o banner SUNBOX/0.7 "
              "não reabriram nenhum achado R3 (C7/I1/C8/I4/I5 continuam "
              "RESOLVIDOS); a R4/R5/R6 são cobertas pelos probes r4/r5/"
              "r6.")
    else:
        print("GATEFALL OFICIAL da R3 = RUN 1 contra a v0.3 (preservado "
              "em sunstrike_probes_v03_r3_run1.txt). Esta corrida é a "
              "NÃO-REGRESSÃO da v0.5: os fixes da v0.5 não reabriram "
              "nenhum achado R3 (C7/I1/C8/I4/I5 continuam RESOLVIDOS); "
              "a R4 (C10/C4) é coberta pelos probes r4."
              if TARGET == "V05" else
              "GATEFALL OFICIAL da R3 = RUN 1 contra a v0.3 (preservado "
              "em sunstrike_probes_v03_r3_run1.txt). Esta corrida é a "
              "NÃO-REGRESSÃO da R5 (v0.6): o limite diário 40%/24 h, a "
              "recarga grid-tied, a telemetria soc_limits e o measure "
              "em curva não reabriram nenhum achado R3 (C7/I1/C8/I4/I5 "
              "continuam RESOLVIDOS); a R4/R5 são cobertas pelos probes "
              "r4/r5.")
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

# EOF:sunstrike_probes_r3.py
