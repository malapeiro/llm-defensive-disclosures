#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# SUNSTRIKE — bateria de probes R2 (M2, ronda 2)
# Grant: GRANT-PVTE-20261112-SS-01 (lab sintético, loopback apenas)
# Alvo:  sunstrike_lab.py — DUAL-TARGET, detetado pelo hash no arranque:
#        v0.2 (b66de6b7…, hash entregue e VERIFICADO pelo supervisor em
#        Python 3.13: selftest PASS, demo 5/5, R1 19V+1R+1 declarado) ou
#        v0.3 (508bf3a3…, entregue neste turno). Nada corre contra um
#        lab que não seja um dos dois hashes verificados.
# Corpus: C4/C5/C6 (Claude, EXECUTADOS) + H1/H2/H3 (Gemini 2.ª auditoria às
#        cegas, EXECUTADOS) + H4/H5/H6/H7 (Gemini, ESTÁTICOS) — registo
#        oficial do operador, GO à v0.3 de 13-11.
# Papel: probes "antes" contra a v0.2 INTOCADA (condição 1 do GO, padrão R1):
#        o output VERMELHO é a evidência do "antes"; os fixes são DEPOIS.
# Protocolo: GATEFALL — previsões PRÉ-REGISTADAS por construção (constantes
#        deste script, hash-verificáveis), impressas ANTES da execução.
#        Veredicto observado != previsto é reportado como PREVISÃO ERRADA.
# Decisão do operador (13-11): C4, C5, C6 e H7 ficam para a R2 seguinte
#        (não são corrigidos na v0.3); H1/H2/H3 são fechados na v0.3
#        (guard proxy + canonicalizador partilhado, fail-closed, tipos
#        estritos — bool NÃO é número); H4/H5 (física) são OBRIGATÓRIOS
#        antes da v0.4 (measure).
# Portabilidade: Python 3.9+, 100% stdlib, 127.0.0.1 apenas.
#
# CHANGELOG DE PROBES (o LAB alvo NUNCA é editado):
#   v0.1 (13-11): primeira versão, alvo v0.2. GATEFALL contra a v0.2
#        pré-registado: todos os 10 probes previstos CONFIRMADO (vermelho
#        do antes). Calibração de desenvolvimento ANTES do pré-registo
#        (raw sockets, documentada): H1a/H1b (byte não-ASCII chega ao
#        routing 404 sem evento non_canonical — fail-open do check),
#        H2a/H2b (query string roteia 200 OK em /setpoint e /mode),
#        H3a/H3b (bool: false→export_limit 0.0, true→1.0), H7a (chunked
#        ignorado — body vazio processado). A calibração não alterou
#        nenhuma previsão: confirmou a leitura estática do código.
#        Run 1 (20261113, preservado em sunstrike_probes_v02_r2_run1.txt):
#        2 previsões erradas + 1 bug de apresentação, TODOS DEFEITOS DO
#        PROBE (o LAB não mudou, hash b66de6b7…): (1) P-R2-01: critério
#        de SoC final dizia 30.0 mas 5 fatias de 15% a partir de 100
#        terminam em 25.0 (erro aritmético do critério; a execução
#        confirmou o C4: 5x200, ZERO alertas, e adicionalmente documenta
#        o boundary exato do floor, já declarado conforme no G7);
#        (2) P-R2-10(e): critério de banner por igualdade exata — o
#        BaseHTTPRequestHandler acrescenta a versão do Python
#        ('SUNBOX/0.1 Python/3.12.14'); corrigido para comparar o
#        PREFIXO SUNBOX/0.1 contra LAB_VERSION 0.2; (3) bug do sumário:
#        o zip(GATEFALL, VEREDICTOS) alinhava por POSIÇÃO, mas o
#        P-R2-08 corre em último (latch/BLACKOUT) — o sumário do run 1
#        trocou os veredictos de P-R2-08/P-R2-09 com P-R2-10; corrigido
#        para alinhar por ID (dict). Os veredictos EXECUTADOS do run 1:
#        8 CONFIRMADO + P-R2-01 e P-R2-10 errados por defeito do próprio
#        critério (achados C4 e H7-e continuam reais).
#   v0.1.1 (13-11): correções de PROBE acima; nenhuma previsão alterada;
#        o LAB alvo continua o v0.2 INTOCADO.
#   v0.3 (13-11): DUAL-TARGET. O lab alvo é DETETADO pelo hash no arranque:
#        v0.2 (b66de6b7…, evidência do ANTES já colhida nos runs 1-2) ou
#        v0.3 (508bf3a3…, entregue neste turno: canonicalizador partilhado
#        fail-closed + strict_number + física H4/H5 + guard proxy §4.5 +
#        7 regras novas). GATEFALL v0.3 PRÉ-REGISTADO NESTA ENTRADA, ANTES
#        de qualquer corrida contra a v0.3 (protocolo GATEFALL):
#          RESOLVIDO (6): P-R2-04 (não-ASCII → 400 + non_canonical_request
#            reason=non_ascii; fail-open morto), P-R2-05 (query → 400
#            reason=query_or_fragment, export intacto), P-R2-06 (bool →
#            400 + strict_type_reject reason=bool_is_not_a_number,
#            export intacto), P-R2-07 (export_kw()==0.0 com export_limit=0
#            e pv_gross_kw() intacto — física deixa de ser cega),
#            P-R2-08 (bateria INTEGRA em ilha: SoC desce a 60.0 antes por
#            2 fatias de 20% e SOBE durante 3s de ilha), P-R2-09 (os
#            eventos do H6 alimentam regras: 5 logins → D-LOGIN-BRUTE-
#            FORCE, 5 PINs → D-LOCAL-CONFIRM-BRUTE-FORCE, // →
#            D-NON-CANONICAL-REQUEST — exatamente as 3 regras no scan).
#          CONFIRMADO-DECLARADO (4): P-R2-01/02/03/10 (C4/C5/C6/H7 ficam
#            para a R2 por DECISÃO DO OPERADOR; critérios de execução
#            IGUAIS aos da v0.2; nota C5: o guard recusa /local_confirm,
#            mas o caminho DIRETO continua — mitigação parcial da via
#            gerida, não do ataque). NENHUMA previsão v0.2 alterada.
#   v0.3.1 (13-11): RUN 3 (contra a v0.3 pré-errata, hash 508bf3a3…,
#        output preservado em sunstrike_probes_v03_r2_run3.txt): 9/10,
#        1 PREVISÃO ERRADA (P-R2-08) — GATEFALL a funcionar, causas
#        documentadas, NUNCA escondidas:
#        (a) ACHADO REAL DO LAB (a causa raiz): step_island integrava
#            energia como kW*dt com dt em SEGUNDOS tratado como kWh —
#            aceleração 3600x (SoC 60.0 → 100.0 em 3.5s de ilha; ~15
#            pontos/s quando o teórico é ~0.004/s). O measure v0.4
#            mediria com física falsa, exatamente o que o GO proibia.
#            CORRIGIDO NO LAB com ERRATA DATADA (novo hash fe6f59ca…):
#            kW*s/3600 → kWh, surplus e deficit; selftest H5
#            re-calibrado (SoC 28.0 + 600s = 0.2 kWh = 3.09 pontos →
#            floor); contagens do demo INALTERADAS (verificado 9/9).
#        (b) DEFEITO DO CRITÉRIO DO PROBE: exigia soc_start == 60.0
#            capturado APÓS 0.5s de EMERGENCY — mas o relé abre já no
#            EMERG (anti-islanding) e a integração começa aí; o soc no
#            início da medição nunca é 60.0. Corrigido: critério mede
#            soc_apos_fatias == 60.0 (logo após as 2 fatias) e exige
#            soc_end > soc_apos_fatias (a bateria CARREGA acima de 60),
#            com a TAXA medida vs teórica como evidência de magnitude
#            (verificação da física, não só da direção).
#        Previsões INALTERADAS para o run 4 (contra a v0.3 pós-errata):
#        P-R2-08 mantém RESOLVIDO (SoC desce a 60.0 por fatias, ilha
#        3s, SoC SOBE acima de 60 com taxa ~0.004-0.005 pontos/s);
#        EXPECTED_LAB_SHA256_V03 atualizado para fe6f59ca… (hash
#        pós-errata; o hash 508bf3a3… fica registado como o alvo
#        histórico do run 3).
#   v0.4 (13-11): TRI-TARGET (não-regressão). Alvo detetado pelo hash no
#        arranque: v0.2 (b66de6b7…, ANTES histórico) ou v0.3 (fe6f59ca…,
#        entregue/verificada) ou v0.4 (cca99757…, entregue neste turno:
#        C7 perfis de irradiância + I1 release do curtail P(f) + C8
#        fórmula/condição/snapshot contínuo + I4 control chars/dot
#        segments + I5 TE qualquer + measure contrafactual). GATEFALL
#        v0.4 PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida
#        contra a v0.4: PREVISÕES IDÊNTICAS às da v0.3 — os fixes da R2
#        têm de se MANTER (não-regressão): P-R2-04..09 RESOLVIDO
#        (critérios de execução iguais aos da v0.3) + P-R2-01/02/03/10
#        CONFIRMADO-DECLARADO (C4/C5/C6/H7 continuam para a ronda
#        seguinte por decisão do operador). Notas v0.4 específicas:
#        (a) P-R2-08: as 2 fatias são /battery (param_change soc, NÃO
#            export_limit) → a transição de banda div=100 em ilha NÃO
#            arma a condição remote da C8 → sem D-CAPACITY-DIVERGENCE
#            no cenário (critério das 3 regras exatas não é atingido
#            por contaminação); (b) P-R2-09: tráfego sem setpoints
#            aplicados → idem; (c) P-R2-10(e): o banner do DEVICE
#            SUNBOX/0.1 continua INTOCADO por decisão R2 (só o guard
#            passou a SUNGUARD/0.4) — o critério mantém-se. NENHUMA
#        previsão v0.2/v0.3 alterada.
# ---------------------------------------------------------------------------
# Probes:
#   v0.5 (13-11): QUAD-TARGET. Quarto alvo: v0.5 (052688ee… — semântica
#        do floor opção A + ISLAND_MIN_SOC 5% + RESERVE_LOCKED_MODE
#        [contrafactual opção B] + measure com dois atacantes + linha
#        OPTION-B + regra D-BATTERY-CUMULATIVE-DRAIN). GATEFALL v0.5
#        PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida contra
#        a v0.5 (protocolo GATEFALL):
#          P-R2-01 RESOLVIDO (C4 FECHADO): as mesmas 5 fatias de 15%
#            (cada <50%) continuam 200 e terminam em 25.0, mas a soma
#            75% >= limiar 50% na janela 3600s DISPARA a nova regra
#            D-BATTERY-CUMULATIVE-DRAIN (WARN) — a descarga fatiada
#            deixa de ser invisível; D-BATTERY-DRAIN-LARGE continua
#            AUSENTE (fatia única 15% < 50% por-op; sem dupla-disparo);
#          P-R2-02/03/10 CONFIRMADO-DECLARADO INALTERADOS (C5/C6/H7
#            ficam para a ronda seguinte por decisão do operador;
#            banner SUNBOX/0.1 do DEVICE intocado por decisão R2);
#          P-R2-04/05/06/07/09 RESOLVIDO INALTERADOS (os fixes R2 não
#            são tocados pela v0.5);
#          P-R2-08 RESOLVIDO com critério INALTERADO: as 2 fatias de
#            20% somam 40% < limiar 50% → a cumulativa NÃO dispara
#            (legítimo de magnitude semelhante fica silencioso); a
#            bateria continua a INTEGRAR em ilha (SoC sobe no surplus).
#        NENHUMA previsão v0.2/v0.3/v0.4 alterada.
#   v0.6 (13-11): PENTA-TARGET. Quinto alvo: v0.6 (698b8cff… — limite
#        diário de descarga remota 40%/24 h + recarga grid-tied J4 +
#        telemetria soc_limits J5 + measure em curva J1/J2 + atacante
#        (c) 2 dias). GATEFALL v0.6 PRÉ-REGISTADO NESTA ENTRADA, ANTES
#        de qualquer corrida contra a v0.6 (protocolo GATEFALL):
#          P-R2-01 RESOLVIDO (C4/limite diário): as 5 fatias de 15%:
#            as fatias 1-2 EXECUTAM (200; SoC 100→85→70) e as fatias
#            3-5 dão 409 remote_discharge_daily_limit (used 30+15 >
#            40; 40+15; 40+15 — 3 eventos remote_daily_limit_block);
#            SoC final 70.0; D-BATTERY-CUMULATIVE-DRAIN e
#            D-BATTERY-DRAIN-LARGE AUSENTES (a soma por janela nunca
#            chega a 50 — o limite SATURA antes; superssenção datada);
#          P-R2-08 RESOLVIDO com critério INALTERADO: as 2 fatias de
#            20% somam used 40, NÃO > 40 (janela inclusiva: passam,
#            200/200, SoC 60.0) e a bateria continua a INTEGRAR em
#            ilha (SoC sobe no surplus) — o limite não morde o caso
#            legítimo de magnitude semelhante;
#          P-R2-02/03/10 CONFIRMADO-DECLARADO INALTERADOS (C5/C6/H7
#            ficam para a ronda seguinte por decisão do operador;
#            banner SUNBOX/0.1 do DEVICE intocado por decisão R2);
#          P-R2-04/05/06/07/09 RESOLVIDO INALTERADOS (os fixes R2 não
#            são tocados pela v0.6).
#        NENHUMA previsão v0.2/v0.3/v0.4/v0.5 alterada.
#   v0.7 (13-11): HEXA-TARGET. Sexto alvo: v0.7 (d3af0d28… — F-C12:
#        esperado da divergência de capacidade = kwp × irr × (1 −
#        curtail_autonomous/100), INDEPENDENTE de inverter_on, fórmula
#        partilhada; a regra arma também por remote_shutdown_change
#        provenance remote_command sem work-order; snapshot contínuo
#        também após shutdown/resume remoto com dedupe determinístico
#        + F-K1: regra 21.ª D-BATTERY-MULTIDAY-DRAIN (soma das
#        descargas remote EXECUTADAS/dev numa janela de 72 h > 70% E
#        ≥ 2 dias-distintos, CRIT, sem prevenção nova) + F-LIMP (c):
#        banner SUNBOX/0.7 no device e no gate + liveness 21/21).
#        GATEFALL v0.7 PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer
#        corrida contra a v0.7 (protocolo GATEFALL):
#          P-R2-01 RESOLVIDO INALTERADO (critério do ramo v0.6): as 5
#            fatias de 15% continuam travadas pelo LIMITE DIÁRIO
#            (2×200, 3×409 daily, SoC final 70.0, 3 eventos
#            remote_daily_limit_block); a janela multiday de 72 h
#            exige > 70% E ≥ 2 dias — aqui só 30% executados num só
#            dia: D-BATTERY-MULTIDAY-DRAIN AUSENTE (não dispara);
#          P-R2-08 RESOLVIDO INALTERADO: as 2 fatias de 20% somam
#            used 40, NÃO > 40 (janela inclusiva: passam, 200/200,
#            SoC 60.0); 40% < 70% e 1 só dia: a multiday NÃO dispara
#            (legítimo de magnitude semelhante continua silencioso);
#          P-R2-10 CONFIRMADO-DECLARADO com o item (e) RESOLVIDO: o
#            banner SUNBOX/0.7 EXISTE na v0.7 (F-LIMP c) — o critério
#            (e) passa a comparar contra SUNBOX/<LAB_VERSION>; (a)-(d)
#            do H7 ficam DECLARADOS para a v0.8;
#          P-R2-02/03 CONFIRMADO-DECLARADO INALTERADOS (C5/C6 ficam
#            para a ronda seguinte por decisão do operador);
#          P-R2-04/05/06/07/09 RESOLVIDO INALTERADOS (os fixes R2
#            não são tocados pela v0.7).
#        NENHUMA previsão v0.2/v0.3/v0.4/v0.5/v0.6 alterada.
#   v0.7 ERRATAS (13-11, datadas):
#        (a) DATAS — errata registada pelo supervisor em
#            ERRATA_v06_datas.md (4f012123…): a entrada v0.6 deste
#            changelog dizia "14-11"; o dia correto é 13-11-2026.
#            Corrigido IN-PLACE nesta versão (r2:148); os ficheiros
#            anteriores ficam inalterados para preservar os hashes
#            verificados.
#        (b) GRAVAGEM — varredura "apogão"→"apagão" em TODO o
#            ficheiro: 0 ocorrências neste probe (nada a corrigir; a
#            varredura fica registada por paridade com o r4/r5).
#   v0.8.1 (13-11, RECONSTRUÇÃO datada pós-incidente INFRA-2026-13-11-B
#        ~18:23): HEPTA-TARGET. Sétimo alvo: v0.7.1 (72c894fe… — lab
#        v0.7.1 RESTAURADO por REPLAY dos edit scripts preservados +
#        errata J5; selftest re-executado BYTE-IDÊNTICO afb98d0c…;
#        fix (.1) pela mesma numeração da recuperação). GATEFALL
#        v0.7.1 PRÉ-REGISTADO NESTA ENTRADA, ANTES de qualquer corrida
#        contra a v0.7.1 (protocolo GATEFALL):
#          P-R2-01 RESOLVIDO INALTERADO (critério do ramo v0.6/v0.7):
#            as 5 fatias de 15% continuam travadas pelo LIMITE DIÁRIO
#            (2×200, 3×409 daily, SoC final 70.0, 3 eventos
#            remote_daily_limit_block); a D-BATTERY-DRAIN-TO-LOW (F-K1,
#            que SUBSTITUIU a MULTIDAY) fica AUSENTE: SoC 70 > 35 e
#            só 30% executados num só dia;
#          P-R2-08 RESOLVIDO INALTERADO: as 2 fatias de 20% somam
#            used 40, NÃO > 40 (200/200, SoC 60.0); SoC 60 > 35: a
#            DRAIN-TO-LOW NÃO dispara;
#          P-R2-10 CONFIRMADO-DECLARADO com o item (e) RESOLVIDO: o
#            banner SUNBOX/0.7.1 EXISTE na v0.7.1 (F-LIMP c mantém-se)
#            — o critério (e) compara contra SUNBOX/<LAB_VERSION>
#            (prefixo: 'Server: SUNBOX/0.7.1 Python/…'); (a)-(d) do
#            H7 ficam DECLARADOS para a v0.8;
#          P-R2-02/03 CONFIRMADO-DECLARADO INALTERADOS (C5/C6);
#          P-R2-04/05/06/07/09 RESOLVIDO INALTERADOS (os fixes R2
#            não são tocados pela v0.7.1).
#        NENHUMA previsão v0.2/v0.3/v0.4/v0.5/v0.6/v0.7 alterada.
# ---------------------------------------------------------------------------
# Probes:
#   P-R2-01  C4  descarga fatiada (<50%/op) evade D-BATTERY-DRAIN-LARGE
#   P-R2-02  C5  5 PINs errados remotos trançam o /local_confirm (DoS dono)
#   P-R2-03  C6  5 logins errados trançam o /fleet/login GLOBAL (DoS op)
#   P-R2-04  H1  byte não-ASCII: _canonical_path FAIL-OPEN (sem auditoria)
#   P-R2-05  H2  query string cruza a canonicalização e ROTEIA (200)
#   P-R2-06  H3  booleano aceite como número (false → export_limit 0.0)
#   P-R2-07  H4  pv_kw ignora export_limit/curtail (física cega)
#   P-R2-08  H5  bateria NÃO se gasta/integra em modo ilha (SoC congelado)
#   P-R2-09  H6  eventos novos (login_fail/lockouts/non_canonical) órfãos
#                de regra no Detector
#   P-R2-10  H7  misc: token local_confirm sem TTL; /login device sem
#                lockout; chunked ignorado; BLOCKED_IN_EMERGENCY morto;
#                banner SUNBOX/0.1 (lab v0.2)
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

EXPECTED_LAB_SHA256_V02 = ("b66de6b7e64b315a9ff5aa821cbec066f82b4cbd978"
                           "10d06d83be5518056bcc7")
# v0.3 pós-errata (run 3 do GATEFALL revelou a unidade 3600x — changelog);
# o hash pré-errata 508bf3a3… é o alvo histórico do run 3.
EXPECTED_LAB_SHA256_V03 = ("fe6f59caae442e239669d13415a38d30f283258"
                           "7436212615b9a608cadc44008")
# v0.4 (tri-target): C7/I1/C8/I4/I5 + measure contrafactual
EXPECTED_LAB_SHA256_V04 = ("cca997578e1f1b108a0d98e151104eec90ceae78"
                           "22e8900cb2ed002b6aa654a4")
EXPECTED_LAB_SHA256_V05 = ("052688ee7ee45c55691242c42f2b3ada223eaddf"
                           "a3f4401e0aa562da224ed209")
EXPECTED_LAB_SHA256_V06 = ("698b8cff89cb87c57ef7cbe46254af960346025a2"
                           "0f7eb4823334cc3d04b3464")
# v0.7 (hexa-target): F-C12 capacity divergence + F-K1 D-BATTERY-
# MULTIDAY-DRAIN + banner SUNBOX/0.7 + liveness 21/21
EXPECTED_LAB_SHA256_V07 = ("d3af0d28715d7cdc25783075ec71530f46055b16"
                           "53bc6e961f0403bf6653b663")
# v0.8.1 (hepta-target): F-C13 work-order + F-K1 D-BATTERY-DRAIN-TO-LOW
# + F-C14 WARN shutdown s/WO + F-SP setpoint com WO + banner SUNBOX/0.7.1
# v0.9.1 (13-11, ERRATA DE RAMO datada, pós-run 1 vs v0.7.2): o run
#        com o v0.9 deu 6/7+3/3 com P-R2-01 PREVISÃO ERRADA POR DEFEITO
#        DE SELEÇÃO DE RAMO do probe (o ramo v0.6+ do P-R2-01 não foi
#        estendido a "v0.7.2" e o cenário caiu no ramo v0.2; a FÍSICA
#        medida foi EXATAMENTE a prevista: fatias [200,200,409,409,
#        409], SoC [100→85→70], 3 eventos daily — output PRESERVADO
#        como errata). Correção datada IN-PLACE: o ramo passa a incluir
#        "v0.7.2" (previsão INALTERADA — cópia da V071). Re-run =
#        run oficial da não-regressão.
# v0.9 (13-11, GO à v0.7.2 ~19:30): alvo NOVO v0.7.2 — octa-target.
# Previsões V072 = cópia da V071 (C4 é /battery; o banner acompanha
# LAB_VERSION dinamicamente — item (e) do H7 verifica
# SUNBOX/0.7.2; o F-C15a/F-C15b não toca nos achados R2).
EXPECTED_LAB_SHA256_V072 = ("1c433df138b90ba8fc7ce8afe28c4298b30206cda0"
                            "0ac38c6e717fd7b40afbd4")
EXPECTED_LAB_SHA256_V071 = ("72c894fe579dfc335f9b072995e472d2de943e0b"
                            "d51fc657a7e7ff0af23d00f7")

with open(LAB_PATH, "rb") as f:
    LAB_BYTES = f.read()
lab_sha = hashlib.sha256(LAB_BYTES).hexdigest()
if lab_sha == EXPECTED_LAB_SHA256_V02:
    TARGET = "v0.2"
elif lab_sha == EXPECTED_LAB_SHA256_V03:
    TARGET = "v0.3"
elif lab_sha == EXPECTED_LAB_SHA256_V04:
    TARGET = "v0.4"
elif lab_sha == EXPECTED_LAB_SHA256_V05:
    TARGET = "v0.5"
elif lab_sha == EXPECTED_LAB_SHA256_V06:
    TARGET = "v0.6"
elif lab_sha == EXPECTED_LAB_SHA256_V07:
    TARGET = "v0.7"
elif lab_sha == EXPECTED_LAB_SHA256_V071:
    TARGET = "v0.7.1"
elif lab_sha == EXPECTED_LAB_SHA256_V072:
    TARGET = "v0.7.2"
else:
    print("SUNSTRIKE probes R2 v0.7 — grant GRANT-PVTE-20261112-SS-01")
    print("hash OBSERVADO   : %s" % lab_sha)
    print("FALHA: o lab alvo não é nem a v0.2, v0.3, v0.4, v0.5, "
          "v0.6, v0.7 nem v0.7.1 restaurada verificadas — "
          "ABORTADO antes de qualquer execução (protocolo: nada corre "
          "contra alvo errado).")
    raise SystemExit(2)
# fixes R2 presentes a partir da v0.3 (v0.3-v0.7 correm os MESMOS
# critérios "fix aplicado", EXCETO P-R2-01 que na v0.5 tem o critério
# próprio do C4 fechado, na v0.6/v0.7 o do LIMITE DIÁRIO, e P-R2-10 que
# na v0.7 tem o item (e) banner RESOLVIDO; a v0.2 mantém os critérios
# do ANTES)
FIXED = TARGET in ("v0.3", "v0.4", "v0.5", "v0.6", "v0.7", "v0.7.1",
                  "v0.7.2")
print("SUNSTRIKE probes R2 v0.8.1 (hepta-target, reconstrucao "
      "pos-incidente INFRA-2026-13-11-B) — grant "
      "GRANT-PVTE-20261112-SS-01")
print("run_id           : %s" %
      (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
       "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]))
print("hash esperado    : %s" %
      (EXPECTED_LAB_SHA256_V071 if TARGET == "v0.7.1" else
       (EXPECTED_LAB_SHA256_V07 if TARGET == "v0.7" else
       (EXPECTED_LAB_SHA256_V06 if TARGET == "v0.6" else
       (EXPECTED_LAB_SHA256_V05 if TARGET == "v0.5" else
       (EXPECTED_LAB_SHA256_V04 if TARGET == "v0.4" else
        (EXPECTED_LAB_SHA256_V03 if TARGET == "v0.3"
         else EXPECTED_LAB_SHA256_V02)))))))
print("ALVO DETETADO    : %s" % TARGET)
print("hash OBSERVADO   : %s  [OK — %s]" % (lab_sha, TARGET))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

LOOPBACK = L.LOOPBACK


# ---------------------------------------------------------------------------
# GATEFALL — previsões PRÉ-REGISTADAS (impressas antes de qualquer execução)
# Contra a v0.2: todos CONFIRMADO = o achado existe (VERMELHO do antes).
# Contra a v0.3 (pré-registadas ANTES da corrida, neste mesmo script):
# 6 RESOLVIDO (H1/H2/H3/H4/H5/H6 fechados) + 4 CONFIRMADO-DECLARADO
# (C4/C5/C6/H7 ficam para a R2 por decisão do operador).
# ---------------------------------------------------------------------------

GATEFALL_V02 = [
    {"id": "P-R2-01", "finding": "C4",
     "prev": "CONFIRMADO — 5 descargas de 15% cada (100→30) executam 200 "
             "sem NENHUM alerta (fatia <50% evade D-BATTERY-DRAIN-LARGE; "
             "acima do floor, sem floor_block)",
     "criterio": "todas 200 E soc final ~30.0 (>25) E 0 alertas no scan"},
    {"id": "P-R2-02", "finding": "C5",
     "prev": "CONFIRMADO — 5 PINs errados via HTTP (endpoint sem auth) "
             "emitem local_confirm_lockout; o PIN CORRETO do dono é negado "
             "(403 pin_locked) durante 600s = DoS à confirmação física",
     "criterio": "5x403 + evento lockout + PIN correto → 403 pin_locked"},
    {"id": "P-R2-03", "finding": "C6",
     "prev": "CONFIRMADO — 5 logins errados trancam o /fleet/login GLOBAL; "
             "o login CORRETO (default_creds) é negado 429 = DoS ao "
             "operador legítimo (lockout global, não por conta)",
     "criterio": "5x401 + login correto → 429 login_rate_blocked"},
    {"id": "P-R2-04", "finding": "H1",
     "prev": "CONFIRMADO — byte não-ASCII na request line: decode ascii "
             "lança exceção e o except devolve True = FAIL-OPEN; o pedido "
             "chega ao routing (404) SEM evento non_canonical_request",
     "criterio": "resposta de routing (404 rota desconhecida) E 0 eventos "
                 "non_canonical_request no cenário"},
    {"id": "P-R2-05", "finding": "H2",
     "prev": "CONFIRMADO — query string cruza o check (raw == self.path "
             "com query) e o routing por split('?') ROTEIA: /setpoint?x=1 "
             "executa 200; regras M3 por URI exato não veriam o pedido",
     "criterio": "200 OK E export_limit==50.0 E param_change no audit"},
    {"id": "P-R2-06", "finding": "H3",
     "prev": "CONFIRMADO — booleano é aceite como número: float(False)=0.0 "
             "passa isfinite e banda; {'value': false} → 200 com "
             "export_limit=0.0 (curtailment total com um bool)",
     "criterio": "200 OK E export_limit == 0.0"},
    {"id": "P-R2-07", "finding": "H4",
     "prev": "CONFIRMADO — pv_kw() ignora export_limit/curtail_pct: com "
             "export_limit=0 a telemetria continua a reportar "
             "kwp*IRRADIANCE_FACTOR (física cega; compromete o measure)",
     "criterio": "200 no setpoint 0 E pv_kw == kwp*0.55 inalterado"},
    {"id": "P-R2-08", "finding": "H5",
     "prev": "CONFIRMADO — em modo ilha (BLACKOUT, relé aberto) o SoC "
             "permanece 100.0 para sempre: a bateria nunca se gasta nem "
             "integra (sem modelo temporal; compromete o measure)",
     "criterio": ">=3s de ilha E soc final == 100.0 (congelado)"},
    {"id": "P-R2-09", "finding": "H6",
     "prev": "CONFIRMADO — eventos login_fail, local_confirm_lockout, "
             "login_rate_blocked, non_canonical_request, session_expired, "
             "inverter_resume_blocked NÃO alimentam NENHUMA regra do "
             "RULE_ATTACK_MAP (12 regras v0.2) — órfãos de deteção",
     "criterio": "eventos reais gerados no cenário E 0 alertas no scan "
                 "do cenário"},
    {"id": "P-R2-10", "finding": "H7",
     "prev": "CONFIRMADO — misc: (a) token de local_confirm sem TTL; "
             "(b) /login do device SEM lockout (10x401, sem evento); "
             "(c) chunked ignorado (body vazio processado); (d) "
             "BLOCKED_IN_EMERGENCY morto (definida, nunca referenciada); "
             "(e) banner SUNBOX/0.1 num lab v0.2",
     "criterio": "todos os 5 sub-achados confirmados"},
]

GATEFALL_V03 = [
    {"id": "P-R2-01", "finding": "C4",
     "prev": "CONFIRMADO-DECLARADO — C4 fica para a R2 por decisão do "
             "operador: a descarga fatiada (<50%/op) continua a evadir "
             "D-BATTERY-DRAIN-LARGE (5x200, ZERO alertas, SoC 100→25.0 "
             "acima do floor)",
     "criterio": "todas 200 E soc final 25.0 E 0 alertas no scan "
                 "(idêntico ao run contra a v0.2)"},
    {"id": "P-R2-02", "finding": "C5",
     "prev": "CONFIRMADO-DECLARADO — C5 fica para a R2 por decisão do "
             "operador: 5 PINs errados no caminho DIRETO continuam a "
             "trancar o /local_confirm (PIN correto → 403 pin_locked "
             "600s). Nota: o guard recusa /local_confirm (mitigação "
             "parcial da via gerida), mas o endpoint direto permanece",
     "criterio": "5x403 + evento lockout + PIN correto → 403 pin_locked "
                 "(idêntico ao run contra a v0.2)"},
    {"id": "P-R2-03", "finding": "C6",
     "prev": "CONFIRMADO-DECLARADO — C6 fica para a R2 por decisão do "
             "operador: o lockout do /fleet/login continua GLOBAL "
             "(login correto → 429 login_rate_blocked)",
     "criterio": "5x401 + login correto → 429 login_rate_blocked "
                 "(idêntico ao run contra a v0.2)"},
    {"id": "P-R2-04", "finding": "H1",
     "prev": "RESOLVIDO — canonicalizador partilhado fail-closed: byte "
             "não-ASCII é rejeitado ANTES do routing (400 + evento "
             "non_canonical_request reason=non_ascii); o fail-open do "
             "except está morto por construção",
     "criterio": "400 E evento non_canonical_request com reason "
                 "non_ascii E nenhuma rota executada"},
    {"id": "P-R2-05", "finding": "H2",
     "prev": "RESOLVIDO — query string rejeitada fail-closed (400 + "
             "evento reason=query_or_fragment); o routing nunca mais "
             "separa '?'; export_limit intacto",
     "criterio": "400 E evento reason query_or_fragment E "
                 "export_limit intacto E 0 param_change"},
    {"id": "P-R2-06", "finding": "H3",
     "prev": "RESOLVIDO — strict_number(): bool NÃO é número; "
             "{'value': false} → 400 + evento strict_type_reject "
             "(reason=bool_is_not_a_number); export_limit intacto",
     "criterio": "400 no false E 400 no true E evento strict_type_reject "
                 "E export_limit intacto"},
    {"id": "P-R2-07", "finding": "H4",
     "prev": "RESOLVIDO — física deixa de ser cega: com export_limit=0 "
             "a telemetria reporta export_kw()==0.0 (nada exportado) "
             "com pv_gross_kw() intacto (kwp*IRRADIANCE_FACTOR)",
     "criterio": "200 no setpoint 0 E export_kw==0.0 E pv_gross_kw == "
                 "kwp*0.55 E pv_kw == pv_gross (curtail 0)"},
    {"id": "P-R2-08", "finding": "H5",
     "prev": "RESOLVIDO — a bateria INTEGRA em modo ilha: SoC desce a "
             "60.0 por 2 fatias remotas de 20%; durante 3s de ilha "
             "o surplus (pv_gross 1.76 > carga 1.2) CARREGA a bateria "
             "(SoC SOBE)",
     "criterio": "fatias descem a 60.0 E ilha 3s E soc_end > soc_start "
                 "E relé aberto"},
    {"id": "P-R2-09", "finding": "H6",
     "prev": "RESOLVIDO — os eventos do H6 alimentam regras: 5 logins "
             "errados → D-LOGIN-BRUTE-FORCE; 5 PINs errados → "
             "D-LOCAL-CONFIRM-BRUTE-FORCE; // crua → D-NON-CANONICAL-"
             "REQUEST. O scan do cenário dispara EXATAMENTE estas 3",
     "criterio": "as 3 regras presentes no scan do cenário (presença, "
                 "não o count: lockout+contagem duplicam o add)"},
    {"id": "P-R2-10", "finding": "H7",
     "prev": "CONFIRMADO-DECLARADO — H7 fica para a R2 por decisão do "
             "operador: (a) token sem TTL; (b) /login device sem "
             "lockout; (c) chunked ignorado no caminho DIRETO (o guard "
             "rejeita, o device não); (d) BLOCKED_IN_EMERGENCY morto; "
             "(e) banner SUNBOX/0.1 num lab v0.3",
     "criterio": "todos os 5 sub-achados confirmados (idêntico ao run "
                 "contra a v0.2)"},
]

# GATEFALL v0.5 — PRÉ-REGISTADO na entrada v0.5 do changelog, ANTES de
# qualquer corrida contra a v0.5 (hash 052688ee…): idêntico ao da v0.3/v0.4
# EXCETO P-R2-01, que passa a RESOLVIDO (a regra cumulativa da v0.5 fecha
# o C4).
GATEFALL_V05 = [dict(e) for e in GATEFALL_V03]
for e in GATEFALL_V05:
    if e["id"] == "P-R2-01":
        e["prev"] = ("RESOLVIDO — C4 FECHADO pela regra cumulativa da "
                     "v0.5: as 5 fatias de 15% continuam 200 e terminam "
                     "em 25.0, mas a soma 75% >= limiar 50% na janela "
                     "3600s dispara D-BATTERY-CUMULATIVE-DRAIN (WARN); "
                     "D-BATTERY-DRAIN-LARGE continua AUSENTE (fatia "
                     "única 15% < 50%; sem dupla-disparo)")
        e["criterio"] = ("todas 200 E soc final 25.0 E "
                         "D-BATTERY-CUMULATIVE-DRAIN PRESENTE no scan E "
                         "D-BATTERY-DRAIN-LARGE AUSENTE")

# GATEFALL v0.6 — PRÉ-REGISTADO na entrada v0.6 do changelog, ANTES de
# qualquer corrida contra a v0.6 (hash 698b8cff…): idêntico ao da
# v0.3/v0.4/v0.5 EXCETO P-R2-01, que passa a ser travado pelo LIMITE
# DIÁRIO (a cumulativa fica inatingível: o limite satura as fatias a
# 40%/dia antes de a soma por janela chegar a 50).
GATEFALL_V06 = [dict(e) for e in GATEFALL_V03]
for e in GATEFALL_V06:
    if e["id"] == "P-R2-01":
        e["prev"] = ("RESOLVIDO — C4 travado pelo LIMITE DIÁRIO da "
                    "v0.6: as 5 fatias de 15% executam as 2 primeiras "
                    "(200; SoC 100→70) e as fatias 3-5 dão 409 "
                    "remote_discharge_daily_limit (used 30+15 > 40; 3 "
                    "eventos remote_daily_limit_block); SoC final 70.0; "
                    "cumulativa e por-operação AUSENTES (o limite SATURA "
                    "o ataque antes de a janela de 1 h acumular 50%)")
        e["criterio"] = ("fatias 1-2: 200 E fatias 3-5: 409 daily E soc "
                         "final 70.0 E D-BATTERY-CUMULATIVE-DRAIN "
                         "AUSENTE E D-BATTERY-DRAIN-LARGE AUSENTE E 3 "
                         "eventos remote_daily_limit_block")
# GATEFALL v0.7 — PRÉ-REGISTADO na entrada v0.7 do changelog, ANTES de
# qualquer corrida contra a v0.7 (hash d3af0d28…): idêntico ao da v0.6
# EXCETO P-R2-10, cujo item (e) banner fica RESOLVIDO pelo F-LIMP (c)
# da v0.7 (SUNBOX/0.7 no device e no gate); (a)-(d) do H7 ficam
# DECLARADOS para a v0.8.
GATEFALL_V07 = [dict(e) for e in GATEFALL_V06]
for e in GATEFALL_V07:
    if e["id"] == "P-R2-10":
        e["prev"] = ("CONFIRMADO-DECLARADO — H7 fica para a v0.8 por "
                     "decisão do operador: (a) token sem TTL; (b) /login "
                     "device sem lockout; (c) chunked ignorado no caminho "
                     "DIRETO (o guard rejeita, o device não); (d) "
                     "BLOCKED_IN_EMERGENCY morto; (e) banner RESOLVIDO "
                     "na v0.7 (F-LIMP c: SUNBOX/0.7 no device e no gate)")
        e["criterio"] = ("(a)-(d) confirmados E (e) banner == "
                         "SUNBOX/<LAB_VERSION> (o resto declarado v0.8)")
# v0.8.1: critérios V071 = CÓPIA dos V06 (= V07), EXCETO P-R2-10
# cujo item (e) banner fica RESOLVIDO pelo F-LIMP (c) mantido na
# v0.7.1 (SUNBOX/0.7.1 no device e no gate); a D-BATTERY-DRAIN-TO-LOW
# (F-K1) fica AUSENTE nos cenários r2 (SoC 70/60 > 35; verificação
# registada na entrada v0.8.1 do changelog); (a)-(d) do H7 ficam
# DECLARADOS para a v0.8.
GATEFALL_V071 = [dict(e) for e in GATEFALL_V06]
for e in GATEFALL_V071:
    if e["id"] == "P-R2-10":
        e["prev"] = ("CONFIRMADO-DECLARADO — H7 fica para a v0.8 por "
                     "decisão do operador: (a) token sem TTL; (b) /login "
                     "device sem lockout; (c) chunked ignorado no caminho "
                     "DIRETO (o guard rejeita, o device não); (d) "
                     "BLOCKED_IN_EMERGENCY morto; (e) banner RESOLVIDO "
                     "na v0.7.1 (F-LIMP c mantém-se: SUNBOX/0.7.1 no "
                     "device e no gate)")
        e["criterio"] = ("(a)-(d) confirmados E (e) banner == "
                         "SUNBOX/<LAB_VERSION> (o resto declarado v0.8)")
GATEFALL_V072 = [dict(e) for e in GATEFALL_V071]
for e in GATEFALL_V072:
    if e["id"] == "P-R2-10":
        e["prev"] = ("CONFIRMADO-DECLARADO — H7 fica para a v0.8 por "
                     "decisão do operador: (a) token sem TTL; (b) /login "
                     "device sem lockout; (c) chunked ignorado no caminho "
                     "DIRETO (o guard rejeita, o device não); (d) "
                     "BLOCKED_IN_EMERGENCY morto; (e) banner RESOLVIDO "
                     "na v0.7.2 (F-LIMP c mantém-se: SUNBOX/0.7.2 no "
                     "device e no gate)")
        e["criterio"] = ("(a)-(d) confirmados E (e) banner == "
                         "SUNBOX/<LAB_VERSION> (o resto declarado v0.8)")
GATEFALL = (GATEFALL_V072 if TARGET == "v0.7.2"
            else GATEFALL_V071 if TARGET == "v0.7.1"
            else GATEFALL_V07 if TARGET == "v0.7"
            else GATEFALL_V06 if TARGET == "v0.6"
            else GATEFALL_V05 if TARGET == "v0.5"
            else GATEFALL_V03 if FIXED else GATEFALL_V02)

# veredicto previsto por ID (para o rótulo do expect() e o sumário)
VER = {e["id"]: e["prev"].split(" —")[0] for e in GATEFALL}

print("\nGATEFALL — PREVISÕES PRÉ-REGISTADAS (antes de qualquer execução)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))
print("DECISÃO DO OPERADOR 13-11: C4/C5/C6/H7 ficam para a ronda seguinte; "
      "H1/H2/H3 fecham na v0.3 (guard + canonicalizador partilhado); "
      "H4/H5 obrigatórios antes da v0.4 (measure).\n")

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


def raw_post(port, target, body, auth=None, chunked=False):
    req = b"POST " + target + b" HTTP/1.1\r\nHost: " + LOOPBACK.encode() + b"\r\n"
    if auth:
        req += b"Authorization: Bearer " + auth.encode() + b"\r\n"
    if chunked:
        req += b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        n = len(body)
        req += (b"%x\r\n" % n) + body + b"\r\n0\r\n\r\n"
    else:
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
    det = lab.detector

    # ================= P-R2-01 — C4: descarga fatiada =================
    print("[P-R2-01] C4 — descarga fatiada evade D-BATTERY-DRAIN-LARGE")
    lab.scenario("P-R2-01")
    reset_all(lab)
    dev = lab.devices[3]
    tok = dev.service_token
    slices_ok, socs = True, [dev.soc]
    st_slices = []
    for _ in range(5):   # 5 fatias de 15%: v0.6: 100→85→70, depois 409
        st, resp = hj(dev.port, "POST", "/battery",
                     {"action": "discharge",
                      "amount_kwh": round(0.15 * dev.batt_kwh, 3)}, token=tok)
        slices_ok = slices_ok and (st == 200)
        st_slices.append(st)
        socs.append(dev.soc)
    alerts = scan_scenario(lab, "P-R2-01")
    drain_large = [a for a in alerts if a["rule"] == "D-BATTERY-DRAIN-LARGE"]
    cumulative = [a for a in alerts
                  if a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"]
    daily_evs = [e for e in scenario_events(lab, "P-R2-01")
                 if e.get("event") == "remote_daily_limit_block"]
    # v0.1.1: 5 fatias de 15% a partir de 100 terminam em 25.0 (o critério
    # do run 1 dizia 30.0 — erro aritmético do PROBE). 25.0 == floor é o
    # boundary exato já declarado CONFORME no G7 (o check é '<' estrito).
    if TARGET in ("v0.6", "v0.7", "v0.7.1", "v0.7.2"):
        # v0.6/v0.7/v0.7.1/v0.7.2: o LIMITE DIÁRIO trava as fatias 3-5
        # (used 30+15 > 40; na v0.7.1 a DRAIN-TO-LOW fica AUSENTE:
        # SoC 70 > 35);
        # a cumulativa fica INATINGÍVEL (soma por janela satura em 30).
        cond = (st_slices[:2] == [200, 200]
                and st_slices[2:] == [409, 409, 409]
                and dev.soc == 70.0
                and not cumulative and not drain_large
                and len(daily_evs) == 3)
        expect("P-R2-01", GATEFALL[0]["prev"], cond,
               VER["P-R2-01"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias: estados %s; SoC: %s — as fatias 1-2 EXECUTAM "
                "(100→70) e as 3-5 dão 409 daily (used 30+15 > 40)"
                % (st_slices, socs),
                "alertas do cenário: %s — cumulativa AUSENTE (o limite "
                "satura o ataque a 30%% numa janela de 1 h, muito antes "
                "do limiar 50%%; superssenção datada no lab)"
                % [(a["rule"], a["count"]) for a in alerts],
                "eventos remote_daily_limit_block: %d (used_pct 30, "
                "requested 15, ×3) — PREVENÇÃO por bloqueio; a deteção "
                "é o próprio evento" % len(daily_evs),
                "D-BATTERY-DRAIN-LARGE: %s (fatia única 15%% < 50%% — "
                "ausente, sem dupla-disparo)" % drain_large,
                "C4 travado na v0.6 pelo limite diário: a evasão fatiada "
                "já não ESVAZIA a bateria (máx. 40%%/dia por "
                "remote_command; dano saturado, não eliminado)"])
    elif TARGET == "v0.5":
        # v0.5: a regra cumulativa fecha o C4 — as fatias continuam 200 e
        # o SoC termina em 25.0, mas a soma 75% >= 50% DISPARA a WARN.
        cond = (slices_ok and dev.soc == 25.0
                and cumulative and not drain_large)
        expect("P-R2-01", GATEFALL[0]["prev"], cond,
               VER["P-R2-01"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias 200=%s; SoC: %s (inalterado — o ataque ainda "
                "EXECUTA; o que muda é a VISIBILIDADE)"
                % (slices_ok, socs),
                "alertas do cenário: %s — D-BATTERY-CUMULATIVE-DRAIN "
                "flagra as 5 fatias (soma 75%% >= 50%% na janela 3600s)"
                % [(a["rule"], a["count"]) for a in alerts],
                "D-BATTERY-DRAIN-LARGE: %s (fatia única 15%% < 50%% — "
                "ausente, sem dupla-disparo)" % drain_large,
                "C4 FECHADO na v0.5: a descarga fatiada deixa de ser "
                "invisível (deteção ≠ prevenção — o OPTION-B mostra que "
                "alertar não evita o dano)"])
    else:
        cond = (slices_ok and dev.soc == 25.0 and not alerts)
        expect("P-R2-01", GATEFALL[0]["prev"], cond,
               VER["P-R2-01"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias 200=%s; SoC: %s" % (slices_ok, socs),
                "alertas do cenário: %s" %
                [(a["rule"], a["count"]) for a in alerts],
                "D-BATTERY-DRAIN-LARGE: %s" % drain_large])

    # ================= P-R2-02 — C5: PIN DoS ao dono ====================
    print("\n[P-R2-02] C5 — lockout do PIN = DoS à confirmação física")
    lab.scenario("P-R2-02")
    reset_all(lab)
    dev = lab.devices[4]
    denied = 0
    for _ in range(5):
        st, _ = hj(dev.port, "POST", "/local_confirm", {"pin": "WRONG"})
        denied += (st == 403)
    st_ok, resp_ok = hj(dev.port, "POST", "/local_confirm",
                        {"pin": dev.local_pin})
    evs = scenario_events(lab, "P-R2-02")
    lockout_ev = [e for e in evs if e.get("event") == "local_confirm_lockout"]
    cond = (denied == 5 and st_ok == 403
            and resp_ok.get("error") == "pin_locked" and lockout_ev)
    expect("P-R2-02", GATEFALL[1]["prev"], cond,
           VER["P-R2-02"],
           "PREVISÃO ERRADA (ver detalhe acima)",
           ["5x403=%d; PIN correto → %s %s" % (denied, st_ok, resp_ok),
            "local_confirm_lockout no audit: %d" % len(lockout_ev)])

    # ================= P-R2-03 — C6: login global DoS ===================
    print("\n[P-R2-03] C6 — lockout de login GLOBAL = DoS ao operador")
    lab.scenario("P-R2-03")
    reset_all(lab)
    denied = 0
    for _ in range(5):
        st, _ = hj(L.PORT_GATE, "POST", "/fleet/login",
                   {"user": "attacker", "pass": "guess"})
        denied += (st == 401)
    st_ok, resp_ok = hj(L.PORT_GATE, "POST", "/fleet/login",
                        {"user": L.DEFAULT_USER, "pass": L.DEFAULT_PASS})
    cond = (denied == 5 and st_ok == 429
            and resp_ok.get("error") == "login_rate_blocked")
    expect("P-R2-03", GATEFALL[2]["prev"], cond,
           VER["P-R2-03"],
           "PREVISÃO ERRADA (ver detalhe acima)",
           ["5x401=%d; login CORRETO → %s %s" % (denied, st_ok, resp_ok)])

    # ================= P-R2-04 — H1: fail-open não-ASCII ================
    print("\n[P-R2-04] H1 — byte não-ASCII: _canonical_path fail-open")
    lab.scenario("P-R2-04")
    reset_all(lab)
    dev = lab.devices[5]
    status, headers, body = raw_post(
        dev.port, b"/mode\xff",
        b'{"action":"grid_reconnect"}', auth=dev.service_token)
    noncanon = [e for e in scenario_events(lab, "P-R2-04")
                if e.get("event") == "non_canonical_request"]
    if FIXED:
        # v0.3: fail-CLOSED — rejeitado ANTES do routing com auditoria.
        reasons = sorted({e.get("reason") for e in noncanon})
        cond = ("400" in status and bool(noncanon)
                and reasons == ["non_ascii"])
        expect("P-R2-04", GATEFALL[3]["prev"], cond,
               VER["P-R2-04"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["status: %s" % status,
                "non_canonical_request: %d, reasons=%s (fail-closed: "
                "rejeitado com auditoria ANTES do routing)"
                % (len(noncanon), reasons),
                "o except fail-open da v0.2 está morto por construção"])
    else:
        # v0.2: fail-open — o check devolveu True (aceitou), o pedido
        # chegou ao routing (404) SEM auditoria de não-canónico.
        cond = ("404" in status and not noncanon)
        expect("P-R2-04", GATEFALL[3]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["status: %s" % status,
                "eventos non_canonical_request: %d (fail-open: check "
                "aceitou sem auditar)" % len(noncanon)])

    # ================= P-R2-05 — H2: query string roteia =================
    print("\n[P-R2-05] H2 — query string cruza a canonicalização")
    lab.scenario("P-R2-05")
    reset_all(lab)
    dev = lab.devices[6]
    st, resp = hj(dev.port, "POST", "/setpoint?x=1", {"value": 50.0},
                  token=dev.service_token)
    pc = [e for e in scenario_events(lab, "P-R2-05")
          if e.get("event") == "param_change"]
    if FIXED:
        reasons = sorted({e.get("reason") for e in scenario_events(
            lab, "P-R2-05") if e.get("event") == "non_canonical_request"})
        cond = (st == 400 and dev.export_limit == 100.0
                and reasons == ["query_or_fragment"] and not pc)
        expect("P-R2-05", GATEFALL[4]["prev"], cond,
               VER["P-R2-05"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["POST /setpoint?x=1 → %s %s; export_limit=%s (intacto)"
                % (st, resp, dev.export_limit),
                "non_canonical_request reasons=%s; param_change=%d "
                "(nada roteou)" % (reasons, len(pc))])
    else:
        cond = (st == 200 and dev.export_limit == 50.0 and pc)
        expect("P-R2-05", GATEFALL[4]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["POST /setpoint?x=1 → %s %s; export_limit=%s"
                % (st, resp, dev.export_limit),
                "param_change no audit: %d" % len(pc),
                "consequência M3: regra por URI exato '/setpoint' não vê "
                "'/setpoint?x=1'"])

    # ================= P-R2-06 — H3: booleano como número ===============
    print("\n[P-R2-06] H3 — booleano aceite como número (bool != número)")
    lab.scenario("P-R2-06")
    reset_all(lab)
    dev = lab.devices[7]
    st, resp = hj(dev.port, "POST", "/setpoint", {"value": False},
                  token=dev.service_token)
    st2, resp2 = hj(dev.port, "POST", "/setpoint", {"value": True},
                    token=dev.service_token)
    if FIXED:
        strict = [e for e in scenario_events(lab, "P-R2-06")
                  if e.get("event") == "strict_type_reject"]
        reasons = sorted({e.get("reason") for e in strict})
        cond = (st == 400 and st2 == 400
                and dev.export_limit == 100.0
                and len(strict) == 2
                and reasons == ["bool_is_not_a_number"])
        expect("P-R2-06", GATEFALL[5]["prev"], cond,
               VER["P-R2-06"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["value=false → %s; value=true → %s; export_limit=%s "
                "(intacto)" % (st, st2, dev.export_limit),
                "strict_type_reject: %d, reasons=%s (bool NÃO é número)"
                % (len(strict), reasons)])
    else:
        cond = (st == 200 and dev.export_limit == 1.0 and st2 == 200)
        expect("P-R2-06", GATEFALL[5]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["value=false → %s export_limit=%s"
                % (st, resp.get("export_limit")),
                "value=true  → %s export_limit=%s"
                % (st2, resp2.get("export_limit")),
                "float(False)==0.0 em Python: bool é subclasse de int — a "
                "verificação de tipo estrito não existe"])

    # ================= P-R2-07 — H4: pv_kw ignora curtail ================
    print("\n[P-R2-07] H4 — pv_kw() ignora export_limit/curtail_pct")
    lab.scenario("P-R2-07")
    reset_all(lab)
    dev = lab.devices[8]
    pv_before = dev.pv_kw()
    st, resp = hj(dev.port, "POST", "/setpoint", {"value": 0.0},
                  token=dev.service_token)
    pv_after = dev.pv_kw()
    expected_pv = round(dev.kwp * L.IRRADIANCE_FACTOR, 2)
    if FIXED:
        gross = dev.pv_gross_kw()
        export = dev.export_kw()
        cond = (st == 200 and dev.export_limit == 0.0
               and export == 0.0 and gross == expected_pv
               and pv_after == expected_pv)
        expect("P-R2-07", GATEFALL[6]["prev"], cond,
               VER["P-R2-07"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["export_limit=0 → export_kw=%s (NADA exportado), "
                "pv_gross_kw=%s, pv_kw=%s (física deixa de ser cega)"
                % (export, gross, pv_after),
                "curtail_pct=%s (0 → pv_kw == pv_gross)" % dev.curtail_pct,
                "é isto que a divergência de capacidade (D-CAPACITY-"
                "DIVERGENCE) mede — pré-requisito do measure v0.4"])
    else:
        cond = (st == 200 and pv_after == pv_before == expected_pv
                and dev.export_limit == 0.0)
        expect("P-R2-07", GATEFALL[6]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["pv antes=%s depois de export_limit=0: %s (esperado cego: %s)"
                % (pv_before, pv_after, expected_pv),
                "ESTÁTICO+EXEC: pv_kw() = kwp*IRR se inverter_on; curtail_pct "
                "e export_limit não entram — física cega para o measure v0.4"])

    # ================= P-R2-09 — H6: eventos órfãos ====================
    # (antes do P-R2-10 para não herdar o lockout do PIN deste)
    print("\n[P-R2-09] H6 — eventos novos órfãos de regra no Detector")
    lab.scenario("P-R2-09")
    reset_all(lab)
    dev = lab.devices[9]
    if FIXED:
        # v0.3: tráfego DELIBERADO até aos limiares (5/5/1) — os eventos
        # do H6 agora ALIMENTAM regras; critério = as 3 regras no scan.
        for _ in range(5):
            hj(L.PORT_GATE, "POST", "/fleet/login",
               {"user": "x", "pass": "y"})
        for _ in range(5):
            hj(dev.port, "POST", "/local_confirm", {"pin": "WRONG"})
        raw_post(dev.port, b"//setpoint", b'{"value": 50.0}',
                 auth=dev.service_token)
        alerts = scan_scenario(lab, "P-R2-09")
        rules = {a["rule"]: a["count"] for a in alerts}
        expected_rules = {"D-LOGIN-BRUTE-FORCE",
                          "D-LOCAL-CONFIRM-BRUTE-FORCE",
                          "D-NON-CANONICAL-REQUEST"}
        cond = (set(rules) == expected_rules)
        expect("P-R2-09", GATEFALL[8]["prev"], cond,
               VER["P-R2-09"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["regras disparadas: %s (esperado: as 3 do H6)"
                % sorted(rules.items()),
                "count pode ser 2 (evento de lockout + bloco de "
                "contagem duplicam o add) — o critério é a PRESENÇA",
                "RULE_ATTACK_MAP: %d regras na v0.3" % len(L.RULE_ATTACK_MAP)])
    else:
        # v0.2: login_fail real (1 falha basta para o evento)
        hj(L.PORT_GATE, "POST", "/fleet/login", {"user": "x", "pass": "y"})
        # local_confirm_denied + local_confirm_lockout reais
        for _ in range(5):
            hj(dev.port, "POST", "/local_confirm", {"pin": "WRONG"})
        # non_canonical_request real (linha crua com //)
        raw_post(dev.port, b"//setpoint", b'{"value": 50.0}',
                 auth=dev.service_token)
        evs = scenario_events(lab, "P-R2-09")
        orphan_events = [e.get("event") for e in evs
                         if e.get("event") in ("login_fail",
                                               "local_confirm_denied",
                                               "local_confirm_lockout",
                                               "non_canonical_request")]
        alerts = scan_scenario(lab, "P-R2-09")
        # órfãos = os eventos existem mas o scan do cenário não dispara nada
        # causado por eles (o único alerta possível seria por regra inexistente)
        orphan_alerts = [a for a in alerts]
        cond = (len(orphan_events) >= 7 and not orphan_alerts)
        expect("P-R2-09", GATEFALL[8]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["eventos órfãos gerados: %s" % sorted(set(orphan_events)),
                "alertas no cenário: %s" %
                [(a["rule"], a["count"]) for a in alerts],
                "RULE_ATTACK_MAP: %d regras; nenhuma cobre estes eventos "
                "(leitura estática confirmada)" % len(L.RULE_ATTACK_MAP)])

    # ================= P-R2-10 — H7: misc ================================
    print("\n[P-R2-10] H7 — misc (TTL token, /login device, chunked, "
          "código morto, banner)")
    lab.scenario("P-R2-10")
    reset_all(lab)
    sub = []
    # (a) token de local_confirm sem TTL (emissão ok; ausência de campo de
    #     expiração é leitura ESTÁTICA: o token vive até uso ou harness_reset)
    dev = lab.devices[10]
    st, resp = hj(dev.port, "POST", "/local_confirm", {"pin": dev.local_pin})
    src = open(L.__file__, encoding="utf-8").read()
    ttl_in_src = "confirm_token_expiry" in src or "confirm_expires" in src
    sub.append(("a", st == 200 and not ttl_in_src,
                "token emitido (200=%s), sem qualquer campo/controle de "
                "expiração no lab (TTL inexistente)" % (st == 200)))
    # (b) /login do device SEM lockout: 10 logins errados → 401 sem evento
    denied = 0
    for _ in range(10):
        st, _ = hj(dev.port, "POST", "/login", {"token": "WRONG"})
        denied += (st == 401)
    login_ev = [e for e in scenario_events(lab, "P-R2-10")
                if e.get("event") in ("login_fail", "login_rate_blocked")]
    sub.append(("b", denied == 10 and not login_ev,
                "10 logins errados → 10x401=%d, SEM lockout e SEM evento "
                "de auditoria (o gate audita; o device não)" % denied))
    # (c) chunked ignorado: body válido em Transfer-Encoding: chunked →
    #     processado como corpo vazio (Content-Length ausente → n=0)
    dev2 = lab.devices[11]
    before = dev2.export_limit
    status, headers, body = raw_post(
        dev2.port, b"/setpoint", b'{"value": 10.0}',
        auth=dev2.service_token, chunked=True)
    sub.append(("c", dev2.export_limit == before and "400" in status,
                "chunked → %s; export_limit intacto (%s): o corpo foi "
                "IGNORADO (sem Content-Length, lê 0 bytes)"
                % (status.split(" ")[1] if " " in status else status,
                   dev2.export_limit)))
    # (d) BLOCKED_IN_EMERGENCY morto: definida e nunca referenciada
    uses = src.count("BLOCKED_IN_EMERGENCY")
    sub.append(("d", uses == 1,
                "BLOCKED_IN_EMERGENCY aparece %d vez(es) no lab: só a "
                "definição — lista negra morta do pré-G2, nunca consultada"
                % uses))
    # (e) banner: Server header do device vs LAB_VERSION
    #     v0.1.1: o BaseHTTPRequestHandler acrescenta a versão do Python ao
    #     server_version — comparar por PREFIXO SUNBOX/<lab>, não igualdade.
    status, headers, body = raw_post(dev2.port, b"/nonexistent", b"{}")
    banner = headers.get("server", "")
    expected_banner = "SUNBOX/%s" % L.LAB_VERSION
    if TARGET in ("v0.7", "v0.7.1", "v0.7.2"):
        # v0.7/v0.7.1/v0.7.2 (F-LIMP c): o banner ACOMPANHA o LAB_VERSION
        # (SUNBOX/0.7, SUNBOX/0.7.1) no device E no gate — o item (e)
        # do H7 fica RESOLVIDO; (a)-(d) ficam DECLARADOS para a v0.8.
        sub.append(("e", banner.startswith(expected_banner),
                    "banner 'Server: %s' == esperado '%s' — o "
                    "server_version ACOMPANHOU o LAB_VERSION (item (e) "
                    "do H7 RESOLVIDO; (a)-(d) ficam para a v0.8)"
                    % (banner, expected_banner)))
    else:
        sub.append(("e", banner.startswith("SUNBOX/0.1")
                    and not banner.startswith(expected_banner),
                    "banner 'Server: %s' num lab v%s — server_version "
                    "nunca acompanhou LAB_VERSION (esperado se "
                    "corrigido: '%s')"
                    % (banner, L.LAB_VERSION, expected_banner)))
    ok_all = all(c for _, c, _ in sub)
    expect("P-R2-10", GATEFALL[9]["prev"], ok_all,
           VER["P-R2-10"],
           "PREVISÃO ERRADA (ver detalhe acima)",
           ["(%s) %s — %s" % (k, "OK" if c else "FALHOU", d)
            for k, c, d in sub])

    # ================= P-R2-08 — H5: bateria congelada em ilha ===========
    # ÚLTIMO: muda o estado da rede (BLACKOUT → latch/anti-islanding).
    print("\n[P-R2-08] H5 — bateria não se gasta em modo ilha")
    lab.scenario("P-R2-08")
    reset_all(lab)
    if FIXED:
        # v0.3: a bateria INTEGRA — é preciso SoC < 100 ANTES da ilha
        # (o v0.2 media o SoC congelado a 100; a v0.3 carrega no surplus).
        # v0.3.1 (run 3): soc medido LOGO APÓS as fatias (o relé abre já
        # no EMERG e a integração começa aí — soc_start pós-EMERG nunca
        # é 60.0); taxa medida vs teórica como evidência de magnitude.
        dev10 = lab.devices[10]
        slices_ok, socs = True, [dev10.soc]
        for _ in range(2):   # 2 fatias remotas de 20%: 100→80→60
            st, resp = hj(dev10.port, "POST", "/battery",
                          {"action": "discharge",
                           "amount_kwh": round(0.2 * dev10.batt_kwh, 3)},
                          token=dev10.service_token)
            slices_ok = slices_ok and (st == 200)
            socs.append(dev10.soc)
        soc_apos_fatias = dev10.soc
        lab.gridsim.set_state("EMERGENCY")   # latch + relé abre (V<195)
        time.sleep(0.5)
        lab.gridsim.set_state("BLACKOUT")
        soc_start = dev10.soc
        island_s = 3.0
        time.sleep(island_s)
        soc_end = dev10.soc
        gross = dev10.pv_gross_kw()
        lab.gridsim.set_state("NORMAL")
        # taxa teórica (física correta pós-errata): (pv-load)/3600/batt*100
        rate_teor = (gross - L.LOAD_LOCAL_KW) / 3600.0 \
            / dev10.batt_kwh * 100.0
        rate_obs = (soc_end - soc_start) / island_s
        cond = (slices_ok and soc_apos_fatias == 60.0
                and soc_end > soc_apos_fatias
                and not dev10.relay_closed)
        expect("P-R2-08", GATEFALL[7]["prev"], cond,
               VER["P-R2-08"],
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["fatias remotas: 200=%s; SoC: %s" % (slices_ok, socs),
                "ilha: soc_start(blackout)=%s → soc_end=%s (%.1fs); "
                "taxa observada ~%.4f pontos/s vs teórica ~%.4f (pós-"
                "errata: kW*s/3600 — o run 3 apanhou a 3600x)"
                % (soc_start, soc_end, island_s, rate_obs, rate_teor),
                "relay_closed=%s (ilha ativa); pv_gross=%s > carga=%s; "
                "SoC acima de 60 = surplus CARREGOU (integração ATIVA)"
                % (dev10.relay_closed, gross, L.LOAD_LOCAL_KW),
                "pré-requisito do measure v0.4 cumprido (H5 fechado)"])
    else:
        lab.gridsim.set_state("EMERGENCY")   # latch + relé abre (V<195)
        time.sleep(0.5)
        lab.gridsim.set_state("BLACKOUT")
        soc_start = lab.devices[10].soc
        sc_start = lab.devices[10].self_consumption_kw()
        island_s = 3.0
        time.sleep(island_s)
        dev10 = lab.devices[10]
        soc_end = dev10.soc
        lab.gridsim.set_state("NORMAL")
        cond = (soc_end == soc_start == 100.0
                and not dev10.relay_closed and sc_start >= 0)
        expect("P-R2-08", GATEFALL[7]["prev"], cond,
               "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)",
               ["ilha %.1fs: SoC %s → %s (CONGELADO); self_consumption=%s "
                "kW servida sem qualquer integração de energia"
                % (island_s, soc_start, soc_end, sc_start),
                "relay_closed=%s (ilha ativa)" % dev10.relay_closed,
                "ESTÁTICO+EXEC: sem modelo temporal de bateria em modo ilha — "
                "a métrica do measure v0.4 seria falsa"])

    # ---------------------------------------------------------------------
    # SUMÁRIO — previsão vs observado (GATEFALL fechado)
    # v0.1.1: alinhamento por ID (o P-R2-08 corre em último por mudar o
    # estado da rede — o zip posicional do run 1 trocou os veredictos).
    # ---------------------------------------------------------------------
    by_id = {v["id"]: v for v in VEREDICTOS}
    print("\n" + "=" * 72)
    print("SUMÁRIO GATEFALL — previsão PRÉ-registada vs veredicto OBSERVADO")
    print("=" * 72)
    prev_erradas = 0
    matches = 0
    for entry in GATEFALL:
        v = by_id.get(entry["id"], {"veredicto": "NÃO EXECUTADO"})
        previsto = VER[entry["id"]]
        match = (v["veredicto"] == previsto)
        if not match:
            prev_erradas += 1
        else:
            matches += 1
        print("  [%s/%s] previsto: %s | observado: %s"
              % (entry["id"], entry["finding"], previsto, v["veredicto"]))
    print("-" * 72)
    if FIXED:
        resolv = sum(1 for e in GATEFALL if VER[e["id"]] == "RESOLVIDO"
                     and by_id.get(e["id"], {}).get("veredicto") == "RESOLVIDO")
        decl = sum(1 for e in GATEFALL
                   if VER[e["id"]] == "CONFIRMADO-DECLARADO"
                   and by_id.get(e["id"], {}).get("veredicto")
                   == "CONFIRMADO-DECLARADO")
        if TARGET == "v0.3":
            print("RESOLVIDOS (depois vs antes, contra a v0.3): %d/6" % resolv)
        elif TARGET == "v0.4":
            print("RESOLVIDOS (NAO-REGRESSAO: os fixes R2 mantem-se na "
                  "v0.4): %d/6" % resolv)
        elif TARGET == "v0.5":
            print("RESOLVIDOS (NAO-REGRESSAO na v0.5 + C4 FECHADO pela "
                  "regra cumulativa): %d/7" % resolv)
        elif TARGET == "v0.6":
            print("RESOLVIDOS (NAO-REGRESSAO na v0.6 + C4 TRAVADO pelo "
                  "limite diario 40%%/24 h): %d/7" % resolv)
        elif TARGET == "v0.7.1":
            print("RESOLVIDOS (NAO-REGRESSAO na v0.7.1 RESTAURADA, "
                  "recuperacao pos-INFRA-2026-13-11-B: C4 TRAVADO "
                  "mantem-se; F-C13/F-K1/F-C14/F-SP/banner nao reabrem "
                  "nenhum fix R2): %d/7" % resolv)
        else:
            print("RESOLVIDOS (NAO-REGRESSAO na v0.7: C4 TRAVADO "
                  "mantem-se; F-C12/F-K1/banner nao reabrem nenhum fix "
                  "R2): %d/7" % resolv)
        if TARGET in ("v0.5", "v0.6"):
            print("CONFIRMADOS-DECLARADOS (C5/C6/H7 ficam para a ronda "
                  "seguinte por decisão do operador): %d/3" % decl)
        elif TARGET in ("v0.7", "v0.7.1", "v0.7.2"):
            print("CONFIRMADOS-DECLARADOS (C5/C6 ficam para a ronda "
                  "seguinte; H7 (a)-(d) ficam para a v0.8 — o item (e) "
                  "banner ficou RESOLVIDO): %d/3" % decl)
        else:
            print("CONFIRMADOS-DECLARADOS (C4/C5/C6/H7 ficam para a ronda "
                  "seguinte por decisão do operador): %d/4" % decl)
    else:
        print("CONFIRMADOS (vermelho do ANTES contra a v0.2): %d/%d"
              % (matches, len(GATEFALL)))
    print("PREVISÕES ERRADAS: %d" % prev_erradas)
    print("LAB ALVO: %s, hash %s (verificado no arranque)"
          % (L.LAB_VERSION, lab_sha))
    if TARGET == "v0.2":
        print("DECISÃO DO OPERADOR 13-11: v0.3 fecha H1/H2/H3 (guard proxy + "
              "canonicalizador partilhado, fail-closed, tipos estritos) + "
              "cenários H3/H4/H5/H4-BLACKOUT + 4 regras novas + regras para "
              "os eventos do H6. C4/C5/C6/H7 ficam para a ronda seguinte.")
    elif TARGET == "v0.3":
        print("DECISÃO DO OPERADOR 13-11: R2 vs v0.3 = evidência do "
              "DEPOIS; C4/C5/C6/H7 ficam para a ronda seguinte; H4/H5 "
              "(física) são OBRIGATÓRIOS antes da v0.4 (measure).")
    elif TARGET == "v0.4":
        print("DECISÃO DO OPERADOR 13-11: v0.4 = C7/I1/C8/I4/I5 + measure "
              "contrafactual de dois braços (pré-requisitos da métrica "
              "principal). Esta corrida R2 é a NÃO-REGRESSÃO dos fixes "
              "da R2. C4/C5/C6/C9/H7/I2/I3/I6 ficam para a ronda "
              "seguinte.")
    elif TARGET == "v0.5":
        print("DECISÃO DO OPERADOR 13-11: v0.5 = floor opção A "
              "(ISLAND_MIN_SOC) + measure com dois atacantes + linha "
              "OPTION-B + regra cumulativa (C4). Esta corrida R2 é a "
              "NÃO-REGRESSÃO dos fixes R2 na v0.5 E a evidência do C4 "
              "FECHADO. C5/C6/C9/H7/I2/I3/I6 ficam para a ronda "
              "seguinte.")
    elif TARGET == "v0.7.1":
        print("DECISÃO DO OPERADOR 13-11 ~17:00 (via supervisor): "
              "v0.7.1 = F-C13 (work-order validada no device contra a "
              "MESMA lista do gate + evento work_order_invalid + WARN "
              "D-INVALID-WORK-ORDER) + F-K1 (D-BATTERY-DRAIN-TO-LOW: SoC "
              "RESULTANTE <= 35, SUBSTITUI a MULTIDAY) + F-C14 (WARN "
              "D-REMOTE-SHUTDOWN-NO-WO por shutdown remoto s/WO válida) "
              "+ F-SP (/setpoint aceita work_order; COM WO válida NÃO "
              "arma a CAPACITY) + banner SUNBOX/0.7.1. Esta corrida R2 "
              "é a NÃO-REGRESSÃO dos fixes R2 na v0.7.1 RESTAURADA "
              "(reconstrução pós-INFRA-2026-13-11-B): o C4 TRAVADO "
              "mantém-se, o item (e) do H7 ficou RESOLVIDO e as regras "
              "novas ficam CALADAS nos cenários r2. C5/C6 ficam para "
              "a v0.8; H7 (a)-(d) para a v0.8.")
    elif TARGET == "v0.7":
        print("DECISÃO DO OPERADOR 13-11 15:30: v0.7 = F-C12 (capacity "
              "divergence: esperado independente de inverter_on + armar "
              "por remote_shutdown_change + snapshot pós shutdown/"
              "resume) + F-K1 (regra 21.ª D-BATTERY-MULTIDAY-DRAIN) + "
              "F-LIMP (banner SUNBOX/0.7 no device e no gate). Esta "
              "corrida R2 é a NÃO-REGRESSÃO dos fixes R2 na v0.7: o C4 "
              "TRAVADO mantém-se (fatias 3-5 → 409 daily) e o item (e) "
              "do H7 ficou RESOLVIDO. C5/C6 ficam para a ronda "
              "seguinte; H7 (a)-(d) para a v0.8.")
    else:
        print("DECISÃO DO OPERADOR 13-11 13:23: v0.6 = limite diário de "
              "descarga remota 40%/24 h (opção 1) + recarga grid-tied "
              "(J4) + telemetria soc_limits (J5) + measure em curva com "
              "minutos (J1/J2) + atacante (c) 2 dias. Esta corrida R2 é "
              "a NÃO-REGRESSÃO dos fixes R2 na v0.6 E a evidência do C4 "
              "TRAVADO pelo limite diário (as fatias 3-5 dão 409 daily; "
              "a cumulativa fica superssenda). C5/C6/C9/H7/I2/I3/I6/"
              "C11/J3 ficam para a ronda seguinte.")
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

# EOF:sunstrike_probes_r2.py
