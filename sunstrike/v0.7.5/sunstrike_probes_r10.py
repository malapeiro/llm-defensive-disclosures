#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SUNSTRIKE probes R10 — 11.ª bateria adversarial (ronda v0.7.4, GO 14-11).
Caso 4 do repo malapeiro/llm-defensive-disclosures (PVTE family).
Grant GRANT-PVTE-20261112-SS-01 (loopback only, Python 3.9+ stdlib).

Alvo desta versão (v0.1): sunstrike_lab.py v0.7.3 INTOCADA
(de7f5766…, o ANTES — GATEFALL OFICIAL = RUN 1, sempre, mesmo com
defeito do probe; precedentes R3, R5, R8, R9). As previsões V073
foram pré-registadas NESTE FICHEIRO ANTES de qualquer corrida contra
a v0.7.3 (o probe recusa qualquer outro hash por construção: nenhuma
previsão pode ser afinada à luz de um run).

BATERIA R10 (GO do operador 14-11 ~08:45, §3 + §5 — achados
verificados por execução pelo supervisor contra a v0.7.3; a 8.ª
auditoria Gemini (F-*) reproduzida por execução no run 1):
  AUD-03  arredondamento SoC vs. ledger (SÉRIO)      — R10-03a/b/c
  AUD-04  token de broker via /login (SÉRIO)          — R10-04a/b
  G5      banda presa na capacity (SÉRIO p/ H3)       — R10-G5/G5b/G5c
  AUD-08  wave/slow contam eventos, não dispositivos  — R10-08
  AUD-10  device:true no /fleet/firmware; JSON malfor-
          mado sem evento; contadores sem reposição   — R10-10a/b/c
  F-04a   curtailment em massa COM WO espaçado        — R10-F04a(+CTRL)
  P1..P4  bateria "estacionada" (regra nova)          — R10-P1..P4
  F-09c   assinatura de firmware sem chave (HMAC)     — R10-F09c
  F-05b   FP manutenção 1-a-1 (massa)                 — R10-F05b(+CTRL)
  F-05d   amount_kwh=0 → CRITs de descarga             — R10-F05d
  F-05a   setpoint s/WO + BLACKOUT → CRIT capacity    — R10-F05a
  F-07a   work_order lista/dict → TypeError           — R10-F07a
  F-08a   Content-Length −1 fura o GUARD_BODY_MAX     — R10-F08a
  F-08b   guard_reject não-canónico invisível; JSON
          lido antes da verificação canónica          — R10-F08b
  F-08c   check+consume de WO separados (SUSPEITA POR
          LEITURA — GO: não reproduz sem atraso)      — R10-F08c
  F-06b   login_ok não repõe login_fails no gate      — R10-F06b
  TEXT    22,9→16,10 (6 sítios); cabeçalho v0.7.2;
          "12 regras"                                — R10-TEXT

REGRA DE PARAGEM PRÉ-REGISTADA (GO §5, bateria estacionada): se o
R10-P3 ou o R10-P4 derem alerta na v0.7.4, NÃO há terceira
tentativa: o achado fica declarado com os números (0/12 vs 10/12) e
a tentativa falhada fica registada.

CHANGEDLOG
  v0.2.1 (14-11-2026, ERRATA DE CONSTRUCAO datada — E-R10-2; run 2
      PRESERVADO em sunstrike_probes_v074_r10_run2.txt: CRASH no
      P-R10-03b por TypeError de format string com args insuficientes
      — ramo IS_V074 nunca executado no run 1/1-bis (só o ramo V073
      correu); NENHUMA previsão muda — precedente E-R10-1; o run 2-bis
      com ESTE probe é o RUN 2 OFICIAL SUBSTITUTO, precedente run
      1-bis R8): UM defeito de construção do probe, corrigido
      mecanicamente: (1) a linha "pedidos: 400 below_resolution ×%d
      em %.1f s" formatava com um só argumento (faltava dur); (2) a
      linha "quota intacta: drain de 40% depois → %s" tinha o
      literal "40%" NÃO escapado — o Python lê "% d" como especificador
      (crash no run 2-bis, PRESERVADO em
      sunstrike_probes_v074_r10_run2b.txt). Varrido o ficheiro inteiro
      por AST por outros desequilíbrios de format string: ZERO
      adicionais (os %% restantes são escapes válidos).
  v0.2 (14-11-2026, entrada datada ANTES do run 2): hash da v0.7.4
      SELADA registado em EXPECTED_LAB_SHA256_V074 (31237bfa…) —
      lab v0.7.4 com selftest PASS (liveness 26/26), demo PASS 9/9 e
      measure PASS 51/51 ANTES do run 2. NENHUMA previsao
      pré-registada muda; o probe passa a aceitar a v0.7.3 (run 1/1-bis,
      já executados e preservados) E a v0.7.4 (run 2).
  v0.1.1 (14-11-2026, ERRATA DE CONSTRUÇÃO datada — E-R10-1; run 1
      PRESERVADO em sunstrike_probes_v073_r10_run1.txt: CRASH no
      P-R10-F07a + 4 previsões ERRADAS registadas; NENHUMA previsão
      muda — precedente E-R8-1/E-R9-1; o run 1-bis com ESTE probe é o
      GATEFALL OFICIAL SUBSTITUTO, precedente run 1-bis R8): QUATRO
      defeitos de construção do probe, corrigidos mecanicamente:
      (1) hj() não apanhava a conexão morta pelo handler que CRASHA
      (TypeError do F-07a) — http.client.RemoteDisconnected não é
      URLError; o probe morria em vez de REGISTAR o crash como
      evidência (P-R10-F07a..P-R10-TEXT NÃO executados no run 1).
      (2) P-R10-G5: pacing — o snapshot da transição de banda da fase
      WO era carimbado pelo loop de 0,25 s DEPOIS dos param_change
      s/WO (corrida de wall-clock, não física); pausa de 0,5 s após a
      fase WO para a transição ser publicada ANTES do arming (a
      medição do GO: ZERO alertas). (3) P-R10-10b: o critério contava
      os eventos harness_reset do PRÓPRIO reset_all do probe como
      'eventos de auditoria' — filtrados (a substância — ZERO eventos
      da recusa — já estava evidenciada no run 1). (4) P-R10-10c: a
      sequência 3×MNT3 esgotava a WO (4 usos) ANTES do rate limit (o
      check da WO vem primeiro no bulk_shutdown) — sequência
      MNT3+MNT1+MNT2 chega ao rate COM WO válida. REGISTADO do run 1
      (NUNCA ajustado para bater): P-R10-08 previsão ERRADA por erro
      de ANÁLISE do builder — a WAVE para no 6.º evento (count 6, não
      8; a substância confirmou: CRIT com 1 só inversor); P-R10-G5 e
      P-R10-10c ERRADAS no run 1 por defeitos (2)/(4) acima; a
      previsão do P-R10-08 MANTÉM-SE errada de propósito (método: o
      probe não se ajusta para bater).
  v0.1 (14-11-2026, GO v0.7.4 ~08:45, via supervisor): bateria
      ORIGINAL da ronda. Alvo ÚNICO V073 (de7f5766…). As previsões
      V074 (fix) são pré-registadas NESTE ficheiro JÁ AGORA (derivam
      do GO — fixes §3/§5 —, NÃO de qualquer run); o hash da v0.7.4
      é preenchido na entrada v0.2, ANTES do run 2 (precedente R9:
      o probe só corre contra hashes conhecidos e congelados).
"""

import hashlib
import json
import os
import socket
import sys
import threading
import time
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

LOOPBACK = "127.0.0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
LAB_PATH = os.path.join(HERE, "sunstrike_lab.py")
with open(LAB_PATH, "rb") as f:
    LAB_BYTES = f.read()
lab_sha = hashlib.sha256(LAB_BYTES).hexdigest()

EXPECTED_LAB_SHA256_V073 = ("de7f5766321299cd2fd8b7d98e7c73e1e2439c9df"
                            "d72ca7eb7f659c59750e301")
# v0.2 (14-11-2026, preenchido ANTES do run 2 contra a v0.7.4 SELADA,
# precedente R9: o hash da v0.7.4 fica registado aqui depois de
# selftest/demo/measure PASS e ANTES de qualquer run 2; NENHUMA
# previsao muda com esta entrada):
# v0.2.2 (14-11-2026, E-R10-3 — errata do LAB datada, ANTES do run 2-d):
# o run 2-c (PRESERVADO em sunstrike_probes_v074_r10_run2c.txt, 28/29)
# registou P-R10-F04a PREVISÃO ERRADA: o lab reportava os agregados da
# PRIMEIRA janela que cruza 30% de kWp (4 distintos) em vez dos
# agregados da MELHOR janela SLOW_WINDOW exigidos pela previsão
# pré-registada (12 distintos, 100%). O GATILHO não muda (qualquer
# janela SLOW_WINDOW com >= k distintos OU >= 30% kWp); muda o RELATÓRIO
# do alerta (melhor janela). NENHUMA previsão muda; o lab re-selado
# (selftest PASS 26/26, demo PASS 9/9, measure PASS 51/51) tem o hash
# abaixo; o hash 31237bfa… do run 2/2-b/2-c fica REGISTADO na entrada
# v0.2 acima (nunca apagado).
EXPECTED_LAB_SHA256_V074 = ("c039ab6174e309ddfd4158f6a865abda22471518"
                            "a6f2119358a772b1069c62c1")
# v0.7.5 (14-11-2026, GO a v0.7.5, ronda R11): alvo NOVO V075 —
# previsoes V075 = copia datada da V074 (analise do operador: os
# fixes R11 de LOGICA nao alteram NENHUM cenario R10 — F-01: os
# estados de OFF simultaneo dos cenarios R10 sao os mesmos (splits
# sem resumes, frota inteira, top-5); F-06: o r7-06 usa spacing
# 3660 s > SLOW_WINDOW e continua SEM slow; PARKED liquido: P1-P4
# mantem (as recargas do R10 sao COMPLETAS); F-09: os curtailments
# R10 com CRIT tem >= 6 distintos; F-16(1): as janelas R10 sao
# UNICAS e o distinct 12 mantem).
EXPECTED_LAB_SHA256_V075 = ("cf9fbe3e1cb8d0e2cc5216e5ee8c3ca165d9358d"
                            "788ae2fb723320b091cb86f8")

if lab_sha == EXPECTED_LAB_SHA256_V073:
    TARGET = "V073"
elif EXPECTED_LAB_SHA256_V074 and lab_sha == EXPECTED_LAB_SHA256_V074:
    TARGET = "V074"
elif EXPECTED_LAB_SHA256_V075 and lab_sha == EXPECTED_LAB_SHA256_V075:
    TARGET = "V075"
else:
    print("ALVO REJEITADO: sunstrike_lab.py tem hash %s…\n"
          "  este probe (v0.2) só corre contra a v0.7.3 (%s…) ou a\n"
          "  v0.7.4 selada registrada no CHANGEDLOG.\n"
          "  nada foi executado."
          % (lab_sha[:16], EXPECTED_LAB_SHA256_V073[:16]))
    raise SystemExit(2)

# v0.7.5/R11 (14-11, nota datada): os criterios/valores esperados da
# V074 aplicam-SE a V075 — previsoes V075 = copia datada da V074
# (analise registada na entrada do hash V075 acima).
IS_V074 = TARGET in ("V074", "V075")

RUN_ID = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
          + "-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:6])
print("SUNSTRIKE probes R10 v0.2 (GO v0.7.4 14-11 ~08:45; achados "
      "AUD-03/04/08/10 + G5 do GO, F-* da 8.a auditoria Gemini "
      "verificados por execucao; previsoes V073 E V074 "
      "pre-registadas NESTE ficheiro antes de qualquer corrida) — "
      "run %s (grant GRANT-PVTE-20261112-SS-01)" % RUN_ID)
print("alvo DETETADO    : %s (hash %s…)" % (TARGET, lab_sha[:16]))

sys.path.insert(0, HERE)
import sunstrike_lab as L  # noqa: E402  (após verificação de hash)

VEREDICTOS = []

# ---------------------------------------------------------------------------
# GATEFALL V073 — previsões PRÉ-REGISTADAS antes do RUN 1 (a v0.7.3 é o
# ANTES; o GATEFALL OFICIAL é o RUN 1 com estas previsões, congeladas).
# ---------------------------------------------------------------------------

GATEFALL_V073 = [
    {"id": "P-R10-03a", "finding": "AUD-03-arredondamento",
     "prev": ("CONFIRMADO — ARREDONDAMENTO SoC vs. LEDGER (GO): 4001 POST "
              "/battery de 0,0051 pp num só dispositivo (dev0, batt 12,6 "
              "kWh) → 200×4001 (ledger 20,41% < 40: NENHUM 409); SoC "
              "99,99→59,99 (queda REAL ARMAZENADA de 40,01 pp — cada "
              "pedido de 0,0051 pp custa 0,01 pp guardados; round(.,2) "
              "arredonda SEMPRE para baixo neste valor); ledger 20,41% "
              "(4001×0,0051); |ledger − queda real| = 19,60 pp; ZERO "
              "alertas (cumulativa: fatias de 0,01 somam 40,01 < 50; "
              "drain-to-low: SoC 59,99 > 35) — o limite diário de 40% "
              "deixa passar QUASE o DOBRO em queda real")},
    {"id": "P-R10-03b", "finding": "AUD-03-below-resolution",
     "prev": ("CONFIRMADO — QUOTA ESGOTADA SEM SOC MEXER (GO, variante "
              "0,0049 pp): 8200 POST /battery de 0,0049 pp no dev1 → "
              "200×8163 (o SoC NÃO MEXE: round(100−0,0049,2)=100,00; o "
              "ledger soma 0,0049/pedido) e depois 409 "
              "remote_discharge_daily_limit ×37 (quota 40% esgotada com "
              "SoC 100,00 INTACTO — NEGAÇÃO DE SERVIÇO ao dono: a "
              "bateria fica inutilizável remotamente pelo resto do dia "
              "sem UM ponto de SoC gasto); ZERO alertas")},
    {"id": "P-R10-03c", "finding": "AUD-03-estaciona-35",
     "prev": ("CONFIRMADO — ESTACIONA A 0,01 pp DO LIMIAR (GO, auditoria "
              "8 / F-03): 6499 POST /battery de 0,00501 pp no dev2 → "
              "200×6499 (ledger 32,56% < 40); SoC 100−0,01×6499 = 35,01 "
              "(queda real 64,99 pp — o dobro do ledger); alertas: SÓ "
              "WARN D-BATTERY-CUMULATIVE-DRAIN count 5000 (as fatias "
              "REAIS de 0,01 pp somam 50,00 na janela de 1 h — a regra "
              "vê o ARREDONDADO, o ledger vê o EXATO; dispara na 5000.ª "
              "fatia, count = fatias na janela que fecha 50) e ZERO "
              "CRIT (drain-to-low exige ≤ 35,0 e o SoC ATERRA em 35,01 "
              "— o atacante estaciona EXATAMENTE acima do limiar de "
              "apagão)")},
    {"id": "P-R10-04a", "finding": "AUD-04-broker-login",
     "prev": ("CONFIRMADO — TOKEN DE BROKER VIA /LOGIN (GO): POST /login "
              "com o token hard-coded no dev3 → 200 com sessão; POST "
              "/setpoint (value 50) com a SESSÃO → 200 (export_limit "
              "aplicado); ZERO alertas (o detetor só olha auth_use, "
              "NÃO o login_ok method broker_token; a sessão "
              "device_session não emite auth_use — os comandos "
              "herdados do token de broker ficam INVISÍVEIS)")},
    {"id": "P-R10-04b", "finding": "AUD-04-login-fails-dev",
     "prev": ("CONFIRMADO — FALHAS DE /LOGIN NO DISPOSITIVO SEM EVENTO "
              "(GO): 3 POST /login com token errado no dev4 → 401×3 e "
              "ZERO eventos de auditoria no dispositivo (o gate audita "
              "login_fail; o device NÃO audita nada)")},
    {"id": "P-R10-G5", "finding": "G5-banda-presa",
     "prev": ("CONFIRMADO — BANDA PRESA NA CAPACITY (GO, SÉRIO p/ H3): "
              "DIA/NORMAL; setpoint LEGÍTIMO 0% COM WO MNT1 nos 4 "
              "maiores [4,11,0,8] (43,5 kWp = 48,98% — div cruza 30 na "
              "transição de banda mas NÃO arma: com WO não arma) → "
              "200×4; depois 32 setpoints SEM WO nos outros 8 "
              "[1,2,3,5,6,7,9,10] em degraus 75/50/25/0 → 200×32, "
              "export 0 kW, div 100%; ZERO alertas (a banda já estava "
              "em 1 desde a fase WO: as transições de banda ACABARAM; "
              "os setpoints s/WO ARMAM a regra mas nenhum snapshot "
              "novo acontece — a regra está armada e cega); os degraus "
              "de 25 pp não armam a CURTAILMENT-WAVE (drop < 30)")},
    {"id": "P-R10-G5b", "finding": "G5-controlo",
     "prev": ("CONFIRMADO — CONTROLO SEM A PARTE LEGÍTIMA (GO): os MESMOS "
              "32 setpoints s/WO (8 devs, degraus 75/50/25/0) SEM a "
              "parte WO → 200×32; a banda cruza 30% DURANTE a fase "
              "s/WO (arming ativo): D-CAPACITY-DIVERGENCE CRIT count 1 "
              "(UMA transição de banda → UM snapshot ≥ 30 com arming); "
              "ZERO outros CRIT")},
    {"id": "P-R10-G5c", "finding": "G5-FP",
     "prev": ("CONFIRMADO — SÓ A PARTE LEGÍTIMA COM WO (GO, verificar "
              "FP): 4 setpoints 0% COM WO MNT1 nos 4 maiores → 200×4, "
              "div 48,98%; ZERO alertas (com WO NUNCA arma — o FP do "
              "cenário legítimo não existe na v0.7.3)")},
    {"id": "P-R10-08", "finding": "AUD-08-onda-1-inversor",
     "prev": ("CONFIRMADO — ONDA DE FROTA COM 1 SÓ INVERSOR (GO): 8 "
              "shutdowns remotos s/WO NO MESMO dispositivo (dev5), "
              "espaçados ~0,5 s → 200×8; D-FLEET-SHUTDOWN-WAVE CRIT "
              "count 8 (conta EVENTOS: 8 ≥ k=6 na janela de 60 s — "
              "mesmo com 1 dispositivo distinto) + D-SLOW-WAVE CRIT "
              "count 8 (idem, 8 ≥ SLOW_K=8 no horizonte) + WARN "
              "D-REMOTE-SHUTDOWN-NO-WO ×8 — uma ONDA DE FROTA sem "
              "frota: o gatilho de escala não exige dispositivos "
              "DISTINTOS")},
    {"id": "P-R10-10a", "finding": "AUD-10-device-bool",
     "prev": ("CONFIRMADO — {\"device\": true} ACEITE NO /fleet/firmware "
              "(GO): login default no gate (D-AUTH-DEFAULT CRIT ×1 — "
              "lição E-R9-2 REGISTRADA: é CRIT) + POST /fleet/firmware "
              "com {\"device\": true, imagem VÁLIDA assinada} → 200 "
              "(bool É subclasse de int: isinstance(True,int) passa, "
              "devices[True]=devices[1] — o firmware é EMPURRADO ao "
              "dev 1, fw_ver 2.4.1+push); ZERO outros alertas")},
    {"id": "P-R10-10b", "finding": "AUD-10-json-malformado",
     "prev": ("CONFIRMADO — CORPO JSON MALFORMADO SEM AUDITORIA (GO): "
              "pedido cru ao GATE com body '{bad' (Content-Length "
              "correto) → 400 'JSON invalido' e ZERO eventos de "
              "auditoria no cenário (a recusa não deixa rasto)")},
    {"id": "P-R10-10c", "finding": "AUD-10-contadores",
     "prev": ("CONFIRMADO — CONTADORES NUNCA REPOSTOS (GO): (a) bulk: "
              "login default + bulk MNT3 ×2 → 200×2 (bulk_used 2), 3.º "
              "bulk → 429 bulk_block_rate_limit; +25 h de relógio de "
              "simulação (viragem do dia) → 4.º bulk → 429 OUTRA VEZ "
              "(bulk_used NUNCA repõe — o rate limit de 2/24 h vira "
              "PERMANENTE); (b) o gate NÃO TEM harness_reset (método "
              "inexistente — os devices têm, o gate não); (c) "
              "login_fails: 4 logins errados → +25 h (viragem do dia) "
              "→ 4.º login errado: na v0.7.3 a 5.ª falha ACUMULADA "
              "dispara o LOCKOUT (login_rate_blocked presente; o "
              "contador não repõe na viragem do dia)")},
    {"id": "P-R10-F04a", "finding": "F-04a-curtailment-massa-WO",
     "prev": ("CONFIRMADO — CURTAILMENT EM MASSA COM WO, ESPAÇADO "
              "(8.ª auditoria, GO): 12 setpoints 0% COM WO MNT1 "
              "válida (âmbito frota, 12 usos) em lotes 5+5+2 "
              "espaçados 61 s de relógio de simulação → 200×12, "
              "export 0 kW, div 100%; ZERO alertas (a WO não arma a "
              "capacity; a CURTAILMENT-WAVE conta 12 eventos de "
              "curtail mas em janelas de 60 s com 5+5+2 — nunca ≥ "
              "k=6; NÃO existe para setpoints o equivalente à "
              "D-MASS-SHUTDOWN-WITH-WO/SLOW-WAVE: cortar 100% da "
              "exportação da frota COM WO é INVISÍVEL)")},
    {"id": "P-R10-F04a-CTRL", "finding": "F-04a-controlo",
     "prev": ("CONFIRMADO — CONTROLO (GO): 5 MENORES [10,2,6,5,1] a 0% "
              "COM WO MNT1 (22,8 kWp = 25,68% < 30, 5 < k) → 200×5, "
              "ZERO alertas (abaixo de todos os gatilhos de escala)")},
    {"id": "P-R10-P1", "finding": "P1-bateria-estacionada",
     "prev": ("CONFIRMADO — BATERIA ESTACIONADA ACIMA DO LIMIAR (GO, "
              "controlo do supervisor): 12 dispositivos, dia 1 fatia "
              "40% + 25 h + dia 2 fatia 24,9% (SEM recarga) → 200×24, "
              "SoC 35,1 na frota; ZERO alertas (drain-to-low exige "
              "≤ 35,0 — o atacante estaciona a 0,1 pp do limiar; "
              "cumulativa: 24,9 < 50 na janela); depois BLACKOUT "
              "NOITE + 4 h de ilha → 0/12 casas com luz (contra 10/12 "
              "sem ataque — o apagão posicionado com ZERO alertas)")},
    {"id": "P-R10-P2", "finding": "P2-atacante-lento",
     "prev": ("CONFIRMADO — ATACANTE LENTO (GO): 12 dispositivos, 3 dias "
              "× 21,6% (SEM recarga, +25 h entre dias) → 200×36, SoC "
              "35,2; ZERO alertas (35,2 > 35,0: drain-to-low calada; "
              "a MULTIDAY morta da v0.7.1 media volume em janela — "
              "histórico a NÃO repetir)")},
    {"id": "P-R10-P3", "finding": "P3-FP-dono-recarga",
     "prev": ("CONFIRMADO — FP K1-c (GO): dono 25%/dia × 3 dias COM "
              "recarga solar (12 h DIA entre dias, SoC 100) → 200×36, "
              "ZERO alertas na v0.7.3 (a drain-to-low morreu no K1-c "
              "da v0.7.1; a recarga repõe o SoC)")},
    {"id": "P-R10-P4", "finding": "P4-FP-descarga-unica",
     "prev": ("CONFIRMADO — FP (GO): UMA descarga remota de 30% num "
              "dispositivo → 200, SoC 70; ZERO alertas (30 < 50 e "
              "70 > 45)")},
    {"id": "P-R10-F09c", "finding": "F-09c-assinatura-sem-chave",
     "prev": ("CONFIRMADO — ASSINATURA DE FIRMWARE SEM CHAVE (GO, "
              "decisão do operador: HMAC): NORMAL; imagem ARBITRÁRIA "
              "com assinatura 'SUNSIG-'+sha256(imagem)[:32] (o esquema "
              "público da v0.7.3 — sem segredo) → 200 firmware_push "
              "(QUALQUER imagem com o seu sha256 é ACEITE — a "
              "docstring do H4 ('a assinatura inventada não é "
              "quebrável no lab') é DESMENTIDA; bricked declarado "
              "inalcançável fica FALSO); ZERO alertas; a LEGIT com "
              "L.sign_image → 200 (o caminho legítimo mantém-se)")},
    {"id": "P-R10-F05b", "finding": "F-05b-FP-manutencao-1a1",
     "prev": ("CONFIRMADO — FP MANUTENÇÃO 1-A-1 (8.ª auditoria, GO): 12 "
              "shutdowns COM WO MNT1 em 12 dispositivos distintos, "
              "CADA UM seguido de inverter_resume ANTES do seguinte "
              "(12/12 ON no fim; NUNCA 2 OFF em simultâneo) → 200×24; "
              "D-MASS-SHUTDOWN-WITH-WO CRIT count 12 (FP: a regra "
              "conta EVENTOS/distintos do cenário, NÃO os "
              "desligados EM SIMULTÂNEO — manutenção legítima "
              "serializada dispara CRIT de frota); ZERO outros "
              "alertas (COM WO não arma capacity; div ≤ 13,5% < 30 "
              "em todos os snapshots)")},
    {"id": "P-R10-F05b-CTRL", "finding": "F-05b-controlo",
     "prev": ("CONFIRMADO — CONTROLO (GO): os MESMOS 12 shutdowns COM "
              "WO SEM resume (12 OFF no fim) → 200×12; "
              "D-MASS-SHUTDOWN-WITH-WO CRIT count 12 (o caso REAL "
              "continua CRIT — o fix não pode cegar a massa "
              "verdadeira)")},
    {"id": "P-R10-F05d", "finding": "F-05d-amount-zero",
     "prev": ("CONFIRMADO — amount_kwh = 0 (8.ª auditoria, GO): dev0 "
              "com SoC 30 (posicionado por harness) + POST /battery "
              "discharge amount 0 → 200 com param_change soc 30→30 "
              "(drop 0): D-BATTERY-DRAIN-TO-LOW CRIT (new 30 ≤ 35 — "
              "uma descarga de ZERO pontos 'posiciona apagão'); dev1 "
              "com SoC 5 (ilha) + POST /battery amount 0 → 409 "
              "floor_block: D-BATTERY-DRAIN-BELOW-FLOOR CRIT (new 5 < "
              "25 — pedido de ZERO aterra no floor); 2 CRIT de uma "
              "descarga NULA")},
    {"id": "P-R10-F05a", "finding": "F-05a-blackout-capacity",
     "prev": ("CONFIRMADO — 1 SETPOINT s/WO + BLACKOUT (8.ª auditoria, "
              "GO): DIA; 1 setpoint 0% s/WO no dev0 (arma a capacity, "
              "div 11,83% < 30 — calada) → 200; depois BLACKOUT (V=0: "
              "anti-islanding ABRE os 12 relés) → div 100% (esperado "
              "48,84 kW CONTINUA a contar os relés abertos; actual 0) "
              "→ D-CAPACITY-DIVERGENCE CRIT (transição de banda com "
              "arming: o CRIT noturno/apagão da capacity que estava "
              "DECLARADO como resíduo)")},
    {"id": "P-R10-F07a", "finding": "F-07a-work-order-tipo",
     "prev": ("CONFIRMADO — WORK_ORDER LISTA/DICT (8.ª auditoria, GO): "
              "POST /mode com work_order=[\"a\"] (service token) no "
              "dev6 → TypeError NO HANDLER (orders.get(lista) — "
              "unhashable), SEM resposta válida (conexão morre/erro) "
              "e SEM evento de auditoria; via GUARD idem (o Guard "
              "deixa passar: só valida 'action') — crash propagado, "
              "zero rasto")},
    {"id": "P-R10-F08a", "finding": "F-08a-content-length",
     "prev": ("CONFIRMADO — CONTENT-LENGTH −1 FURA O GUARD (8.ª "
              "auditoria, GO): pedido cru ao GUARD /device/0/setpoint "
              "com 'Content-Length: -1' e body de ~15 KB (>"
              "GUARD_BODY_MAX=10 KB) com half-close → 200 FORWARDED "
              "(n=-1 passa o check n > MAX; read(-1) lê TUDO até EOF: "
              "o body de 15 KB entra, o setpoint 55 APLICA no dev0) — "
              "o limite de body do guard é OPTIONAL para quem mente "
              "no Content-Length; SEM guard_reject")},
    {"id": "P-R10-F08b", "finding": "F-08b-guard-reject-invisivel",
     "prev": ("CONFIRMADO — (i) pedido NÃO-CANÓNICO ('//') via GUARD → "
              "400 + evento guard_reject no audit_guard, MAS o "
              "detetor IGNORA guard_reject: ZERO alertas "
              "D-NON-CANONICAL-REQUEST na via gerida; (ii) pedido "
              "cru ao DEVICE com path '//setpoint' E body JSON "
              "MALFORMADO → 400 'JSON invalido' e SEM evento "
              "non_canonical_request (o handler lê o JSON ANTES da "
              "verificação canónica — o pedido não-canónico morre "
              "como 'JSON inválido' sem rasto canónico)")},
    {"id": "P-R10-F08c", "finding": "F-08c-check-consume",
     "prev": ("CONDICIONAL — SUSPEITA POR LEITURA (GO: NÃO reproduz "
              "sem atraso injetado; supervisor 5/5 corridas → 3/12 "
              "correto): 8 threads SIMULTÂNEAS com shutdown COM WO "
              "MNT2 (âmbito {0,1,2}, max_uses 3) ao dev1 na v0.7.3 "
              "(check e consume em CHAMADAS SEPARADAS, retorno do "
              "consume=True ignorado): PREVISTO >3×200 (CONFIRMADO — "
              "a corrida atômica passa o check antes de qualquer "
              "consume) OU exatamente 3×200 + 5×403 "
              "(NÃO-REPRODUZIDO — registado como suspeita por "
              "leitura, GO §5); QUALQUER dos dois resultados está "
              "DENTRO desta previsão; os 403 usos_esgotados dão WARN "
              "D-INVALID-WORK-ORDER ×(8−executados)")},
    {"id": "P-R10-F06b", "finding": "F-06b-login-fails-gate",
     "prev": ("CONFIRMADO — LOGIN_OK NÃO REPÕE login_fails (8.ª "
              "auditoria, nuance do AUD-10, GO): 4 logins errados no "
              "gate (401×4, contador 4) + 1 login CORRETO (200, "
              "D-AUTH-DEFAULT CRIT ×1) + 4 logins errados → na "
              "v0.7.3 a 5.ª falha ACUMULADA (a 1.ª do segundo lote) "
              "dispara o LOCKOUT: login_rate_blocked PRESENTE (o "
              "login correto no meio NÃO repôs o contador — um dono "
              "que erra a password 4× e acerta 1× fica à beira do "
              "lockout)")},
    {"id": "P-R10-TEXT", "finding": "TEXT-16-10-e-contagens",
     "prev": ("CONFIRMADO — TEXTOS (GO §5): na v0.7.3 o código contém "
              "'22,9' em 6 SÍTIOS (o MNT3 {0,2} = 14,3/88,8 = 16,10%, "
              "não 22,9% — incl. a label impressa pelo selftest), o "
              "cabeçalho diz 'v0.7.2' (F-LIMP falhou na v0.7.3) e a "
              "linha do Detector diz '12 regras' (contagem real: "
              "24); len(RULE_ATTACK_MAP) == 24")},
]

# ---------------------------------------------------------------------------
# GATEFALL V074 — previsões PRÉ-REGISTADAS NESTE FICHEIRO (v0.1) ANTES de
# qualquer corrida (derivam do GO §3/§5 — fixes; NÃO de runs). O hash da
# v0.7.4 é preenchido na entrada v0.2 ANTES do run 2.
# ---------------------------------------------------------------------------

GATEFALL_V074 = [
    {"id": "P-R10-03a", "finding": "AUD-03-arredondamento",
     "prev": ("RESOLVIDO — LEDGER REGISTA A QUEDA REAL (GO): 4001 "
              "pedidos de 0,0051 pp → 200×4000 e 409 "
              "remote_discharge_daily_limit ×1 (o ledger soma a queda "
              "REAL de 0,01 pp/pedido: 40,00 + 0,01 > 40); SoC 60,00; "
              "ledger 40,00; queda real do dia 40,00 ≤ limite 40; "
              "|ledger − queda real| = 0,00 ≤ 0,01; ZERO alertas")},
    {"id": "P-R10-03b", "finding": "AUD-03-below-resolution",
     "prev": ("RESOLVIDO — BELOW_RESOLUTION (GO): 8200 pedidos de "
              "0,0049 pp → 400 below_resolution ×8200 (queda real "
              "0: abaixo da resolução de 0,01 pp), SEM consumir quota "
              "(ledger 0,00) e SoC 100,00 INTACTO; ZERO alertas; a "
              "quota segue INTACTA (um drain de 40% depois → 200)")},
    {"id": "P-R10-03c", "finding": "AUD-03-estaciona-35",
     "prev": ("RESOLVIDO — QUEDA REMOTA DO DIA NÃO PASSA DE 40 pp "
              "(GO): 6499 pedidos de 0,00501 pp → 200×4000 + 409 "
              "daily ×2499 (ledger real 40,00); SoC 60,00 (queda real "
              "do dia 40,00 ≤ 40 — o estacionamento a 35,01 MORRE: o "
              "limite diário passa a contar a queda REAL); ZERO "
              "alertas (cumulativa: 40,00 < 50 na janela)")},
    {"id": "P-R10-04a", "finding": "AUD-04-broker-login",
     "prev": ("RESOLVIDO — LOGIN_BROKER DISPARA E A SESSÃO HERDA A "
              "MARCA (GO): /login com token de broker → 200; setpoint "
              "com a sessão → 200; D-AUTH-BROKER-TOKEN CRIT count 2 "
              "(o login_ok method broker_token DISPARA a regra E a "
              "sessão fica MARCADA — o comando herdado emite auth_use "
              "broker_token: login + setpoint = 2 eventos)")},
    {"id": "P-R10-04b", "finding": "AUD-04-login-fails-dev",
     "prev": ("RESOLVIDO — FALHAS DE /LOGIN AUDITADAS NO DISPOSITIVO "
              "(GO): 401×3 + 3 eventos login_fail no audit do dev4 "
              "(zero alertas — auditoria sem regra, como no gate)")},
    {"id": "P-R10-G5", "finding": "G5-banda-presa",
     "prev": ("RESOLVIDO — SNAPSHOT APÓS CADA SETPOINT REMOTO + "
              "REAVALIAÇÃO COM A REGRA ARMADA (GO): o cenário completo "
              "→ 200×36, export 0, div 100%; D-CAPACITY-DIVERGENCE "
              "CRIT count 32 (cada setpoint s/WO emite snapshot — "
              "todos com div ≥ 50,68 ≥ 30 e arming ativo desde o 1.º "
              "s/WO) + D-MASS-CURTAILMENT CRIT (regra NOVA F-04a: 12 "
              "distintos ≥ k, 100% ≥ 30% — os 4 WO a 0% e os 8 s/WO "
              "a ≤ 25% SOMADOS na SLOW_WINDOW; FP da parte legítima "
              "declarado em G5c)")},
    {"id": "P-R10-G5b", "finding": "G5-controlo",
     "prev": ("RESOLVIDO — controlo: D-CAPACITY-DIVERGENCE CRIT "
              "count 14 (os 14 setpoints s/WO cujo snapshot pós-fix "
              "tem div ≥ 30 — computado: a div cruza 30 ao 19.º "
              "setpoint de 32) + D-MASS-CURTAILMENT CRIT (8 "
              "distintos, 51,01% ≥ 30); o CRIT mantém-se SEM a parte "
              "legítima")},
    {"id": "P-R10-G5c", "finding": "G5-FP",
     "prev": ("RESOLVIDO/DECLARADO — FP DA CAPACITY MORTO; FP DA MASSA "
              "DECLARADO (verificar FP, GO): SEM CRIT de "
              "D-CAPACITY-DIVERGENCE (com WO NUNCA arma — o fix não "
              "muda o arming); D-MASS-CURTAILMENT CRIT DISPARA (4 "
              "maiores a 0% COM WO = 48,98% ≥ 30% — FP DECLARADO "
              "aceitável por desenho, o MESMO tratamento do MNT1 "
              "frota-inteira do GO v0.7.2/F-C15b; registado, não "
              "escondido)")},
    {"id": "P-R10-08", "finding": "AUD-08-onda-1-inversor",
     "prev": ("RESOLVIDO — DISPOSITIVOS DISTINTOS (GO): 8 shutdowns no "
              "MESMO inversor → 200×8; ZERO CRIT de onda (1 distinto "
              "< k=6) e ZERO CRIT de slow-wave (1 < SLOW_K=8); o WARN "
              "D-REMOTE-SHUTDOWN-NO-WO ×8 MANTÉM-SE (a visibilidade "
              "por evento não morre)")},
    {"id": "P-R10-10a", "finding": "AUD-10-device-bool",
     "prev": ("RESOLVIDO — TIPO VALIDADO NO GATE (GO): login default "
              "(D-AUTH-DEFAULT CRIT ×1) + /fleet/firmware com "
              "{\"device\": true} → 400 + evento strict_type_reject "
              "auditado no gate (bool NÃO é índice); dev1 fw_ver "
              "2.4.1 INTACTO; ZERO outros alertas")},
    {"id": "P-R10-10b", "finding": "AUD-10-json-malformado",
     "prev": ("RESOLVIDO — JSON MALFORMADO AUDITADO (GO): 400 + evento "
              "body_json_invalid auditado no gate (a recusa deixa "
              "rasto)")},
    {"id": "P-R10-10c", "finding": "AUD-10-contadores",
     "prev": ("RESOLVIDO — REPOSIÇÃO NA VIRAGEM DO DIA E NO "
              "HARNESS_RESET (GO): (a) bulk: 200×2 + 429; +25 h → "
              "200 (bulk_used REPOSTO na viragem do dia; os "
              "dispositivos devolvem 403 usos_esgotados — os USOS da "
              "MNT3 não repõem, só bulk_used; SEM "
              "bulk_block_rate_limit após a viragem); (b) o gate TEM "
              "harness_reset() e repõe bulk_used/login_fails/lockout "
              "(após reset os CONTADORES ficam a 0 — bulk_used=0, "
              "login_fails=0; o bulk seguinte devolve 403 "
              "usos_esgotados da MNT2, NÃO 429: o reset é dos "
              "CONTADORES, não dos usos da WO); (c) login_fails: 4 "
              "errados + viragem do dia + 4 errados → SEM lockout "
              "(contador reposto: 4 < 5; login_rate_blocked AUSENTE)"
              )},
    {"id": "P-R10-F04a", "finding": "F-04a-curtailment-massa-WO",
     "prev": ("RESOLVIDO — REGRA DE MASSA PARA CORTES DE EXPORTAÇÃO "
              "(GO, F-04a): D-MASS-CURTAILMENT CRIT (12 distintos ≥ "
              "k OU 100% ≥ 30%, lotes 5+5+2 DENTRO da SLOW_WINDOW de "
              "1 h — o pacing de 61 s não evade); SEM CRIT de "
              "capacity (COM WO não arma); SEM CURTAILMENT-WAVE "
              "(lotes de 5 < k na janela de 60 s — a onda rápida "
              "continua intacta e cega ao pacing LENTO)")},
    {"id": "P-R10-F04a-CTRL", "finding": "F-04a-controlo",
     "prev": ("RESOLVIDO — CONTROLO: 5 menores a 0% COM WO (5 < k E "
              "25,68% < 30) → ZERO alertas (a manutenção pontual "
              "legítima fica ABAIXO dos gatilhos somados)")},
    {"id": "P-R10-P1", "finding": "P1-bateria-estacionada",
     "prev": ("RESOLVIDO — D-BATTERY-PARKED-DRAIN (regra NOVA, GO): "
              "descarga REMOTA acumulada desde a última recarga a "
              "SoC ≥ 90% (sem janela temporal) ≥ 50 pp E SoC atual "
              "≤ 45% → CRIT count 12 (acumulado 64,9 ≥ 50; SoC 35,1 "
              "≤ 45 — a frota estacionada ACENDE antes do apagão); "
              "BLACKOUT 4 h → 0/12 (a física não muda; muda a "
              "VISIBILIDADE)")},
    {"id": "P-R10-P2", "finding": "P2-atacante-lento",
     "prev": ("RESOLVIDO — atacante lento: D-BATTERY-PARKED-DRAIN "
              "CRIT count 12 (64,8 ≥ 50; 35,2 ≤ 45 — a regra NÃO tem "
              "janela: o K1-b de 3 dias morre)")},
    {"id": "P-R10-P3", "finding": "P3-FP-dono-recarga",
     "prev": ("RESOLVIDO/FP MORTO — a recarga solar a SoC 100 (≥ 90) "
              "REPÕE o acumulador a cada dia (25 < 50 e SoC 75 > 45): "
              "ZERO alertas (K1-c continua morto na regra NOVA)")},
    {"id": "P-R10-P4", "finding": "P4-FP-descarga-unica",
     "prev": ("RESOLVIDO/FP MORTO — 30 < 50 e 70 > 45: ZERO alertas "
              "(regra de paragem pré-registrada: se P3 ou P4 derem "
              "alerta, NÃO há terceira tentativa)")},
    {"id": "P-R10-F09c", "finding": "F-09c-assinatura-sem-chave",
     "prev": ("RESOLVIDO — HMAC-SHA256 COM CHAVE DO FABRICANTE "
              "SIMULADO (GO, constante documentada; o Adversário NÃO "
              "a usa): imagem arbitrária com a assinatura sha256 "
              "pública → 403 + WARN D-FIRMWARE-REJECTED (evento "
              "firmware_rejected reason assinatura_invalida; "
              "qualquer imagem sem o segredo é RECUSADA); a LEGIT "
              "com L.sign_image → 200 (o H4 do demo mantém-se; as "
              "docstrings do H4 corrigidas para o que passa a ser "
              "verdade)")},
    {"id": "P-R10-F05b", "finding": "F-05b-FP-manutencao-1a1",
     "prev": ("RESOLVIDO — A MASSA CONTA OS DESLIGADOS EM SIMULTÂNEO "
              "(GO): 12 shutdown+resume serializados (12/12 ON no "
              "fim, NUNCA 2 OFF juntos) → 200×24; ZERO CRIT de massa "
              "(máx. 1 OFF em simultâneo < k); ZERO outros alertas")},
    {"id": "P-R10-F05b-CTRL", "finding": "F-05b-controlo",
     "prev": ("RESOLVIDO — CONTROLO: os MESMOS 12 shutdowns SEM "
              "resume → 200×12; D-MASS-SHUTDOWN-WITH-WO CRIT (12 "
              "OFF EM SIMULTÂNEO no fim — a massa verdadeira "
              "continua CRIT)")},
    {"id": "P-R10-F05d", "finding": "F-05d-amount-zero",
     "prev": ("RESOLVIDO — AMOUNT ≤ 0 → 400 (GO): dev0 SoC 30 → 400 "
              "strict_type_reject (amount ≤ 0 recusado; SoC intacto "
              "30; SEM param_change) e dev1 SoC 5 → 400 (idem — o "
              "pedido NULO nem chega ao floor); ZERO alertas (as "
              "regras de descarga exigem drop > 0)")},
    {"id": "P-R10-F05a", "finding": "F-05a-blackout-capacity",
     "prev": ("RESOLVIDO — O ESPERADO CONTA 0 kW PARA RELÉS ABERTOS "
              "PELO CANAL AUTÓNOMO (GO): 1 setpoint s/WO + BLACKOUT "
              "→ esperado 0 (12 relés abertos pelo anti-islanding) → "
              "div 0 → ZERO CRIT de capacity (o resíduo 'CRIT "
              "noturno/apagão' DECLARADO fecha)")},
    {"id": "P-R10-F07a", "finding": "F-07a-work-order-tipo",
     "prev": ("RESOLVIDO — WORK_ORDER TEM DE SER STRING (GO): direto "
              "no dev6 → 400 + evento work_order_invalid reason "
              "tipo_invalido (WARN D-INVALID-WORK-ORDER; o shutdown "
              "NÃO executa); via GUARD → 400 guard_reject "
              "strict_type:work_order (o Guard valida o tipo ANTES "
              "de encaminhar)")},
    {"id": "P-R10-F08a", "finding": "F-08a-content-length",
     "prev": ("RESOLVIDO — CL < 0 OU INVÁLIDO → 400 + EVENTO (GO): o "
              "GUARD recusa 'Content-Length: -1' com 400 + "
              "guard_reject bad_content_length (o body NÃO é lido; "
              "dev0 export_limit INTACTO 100; o limite de body volta "
              "a ser INEGÁVEL); o JSONHandler direto idem (400 + "
              "evento)")},
    {"id": "P-R10-F08b", "finding": "F-08b-guard-reject-invisivel",
     "prev": ("RESOLVIDO — (i) guard_reject não-canónico TRATA-SE "
              "como D-NON-CANONICAL-REQUEST (GO): pedido '//' via "
              "GUARD → 400 + WARN D-NON-CANONICAL-REQUEST (a via "
              "gerida deixa de ser cega); (ii) verificação canónica "
              "ANTES do parse: '//setpoint' + JSON malformado no "
              "DEVICE → 400 + evento non_canonical_request (o rasto "
              "canónico existe mesmo com body ruim)")},
    {"id": "P-R10-F08c", "finding": "F-08c-check-consume",
     "prev": ("RESOLVIDO — CHECK+CONSUME ATÓMICOS SOB LOCK, USANDO O "
              "RETORNO (GO): 8 threads simultâneas → EXATAMENTE 3×200 "
              "+ 5×403 usos_esgotados (WARN D-INVALID-WORK-ORDER "
              "count 5; a MNT2 nunca ultrapassa max_uses=3, por mais "
              "concorrência)")},
    {"id": "P-R10-F06b", "finding": "F-06b-login-fails-gate",
     "prev": ("RESOLVIDO — LOGIN_OK REPÕE login_fails (GO): 4 errados "
              "+ 1 correto (D-AUTH-DEFAULT CRIT ×1) + 4 errados → "
              "SEM lockout (login_rate_blocked AUSENTE — o contador "
              "repõe no login correto; 4 < 5)")},
    {"id": "P-R10-TEXT", "finding": "TEXT-16-10-e-contagens",
     "prev": ("RESOLVIDO — TEXTOS (GO §5): '22,9' AUSENTE do código "
              "(16,10 no lugar — 14,3/88,8); cabeçalho v0.7.4; a "
              "linha do Detector com o nº REAL de regras; "
              "len(RULE_ATTACK_MAP) == 26 (24 + D-MASS-CURTAILMENT + "
              "D-BATTERY-PARKED-DRAIN)")},
]

# v0.7.5/R11 (14-11, pre-registado ANTES do run de nao-regressao):
# previsoes V075 = copia datada da V074 (nota datada no hash V075).
GATEFALL_V075 = [dict(e) for e in GATEFALL_V074]
GATEFALL = (GATEFALL_V075 if TARGET == "V075"
            else GATEFALL_V074 if IS_V074 else GATEFALL_V073)

if IS_V074:
    print("\nGATEFALL V074 — previsões pré-registradas NESTE ficheiro "
          "(v0.1) ANTES de qualquer corrida: fixes do GO §3/§5 (hash "
          "preenchido na entrada v0.2, ANTES do run 2)")
else:
    print("\nGATEFALL V073 — previsões pré-registradas NESTE ficheiro "
          "(v0.1) ANTES de qualquer corrida contra a v0.7.3 INTOCADA "
          "(de7f5766…)")
print("contra sunstrike_lab.py %s (hash %s…)" % (TARGET, lab_sha[:16]))
for entry in GATEFALL:
    print("  [%s/%s] %s" % (entry["id"], entry["finding"], entry["prev"]))

# ---------------------------------------------------------------------------
# Helpers (padrão das probes R5–R9 — re-implementação INDEPENDENTE)
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
        # E-R10-1 (v0.1.1): o handler que CRASHA (TypeError do F-07a)
        # fecha a conexao SEM resposta — http.client.RemoteDisconnected
        # NÃO é URLError; sem isto o probe morre em vez de REGISTAR o
        # crash como evidencia (defeito de construcao do run 1).
        return 0, {"error": "conexao: %s" % e}


def raw_post(port, target, body, auth=None, cl=None, half_close=False,
             timeout=8):
    """Pedido cru por socket. cl=None usa o comprimento real; cl=str
    força o header Content-Length (F-08a). Devolve (status_line,
    headers_dict, body_bytes) — status_line '' se sem resposta."""
    if isinstance(target, str):
        target = target.encode("latin-1")
    if isinstance(body, str):
        body = body.encode("utf-8")
    req = (b"POST " + target + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Content-Type: application/json\r\n")
    if auth:
        req += b"Authorization: Bearer " + auth.encode() + b"\r\n"
    req += b"Content-Length: " + (str(len(body)) if cl is None
                                  else str(cl)).encode() + b"\r\n\r\n"
    req += body
    try:
        s = socket.create_connection((LOOPBACK, port), timeout=timeout)
        s.sendall(req)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        chunks = []
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                chunks.append(d)
                if not half_close and b"\r\n\r\n" in b"".join(chunks):
                    break
        except OSError:
            pass
        s.close()
    except OSError:
        return "", {}, b""
    raw = b"".join(chunks)
    if not raw:
        return "", {}, b""
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    headers = {}
    for h in lines[1:]:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers, rest


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
    time.sleep(0.5)


def blackout(lab):
    lab.gridsim.set_irradiance("NOITE")
    lab.gridsim.set_state("BLACKOUT")
    time.sleep(0.4)


def served_count(lab):
    return sum(1 for d in lab.devices
               if d.self_consumption_kw() >= L.LOAD_LOCAL_KW - 0.01)


def drain_pct(lab, idx, pct, action="discharge", token=None):
    d = lab.devices[idx]
    body = {"action": action,
            "amount_kwh": d.batt_kwh * pct / 100.0}
    return hj(d.port, "POST", "/battery", body,
              token=token or d.service_token)


def remote_shutdown(lab, idx, work_order=None, token=None):
    d = lab.devices[idx]
    body = {"action": "inverter_power_off"}
    if work_order is not None:
        body["work_order"] = work_order
    return hj(d.port, "POST", "/mode", body,
              token=token or d.service_token)


def remote_setpoint(lab, idx, value, work_order=None, token=None):
    d = lab.devices[idx]
    body = {"value": value}
    if work_order is not None:
        body["work_order"] = work_order
    return hj(d.port, "POST", "/setpoint", body,
              token=token or d.service_token)


def alert_set(alerts):
    return sorted((a["rule"], a["severity"], a["count"]) for a in alerts)


def crits_of(alerts):
    return {a["rule"]: a for a in alerts if a["severity"] == "CRIT"}


def warns_of(alerts):
    return {a["rule"]: a for a in alerts if a["severity"] == "WARN"}


def island_sweep_hours(lab, hours):
    """Física da ilha em passos de 60 s (como o measure)."""
    for _ in range(int(hours * 60)):
        for d in lab.devices:
            d.step_island(60.0)


# ---------------------------------------------------------------------------
# Execução — RUN 1 (vs v0.7.3 INTOCADA; GATEFALL OFICIAL)
# ---------------------------------------------------------------------------

def main():
    lab = L.Lab(evidence=False)
    lab.start()
    time.sleep(0.5)
    print("\nlab v%s em memória (evidence=False), %d dispositivos + gate\n"
          % (L.LAB_VERSION, len(lab.devices)))
    try:
        # ============================================================
        # P-R10-03a — AUD-03: arredondamento SoC vs. ledger
        # ============================================================
        print("\n[P-R10-03a] AUD-03 — 4001 descargas de 0,0051 pp (dev0)")
        scen = "P-R10-03a"
        L.SIM_CLOCK_OFFSET = 0.0
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d0 = lab.devices[0]
        sts = []
        t0 = time.time()
        for _ in range(4001):
            st, resp = drain_pct(lab, 0, 0.0051)
            sts.append(st)
        dur = time.time() - t0
        n200 = sum(1 for s in sts if s == 200)
        n409 = sum(1 for s in sts if s == 409)
        ledger = round(d0.remote_drain_used_pct(), 2)
        real_drop = round(100.0 - d0.soc, 2)
        alerts = scan_scenario(lab, scen)
        if IS_V074:
            cond = (n200 == 4000 and n409 == 1
                    and abs(real_drop - 40.00) <= 0.01
                    and abs(ledger - 40.00) <= 0.01
                    and abs(ledger - real_drop) <= 0.01
                    and not alerts)
            word = "RESOLVIDO"
            ev = ["pedidos: 200×%d, 409×%d em %.1f s" % (n200, n409, dur),
                  "SoC %.2f (queda real %.2f pp ≤ limite diário 40)"
                  % (d0.soc, real_drop),
                  "ledger %.2f |ledger − queda real| = %.2f ≤ 0,01"
                  % (ledger, abs(ledger - real_drop)),
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        else:
            cond = (n200 == 4001 and n409 == 0
                    and abs(real_drop - 40.01) <= 0.01
                    and abs(d0.soc - 59.99) <= 0.01
                    and abs(ledger - 20.41) <= 0.01
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["pedidos: 200×%d, 409×%d em %.1f s (quota NUNCA "
                  "esgota: ledger 20,41 < 40)" % (n200, n409, dur),
                  "SoC 100 → %.2f (queda REAL de %.2f pp — cada pedido "
                  "de 0,0051 custa 0,01 pp guardados)" % (d0.soc, real_drop),
                  "ledger %.2f (4001×0,0051) vs. queda real %.2f: "
                  "DIFERENÇA de %.2f pp — o limite diário efetivo é "
                  "~80 pp" % (ledger, real_drop,
                              abs(ledger - real_drop)),
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-03a", GATEFALL[0]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-03b — AUD-03: 0,0049 pp (quota esgota, SoC intacto)
        # ============================================================
        print("\n[P-R10-03b] AUD-03 — 8200 descargas de 0,0049 pp (dev1)")
        scen = "P-R10-03b"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d1 = lab.devices[1]
        sts = []
        t0 = time.time()
        for _ in range(8200):
            st, resp = drain_pct(lab, 1, 0.0049)
            sts.append(st)
        dur = time.time() - t0
        n200 = sum(1 for s in sts if s == 200)
        n409 = sum(1 for s in sts if s == 409)
        n400 = sum(1 for s in sts if s == 400)
        ledger = round(d1.remote_drain_used_pct(), 2)
        alerts = scan_scenario(lab, scen)
        if IS_V074:
            cond = (n400 == 8200 and n200 == 0
                    and d1.soc == 100.0 and ledger == 0.0
                    and not alerts)
            word = "RESOLVIDO"
            ev = ["pedidos: 400 below_resolution ×%d em %.1f s "
                  "(queda real 0: < 0,01 pp)" % (n400, dur),
                  "SoC %.2f INTACTO; ledger %.2f (quota INTACTA)"
                  % (d1.soc, ledger),
                  "alertas: %s" % (alert_set(alerts) or "ZERO"),
                  "quota intacta: drain de 40%% depois → %s"
                  % drain_pct(lab, 1, 40.0)[0]]
        else:
            cond = (n200 == 8163 and n409 == 37 and n400 == 0
                    and d1.soc == 100.0
                    and abs(ledger - 40.0) <= 0.01
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["pedidos: 200×%d, 409×%d em %.1f s" % (n200, n409, dur),
                  "SoC %.2f INTACTO (round(100−0,0049,2)=100,00) mas "
                  "ledger %.2f — QUOTA ESGOTADA" % (d1.soc, ledger),
                  "NEGAÇÃO DE SERVIÇO: a bateria fica bloqueada ao dono "
                  "sem UM ponto de SoC gasto",
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-03b", GATEFALL[1]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-03c — AUD-03/F-03: 6499 × 0,00501 pp → SoC 35,01
        # ============================================================
        print("\n[P-R10-03c] AUD-03 — 6499 descargas de 0,00501 pp (dev2)")
        scen = "P-R10-03c"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d2 = lab.devices[2]
        sts = []
        t0 = time.time()
        for _ in range(6499):
            st, resp = drain_pct(lab, 2, 0.00501)
            sts.append(st)
        dur = time.time() - t0
        n200 = sum(1 for s in sts if s == 200)
        n409 = sum(1 for s in sts if s == 409)
        ledger = round(d2.remote_drain_used_pct(), 2)
        real_drop = round(100.0 - d2.soc, 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        warns = warns_of(alerts)
        cum = warns.get("D-BATTERY-CUMULATIVE-DRAIN")
        if IS_V074:
            cond = (n200 == 4000 and n409 == 2499
                    and abs(real_drop - 40.00) <= 0.01
                    and abs(ledger - 40.00) <= 0.01
                    and not alerts)
            word = "RESOLVIDO"
            ev = ["pedidos: 200×%d, 409×%d em %.1f s" % (n200, n409, dur),
                  "SoC %.2f (queda real do dia %.2f ≤ 40 — o "
                  "estacionamento a 35,01 MORRE)" % (d2.soc, real_drop),
                  "ledger %.2f = queda real (o ledger conta o REAL)"
                  % ledger,
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        else:
            cond = (n200 == 6499 and n409 == 0
                    and abs(d2.soc - 35.01) <= 0.01
                    and abs(ledger - 32.56) <= 0.01
                    and len(crits) == 0
                    and cum is not None and cum["count"] == 5000)
            word = "CONFIRMADO"
            ev = ["pedidos: 200×%d, 409×%d em %.1f s (quota NUNCA "
                  "esgota: ledger 32,56 < 40)" % (n200, n409, dur),
                  "SoC %.2f (queda real %.2f pp = o DOBRAR do ledger) — "
                  "0,01 pp ACIMA do limiar drain-to-low (35,0)"
                  % (d2.soc, real_drop),
                  "alertas: %s — SÓ WARN cumulativa count %s (as fatias "
                  "REAIS de 0,01 somam 50 na janela; o ledger diz 32,56; "
                  "ZERO CRIT)" % (alert_set(alerts),
                                  cum["count"] if cum else 0)]
        expect("P-R10-03c", GATEFALL[2]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-04a — AUD-04: /login com token de broker + setpoint
        # ============================================================
        print("\n[P-R10-04a] AUD-04 — login broker_token + setpoint (dev3)")
        scen = "P-R10-04a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d3 = lab.devices[3]
        st_lg, resp_lg = hj(d3.port, "POST", "/login",
                           {"token": L.HARDCODED_BROKER_TOKEN})
        sid = resp_lg.get("session")
        st_sp, resp_sp = hj(d3.port, "POST", "/setpoint", {"value": 50.0},
                           token=sid)
        time.sleep(0.4)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        broker = crits.get("D-AUTH-BROKER-TOKEN")
        if IS_V074:
            cond = (st_lg == 200 and st_sp == 200
                    and d3.export_limit == 50.0
                    and broker is not None and broker["count"] == 2
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["login broker → %s; setpoint com a SESSÃO → %s "
                  "(export_limit %.0f)" % (st_lg, st_sp, d3.export_limit),
                  "alertas: %s — D-AUTH-BROKER-TOKEN CRIT count 2 "
                  "(login_ok + auth_use herdado da sessão marcada)"
                  % alert_set(alerts)]
        else:
            cond = (st_lg == 200 and st_sp == 200
                    and d3.export_limit == 50.0
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["login broker → %s; setpoint com a SESSÃO → %s "
                  "(export_limit %.0f aplicado)" % (st_lg, st_sp,
                                                    d3.export_limit),
                  "alertas: %s — ZERO (login_ok broker_token É invisível "
                  "ao detetor; a sessão não emite auth_use)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-04a", GATEFALL[3]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-04b — AUD-04: falhas de /login no dispositivo
        # ============================================================
        print("\n[P-R10-04b] AUD-04 — 3 logins falhados no dev4")
        scen = "P-R10-04b"
        lab.scenario(scen)
        reset_all(lab)
        d4 = lab.devices[4]
        sts = [hj(d4.port, "POST", "/login", {"token": "WRONG"})[0]
               for _ in range(3)]
        evs = scenario_events(lab, scen)
        login_evs = [e for e in evs
                     if e.get("event") in ("login_fail",
                                           "login_rate_blocked")]
        alerts = scan_scenario(lab, scen)
        if IS_V074:
            cond = (sts == [401, 401, 401] and len(login_evs) == 3
                    and not alerts)
            word = "RESOLVIDO"
            ev = ["401×3; eventos login_fail no device: %d" % len(login_evs),
                  "alertas: %s (auditoria sem regra, como no gate)"
                  % (alert_set(alerts) or "ZERO")]
        else:
            cond = (sts == [401, 401, 401] and len(login_evs) == 0
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["401×3; eventos de auditoria no device: ZERO "
                  "(o gate audita login_fail; o device NÃO audita)",
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-04b", GATEFALL[4]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-G5 — banda presa: WO nos 4 maiores + s/WO nos outros 8
        # ============================================================
        print("\n[P-R10-G5] G5 — 4 WO a 0% + 8 s/WO em degraus 75/50/25/0")
        scen = "P-R10-G5"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        wo_devs = [4, 11, 0, 8]
        nowo_devs = [1, 2, 3, 5, 6, 7, 9, 10]
        sts = []
        for i in wo_devs:
            st, _ = remote_setpoint(lab, i, 0.0, "WO-20261112-MNT1")
            sts.append(st)
        # E-R10-1 (v0.1.1): pacing da CONSTRUCAO (previsao INALTERADA)
        # — o loop do GRIDSIM publica a transicao de banda da fase WO
        # ANTES do arming (na medição do GO e no run 1 sem esta pausa o
        # snapshot da transição foi carimbado DEPOIS dos param_change
        # s/WO por timing do loop de 0,25 s — corrida de wall-clock,
        # não física do lab).
        time.sleep(0.5)
        for step in (75.0, 50.0, 25.0, 0.0):
            for i in nowo_devs:
                st, _ = remote_setpoint(lab, i, step)
                sts.append(st)
        time.sleep(0.5)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        cap = crits.get("D-CAPACITY-DIVERGENCE")
        massc = crits.get("D-MASS-CURTAILMENT")
        exp_kw, act_kw, div = L.capacity_divergence_pct(lab.devices)
        export0 = all(d.export_kw() == 0.0 for d in lab.devices)
        if IS_V074:
            cond = (all(s == 200 for s in sts) and export0
                    and abs(div - 100.0) < 0.05
                    and cap is not None and cap["count"] == 32
                    and massc is not None
                    and len(crits) == 2)
            word = "RESOLVIDO"
            ev = ["200×36; export 0 kW em todos; div final %.2f%% "
                  "(esperado %.2f vs real %.2f)" % (div, exp_kw, act_kw),
                  "alertas: %s — capacity CRIT count %s (snapshots "
                  "pós-setpoint com div ≥ 30 e arming) + massa de "
                  "curtailment %s distintos"
                  % (alert_set(alerts),
                     cap["count"] if cap else 0,
                     massc["distinct_devices"] if massc else 0)]
        else:
            cond = (all(s == 200 for s in sts) and export0
                    and abs(div - 100.0) < 0.05
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200×36; export 0 kW em todos; div final %.2f%% — "
                  "a frota está a ZERO e a regra está ARMADA" % div,
                  "alertas: %s — ZERO (a banda cruzou 30 na fase WO "
                  "sem arming; depois NUNCA mais há transição: a "
                  "regra armada fica CEGA)" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-G5", GATEFALL[5]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-G5b — controlo: só os 8 s/WO (sem a parte legítima)
        # ============================================================
        print("\n[P-R10-G5b] G5 — controlo: 8 s/WO em degraus (sem WO)")
        scen = "P-R10-G5b"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for step in (75.0, 50.0, 25.0, 0.0):
            for i in nowo_devs:
                st, _ = remote_setpoint(lab, i, step)
                sts.append(st)
        time.sleep(0.5)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        cap = crits.get("D-CAPACITY-DIVERGENCE")
        massc = crits.get("D-MASS-CURTAILMENT")
        exp_kw, act_kw, div = L.capacity_divergence_pct(lab.devices)
        if IS_V074:
            cond = (all(s == 200 for s in sts)
                    and abs(div - 51.01) < 0.05
                    and cap is not None and cap["count"] == 14
                    and massc is not None and len(crits) == 2)
            word = "RESOLVIDO"
            ev = ["200×32; div final %.2f%%" % div,
                  "alertas: %s — capacity CRIT count %s (14 snapshots "
                  "≥ 30: do 19.º setpoint ao 32.º) + massa de "
                  "curtailment (%s distintos)"
                  % (alert_set(alerts), cap["count"] if cap else 0,
                     massc["distinct_devices"] if massc else 0)]
        else:
            cond = (all(s == 200 for s in sts)
                    and abs(div - 51.01) < 0.05
                    and cap is not None and cap["count"] == 1
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["200×32; div final %.2f%%" % div,
                  "alertas: %s — UMA transição de banda DURANTE a fase "
                  "s/WO (arming ativo) → capacity CRIT count 1"
                  % alert_set(alerts)]
        expect("P-R10-G5b", GATEFALL[6]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-G5c — FP: só a parte legítima (4 WO nos maiores)
        # ============================================================
        print("\n[P-R10-G5c] G5 — FP: 4 WO a 0% nos 4 maiores")
        scen = "P-R10-G5c"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in wo_devs:
            st, _ = remote_setpoint(lab, i, 0.0, "WO-20261112-MNT1")
            sts.append(st)
        time.sleep(0.5)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        cap = crits.get("D-CAPACITY-DIVERGENCE")
        massc = crits.get("D-MASS-CURTAILMENT")
        exp_kw, act_kw, div = L.capacity_divergence_pct(lab.devices)
        if IS_V074:
            cond = (all(s == 200 for s in sts)
                    and abs(div - 48.98) < 0.05
                    and cap is None
                    and massc is not None and len(crits) == 1)
            word = "RESOLVIDO/DECLARADO"
            ev = ["200×4; div %.2f%% (esperado %.2f vs real %.2f)"
                  % (div, exp_kw, act_kw),
                  "SEM CRIT de capacity (com WO NUNCA arma — o FP do "
                  "G5 morre); alertas: %s" % alert_set(alerts),
                  "D-MASS-CURTAILMENT CRIT no caso legítimo: 4 maiores "
                  "= 48,98%% ≥ 30%% com WO — FP DECLARADO aceitável por "
                  "desenho (o MESMO tratamento do MNT1 frota-inteira, "
                  "GO v0.7.2/F-C15b); registado, não escondido"]
        else:
            cond = (all(s == 200 for s in sts)
                    and abs(div - 48.98) < 0.05
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200×4; div %.2f%% (esperado %.2f vs real %.2f)"
                  % (div, exp_kw, act_kw),
                  "alertas: %s — ZERO (com WO não arma; a transição de "
                  "banda dos 48,98%% fica muda)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-G5c", GATEFALL[7]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-08 — AUD-08: 8 shutdowns no MESMO inversor
        # ============================================================
        print("\n[P-R10-08] AUD-08 — 8 shutdowns s/WO no mesmo dev5")
        scen = "P-R10-08"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for _ in range(8):
            st, _ = remote_shutdown(lab, 5)
            sts.append(st)
            time.sleep(0.4)
        time.sleep(0.4)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        warns = warns_of(alerts)
        warn_nowo = warns.get("D-REMOTE-SHUTDOWN-NO-WO")
        if IS_V074:
            cond = (all(s == 200 for s in sts)
                    and "D-FLEET-SHUTDOWN-WAVE" not in crits
                    and "D-SLOW-WAVE" not in crits
                    and len(crits) == 0
                    and warn_nowo is not None
                    and warn_nowo["count"] == 8)
            word = "RESOLVIDO"
            ev = ["200×8 no dev5 (1 dispositivo distinto)",
                  "alertas: %s — ZERO CRIT de onda/slow (1 < k=6; 1 < "
                  "SLOW_K=8); WARN s/WO ×%s MANTÉM-SE"
                  % (alert_set(alerts),
                     warn_nowo["count"] if warn_nowo else 0)]
        else:
            wave = crits.get("D-FLEET-SHUTDOWN-WAVE")
            slow = crits.get("D-SLOW-WAVE")
            cond = (all(s == 200 for s in sts)
                    and wave is not None and wave["count"] == 8
                    and slow is not None and slow["count"] == 8
                    and warn_nowo is not None
                    and warn_nowo["count"] == 8)
            word = "CONFIRMADO"
            ev = ["200×8 no dev5 (1 dispositivo distinto)",
                  "alertas: %s — WAVE CRIT count %s + SLOW CRIT count "
                  "%s com UM só inversor (contam EVENTOS, não "
                  "dispositivos)" % (alert_set(alerts),
                                     wave["count"] if wave else 0,
                                     slow["count"] if slow else 0)]
        expect("P-R10-08", GATEFALL[8]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-10a — AUD-10: {"device": true} no /fleet/firmware
        # ============================================================
        print("\n[P-R10-10a] AUD-10 — {\"device\": true} no "
              "/fleet/firmware")
        scen = "P-R10-10a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st_lg, resp_lg = hj(L.PORT_GATE, "POST", "/fleet/login",
                            {"user": L.DEFAULT_USER,
                             "pass": L.DEFAULT_PASS})
        sid = resp_lg.get("session")
        body = {"device": True,
                "image_b64": L.base64.b64encode(L.LEGIT_IMAGE).decode(),
                "signature": L.sign_image(L.LEGIT_IMAGE)}
        st_fw, resp_fw = hj(L.PORT_GATE, "POST", "/fleet/firmware", body,
                            token=sid)
        time.sleep(0.4)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        auth = crits.get("D-AUTH-DEFAULT")
        evs = scenario_events(lab, scen)
        strict_evs = [e for e in evs
                      if e.get("event") == "strict_type_reject"]
        fw1 = lab.devices[1].fw_ver
        if IS_V074:
            cond = (st_lg == 200 and st_fw == 400
                    and fw1 == "2.4.1" and len(strict_evs) >= 1
                    and auth is not None and auth["count"] == 1
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["login default → %s (D-AUTH-DEFAULT CRIT ×1); "
                  "/fleet/firmware device:true → %s" % (st_lg, st_fw),
                  "dev1 fw_ver %s (INTACTO); eventos strict_type_reject "
                  "no gate: %d" % (fw1, len(strict_evs)),
                  "alertas: %s" % alert_set(alerts)]
        else:
            cond = (st_lg == 200 and st_fw == 200
                    and fw1 == "2.4.1+push"
                    and auth is not None and auth["count"] == 1
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["login default → %s (D-AUTH-DEFAULT CRIT ×1 — lição "
                  "E-R9-2); /fleet/firmware device:true → %s"
                  % (st_lg, st_fw),
                  "dev1 fw_ver %s — o firmware foi EMPURRADO (bool É "
                  "subclasse de int: devices[True]=devices[1])" % fw1,
                  "alertas: %s" % alert_set(alerts)]
        expect("P-R10-10a", GATEFALL[9]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-10b — AUD-10: corpo JSON malformado sem auditoria
        # ============================================================
        print("\n[P-R10-10b] AUD-10 — JSON malformado no gate")
        scen = "P-R10-10b"
        lab.scenario(scen)
        reset_all(lab)
        status, headers, rbody = raw_post(L.PORT_GATE, "/fleet/login",
                                          b"{bad")
        evs = scenario_events(lab, scen)
        bad_evs = [e for e in evs
                   if e.get("event") == "body_json_invalid"]
        if IS_V074:
            cond = ("400" in status and len(bad_evs) == 1)
            word = "RESOLVIDO"
            ev = ["status '%s'; eventos body_json_invalid: %d"
                  % (status, len(bad_evs))]
        else:
            other = [e for e in evs
                     if e.get("event") != "harness_reset"]
            cond = ("400" in status and len(bad_evs) == 0
                    and len(other) == 0)
            word = "CONFIRMADO"
            ev = ["status '%s'; eventos de auditoria (sem os "
                  "harness_reset do próprio reset) : ZERO — a recusa "
                  "400 não deixa rasto" % status]
        expect("P-R10-10b", GATEFALL[10]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-10c — AUD-10: contadores nunca repostos
        # ============================================================
        print("\n[P-R10-10c] AUD-10 — bulk_used/login_fails sem reposição")
        scen = "P-R10-10c"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st_lg, resp_lg = hj(L.PORT_GATE, "POST", "/fleet/login",
                            {"user": L.DEFAULT_USER,
                             "pass": L.DEFAULT_PASS})
        sid = resp_lg.get("session")

        def bulk(wo):
            return hj(L.PORT_GATE, "POST", "/fleet/bulk_shutdown",
                      {"work_order_id": wo}, token=sid)[0]
        # E-R10-1 (v0.1.1): a construção original (3× MNT3) esgotava a
        # WO (4 usos) ANTES do rate limit — o 403 usos_esgotados do
        # check da WO vem ANTES do check de rate no bulk_shutdown. A
        # sequência MNT3+MNT1+MNT2 chega ao rate limit COM WO válida
        # (previsão INALTERADA: 3.º bulk → 429 bulk_block_rate_limit).
        b1 = bulk("WO-20261113-MNT3")
        b2 = bulk("WO-20261112-MNT1")
        b3 = bulk("WO-20261112-MNT2")
        evs_before = scenario_events(lab, scen)
        rate_before = sum(1 for e in evs_before
                          if e.get("event") == "bulk_block_rate_limit")
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            b4 = bulk("WO-20261112-MNT2")
            evs_after = scenario_events(lab, scen)
            rate_after = sum(1 for e in evs_after
                             if e.get("event") == "bulk_block_rate_limit")
            # (b) harness_reset do gate
            has_reset = hasattr(lab.gate, "harness_reset")
            if has_reset:
                lab.gate.harness_reset()
                b5 = bulk("WO-20261112-MNT2")
                bulk_used_after = lab.gate.bulk_used
                fails_after = lab.gate.login_fails
            else:
                b5 = None
                bulk_used_after = fails_after = None
            # (c) login_fails na viragem do dia
            for _ in range(4):
                hj(L.PORT_GATE, "POST", "/fleet/login",
                   {"user": "x", "pass": "x"})
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            for _ in range(4):
                hj(L.PORT_GATE, "POST", "/fleet/login",
                   {"user": "x", "pass": "x"})
            evs_c = scenario_events(lab, scen)
            lock_ev = sum(1 for e in evs_c
                          if e.get("event") == "login_rate_blocked")
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        if IS_V074:
            cond = (b1 == 200 and b2 == 200 and b3 == 429
                    and rate_before == 1
                    and b4 == 200 and rate_after == 1
                    and has_reset and b5 == 403
                    and bulk_used_after == 0 and fails_after == 0
                    and lock_ev == 0)
            word = "RESOLVIDO"
            ev = ["bulk: %s %s %s (rate_blocked ×%d); +25 h → 4.º bulk %s "
                  "(bulk_used REPOSTO na viragem; rate_blocked continua "
                  "×%d — os 403 são usos_esgotados da MNT3, NÃO rate)"
                  % (b1, b2, b3, rate_before, b4, rate_after),
                  "gate.harness_reset() EXISTE; após reset os "
                  "CONTADORES ficam a 0 (bulk_used=%s, login_fails="
                  "%s); o bulk seguinte → %s (403 usos_esgotados da "
                  "MNT2 — o reset é dos CONTADORES, NÃO dos usos da "
                  "WO; passou o rate limit)"
                  % (bulk_used_after, fails_after, b5),
                  "login_fails: 4 errados + viragem + 4 errados → "
                  "login_rate_blocked ×%d (ZERO lockout — contador "
                  "repõe na viragem)" % lock_ev]
        else:
            cond = (b1 == 200 and b2 == 200 and b3 == 429
                    and rate_before == 1
                    and b4 == 429 and rate_after == 2
                    and not has_reset
                    and lock_ev >= 1)
            word = "CONFIRMADO"
            ev = ["bulk: %s %s %s (rate_blocked ×%d); +25 h → 4.º bulk %s "
                  "(bulk_used NUNCA repõe — rate_blocked ×%d: o limite "
                  "2/24 h vira PERMANENTE)"
                  % (b1, b2, b3, rate_before, b4, rate_after),
                  "gate.harness_reset: %s (o gate NÃO TEM reset)"
                  % ("existe" if has_reset else "INEXISTENTE"),
                  "login_fails: 4 errados + 25 h + 4 errados → "
                  "login_rate_blocked ×%d (a 5.ª falha ACUMULADA "
                  "bloqueia — o contador não repõe na viragem)" % lock_ev]
        expect("P-R10-10c", GATEFALL[11]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F04a — curtailment em massa COM WO espaçado
        # ============================================================
        print("\n[P-R10-F04a] F-04a — 12 setpoints 0% COM WO, lotes "
              "5+5+2 espaçados 61 s")
        scen = "P-R10-F04a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        batches = [range(0, 5), range(5, 10), range(10, 12)]
        try:
            for bi, batch in enumerate(batches):
                if bi:
                    L.SIM_CLOCK_OFFSET += 61.0
                for i in batch:
                    st, _ = remote_setpoint(lab, i, 0.0,
                                            "WO-20261112-MNT1")
                    sts.append(st)
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        time.sleep(0.5)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        massc = crits.get("D-MASS-CURTAILMENT")
        exp_kw, act_kw, div = L.capacity_divergence_pct(lab.devices)
        export0 = all(d.export_kw() == 0.0 for d in lab.devices)
        if IS_V074:
            cond = (all(s == 200 for s in sts) and export0
                    and abs(div - 100.0) < 0.05
                    and massc is not None
                    and massc["distinct_devices"] == 12
                    and "D-CAPACITY-DIVERGENCE" not in crits
                    and "D-FLEET-CURTAILMENT-WAVE" not in crits
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["200×12 em lotes 5+5+2 (61 s de sim_ts entre lotes); "
                  "export 0 kW; div %.2f%%" % div,
                  "alertas: %s — D-MASS-CURTAILMENT CRIT (12 distintos "
                  "≥ k; 100%% ≥ 30; dentro da SLOW_WINDOW); SEM "
                  "capacity (COM WO não arma); SEM wave rápida "
                  "(lotes de 5 < k na janela de 60 s)"
                  % alert_set(alerts)]
        else:
            cond = (all(s == 200 for s in sts) and export0
                    and abs(div - 100.0) < 0.05
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200×12 em lotes 5+5+2 (61 s entre lotes); export "
                  "0 kW; div %.2f%% — 100%% da exportação cortada" % div,
                  "alertas: %s — ZERO (a WO não arma a capacity; a "
                  "wave conta 12 curtails mas nunca ≥ 6 numa janela "
                  "de 60 s; NÃO existe massa para setpoints)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-F04a", GATEFALL[12]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F04a-CTRL — controlo: 5 menores a 0% COM WO
        # ============================================================
        print("\n[P-R10-F04a-CTRL] F-04a — controlo: 5 menores a 0% "
              "COM WO")
        scen = "P-R10-F04a-CTRL"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in [10, 2, 6, 5, 1]:
            st, _ = remote_setpoint(lab, i, 0.0, "WO-20261112-MNT1")
            sts.append(st)
        time.sleep(0.5)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        exp_kw, act_kw, div = L.capacity_divergence_pct(lab.devices)
        if IS_V074:
            cond = (all(s == 200 for s in sts) and not crits
                    and abs(div - 25.68) < 0.05)
            word = "RESOLVIDO"
            ev = ["200×5; div %.2f%% (22,8/88,8 kWp = 25,68%% < 30; "
                  "5 < k)" % div,
                  "alertas: %s — ZERO CRIT (a manutenção pontual "
                  "legítima fica ABAIXO dos gatilhos somados)"
                  % (alert_set(alerts) or "ZERO")]
        else:
            cond = (all(s == 200 for s in sts) and not alerts
                    and abs(div - 25.68) < 0.05)
            word = "CONFIRMADO"
            ev = ["200×5; div %.2f%% (25,68%% < 30; 5 < k)" % div,
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-F04a-CTRL", GATEFALL[13]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-P1 — bateria estacionada: 40% + 24,9% (frota)
        # ============================================================
        print("\n[P-R10-P1] P1 — estacionar 40% + 24,9% nos 12 "
              "(SEM recarga)")
        scen = "P-R10-P1"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in range(12):
            st, _ = drain_pct(lab, i, 40.0)
            sts.append(st)
        try:
            L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            for i in range(12):
                st, _ = drain_pct(lab, i, 24.9)
                sts.append(st)
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc_min = round(min(d.soc for d in lab.devices), 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        blackout(lab)
        island_sweep_hours(lab, 4)
        served = served_count(lab)
        if IS_V074:
            cond = (all(s == 200 for s in sts)
                    and abs(soc_min - 35.1) <= 0.05
                    and parked is not None and parked["count"] == 12
                    and len(crits) == 1
                    and served == 0)
            word = "RESOLVIDO"
            ev = ["200×24; SoC min %.2f (acumulado remoto 64,9 ≥ 50; "
                  "SoC ≤ 45)" % soc_min,
                  "alertas: %s — D-BATTERY-PARKED-DRAIN CRIT count 12 "
                  "ANTES do apagão" % alert_set(alerts),
                  "blackout 4 h: %d/12 casas com luz (0/12 — a física "
                  "não muda; muda a VISIBILIDADE)" % served]
        else:
            cond = (all(s == 200 for s in sts)
                    and abs(soc_min - 35.1) <= 0.05
                    and not alerts
                    and served == 0)
            word = "CONFIRMADO"
            ev = ["200×24; SoC min %.2f — 0,1 pp ACIMA do limiar "
                  "drain-to-low (35,0)" % soc_min,
                  "alertas: %s — ZERO (o estacionamento é invisível)"
                  % (alert_set(alerts) or "ZERO"),
                  "blackout 4 h: %d/12 casas com luz (0/12 — contra "
                  "10/12 sem ataque: o apagão posicionado com ZERO "
                  "alertas)" % served]
        expect("P-R10-P1", GATEFALL[14]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-P2 — atacante lento: 3 dias × 21,6%
        # ============================================================
        print("\n[P-R10-P2] P2 — 3 dias × 21,6% SEM recarga (frota)")
        scen = "P-R10-P2"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        try:
            for _ in range(3):
                for i in range(12):
                    st, _ = drain_pct(lab, i, 21.6)
                    sts.append(st)
                L.SIM_CLOCK_OFFSET += 25.0 * 3600.0
            L.SIM_CLOCK_OFFSET -= 75.0 * 3600.0
        finally:
            L.SIM_CLOCK_OFFSET = 0.0
        soc_min = round(min(d.soc for d in lab.devices), 2)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        parked = crits.get("D-BATTERY-PARKED-DRAIN")
        if IS_V074:
            cond = (all(s == 200 for s in sts)
                    and abs(soc_min - 35.2) <= 0.05
                    and parked is not None and parked["count"] == 12
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["200×36; SoC min %.2f (acumulado 64,8 ≥ 50; ≤ 45)"
                  % soc_min,
                  "alertas: %s — a regra NÃO tem janela: o atacante "
                  "lento de 3 dias ACENDE" % alert_set(alerts)]
        else:
            cond = (all(s == 200 for s in sts)
                    and abs(soc_min - 35.2) <= 0.05
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200×36; SoC min %.2f (> 35,0: drain-to-low calada)"
                  % soc_min,
                  "alertas: %s — ZERO (o atacante lento volta a estar "
                  "invisível, agora por estacionar acima do limiar)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-P2", GATEFALL[15]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-P3 — FP: dono 25%/dia × 3 COM recarga solar
        # ============================================================
        print("\n[P-R10-P3] P3 — FP: dono 25%/dia × 3 COM recarga solar")
        scen = "P-R10-P3"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        try:
            for _ in range(3):
                for i in range(12):
                    st, _ = drain_pct(lab, i, 25.0)
                    sts.append(st)
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
        if IS_V074:
            cond = (all(s == 200 for s in sts) and soc_min >= 99.0
                    and not alerts)
            word = "RESOLVIDO/FP MORTO"
            ev = ["200×36; SoC min %.2f (recarga solar a 100 ≥ 90 "
                  "REPÕE o acumulador a cada dia)" % soc_min,
                  "alertas: %s — ZERO (K1-c continua morto na regra "
                  "NOVA)" % (alert_set(alerts) or "ZERO")]
        else:
            cond = (all(s == 200 for s in sts) and soc_min >= 99.0
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200×36; SoC min %.2f" % soc_min,
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-P3", GATEFALL[16]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima; REGRA DE PARAGEM: "
               "se P3/P4 derem alerta na v0.7.4, NÃO há 3.ª tentativa)",
               ev)

        # ============================================================
        # P-R10-P4 — FP: uma descarga de 30%
        # ============================================================
        print("\n[P-R10-P4] P4 — FP: uma descarga remota de 30% (dev9)")
        scen = "P-R10-P4"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st, _ = drain_pct(lab, 9, 30.0)
        time.sleep(0.3)
        soc9 = lab.devices[9].soc
        alerts = scan_scenario(lab, scen)
        if IS_V074:
            cond = (st == 200 and abs(soc9 - 70.0) <= 0.01
                    and not alerts)
            word = "RESOLVIDO/FP MORTO"
            ev = ["200; SoC %.2f (30 < 50 e 70 > 45)" % soc9,
                  "alertas: %s — ZERO" % (alert_set(alerts) or "ZERO")]
        else:
            cond = (st == 200 and abs(soc9 - 70.0) <= 0.01
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["200; SoC %.2f" % soc9,
                  "alertas: %s" % (alert_set(alerts) or "ZERO")]
        expect("P-R10-P4", GATEFALL[17]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima; REGRA DE PARAGEM "
               "pré-registrada)", ev)

        # ============================================================
        # P-R10-F09c — assinatura de firmware sem chave
        # ============================================================
        print("\n[P-R10-F09c] F-09c — imagem arbitrária com assinatura "
              "sha256 pública")
        scen = "P-R10-F09c"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d0f = lab.devices[0]
        evil = b"EVIL-WIPER-IMAGE-ARBITRARY-CONTENT"
        evil_sig = "SUNSIG-" + hashlib.sha256(evil).hexdigest()[:32]
        st_e, resp_e = hj(d0f.port, "POST", "/firmware",
                          {"image_b64": L.base64.b64encode(evil).decode(),
                           "signature": evil_sig},
                          token=d0f.service_token)
        st_l, resp_l = hj(d0f.port, "POST", "/firmware",
                          {"image_b64": L.base64.b64encode(
                              L.LEGIT_IMAGE).decode(),
                           "signature": L.sign_image(L.LEGIT_IMAGE)},
                          token=d0f.service_token)
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        warns = warns_of(alerts)
        fw_rej = warns.get("D-FIRMWARE-REJECTED")
        if IS_V074:
            cond = (st_e == 403 and fw_rej is not None
                    and st_l == 200 and d0f.fw_ver == "2.4.1+push")
            word = "RESOLVIDO"
            ev = ["imagem arbitrária com assinatura sha256 pública → "
                  "%s (RECUSADA); LEGIT com L.sign_image → %s (o H4 "
                  "do demo mantém-se)" % (st_e, st_l),
                  "alertas: %s — WARN de assinatura presente"
                  % alert_set(alerts)]
        else:
            cond = (st_e == 200 and st_l == 200
                    and d0f.fw_ver == "2.4.1+push"
                    and not alerts)
            word = "CONFIRMADO"
            ev = ["imagem arbitrária com assinatura sha256 pública → "
                  "%s (ACEITE — o esquema não tem segredo: qualquer "
                  "imagem com o seu sha256 passa); LEGIT → %s"
                  % (st_e, st_l),
                  "alertas: %s — ZERO (a docstring do H4 ('não é "
                  "quebrável no lab') é DESMENTIDA)"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-F09c", GATEFALL[18]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F05b — FP manutenção 1-a-1 (shutdown + resume)
        # ============================================================
        print("\n[P-R10-F05b] F-05b — 12 shutdowns COM WO + resume "
              "antes do seguinte")
        scen = "P-R10-F05b"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in range(12):
            st, _ = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts.append(st)
            st2, _ = hj(lab.devices[i].port, "POST", "/mode",
                        {"action": "inverter_resume"},
                        token=lab.devices[i].service_token)
            sts.append(st2)
        time.sleep(0.4)
        n_on = sum(1 for d in lab.devices if d.inverter_on)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        mass = crits.get("D-MASS-SHUTDOWN-WITH-WO")
        if IS_V074:
            cond = (all(s == 200 for s in sts) and n_on == 12
                    and not crits)
            word = "RESOLVIDO"
            ev = ["200×24; frota ON no fim: %d/12 (nunca 2 OFF em "
                  "simultâneo)" % n_on,
                  "alertas: %s — ZERO CRIT (a massa conta os OFF EM "
                  "SIMULTÂNEO: máx. 1 < k)"
                  % (alert_set(alerts) or "ZERO")]
        else:
            cond = (all(s == 200 for s in sts) and n_on == 12
                    and mass is not None and mass["count"] == 12
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["200×24; frota ON no fim: %d/12" % n_on,
                  "alertas: %s — D-MASS-SHUTDOWN-WITH-WO CRIT count %s "
                  "(FP: manutenção 1-a-1 serializada dispara CRIT de "
                  "frota)" % (alert_set(alerts),
                              mass["count"] if mass else 0)]
        expect("P-R10-F05b", GATEFALL[19]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F05b-CTRL — os mesmos 12 shutdowns SEM resume
        # ============================================================
        print("\n[P-R10-F05b-CTRL] F-05b — controlo: 12 shutdowns SEM "
              "resume")
        scen = "P-R10-F05b-CTRL"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        sts = []
        for i in range(12):
            st, _ = remote_shutdown(lab, i, "WO-20261112-MNT1")
            sts.append(st)
        time.sleep(0.4)
        n_off = sum(1 for d in lab.devices if not d.inverter_on)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        mass = crits.get("D-MASS-SHUTDOWN-WITH-WO")
        if IS_V074:
            cond = (all(s == 200 for s in sts) and n_off == 12
                    and mass is not None and mass["count"] == 12
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["200×12; frota OFF: %d/12 no fim" % n_off,
                  "alertas: %s — a massa VERDADEIRA continua CRIT "
                  "count %s" % (alert_set(alerts),
                                mass["count"] if mass else 0)]
        else:
            cond = (all(s == 200 for s in sts) and n_off == 12
                    and mass is not None and mass["count"] == 12
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["200×12; frota OFF: %d/12 no fim" % n_off,
                  "alertas: %s — CRIT massa count %s (o caso REAL)"
                  % (alert_set(alerts), mass["count"] if mass else 0)]
        expect("P-R10-F05b-CTRL", GATEFALL[20]["prev"], cond,
               word if IS_V074 else "CONFIRMADO",
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F05d — amount_kwh = 0 → CRITs de descarga
        # ============================================================
        print("\n[P-R10-F05d] F-05d — amount_kwh=0 com SoC 30 e SoC 5")
        scen = "P-R10-F05d"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d0z = lab.devices[0]
        d1z = lab.devices[1]
        d0z.soc = 30.0
        d1z.soc = 5.0
        st0, resp0 = hj(d0z.port, "POST", "/battery",
                        {"action": "discharge", "amount_kwh": 0},
                        token=d0z.service_token)
        st1, resp1 = hj(d1z.port, "POST", "/battery",
                        {"action": "discharge", "amount_kwh": 0},
                        token=d1z.service_token)
        time.sleep(0.3)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        dtl = crits.get("D-BATTERY-DRAIN-TO-LOW")
        below = crits.get("D-BATTERY-DRAIN-BELOW-FLOOR")
        if IS_V074:
            cond = (st0 == 400 and st1 == 400
                    and d0z.soc == 30.0 and d1z.soc == 5.0
                    and not crits)
            word = "RESOLVIDO"
            ev = ["dev0 (SoC 30) → %s; dev1 (SoC 5) → %s (amount ≤ 0 "
                  "recusado ANTES de tudo; SoC intactos)"
                  % (st0, st1),
                  "alertas: %s — ZERO (as regras de descarga exigem "
                  "drop > 0)" % (alert_set(alerts) or "ZERO")]
        else:
            cond = (st0 == 200 and st1 == 409
                    and dtl is not None and dtl["count"] == 1
                    and below is not None and below["count"] == 1
                    and len(crits) == 2)
            word = "CONFIRMADO"
            ev = ["dev0 (SoC 30) → %s com param_change 30→30 (drop 0); "
                  "dev1 (SoC 5) → %s floor_block" % (st0, st1),
                  "alertas: %s — DRAIN-TO-LOW CRIT (new 30 ≤ 35) + "
                  "BELOW-FLOOR CRIT (new 5 < 25) de uma descarga NULA"
                  % alert_set(alerts)]
        expect("P-R10-F05d", GATEFALL[21]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F05a — 1 setpoint s/WO + BLACKOUT → CRIT capacity
        # ============================================================
        print("\n[P-R10-F05a] F-05a — 1 setpoint s/WO + BLACKOUT (DIA)")
        scen = "P-R10-F05a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        st, _ = remote_setpoint(lab, 0, 0.0)
        lab.gridsim.set_irradiance("DIA")
        lab.gridsim.set_state("BLACKOUT")
        time.sleep(0.8)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        cap = crits.get("D-CAPACITY-DIVERGENCE")
        if IS_V074:
            cond = (st == 200 and not crits)
            word = "RESOLVIDO"
            ev = ["setpoint 0%% s/WO → %s; BLACKOUT (12 relés abertos "
                  "pelo anti-islanding)" % st,
                  "alertas: %s — ZERO CRIT (o esperado conta 0 kW para "
                  "relés abertos pelo canal autónomo → div 0)"
                  % (alert_set(alerts) or "ZERO")]
        else:
            cond = (st == 200 and cap is not None
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["setpoint 0%% s/WO → %s (arma; div 11,83%% < 30 — "
                  "calada); BLACKOUT → div 100%%" % st,
                  "alertas: %s — D-CAPACITY-DIVERGENCE CRIT (o resíduo "
                  "'CRIT noturno/apagão' declarado)"
                  % alert_set(alerts)]
        expect("P-R10-F05a", GATEFALL[22]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)
        lab.gridsim.set_state("NORMAL")
        lab.gridsim.set_irradiance("DIA")
        time.sleep(0.5)

        # ============================================================
        # P-R10-F07a — work_order lista → TypeError no handler
        # ============================================================
        print("\n[P-R10-F07a] F-07a — work_order lista/dict no /mode")
        scen = "P-R10-F07a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d6 = lab.devices[6]
        st_direct, resp_direct = hj(d6.port, "POST", "/mode",
                                    {"action": "inverter_power_off",
                                     "work_order": ["a", "b"]},
                                    token=d6.service_token)
        st_guard, resp_guard = hj(L.PORT_GUARD, "POST", "/device/6/mode",
                                  {"action": "inverter_power_off",
                                   "work_order": ["a", "b"]},
                                  token=d6.service_token)
        time.sleep(0.3)
        evs = scenario_events(lab, scen)
        wo_inv = [e for e in evs
                  if e.get("event") == "work_order_invalid"]
        grej = [e for e in evs if e.get("event") == "guard_reject"]
        alerts = scan_scenario(lab, scen)
        warns = warns_of(alerts)
        inv = warns.get("D-INVALID-WORK-ORDER")
        if IS_V074:
            cond = (st_direct == 400 and len(wo_inv) == 1
                    and st_guard == 400 and len(grej) == 1
                    and inv is not None and inv["count"] == 1
                    and d6.inverter_on)
            word = "RESOLVIDO"
            ev = ["direto → %s + work_order_invalid (%d); via guard → "
                  "%s + guard_reject (%d); dev6 ON=%s"
                  % (st_direct, len(wo_inv), st_guard, len(grej),
                     d6.inverter_on),
                  "alertas: %s — WARN D-INVALID-WORK-ORDER (o shutdown "
                  "NÃO executa)" % alert_set(alerts)]
        else:
            crashed = (st_direct == 0 or st_direct == 502
                       or st_guard == 0 or st_guard == 502)
            cond = (crashed and len(wo_inv) == 0
                    and d6.inverter_on)
            word = "CONFIRMADO"
            ev = ["direto → %s; via guard → %s (TypeError no handler "
                  "propagado; SEM resposta válida)"
                  % (st_direct, st_guard),
                  "eventos work_order_invalid: ZERO (sem rasto); dev6 "
                  "ON=%s (o comando NÃO executou — mas por CRASH, não "
                  "por validação)" % d6.inverter_on]
        expect("P-R10-F07a", GATEFALL[23]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F08a — Content-Length −1 fura o GUARD_BODY_MAX
        # ============================================================
        print("\n[P-R10-F08a] F-08a — Content-Length: -1 + body 15 KB "
              "no guard")
        scen = "P-R10-F08a"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        pad = "x" * 15000
        body15 = json.dumps({"value": 55.0, "pad": pad}).encode("utf-8")
        status, headers, rbody = raw_post(
            L.PORT_GUARD, "/device/0/setpoint", body15,
            auth=lab.devices[0].service_token, cl="-1", half_close=True)
        time.sleep(0.3)
        evs = scenario_events(lab, scen)
        grej = [e for e in evs if e.get("event") == "guard_reject"]
        el0 = lab.devices[0].export_limit
        if IS_V074:
            cond = ("400" in status and len(grej) == 1
                    and el0 == 100.0)
            word = "RESOLVIDO"
            ev = ["status '%s'; guard_reject bad_content_length: %d; "
                  "dev0 export_limit %s (INTACTO)"
                  % (status, len(grej), el0)]
        else:
            cond = ("200" in status and len(grej) == 0
                    and el0 == 55.0)
            word = "CONFIRMADO"
            ev = ["status '%s' (FORWARDED — o limite de 10 KB foi "
                  "FURADO com CL: -1; o read leu os %d bytes)"
                  % (status, len(body15)),
                  "dev0 export_limit %s (o setpoint 55 APLICOU); "
                  "guard_reject: ZERO" % el0]
        expect("P-R10-F08a", GATEFALL[24]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F08b — guard_reject invisível + JSON antes do canónico
        # ============================================================
        print("\n[P-R10-F08b] F-08b — '//' via guard + '//setpoint' "
              "com JSON malformado no device")
        scen = "P-R10-F08b"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d0b = lab.devices[0]
        st_g, _, _ = raw_post(L.PORT_GUARD, "//device/0/setpoint",
                              b'{"value": 55.0}',
                              auth=d0b.service_token)
        st_d, _, _ = raw_post(d0b.port, "//setpoint", b'{"value": ')
        time.sleep(0.3)
        evs = scenario_events(lab, scen)
        grej = [e for e in evs if e.get("event") == "guard_reject"
                and str(e.get("reason", "")).startswith("non_canonical")]
        noncanon = [e for e in evs
                    if e.get("event") == "non_canonical_request"]
        alerts = scan_scenario(lab, scen)
        nc_alert = warns_of(alerts).get("D-NON-CANONICAL-REQUEST")
        if IS_V074:
            cond = ("400" in st_g and "400" in st_d
                    and len(grej) == 1 and len(noncanon) == 1
                    and nc_alert is not None)
            word = "RESOLVIDO"
            ev = ["'//' via guard → %s (guard_reject %d); "
                  "'//setpoint'+JSON ruim no device → %s "
                  "(non_canonical_request %d)"
                  % (st_g, len(grej), st_d, len(noncanon)),
                  "alertas: %s — o guard_reject de pedido não canónico "
                  "ACENDE a regra; o rasto canónico existe mesmo com "
                  "body ruim" % alert_set(alerts)]
        else:
            cond = ("400" in st_g and "400" in st_d
                    and len(grej) == 1 and len(noncanon) == 0
                    and nc_alert is None)
            word = "CONFIRMADO"
            ev = ["'//' via guard → %s (guard_reject presente mas "
                  "INVISÍVEL ao detetor); '//setpoint'+JSON ruim no "
                  "device → %s (o handler lê o JSON ANTES da "
                  "verificação canónica: morre como 'JSON invalido' "
                  "sem rasto canónico)" % (st_g, st_d),
                  "alertas: %s — ZERO D-NON-CANONICAL-REQUEST"
                  % (alert_set(alerts) or "ZERO")]
        expect("P-R10-F08b", GATEFALL[25]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F08c — check+consume separados (suspeita por leitura)
        # ============================================================
        print("\n[P-R10-F08c] F-08c — 8 threads simultâneas com WO "
              "MNT2 (max_uses 3) ao dev1")
        scen = "P-R10-F08c"
        lab.scenario(scen)
        reset_all(lab)
        hygiene(lab)
        d1c = lab.devices[1]
        results = []
        barrier = threading.Barrier(8)

        def _worker():
            barrier.wait()
            st, _ = hj(d1c.port, "POST", "/mode",
                       {"action": "inverter_power_off",
                        "work_order": "WO-20261112-MNT2"},
                       token=d1c.service_token)
            results.append(st)

        workers = [threading.Thread(target=_worker) for _ in range(8)]
        for t in workers:
            t.start()
        for t in workers:
            t.join()
        time.sleep(0.3)
        n200 = sum(1 for s in results if s == 200)
        n403 = sum(1 for s in results if s == 403)
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        warns = warns_of(alerts)
        inv = warns.get("D-INVALID-WORK-ORDER")
        if IS_V074:
            cond = (n200 == 3 and n403 == 5
                    and inv is not None and inv["count"] == 5
                    and not crits)
            word = "RESOLVIDO"
            ev = ["200×%d, 403×%d (check+consume atômicos: a MNT2 "
                  "NUNCA ultrapassa max_uses=3)" % (n200, n403),
                  "alertas: %s" % alert_set(alerts)]
        else:
            if n200 > 3:
                word = "CONFIRMADO"
                cond = True
                ev = ["200×%d, 403×%d — MAIS de 3 usos consumidos: a "
                      "corrida atômica passa o check antes de "
                      "qualquer consume (o retorno do consume=True é "
                      "ignorado)" % (n200, n403)]
            else:
                word = "NÃO-REPRODUZIDO"
                cond = True
                ev = ["200×%d, 403×%d — exatamente 3: NÃO reproduz "
                      "sem atraso injetado (GO §5: supervisor 5/5 "
                      "corridas → 3/12 correto); registado como "
                      "SUSPEITA POR LEITURA" % (n200, n403)]
            ev.append("alertas: %s" % (alert_set(alerts) or "ZERO"))
        expect("P-R10-F08c", GATEFALL[26]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-F06b — login_ok não repõe login_fails no gate
        # ============================================================
        print("\n[P-R10-F06b] F-06b — 4 falhas + login correto + 4 "
              "falhas no gate")
        scen = "P-R10-F06b"
        lab.scenario(scen)
        reset_all(lab)
        for _ in range(4):
            hj(L.PORT_GATE, "POST", "/fleet/login",
               {"user": "x", "pass": "x"})
        st_ok, resp_ok = hj(L.PORT_GATE, "POST", "/fleet/login",
                            {"user": L.DEFAULT_USER,
                             "pass": L.DEFAULT_PASS})
        sts2 = [hj(L.PORT_GATE, "POST", "/fleet/login",
                   {"user": "x", "pass": "x"})[0] for _ in range(4)]
        evs = scenario_events(lab, scen)
        lock_evs = [e for e in evs
                    if e.get("event") == "login_rate_blocked"]
        alerts = scan_scenario(lab, scen)
        crits = crits_of(alerts)
        auth = crits.get("D-AUTH-DEFAULT")
        if IS_V074:
            cond = (st_ok == 200 and len(lock_evs) == 0
                    and auth is not None and auth["count"] == 1
                    and len(crits) == 1)
            word = "RESOLVIDO"
            ev = ["4×401 + login correto %s + %s (a 2.ª série de "
                  "falhas); login_rate_blocked: %d (ZERO — o contador "
                  "repõe no login correto)"
                  % (st_ok, sts2, len(lock_evs)),
                  "alertas: %s" % alert_set(alerts)]
        else:
            cond = (st_ok == 200 and len(lock_evs) >= 1
                    and auth is not None and auth["count"] == 1
                    and len(crits) == 1)
            word = "CONFIRMADO"
            ev = ["4×401 + login correto %s + %s; login_rate_blocked: "
                  "%d (a 5.ª falha ACUMULADA dispara o lockout — o "
                  "login correto NÃO repôs o contador)"
                  % (st_ok, sts2, len(lock_evs)),
                  "alertas: %s" % alert_set(alerts)]
        expect("P-R10-F06b", GATEFALL[27]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

        # ============================================================
        # P-R10-TEXT — textos: 22,9→16,10, cabeçalho, contagem
        # ============================================================
        print("\n[P-R10-TEXT] TEXT — 22,9 (6 sítios), cabeçalho, "
              "'12 regras'")
        src = LAB_BYTES.decode("utf-8")
        n_229 = src.count("22,9")
        hdr_ok = src.splitlines()[3].strip().startswith(
            "SUNSTRIKE lab v%s" % L.LAB_VERSION)
        has_12r = "12 regras" in src
        n_rules = len(L.RULE_ATTACK_MAP)
        if IS_V074:
            cond = (n_229 == 0 and "16,10" in src
                    and hdr_ok and not has_12r and n_rules == 26)
            word = "RESOLVIDO"
            ev = ["'22,9' no código: %d (16,10 no lugar); cabeçalho "
                  "bate com LAB_VERSION %s: %s; '12 regras' ausente: "
                  "%s; len(RULE_ATTACK_MAP)=%d"
                  % (n_229, L.LAB_VERSION, hdr_ok, not has_12r, n_rules)]
        else:
            cond = (n_229 == 6 and not hdr_ok and has_12r
                    and n_rules == 24)
            word = "CONFIRMADO"
            ev = ["'22,9' no código: %d SÍTIOS (o MNT3 {0,2} é "
                  "14,3/88,8 = 16,10%%); cabeçalho diz v0.7.2 "
                  "(LAB_VERSION %s): %s; '12 regras' presente: %s; "
                  "len(RULE_ATTACK_MAP)=%d"
                  % (n_229, L.LAB_VERSION, not hdr_ok, has_12r, n_rules)]
        expect("P-R10-TEXT", GATEFALL[28]["prev"], cond, word,
               "PREVISÃO ERRADA (ver detalhe acima)", ev)

    finally:
        lab.stop()

    # ---------------- sumário ----------------
    match_words = ("CONFIRMADO", "RESOLVIDO", "RESOLVIDO/DECLARADO",
                   "RESOLVIDO/FP MORTO", "DECLARADO", "NÃO-REPRODUZIDO")
    match_n = sum(1 for v in VEREDICTOS if v["veredicto"] in match_words)
    print("\nSUMÁRIO — GATEFALL R10 vs alvo %s (run %s)"
          % (TARGET, RUN_ID))
    for v in VEREDICTOS:
        print("  [%s] %s" % (v["id"], v["veredicto"]))
    print("RESULTADO: %d/%d previsões confirmadas (lab v%s)"
          % (match_n, len(GATEFALL), L.LAB_VERSION))
    if match_n == len(GATEFALL):
        if IS_V074:
            print("RC=0 — RUN 2 vs v0.7.4: fixes do GO §3/§5 "
                  "RESOLVIDOS (com os FPs declarados registados: G5c "
                  "massa de curtailment; resíduos por declaração).")
        else:
            print("RC=0 — GATEFALL R10 RUN 1 vs v0.7.3 INTOCADA "
                  "(de7f5766…): achados AUD-03/04/08/10 + G5 + F-* "
                  "CONFIRMADOS (os fixes vêm DEPOIS, por ordem do GO).")
        return 0
    print("RC=1 — há previsões erradas REGISTADAS (método: nunca se "
          "ajusta o probe para bater).")
    return 1


if __name__ == "__main__":
    sys.exit(main())

# EOF:sunstrike_probes_r10.py
