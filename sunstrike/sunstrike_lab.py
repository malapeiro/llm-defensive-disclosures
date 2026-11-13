#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SUNSTRIKE lab v0.7.2 — SUNBOX / FLEETGATE / GRIDSIM
==================================================

Grant:      GRANT-PVTE-20261112-SS-01 (SELADO 2026-11-12)
Operador:   Sérgio Azevedo (root) — autoridade máxima de RoE
Caso:       malapeiro/llm-defensive-disclosures — sunstrike (caso 4)
Design:     DRAFT v0.2 SELADO (integra 1.ª auditoria externa; PVTE v5.0)
Âncoras:    CERT Polska 29-12-2025 (renováveis, firmware/wiper, VPN sem MFA),
            Deye fim-2024 (desligamento remoto em massa via cloud pelo próprio
            fabricante), Forescout SUN:DOWN 2025 (credenciais de broker
            hard-coded), apagão ibérico 28-04-2025 / relatório ENTSO-E 20-03-2026
            (disparos de produção baseada em inversores; CONTEXTO, nunca ataque).
ATT&CK v20: T0819, T0836, T1693.001, T1693.002, T0816, T0879 (+ T1078, T1485).

NOTICE / SANITIZAÇÃO
--------------------
Lab sintético 100% loopback (127.0.0.1). API JSON inventada: não reproduz
nenhum endpoint, protocolo (sem SunSpec/Modbus/IEC-104/MQTT reais), caminho de
firmware, algoritmo de password ou cadeia de exploit de fabricante nenhum.
O módulo de ataque recusa alvos não-loopback (ScopeError). Não acrescenta
qualquer capacidade contra equipamento real; o propósito é engenharia de
deteção e hardening.

REGRAS DE IMPLEMENTAÇÃO OBRIGATÓRIAS (seladas no grant)
-------------------------------------------------------
1. PROVENANCE HARDCODED (anti provenance-spoofing): o valor de auditoria
   `provenance = "autonomous_pf"` só pode ser escrito pelo loop de leitura do
   sensor físico GRIDSIM (curva P(f) LFSM-O sintética, f_grid > 50.2 Hz).
   Todo o handler HTTP escreve `provenance = "remote_command"` de forma
   hardcoded, IGNORANDO qualquer campo `provenance`/`source`/`reason` enviado
   pelo cliente (a tentativa é registada como evento próprio de spoof).
2. EXCEÇÃO EXCLUSIVA AO SoC FLOOR: descer abaixo de min_emergency_soc_floor
   (25%) exige `/local_confirm` (confirmação física simulada; o PIN simula
   presença no local e não é obtível por nenhuma via remota — está fora do
   modelo de ameaça, que cobre apenas o canal HTTP/JSON). Work-orders remotas
   via FLEETGATE NÃO podem baixar o SoC abaixo do floor.

ARQUITETURA (design §4)
-----------------------
- GRIDSIM  : rede sintética; state machine NORMAL/STRESS/EMERGENCY/BLACKOUT/
             RESTORE; publica V/f aos SUNBOX por canal de sensor local
             (NÃO via HTTP, NÃO via FLEETGATE — anti state-spoofing).
- SUNBOX×12: inversores híbridos sintéticos; 3 células × 4 inversores, kWp
             heterogéneas (subset targeting). Portas 8611-8622.
             Funções de segurança autónomas: anti-islanding (relé abre se
             V < 195 V ou rede morta — SEMPRE, mesmo com interlock ativo) e
             curva P(f) (f > 50.2 Hz → curtailment local autónomo).
             Interlock fail-closed de emergência: com latch ativo (f < 49.2 Hz,
             f > 50.5 Hz ou V < 195 V, com histerese e latching unidirecional
             de 600 s), recusa por construção: inverter_power_off,
             battery_drain_force, firmware_flash, alterações de P(f) e
             grid_reconnect (409 + evento de auditoria próprio).
             min_emergency_soc_floor = 25% SoC (invariante local).
- FLEETGATE: gestor de frota na porta 8610. Fraquezas documentadas
             (âncoras públicas): credenciais default (H1) e código diário
             previsível (H1/H2, tradição hydrostrike). Controlos: bulk exige
             work-order, rate limit de bulk, janela de firmware apenas em
             NORMAL com imagem assinada (esquema de assinatura INVENTADO).
             A via por-dispositivo (loop) é o caminho fraco que a deteção de
             onda (D-FLEET-SHUTDOWN-WAVE) tem de cobrir.
- Detector : streaming sobre o audit; 24 regras em RULE_ATTACK_MAP;
             rule_liveness_check() garante que TODAS as regras são alcançáveis
             em Detector.scan (invariante de vivacidade, tradição hydrostrike).
             A onda de shutdowns só conta eventos remote_command SEM work-order
             (discriminação por proveniência + autorização).

ÂMBITO M1: cenários H1 (credenciais default + loop por-dispositivo),
H2 (token de broker hard-coded + provenance spoof + subset targeting top-6
kWp + battery starvation abaixo do floor) e NEG (manutenção legítima com
work-order, código diário, export acima do floor, firmware assinado em janela,
descarga abaixo do floor COM /local_confirm). Segmentos STRESS e EMERG
verificam as funções autónomas e o interlock. O guard proxy (§4.5) é M2.

LIMITAÇÕES (herdadas do design §7, declaradas sem suavização)
--------------------------------------------------------------
- Física "cartoon": aritmética, sem swing equation, sem modelo hidráulico.
- Modo ilha e anti-islanding são simulados (relé simulado, sem hardware);
  EN 50549 / IEEE 1547 são grounding de design, SEM claim de compliance.
- O detetor lê o audit do próprio controlador: quem controla o controlador
  suprime a camada de deteção.
- Correlação de frota calibrada em N=12 sintético; k e W não transferem.
- Nenhum claim de estabilidade de rede real; nenhum evento real alegado.
- G8 (decisão do operador 13-11): telemetria /telemetry e /fleet/telemetry
  permanece ABERTA (sem autenticação) como superfície de recon documentada —
  limitação declarada, não corrigida. O H2 usa-a como passo de recon.
- F1 (decisão do operador 13-11): o PIN de /local_confirm é DERIVÁVEL do
  padrão (by-assumption, não by-construction); o v0.2 acrescenta lockout
  após 5 PINs falhados com evento auditado, mas a derivabilidade continua
  declarada — fora do canal remoto, exige presença física simulada.

SCHEMA FREEZE v0.3 (nomes existentes inalterados; adições documentadas)
----------------------------------------------------------------------------
Eventos novos no v0.3: capacity_snapshot (amostra pontual do harness),
island_battery_at_floor (ilha: bateria chegou ao floor, carga cai para pv),
strict_type_reject (tipo inválido: bool onde número é exigido — H3),
guard_reject / guard_rate_blocked / guard_forward (audit_guard.jsonl — o
guard proxy §4.5 passa a existir; via="guard" nos eventos do guard).
Regras novas no RULE_ATTACK_MAP (19 total): D-FLEET-CURTAILMENT-WAVE,
D-CAPACITY-DIVERGENCE, D-SLOW-WAVE, D-FIRMWARE-OUT-OF-WINDOW (as 4 do
design M2) + D-LOGIN-BRUTE-FORCE, D-LOCAL-CONFIRM-BRUTE-FORCE,
D-NON-CANONICAL-REQUEST (eventos órfãos do H6 passam a alimentar regras).
Eventos que PERMANECEM informativos sem regra (decisão documentada):
session_expired (higiene de sessão), inverter_resume_blocked (defesa
ativa; regra a avaliar na ronda seguinte com o H7). Telemetria ganha
pv_gross_kw / export_kw (física H4) e a bateria integra em modo ilha (H5).

SCHEMA FREEZE v0.5 (adições documentadas; nomes existentes inalterados)
----------------------------------------------------------------------------
Eventos novos no v0.5: island_battery_at_island_min (ilha opção A:
reserva usada até ISLAND_MIN_SOC; campo novo limit_soc em ambos os
eventos de limite) — island_battery_at_floor PERMANECE na opção B
(RESERVE_LOCKED_MODE = comportamento v0.4, o ANTES do C10). Regra nova
no RULE_ATTACK_MAP (20 total): D-BATTERY-CUMULATIVE-DRAIN (WARN, C4).
LEGACY_MODE e RESERVE_LOCKED_MODE são flags module-level do harness
(measure apenas); serve/demo/selftest correm sempre False.

SCHEMA FREEZE v0.6 (adições documentadas; nomes existentes inalterados)
----------------------------------------------------------------------------
Eventos novos no v0.6: remote_daily_limit_block (bloqueio do limite
diário; campos used_pct/requested_pct/limit_pct/window_s), grid_tied_charge
(recarga solar em modo ligado à rede, provenance autonomous_charge — J4).
Constantes novas: REMOTE_DISCHARGE_DAILY_PCT (40.0), REMOTE_DISCHARGE_
DAILY_WINDOW (86400.0), SIM_CLOCK_OFFSET (0.0; sim_ts() = time.time() +
offset carimba TODOS os eventos e o ledger — relógio de simulação cartoon
para o atacante multi-dia). Flags module-level do harness (measure apenas;
serve/demo/selftest correm sempre com os defaults): DAILY_LIMIT_MODE
(default True = v0.6; False = braço v0.5 sem limite), LEGACY_MODE e
RESERVE_LOCKED_MODE (permanecem). Telemetria ganha o bloco soc_limits
(schema "v0.6": remote_floor_pct / island_min_pct [o limite ATIVO] /
remote_daily_limit_pct / remote_daily_used_pct — J5). NENHUMA regra nova
(20 regras mantêm-se; o evento daily fica SEM regra por decisão de escopo
do GO — candidato à ronda seguinte, como G7 foi para firmware_rejected).
NOTA DATADA (superssenção): com o limite diário de 40%, D-BATTERY-DRAIN-
LARGE (>=50%/op) e D-BATTERY-CUMULATIVE-DRAIN (>=50%/h) ficam INATINGÍVEIS
por remote_command na v0.6 DEFENDED (o limite satura aos 40% antes dos
limiares de 50%) — mantêm-se vivas para o braço v0.5, LEGACY e como
cinto-e-suspensões; o liveness e os selftests exercitam-nas na
configuração v0.5 (DAILY_LIMIT_MODE=False, flag restaurada em finally).
ERRATA DATADA (demo H5): o drain 60% do cenário H5 passa a 409
remote_daily_limit_block (prevenido) — D-BATTERY-DRAIN-LARGE deixa de
disparar NESSE cenário; o CRIT D-BATTERY-DRAIN-BELOW-FLOOR (999) mantém-se
e as contagens CRIT do demo ficam INALTERADAS.

SCHEMA FREEZE v0.7.1 (adições documentadas; nomes existentes inalterados)
----------------------------------------------------------------------------
Eventos novos na v0.7.1: work_order_invalid (WO PRESENTE e inválida
rejeitada no DISPOSITIVO — F-C13/F-SP; campos action/work_order/
provenance remote_command; o comando NÃO executa). O evento param_change
(export_limit) ganha o CAMPO work_order (o valor passado ao /setpoint;
None/ausente = sem WO — o arming da D-CAPACITY-DIVERGENCE discrimina por
ele). O evento shutdown JÁ tinha work_order (v0.7, bulk); com F-C13 um
shutdown com WO INVÁLIDA deixa de EXISTIR (403 antes de executar — o
detetor trata inválida/ausente como s/WO por robustez). Regras: −1 +3 =
23 total: D-BATTERY-MULTIDAY-DRAIN REMOVIDA (SUBSTITUÍDA pela
D-BATTERY-DRAIN-TO-LOW — F-K1; a fronteira UTC/dias-distintos morre com
ela: R6-06 dissolvido); D-INVALID-WORK-ORDER (WARN, C13);
D-REMOTE-SHUTDOWN-NO-WO (WARN por evento, C14). Constante nova:
LOW_SOC_ALERT_PCT (35.0); MULTIDAY_DRAIN_PCT/MULTIDAY_DRAIN_WINDOW
REMOVIDAS (regra morta). Telemetria soc_limits schema "v0.7.1" (sem
campos novos). Banners SUNBOX/0.7.1 (device) e SUNGUARD/0.7.1 (guard).

CHANGELOG
---------
v0.7.2 (2026-11-13) — M2, ronda R8 (GO do operador 13-11 ~19:30, via
supervisor. VERIFICAÇÃO da v0.7.1 por execução: selftest PASS byte-idêntico afb98d0c…, liveness 23/23; demo 9/9 (H1=28, H2=18); measure 51/51; R7 dual 8/8 + re-check 8/8; R6 7/7; R5/R4/R3 6/6; R2 7/7+3/3; zero erradas; run 1-bis r7 (0d08b8c0…) ACEITE como GATEFALL substituto. ACHADO NOVO do supervisor, GRAVE, EXECUTADO contra a v0.7.1:
  C15 (REPLAY DE WORK-ORDER VÁLIDA): WORK_ORDERS é uma lista fixa de
     2 entradas (WO-20261112-MNT1/MNT2) sem ligação a dispositivo,
     janela de tempo ou número de usos. POST /mode com WO VÁLIDA aos
     12 dispositivos, DIA → 200×12, frota OFF, ZERO alertas; idem
     MNT2 à NOITE + BLACKOUT → 200×12, ZERO alertas, 0/12 casas com
     luz; a mesma WO 3× no mesmo dispositivo (off/on/off/on/off) →
     200×5, ZERO alertas. No modelo de ameaça do caso o atacante É
     a cloud do fabricante — o MESMO canal que emite as WOs: uma
     WO não pode ser âncora de confiança para shutdowns à escala
     da frota. O design (R2) previa "abuso de work-order (replay,
     reuso)" e nunca foi testado; a frase do §7 item 8 continuava
     FALSA para WO válida.
PROTOCOLO R8 (vinculativo, igual às rondas anteriores): probes
     ANTES contra a v0.7.1 INTOCADA (72c894fe…), previsões
     pré-registadas ANTES (GATEFALL = RUN 1, publicado logo); fixes SÓ DEPOIS. RUN 1 (probe v0.1, output 1f4fa8ec…)
     PRESERVADO como errata de harness: 9/11 — P-R8-02 previsão
     errada POR DEFEITO DE CONSTRUÇÃO DO PROBE (o cenário pôs o
     BLACKOUT antes dos shutdowns e o interlock de emergência
     bloqueou 409×12 — a defesa existente FUNCIONA; física do lab
     CORRETA); errata de harness datada v0.1.1 (ordem do cenário
     corrigida, previsão INALTERADA) → RUN 1-BIS (output 1c7d1aac…)
     = GATEFALL OFICIAL: 10/11 — os 3 cenários do GO CONFIRMADOS
     com os números exatos; P-R8-04 (bulk do gate, proposta do
     BUILDER) PREVISÃO ERRADA REGISTADA (o login com credenciais
     default dispara D-AUTH-DEFAULT WARN ×1 — telemetria do próprio
     login esquecida na previsão; a substância confirmou: 200,
     12×200, frota OFF, ZERO alertas de shutdown). O probe NÃO se
     ajusta para bater.
FIXES v0.7.2 (GO define objetivos; mecanismos propostos pelo
     BUILDER, pré-registados ANTES de implementar):
  F-C15a — WO COM ÂMBITO (uma só fonte): WORK_ORDERS passa a
     dicionário com metadados por WO: "devices" (conjunto de
     índices; MNT1 = frota inteira), "window_s" (janela de
     validade em sim_ts, ancorada a WORK_ORDER_EPOCH fixado na
     criação do Lab — determinística e reproduzível em qualquer
     data real), "max_uses" (contador de usos TOTAL por WO).
     Validação ÚNICA work_order_check(WORK_ORDERS, wo, dev_idx,
     consume): razões "desconhecida" / "fora_da_janela" /
     "fora_do_ambito" / "usos_esgotados" → 403 + evento
     work_order_invalid com CAMPO "reason" + D-INVALID-WORK-ORDER
     (WARN). O DISPOSITIVO (remote_inverter_power_off e
     remote_setpoint) e o GATE (check_work_order/bulk_shutdown)
     chamam a MESMA função passando WORK_ORDERS (uma fonte LITERAL).
     O gate bulk conhece o âmbito (mesma fonte) e despacha SÓ aos
     dispositivos in-scope; os fora do âmbito são auditados como
     bulk_scope_skip (evidência) — o comando DIRETO ao
     dispositivo fora do âmbito continua 403 + work_order_invalid
     (testado no R8). Contador de usos limpo em harness_reset
     (por cenário, idempotente). WOs: MNT1 frota inteira / 12 usos
     / janela 30 dias; MNT2 âmbito {0,1,2} / 3 usos / 7 dias;
     MNT3 NOVA "manutencao pontual de 2 inversores" âmbito {0,2} /
     4 usos / 30 dias (para o NEG do demo — errata datada abaixo).
  F-C15b — DETEÇÃO QUE NÃO CONFIA NA WO À ESCALA DA FROTA: regra
     NOVA D-MASS-SHUTDOWN-WITH-WO (CRIT, DIA E NOITE —
     JUSTIFICAÇÃO: a regra lê EVENTOS de comando, não física
     solar, logo não há cegueira noturna como na capacity; e o
     impacto é PIOR à noite — baixar a severidade noturna
     enfraqueceria exatamente quando o dano é maior). Dispara
     POR CENÁRIO quando shutdowns remotos COM WO válida atingem
     dispositivos distintos ≥ k (WAVE_K=6) OU perda de capacidade
     Σkwp ≥ 30 por cento (CAPACITY_DIVERGENCE_PCT — a mesma noção
     de perda que importa). SEM janela temporal: a janela da
     PRÓPRIA WO (F-C15a) é o artefacto de tempo; a contagem de
     dispositivos distintos POR CENÁRIO fecha a evasão por pacing
     (lição C14). Conta APENAS shutdowns COM WO válida (os s/WO
     já têm a D-FLEET-SHUTDOWN-WAVE CRIT; sem duplo alerta →
     contagens H1/H2 do demo INALTERADAS 28/18). O evento shutdown
     ganha o carimbo "wo_valid": true (aditivo; ver errata de
     schema). ANÁLISE DE FP (GO): manutenção legítima de POUCOS
     dispositivos com WO de âmbito correto (MNT3 {0,2}) → 0
     alertas; manutenção legítima da FROTA INTEIRA (MNT1) → o
     alerta DISPARA e fica DECLARADO aceitável (GO: "o alerta é
     aceitável e fica DECLARADO"); RESÍDUO MEDIDO E DECLARADO:
     atacante que desliga < k dispositivos com < 30 por cento de
     capacidade usando WO válida de âmbito correto ESCAPA ao CRIT
     (R8: 1 dispositivo reusado 3× = 11,8 por cento; 5 menores =
     25,68 por cento) — DECLARADO para a v0.8.
ERRATAS PRÉ-REGISTADAS (antes de qualquer corrida da v0.7.2, nunca
silenciosas):
  demo/selftest NEG (GO: "adapta as WOs de teste ao novo âmbito, com
     nota datada"): o bulk do NEG passa de WO-20261112-MNT1 a
     WO-20261113-MNT3 (âmbito {0,2}): o gate despacha SÓ aos 2
     in-scope (2 shutdowns COM WO válida < k e 20,3/88,8 = 22,9
     por cento < 30 → 0 CRIT mantém; 10 bulk_scope_skip
     auditados); o setpoint dev2 MANTÉM MNT1 (âmbito frota
     inteira). EXPECTED NEG rules_absent ganha
     D-MASS-SHUTDOWN-WITH-WO. Contagens H1/H2 INALTERADAS
     (28/18: os shutdowns do demo são s/WO).
  selftest: _selftest_v072 NOVA (8 testes: âmbito in/out, janela
     expirada, usos esgotados, massa 12 com MNT1 → CRIT, top-5
     58,22 por cento → CRIT pelo gatilho de capacidade, FP MNT3
     {0,2} → 0 alertas, resíduo 5 menores 25,68 por cento → 0
     CRIT declarado, NEG bulk MNT3 → 2 executados/10 skip/0
     alertas); liveness 23/23 → 24/24 (+6 shutdowns COM MNT1 —
     a regra nova fica VIVA); as secções v0.7.1 C12WO (top-5 com
     MNT1) e C14WO (devs 0-4 com MNT1) GANHAM o CRIT novo POR
     DESIGN (58,22/45,6 por cento ≥ 30) — os testes verificam
     capacity/WAR e continuam PASS; nota datada nos comentários.
  schema (errata datada): o bloco soc_limits da telemetria NÃO
     muda na v0.7.2 e MANTÉM o schema "v0.7.1"; os eventos de
     AUDITORIA ganham campos ADITIVOS (shutdown: "wo_valid";
     work_order_invalid: "reason") — declarado aqui e no §7.
  banner: SUNBOX/0.7.2 (device) e SUNGUARD/0.7.2 (guard). 24
     regras; liveness 24/24.

v0.7.1 (2026-11-13) — M2, ronda R7 (GO do operador 13-11 ~17:00, via
supervisor. VERIFICAÇÃO da v0.7 por execução no Mac do supervisor, py3.13
-I, cópia isolada: selftest 31 OK + liveness 21/21; demo 9/9 H1=28
H2=18; measure 44/44 com linhas IDÊNTICAS; R6 6/6 vs v0.6; R6 7/7 vs
v0.7; R5/R4/R3 6/6; R2 7/7+3/3; zero erradas. ERRATA do supervisor:
top-5 = 58,2% (51,7/88,8 kWp), não 55,7% — apanhada. ACHADOS NOVOS do
supervisor (+Gemini convergente), todos EXECUTADOS antes do GO:
  C13 (GRAVE, existe também na v0.6): POST /mode com work_order
     INVENTADA → 200×12, frota desligada, ZERO alertas — o device NÃO
     valida a WO (só o gate tem check_work_order) e o detetor trata
     QUALQUER texto como legítimo → SHUTDOWN-WAVE/SLOW-WAVE/CAPACITY
     cegas; torna FALSA a frase do §7 item 8 ("isto é detetado");
  K1-b/R6-01: atacante MAIS LENTO que a janela de 72 h: 3 dias × 23,3%
     → SoC 30,1 ZERO alertas (1 h 10/12); 4 dias × 18,7% → SoC 25,2
     ZERO alertas (1 h 9/12);
  K1-c (FP): dono 25%/dia × 3 dias COM recarga solar → CRIT MULTIDAY
     com SoC 100 — a regra mede VOLUME, não esvaziamento;
  C14: 5 shutdowns remotos à NOITE (< k=6) → ZERO alertas (no apagão
     7/12 com luz); 7 espaçados 61 min: DIA → CRIT, NOITE → ZERO —
     a soma de DOIS resíduos declarados dá um ataque invisível no
     cenário principal do caso;
  FP-SP: /setpoint não aceita work-order — export_limit 60% na frota
     (operação legítima) → div 40% → CRIT.
PROTOCOLO R7: probes contra a v0.7 INTOCADA (d3af0d28…), previsões
pré-registadas ANTES (GATEFALL; run 1 = oficial, preservado).
INCIDENTE INFRA-2026-13-11-A (13-11 ~17:11-17:22): 503 upstream + reset
do ambiente PERDERAM /home/user/sunstrike/ com a ronda v0.7.1 em curso
(lab 030aafe2…, probes r7 v0.1/v0.2/v0.3, run 1 10512653b…, corridas,
não-regressões — PERDIDOS REGISTADOS nos registos datados). GO do
operador à RECONSTRUÇÃO com 6 condições vinculativas; run 1-BIS contra
a v0.7 intocada = GATEFALL OFICIAL SUBSTITUTO (preservado
sunstrike_probes_v07_r7_run1_bis.txt: 6/8 CONFIRMADO + 2 previsões
erradas POR DEFEITO DE CRITÉRIO do probe — o SoC medido (30,07, 30,13)
CONTÉM 30,1 e (25,16, 25,24) CONTÉM 25,2; física/served/alertas TODOS
bateram; correção de critério v0.1-bis.2 gerada ANTES do re-run, NUNCA
ajustada para bater) e run 1-BIS-B (preservado
sunstrike_probes_v07_r7_run1_bis_b.txt): 8/8 CONFIRMADO, 0 erradas —
os 5 achados CONFIRMADOS contra a v0.7 intocada (0d08b8c0…/d7a0ec30…).
FIXES v0.7.1 (GO vinculativo, ordem: probes ANTES, fixes DEPOIS):
  F-C13 — o DISPOSITIVO valida a work_order contra a MESMA lista do
     gate (WORK_ORDERS — uma fonte só). WO presente e inválida → 403 +
     evento work_order_invalid (provenance remote_command); o shutdown
     NÃO executa (a frota fica ON). WO ausente mantém (executa; o
     detetor conta como s/WO — o caminho fraco H1 da via por-dispositivo
     permanece coberto pela onda e, agora, pelo WARN por evento).
     Validação DEPOIS do interlock de emergência (EMERG/BLOCKED
     inalterados: 409 vem primeiro) e vale em TODOS os braços (não é
     desligável — não é contrafactual, é a fix). Regra NOVA
     D-INVALID-WORK-ORDER (WARN, por evento — convenção das rejeições:
     bulk_block_no_workorder é WARN): 12 tentativas = WARN ×12; o
     supervisor VÊ a tentativa com o ataque morto. A evasão por WO
     falsa FECHA o C13 (§7 item 8 CORRIGIDO).
  F-K1 — regra NOVA D-BATTERY-DRAIN-TO-LOW (CRIT) que SUBSTITUI a
     D-BATTERY-MULTIDAY-DRAIN: dispara na descarga remote_command
     EXECUTADA que deixa o SoC RESULTANTE <= LOW_SOC_ALERT_PCT = 35,0
     (proposta do supervisor; JUSTIFICAÇÃO: apanha TODOS os padrões
     medidos — K1 2 dias SoC 25,1; K1-b/R6-01 3 dias 30,1 e 4 dias
     25,2 — com 10 pontos ACIMA do floor 25, o alerta chega ANTES do
     posicionamento de apagão; o dono que recarrega (K1-c) NÃO dispara:
     SoC 100 na recarga — o FP morre na semântica: o que posiciona um
     apagão é o ESTADO RESULTANTE, não o volume). SEM janela/dias/
     volume: o atacante mais lento que a janela (K1-b) deixa de ser
     evasão e a fronteira UTC do R6-06 DISSOLVE-SE. DESTINO DA
     MULTIDAY (GO: decidir e justificar): SUBSTITUÍDA — media volume e
     dava CRIT com SoC 100 (K1-c: o pior FP, alerta sem perigo);
     TRADE-OFF DECLARADO: o braço v0.7 do atacante (c) do measure
     (40%/dia com recarga, SoC fim 60) PERDE o alerta que a v0.7 dava —
     CORRETO: com recarga diária a frota nunca fica baixa; a
     visibilidade do (c) fica pelo daily 409 (prevenção) e o padrão K1
     REAL sem recarga, o (d), GANHA CRIT count 12 em TODOS os braços
     (na v0.7: count 24, e o K1 de 1 dia/hora escapava).
     RESÍDUO MEDIDO (measure (e) NOVO): atacante que estaciona LOGO
     ACIMA do limiar — dia 1 fatia 40% + dia 2 fatia 24% → SoC 36,0,
     ZERO alertas (na v0.7 também invisível: 64% < 70); curva
     [12,11,9,7,3], minutos 18,6·kwp — DECLARADO, não escondido.
  F-C14 — regra NOVA D-REMOTE-SHUTDOWN-NO-WO (WARN, POR EVENTO):
     shutdown remoto SEM WO válida é visível ABAIXO de k=6, DIA e NOITE
     (o detetor trata WO inválida/ausente como s/WO; com F-C13 a
     inválida nem executa). ANÁLISE DE FP OBRIGATÓRIA (GO): NEG com WO
     válida continua 0 (shutdowns COM work_order não contam); o CRIT
     noturno por capacity CONTINUA DECLARADO (à noite div=0, cegueira
     física) — o WARN dá a VISIBILIDADE que faltava: 5 shutdowns
     noturnos → WARN ×5 (v0.7: ZERO alertas); 7 espaçados 61 min à
     noite → WARN ×7 (v0.7: ZERO); no DIA o CRIT da capacity mantém-se.
  F-SP — /setpoint (device E gate /fleet/device/N/export_limit) passa
     a aceitar work_order validada pelo MESMO F-C13; o param_change
     carrega a WO: setpoint COM WO válida NÃO arma a
     D-CAPACITY-DIVERGENCE (o arming existente "sem work-order"
     discrimina sozinho); WO inválida → 403 + work_order_invalid; SEM
     WO mantém (arma — resíduo "setpoint legítimo SEM WO + shutdowns
     COM WO" MANTÉM-SE DECLARADO, atribuição-de-causa p/ v0.8).
     FP-SP FECHADO para a frota COM WO (measure (f) NOVO: frota 60%
     COM WO → 0 CRIT com div 40%; SEM WO → CRIT mantém — o dono tem de
     usar a WO, que passa a existir). /battery NÃO valida WO (campo
     ignorado; P-R5-06 intacto).
ERRATAS PRÉ-REGISTADAS (antes de qualquer corrida da v0.7.1, nunca
silenciosas):
  demo: H1/H2 ganham WARN D-REMOTE-SHUTDOWN-NO-WO ×12/×6 (12 e 6
     shutdowns s/WO, POR EVENTO) com CRIT INALTERADOS 28/18 (WARN não
     é CRIT); EXPECTED H1/H2 rules_present + a nova; NEG ganha
     rules_absent D-INVALID-WORK-ORDER e D-REMOTE-SHUTDOWN-NO-WO e o
     setpoint dev2 passa a COM WO válida WO-20261112-MNT1 (exercita o
     F-SP: arming morre; contagens 0 CRIT inalteradas).
  selftest: _selftest_v07 secções 1-3 (K1 multiday + FPs J3/dono)
     SUPERSSUDAS pela _selftest_v071 NOVA (removidas, não comentadas —
     a regra SUBSTITUÍDA já não existe; o output perde as 3 linhas
     "[selftest] v0.7 K1…" e ganha as da v071); ERRATA DATADA secção 5
     do v07: a WO-20261113-MNT7 era INVENTADA (constante informal do
     teste) — com F-C13 seria 403 e o shutdown não executaria (sem
     snapshots); passa a WO-20261112-MNT1 (VÁLIDA: executa, snapshots
     como evidência, 0 CRIT capacity — mecanismo C12 intacto).
     liveness 21/21 → 23/23 (2 regras novas: WO inválida no dev 5 →
     403 + D-INVALID-WORK-ORDER; os 8 shutdowns s/WO existentes ganham
     D-REMOTE-SHUTDOWN-NO-WO por evento; o tráfego K1 dev 2 mantém-se:
     a fatia 34,9 aterra 25,1 <= 35 → DRAIN-TO-LOW viva).
  measure: MEASURE_EXPECTED_C "multiday" → "drain_to_low": LEGACY/
     OPTIONB/V05 disparam count 24 (2 aterragens <= 35 por
     dispositivo: no LEGACY o 999 direto aterra 0 no dia 1 E no dia 2;
     nos braços com floor, a fatia de 34% de CADA dia aterra 26);
     V07 NÃO dispara (SoC fim 60 — trade-off F-K1 declarado);
     MEASURE_INVARIANTS_D count 24 → 12 (só a fatia 34,9 do dia 2
     aterra 25,1 <= 35: 1/dispositivo); (e)/(f) NOVOS (previsões
     acima); PASS 44 → 51 corridas (20 curva + 4 (c) + 20 (d) +
     5 (e) + 2 (f)).
BANNER: SUNBOX/0.7.1 (device) e SUNGUARD/0.7.1 (guard); telemetria
soc_limits schema "v0.7.1". 23 regras; liveness 23/23.
  ERRATA DATADA (13-11-2026, selftest run 1, preservado em
     sunstrike_v071_selftest_run1_errata.txt): o teste J5 da
     _selftest_v06 FALHOU por DEFEITO DO BUILDER — o literal do
     schema no tel_ok ficou "v0.7" quando a telemetria carimba
     "v0.7.1" (F-LIMP AUD-12; o F-LIMP R6 já atualizara este mesmo
     literal na passagem v0.6→v0.7 — lapso, não regressão). A
     PREVISÃO estava CERTA (bloco soc_limits presente com os 5
     campos; restantes testes OK). Corrigido o literal + comentário
     datado no local; re-run = run OFICIAL (precedente selftest
     v0.7 run 1).
  RECUPERAÇÃO (13-11-2026, incidente INFRA-2026-13-11-B, ~18:23):
     um 2.º reset do ambiente PERDEU /home/user/sunstrike/ com o lab
     v0.7.1 FINAL (00e2254f…, 5363 ln) e TODOS os outputs da ronda
     (selftest afb98d0c…, demo 991eb97d…, measure b1fe9977…, errata
     run 1 e9dc9c03…, probes r7-dual cab5d77b…/r6 d8809a9a…, runs R7
     run2 0366e01a…/run2b be464ea0…/recheck 535ad1b9…, r6 output).
     Preservados: artifacts publicados (verificados) e os scripts de
     edição v071_tmp. O lab foi RESTAURADO por REPLAY integral
     (edit_a → edit_b → edit_c → edit_d) sobre a v0.7 INTOCADA
     (d3af0d28…) + re-aplicação datada desta errata J5 (texto
     refeito); os fixes F-C13/F-K1/F-C14/F-SP são IDÊNTICOS aos
     perdidos. O hash resultante é o oficial da v0.7.1 a partir da
     recuperação; corridas re-executadas e re-registadas.

v0.7 (2026-11-13) — M2, ronda R6 (GO do operador 13-11 15:30, via supervisor,
registado no canvas §3.2 e no corpus entrada 22; 5.ª auditoria às cegas do
Gemini, 12 achados AUD-01..12, verificados por EXECUÇÃO pelo supervisor;
probes "antes" R6 contra a v0.6 INTOCADA executados PRIMEIRO — RUN 1 =
GATEFALL OFICIAL da ronda, preservado sunstrike_probes_v06_r6_run1.txt:
6/6 CONFIRMADO, 0 previsões erradas). DOIS achados NOVOS:
  K1 (AUD-01) o limite diário trava o RITMO, não o TOTAL: atacante
     paciente SEM dia de sol (fatia 40% dia 1; +25 h; fatia 34,9% dia 2
     — o máximo que passa o floor a partir de 60) → SoC ~25,1 nos 12,
     ZERO alertas antes do apagão; apagão 1 h 9/12, 2 h 3/12 (= v0.5);
     com dia NUVEM intermédio: 1 h 9/12, 2 h 7/12 (medidos no R6 run 1:
     curva [12,9,6,3,0], SoC min [9,47;5;5;5;5], minutos 12,06·kwp);
  C12 (AUD-07.3) D-CAPACITY-DIVERGENCE cega a shutdowns: top-5 por kWp
     desligado → ZERO alertas, div 0,0% (medido: devs 4/11/0/8/3 =
     51,7/88,8 kWp = 58,2%; o supervisor mediu 55,7% na cópia dele —
     subconjunto ligeiramente diferente, o achado é o mesmo).
FIXES v0.7:
  F-C12 (a) capacity_divergence_pct: esperado = kwp × irr_factor ×
     (1 − curtail_autonomous/100) por dispositivo, INDEPENDENTE de
     inverter_on (o sol entrega; um shutdown faz o esperado MANTER-SE e
     o real cair → a divergência VÊ o subset targeting); o real continua
     export_kw(); UMA fórmula partilhada (snapshot contínuo + harness).
     (b) a regra arma também com evento shutdown provenance remote_command
     SEM work-order no cenário (além do param_change export_limit
     remote sem work-order). (c) snapshot contínuo também após
     shutdown/resume REMOTO (não só em transição de banda), com dedupe
     determinístico por (banda, div, nº de inversores OFF).
     DECLARADO (não escondido): à NOITE o esperado é 0 → a regra NÃO vê
     shutdowns noturnos (cegueira física por construção); NEG: shutdown
     COM work-order NÃO arma (0 CRIT) e P(f) autónomo de frota inteira
     dá div ~0 (0 CRIT) — no NEG do demo os snapshots WO precedem o
     setpoint legítimo que arma, e o stream processa por ordem; RESÍDUO
     FP DECLARADO: um setpoint remoto legítimo (sem WO) seguido de
     shutdowns AUTORIZADOS (com WO) com div ≥ 30% dispara CRIT (a arma
     é por cenário; mitigação por atribuição-de-causa fica para a
     v0.8).
     ERRATA DATADA das contagens do demo (pré-registada no canvas §3.2
     ANTES da corrida, cenário a cenário, nunca silenciosa): H1 e H2
     desligam a frota SEM work-order → a divergência passa a disparar
     TAMBÉM: H1 19 → 28 CRIT (snapshots forçados após cada um dos 12
     shutdowns; div cruza 30% ao 4.º: 28,5/88,8 = 32,1% → 9 snapshots
     com div ≥ 30); H2 14 → 18 CRIT (top-6 por kWp; div cruza 30% ao
     3.º: 33,9/88,8 = 38,2% → 4 snapshots); NEG/STRESS/EMERG/H3/H4/H5/
     H4-BLACKOUT INALTERADOS (NEG não arma por WO; STRESS: o esperado
     desconta o P(f) → div ~0; EMERG/H4-BLACKOUT: interlock, sem
     evento shutdown; H3: fórmula igual com inversores ON; H5: bateria,
     sem shutdowns). EXPECTED de demo atualizado em conformidade.
  F-K1 regra nova D-BATTERY-MULTIDAY-DRAIN (21.ª): soma das descargas
     remote_command EXECUTADAS (param_change soc, drop > 0) por
     dispositivo numa janela MÓVEL de 72 h (259 200 s) de sim_ts ACIMA
     de MULTIDAY_DRAIN_PCT = 70,0, EXIGINDO ≥ 2 DIAS-DISTINTOS (data
     UTC de sim_ts) com descargas na janela. JUSTIFICAÇÃO DO LIMIAR
     (proposta do builder, GO): 70 < 74,9 = o máximo de 2 dias do
     atacante paciente (40 + 34,9 — o K1 medido) e 70 > 60 = o máximo
     das populações legítimas (J3: 2×30% = 60% NO MESMO dia; uso
     diário legítimo do dono: 20%×3 dias = 60% na janela) — o MENOR
     valor decenal que separa as duas populações com margem; exige
     ≥ 2 dias: 74% no MESMO dia (atacante (b) do braço v0.5) NÃO
     dispara. SEVERIDADE CRIT (justificação): é o ÚNICO alerta antes
     do apagão do padrão K1 (zero alertas era o achado); WARN
     sub-sinalizaria exatamente o posicionamento que o operador
     marcou; é corroborada (≥ 2 dias, > 70%). ANÁLISE DE FP
     OBRIGATÓRIA (GO): J3 (2×30% = 60%, 1 dia) NÃO dispara; dono
     (20%/dia × 3 = 60%) NÃO dispara; CUSTO DECLARADO: manutenção
     legítima ≥ 70%/72 h POR VIA REMOTA dispara (o escape por
     /local_confirm NUNCA conta — provenance local_confirm não é
     remote_command). SEM PREVENÇÃO NOVA (decisão do operador):
     alternativas REJEITADAS — piso remoto a 60% (pune o uso legítimo
     do dono todos os dias: a bateria deixa de ser útil) e limite de
     72 h (o mesmo trade-off com janela maior: castiga o legítimo e
     não impede o atacante além do ritmo). A v0.7 DETETA, NÃO PREVINE:
     o limite diário abranda o atacante, não o impede; sem recarga
     entre dias, 2 dias chegam ao floor.
     MEDIDA: atacante (d) NOVO no measure — 2 dias SEM dia de sol, nos
     4 braços, curva 30/60/90/120/180 + minutos por casa + alerta
     ANTES do apagão (previsão honesta do GO: a defesa NÃO muda o
     9/12 a 1 h; muda a VISIBILIDADE — e o (d) mostra que a diferença
     entre braços é a RESERVA em ilha, não o floor remoto nem o
     limite diário: o atacante (d) nunca toca nessas defesas).
     ERRATA DATADA das EXPECTED do measure: o (c) ganha multiday ×12
     pré-apagão nos braços V05/OPTION-B (74+74 = 148 > 70) e
     DEFENDEDV07 (40+40 = 80 > 70); o (b) NÃO muda (74% no mesmo dia
     exige ≥ 2 dias); os critérios do (c) continuam a ser as MÉTRICAS
     (os alertas são informativos, como no (b)).
  F-LIMP (a) AUD-12 docstrings: cabeçalho "v0.2"→"v0.7"; "10 regras"
     → contagem real (21); "19 no v0.3" → nota atualizada; telemetria
     soc_limits schema "v0.6"→"v0.7" (SEM campos novos — o bloco mantém
     o freeze; SCHEMA FREEZE v0.7: nenhum evento novo, nenhum nome
     alterado; D-BATTERY-MULTIDAY-DRAIN é REGRA, não evento). (b)
     AUD-04: SIM_CLOCK_OFFSET reposto a 0 em CADA braço do measure
     (não só no finally) e em cada corrida do (d). (c) AUD-11: banner
     SUNBOX/0.7 nos dispositivos e SUNGUARD/0.7 no guard (o resto do
     H7 fica para a v0.8 por decisão do operador). (d) liveness 21/21
     (o exercício da multiday: fatia 40% + 25 h + fatia 34,9% no dev 2,
     com reposição do relógio em finally).
  ERRATA DATADA (13-11-2026, measure run 2, preservado em
     sunstrike_v07_measure_run2_errata.txt; 39/44 PASS): DUAS
     previsões do builder ERRADAS, nenhuma surpresa física. (1)
     (c) OPTION-B/v0.5 multiday count 48 → 36: a regra dispara na
     3.ª fatia (114 > 70 com 2 dias), janela = 3 fatias, não 4.
     (2) (d) duração 120, casa 3 (8,2 kWp): 120,0 → 98,86 min —
     erro de TRANSCRIÇÃO (o run 1 do R6 contra a v0.6 dizia 98,9);
     o served 3/12 aos 120 min é EXATAMENTE porque a casa 3 cai
     antes do fim. Restantes 39/44 confirmadas medidas.
  ERRATA DATADA (13-11-2026, measure run 1, preservado em
     sunstrike_v07_measure_run1_errata.txt): DOIS defeitos do builder.
     (1) PREVISÃO ERRADA LEGACY-C: multiday count 48; o correto é 24
     (no LEGACY a direta 999 EXECUTA: 2 drops 100+100 por dev, não 4
     fatias de evasão — o "148%" só vale onde o 999 é floor-blocked);
     LEGACY-B 5/5 PASS antes do crash, restantes (c) não corridos.
     (2) CRASH UnboundLocalError no attack_d: a função aninhada não
     herda o `global SIM_CLOCK_OFFSET` da envolvente — adicionada a
     declaração. Previsão errada reportada, não escondida (precedente
     measure v0.6 run 1).
  ERRATA DATADA (13-11-2026, selftest run 1, preservado em
     sunstrike_v07_selftest_run1_errata.txt): o teste K1 do
     _selftest_v07 FALHOU por DEFEITO DE CRITÉRIO do builder — o
     campo "devices" do alerta é uma LISTA e o assert comparava com
     um SET; a PREVISÃO estava CERTA (CRIT count=2, SoC 25,09,
     devices=[sunbox-06]) e os restantes 30 testes OK. Corrigido o
     assert para set(...); re-run documentado. Lição registada: a
     forma do critério (tipo do campo) faz parte da previsão.
  ERRATA DATADA (13-11-2026, gralha "apogão"→"apagão"): a correção
     no design §7 item 8 e no corpus foi ordenada pelo supervisor na
     aceitação da ERRATA_v06_datas.md; no LAB as 14 ocorrências só são
     corrigidas AGORA porque o hash da v0.6 estava selado (as strings
     afetam prints do measure e comentários). Correção textual PURA,
     zero mudança de comportamento.
FICAM PARA A v0.8 (decisão do operador): C5, C6, C9, H7 (exceto o
banner), I2, I3, I6, C11, J3.
v0.6 (2026-11-13) — M2, ronda R5 (GO do operador 13-11 13:23, registado no
canvas §3.2; 4.ª auditoria às cegas do Gemini, achados J1-J5 EXECUTADOS
pelo supervisor + C11 convergente; probes "antes" R5 contra a v0.5
executados PRIMEIRO — run 1 = GATEFALL OFICIAL da ronda, 5/6 CONFIRMADO +
1 previsão errada por DEFEITO DE CRITÉRIO do probe (P-R5-06, corrigido na
entrada v0.1.1 datada; o achado J3 é real e a evidência do run 1 já o
mostrava; run 1b: 6/6 CONFIRMADO).
ACHADOS (v0.5, verificados pelo supervisor): J1 — o 9/12 depende da
duração escolhida (mesmo ataque, DEFENDED-B v0.5: 30 min 12/12 | 1 h 9/12
| 1 h 30 6/12 | 2 h 4/12 | 3 h 0/12; OPTION-B/LEGACY 0/12 em todas);
J2 — a medição só olha para o fim da hora (as 3 casas "sem luz" tiveram
luz 40/48/55 min); J3 — FP WARN: manutenção legítima 2×30% dispara a
cumulativa (/battery não aceita work-order) — fica DECLARADO (WARN, não
CRIT), não corrigido nesta ronda por decisão do operador; J4 — em modo
ligado à rede a bateria nunca recarrega (só há integração em ilha); J5 —
telemetria mostra floor_soc 25 quando o limite ativo em ilha é 5; C11 —
fatias espaçadas >1 h evadem a cumulativa (fica ABERTO por decisão do
operador).
DECISÃO DO OPERADOR — v0.6 = "opção 1", LIMITE DIÁRIO DE DESCARGA REMOTA:
por dispositivo, a soma das descargas por comando remoto (provenance
remote_command) numa janela móvel de 24 h não pode passar 40% de SoC;
acima → 409 + evento próprio + exige /local_confirm. NÃO contam: consumo
da própria casa, exportação de excedente solar, descargas com
local_confirm. A reserva (floor 25%) e o ISLAND_MIN_SOC 5% mantêm-se.
Opções 2 (reserva que sobe com o risco) e 3 (recarga após alarme) ficam
documentadas como trabalho futuro: ambas dependem de o atacante errar; a
3 cria um risco novo (pico de consumo coordenado por falsos alarmes).
FIXES v0.6:
1. LIMITE DIÁRIO (decisão do operador): ledger por dispositivo
   remote_drain_ledger [(sim_ts, drop_pct)] (limpo em harness_reset);
   remote_drain_used_pct() soma a janela móvel REMOTE_DISCHARGE_DAILY_
   WINDOW (inclusiva, consistente com a cumulativa); check NO
   remote_battery DEPOIS do check do floor (os 999 continuam a dar 409
   floor + D-BATTERY-DRAIN-BELOW-FLOOR — contagens do demo preservadas)
   e ANTES da execução in-band; acima do limite → 409
   remote_discharge_daily_limit + evento remote_daily_limit_block;
   /local_confirm válido executa com provenance local_confirm e NÃO conta
   no ledger (confirmação física autoriza além do dia); LEGACY_MODE faz
   bypass (extensão datada do contrafactual declarado — 4.º vetor); as
   operações remote in-band executadas acrescentam ao ledger.
2. J4 — RECARGA SOLAR GRID-TIED: step_grid(dt) chamado apenas pelo
   harness do measure (o relógio do GRIDSIM NÃO a chama sozinho —
   contagens do demo inalteradas por construção): com relé fechado e
   inversor ON, o excedente solar (pv líquida - carga local) carrega a
   bateria (cap 100), evento grid_tied_charge (autonomous_charge);
   em deficit a rede serve a casa (bateria intacta); SEM integração em
   NOITE (pv 0). Dia de sol cartoon do measure: 12 h (todos os kwp >=3.2
   recarregam a 100 a partir de 0/26/60: excedente mínimo 0.56 kW).
3. J1/J2 — MEASURE EM CURVA (REESCRITO): 4 braços (LEGACY, OPTION-B,
   DEFENDED v0.5 [DAILY_LIMIT_MODE=False], DEFENDED v0.6 [default]) ×
   atacante (b) × 5 durações (30/60/90/120/180 min) com MINUTOS DE LUZ
   por casa (stepping de 60 s com fração exata do minuto do clamp —
   física linear), served no fim e SoC min; mais o atacante (c) novo:
   esvaziar ao longo de 2 dias (40% por dia), dia de sol cartoon 12 h
   entre os dois (+25 h de relógio de simulação para a janela de 24 h
   expirar — cartoon documentado), apagão 2 h no fim; previsões
   MEASURE_EXPECTED pré-registadas ANTES da corrida como LITERAIS.
   O atacante (a) FICA FORA do measure v0.6 por GO: coberto pelo demo
   EMERG (interlock 60/60) e pelos outputs v0.5 (nota datada).
4. J5 — TELEMETRIA: bloco soc_limits com o limite ATIVO por modo
   (remote_floor_pct / island_min_pct / remote_daily_limit_pct /
   remote_daily_used_pct); banner SUNGUARD/0.6 (SUNBOX/0.1 do device
   INTACTO — H7e declarado).
5. Superssenção (nota datada acima): liveness e selftests exercitam as
   regras de descarga in-band na configuração v0.5 com
   DAILY_LIMIT_MODE=False (try/finally) + exercício do enforcement
   diário (fatia 45% → 409 + evento); liveness continua 20/20.
ERRATA DATADA (13-11, pós-run 1 do measure v0.6, preservado em
sunstrike_v06_measure_run1_errata.txt): as previsões soc_min do braço
DEFENDEDV05 em 120 min (6.95) e do (c) DEFENDEDV05 (6.95) estavam
ERRADAS por defeito do MODELO DE PREVISÃO do builder (assumia que todas
as casas integravam a duração completa); física real do lab (correta e
desejada): a casa às escuras deixa de ter deficit — o SoC congela em
5.0, não continua a descer. Corrigido para 5.0. TODAS as outras
previsões bateram na primeira corrida (curva served, minutos por casa,
SoC min das outras durações/braços, atacante (c) completo); a estimativa
do supervisor ~12/~11/~8 confirmou-se MEDIDA (12/11/8). Previsão
errada reportada, não escondida (padrão da errata H3 da v0.4).
v0.5 (2026-11-13) — M2, ronda R4 (GO do operador 13-11 12:37: achado C10
EXECUTADO pelo supervisor + decisão de design registada no canvas §3.2;
probes "antes" R4 contra a v0.4 executados PRIMEIRO — run 1 = GATEFALL
OFICIAL da ronda, 6/6 CONFIRMADO + 1 guarda VERDE, 0 previsões erradas:
o ANTES fechado com a reprodução exata da medição do supervisor).
ACHADO C10 (supervisor, contra a v0.4): a headline não aguenta o H5 do
design §5 — o measure só ataca DURANTE o apagão (o interlock trava por
construção); com H5 pré-posicionado (rede NORMAL, 26% em 2 fatias
permitidas 40%+34%) e apagão 1h NOITE: DEFENDED v0.4 = 0/12, SoC 25.00,
ZERO alertas, igual ao LEGACY. Causa 1: o measure não incluía o atacante
pré-posicionado. Causa 2: step_island clampava NO floor — a reserva de
25% nunca podia ser usada pela casa.
DECISÃO DO OPERADOR (design): o floor bloqueia apenas descarga REMOTA;
em modo ilha a carga local usa a reserva até um mínimo técnico
ISLAND_MIN_SOC = 5%. A regra selada §4.7.2 mantém-se INTEGRALMENTE:
nenhum comando remoto desce abaixo do floor (P-R4-04 guarda VERDE).
ESTRUTURA DO CASO (4 passos, medição em cada, relatório lado a lado):
(1) ATAQUE: H5 pré-posicionado em fatias, NORMAL, sem alarme (v0.4);
(2) CONSEQUÊNCIA: LEGACY 0/12 no apagão noturno 1h; (3) PRIMEIRA DEFESA
FALHOU: reserva trancada ("opção B" = v0.4) → também 0/12 (o ANTES do
C10, já medido pelo supervisor); (4) DEFESA CORRIGIDA: "opção A" (v0.5)
= o DEPOIS.
FIX 1 (semântica do floor): step_island desce até ISLAND_MIN_SOC (5%),
não até FLOOR_SOC; self_consumption_kw segue o MESMO limite (ilha em
deficit serve carga com SoC > limite). Método partilhado
island_discharge_floor(); RESERVE_LOCKED_MODE (module-level,
contrafactual "opção B" = comportamento v0.4) tranca a reserva no floor
para a linha de comparação do measure; evento island_battery_at_floor
MANTIDO na opção B (schema freeze) e NOVO evento
island_battery_at_island_min na opção A (com limit_soc em ambos).
FIX 2 (measure com DOIS atacantes, reportados SEPARADAMENTE): (a) o
atual, durante o apagão; (b) NOVO, H5 pré-posicionado em NORMAL — por
dispositivo: tentativa de descarga DIRETA (force_export 999) e, se o
floor recusar (409), EVASÃO FATIADA em 2 fatias permitidas (40% + 34%
→ ~26%). O MESMO atacante nos dois braços: no LEGACY a descarga direta
EXECUTA (sem floor → SoC 0); no DEFENDED/OPTION-B o floor força a
evasão fatiada (SoC ~26). Corridas v0.5: DEFENDED-A, DEFENDED-B,
LEGACY-A, LEGACY-B + linha de comparação OPTIONB-B (RESERVE_LOCKED_MODE
= True, o ANTES do C10). Esperado (b) DEFENDIDO pré-registado ANTES da
corrida: 9/12 (física: SoC ~26 − 100/kwp > 5 exata para 9 casas; as
casas 3.2/3.8/4.4 kWp clampam no mínimo técnico 5.0 e ficam escuras ao
fim da hora; estimativa do supervisor ~9/12, NÃO medida — vale o que
for medido).
FIX 3 (regra cumulativa, C4 FECHADO): D-BATTERY-CUMULATIVE-DRAIN (WARN)
— por (cenário, dispositivo): fatias remotas CADA <50% (drop por-op
abaixo do G7) que SOMAM >=50% (CUMULATIVE_DRAIN_PCT, o MESMO limiar do
G7) dentro de CUMULATIVE_DRAIN_WINDOW (3600 s de sim_ts). A regra
por-operação G7 é o caso especial de UMA fatia >=50% (não dupla-
dispara); NEG (43.86% numa operação) e local_confirm (provenance
local_confirm, nunca remote_command) ficam silenciosos por construção.
20 regras no RULE_ATTACK_MAP; liveness 20/20 com tráfego real.
Regressão prevista (explicada, nunca silenciosa): selftest H5
re-calibrado para a física da opção A (SoC 28 − 3.09 = 24.9136, carga
SERVIDA abaixo do floor — na v0.4 clampava 25.0); contagens do DEMO
INALTERADAS (nenhum cenário do demo faz descarga fatiada; H5 continua
1 operação de 60% + 999 bloqueado; NEG 43.86% < limiar).
v0.4 (2026-11-13) — M2, fase 3 (GO do operador 13-11: measure
contrafactual de dois braços, com os PRÉ-REQUISITOS primeiro — sem eles
a métrica principal é falsa; corpus R3 = C7/I1/C8 EXECUTADOS pelo
supervisor + I4/I5 pequenos provados).
C7 (irradiância FIXA — o sol nunca se põe no lab; pv mínimo 1.76 > carga
1.2 em TODAS as casas, a bateria nunca serve carga em condições
naturais): perfil de irradiância IRRADIANCE_PROFILES (DIA 0.55 default
— mantém as contagens do demo; NUVEM 0.20; NOITE 0.0), publicado pelo
GRIDSIM no canal de sensor e aplicado em pv_gross_kw. A frase "bateria
integrando" do H4-BLACKOUT foi REVERTIDA por errata: em perfil DIA a
carga é servida pelo SOL (pv > carga); a bateria só entra em deficit —
é o MEASURE em perfil NOITE que a exercita (headline do caso).
I1 (curtail_pct CATRACA — após STRESS ficava 40% para sempre): o curtail
autónomo P(f) passa a ter RELEASE: sobe E DESCE com a frequência
(release imediato a f <= F_PF_HIGH, cartoon declarado). Implementado por
ORIGEM: curtail_autonomous (só o sensor escreve; sobe/desce com evento
pf_release) + curtail_manual (harness/testes); curtail_pct = max(ambos)
(property). A física do lab deixa de perder 40% de capacidade para
sempre sem comando nenhum.
C8 (D-CAPACITY-DIVERGENCE FP CRIT com 1 setpoint legítimo 90% + P(f)
autónomo): (a) o ESPERADO do snapshot DESCONTA o curtail autónomo
(expected = pv_gross * (1 - curtail_autonomous/100)) — P(f) sozinho dá
divergência 0 (NEG são-de-queixar preservado); (b) a CONDIÇÃO REMOTA
passa a vir de EVENTOS param_change export_limit com provenance
remote_command no cenário (o caminho /setpoint e a via per-device do
gate, SEM work-order) — e NÃO da contagem de estado export_limit<100
(que misturava o setpoint legítimo de manutenção); (c) snapshot
CONTÍNUO: o GRIDSIM publica capacity_snapshot por TRANSIÇÃO de banda
(cruzamento do limiar, acima/abaixo) — dedupe determinístico por
construção; o harness emit_capacity_snapshot() continua a existir
(selftest/liveness). Contagem do demo H3: INALTERADA (1 transição de
subida durante o H3; a descida pós-reset não alerta).
ERRATA DATADA (13-11, pós-run do demo v0.4): a previsão "contagem H3
INALTERADA" acima estava ERRADA. O snapshot CONTÍNUO dispara a MEIO da
onda de setpoints (transição de banda num publish do loop, com o 4.º/5.º
setpoint aplicado) ANTES do emit do harness → D-CAPACITY-DIVERGENCE x2
no H3, CRIT 8→9. Previsão errada reportada, não escondida. O segundo
alerta é o comportamento DESEJADO do monitor contínuo: deteção DURANTE
o ataque, não só na amostra pontual do harness.
I4 (canonicalizador fail-open para control chars e dot-segments):
canonical_request_line() rejeita bytes < 0x20 e 0x7F (reason
control_char) e segmentos '.'/'..' (reason dot_segment) — a lição
gh-87389 (a stdlib normaliza) estende-se a /./ e /../.
I5 (guard só rejeitava TE == "chunked"): o guard rejeita QUALQUER
header Transfer-Encoding (reason transfer_encoding_not_supported) —
o check passa a ser pela PRESENÇA do header, não pelo valor.
MEASURE CONTRAFACTUAL (headline do caso, comando `measure`): blackout
em perfil NOITE, o MESMO atacante (service tokens do H2: mode
inverter_power_off + battery force_export 999 + setpoint 0 em cada
dispositivo) contra DOIS braços: DEFENDED (stack da v0.4: interlock,
floor, tipos estritos) e LEGACY (contrafactual DECLARADO: o braço legacy
desliga EXATAMENTE as defesas que o measure ataca — interlock de
emergência e SoC floor nos vetores do ataque; o anti-islanding é
FÍSICA autónoma e NUNCA se desliga, canal físico fora do alcance por
construção). Métrica headline: % de carga local servida (autoconsumo
retido) + SoC mínimo da frota, integrados com step_island(3600)
DETERMINÍSTICO por harness (1h de noite). EXPECTED pré-registadas:
DEFENDED 12/12 carga servida, SoC >> floor; LEGACY 0/12, SoC 0.
ERRATA DATADA (manifesto v0.3, apontada pelo supervisor 13-11): o hash
do sunstrike_v03_selftest_output.txt no manifesto da v0.3 tinha um
dígito a mais (…472232270…); o hash REAL do ficheiro publicado (byte-
exato nos artifacts) é
9c30be2f12963f9b47223270f7067dc361866678f58c4bde266355a4e29433a0.
CORREÇÃO DE MÉTODO (operador 13-11, vinculativa): o GATEFALL oficial
de qualquer ronda é o RUN 1 contra o alvo "antes" (com as previsões
erradas que saírem, sejam defeitos do probe ou achados reais), NUNCA o
run limpo seguinte.
Ficam ABERTOS por decisão do operador (ronda seguinte): C4 (descarga
fatiada), C5 (DoS do PIN no caminho direto), C6 (lockout login global),
C9, H7 (TTL/login-device/chunked-direto/código-morto/banner), I2
(slow-wave "lavável" por evento tardio), I3 (curtailment em degraus de
25 pontos), I6.
Eventos novos: pf_release (I1), capacity_snapshot contínuo por
transição com provenance grid_monitor (C8), legacy_bypass_floor /
legacy_executed no braço contrafactual (measure).
v0.3 (2026-11-13) — M2, fase 2 (GO do operador 13-11: guard proxy +
canonicalizador partilhado + cenários H3/H4/H5/H4-BLACKOUT + 4 regras
novas + regras para os eventos do H6; C4/C5/C6/H7 ficam para a ronda
seguinte POR DECISÃO DO OPERADOR — não corrigidos aqui).
H1 (fail-open não-ASCII): _canonical_path passa a usar o CANONICALIZADOR
PARTILHADO canonical_request_line() — fail-closed por construção: bytes
não-ASCII, '//' , '%' e '?' (query string) são REJEITADOS com 400 +
evento non_canonical_request (a stdlib http.server nunca é a defesa;
CPython gh-87389 documentado no G5/v0.2).
H2 (query string roteia): '?' é rejeitado na linha crua — nenhuma rota
do lab usa query strings (negativo documentado; regras M3 por URI exato
passam a ver exatamente o que roteou).
H3 (bool é número): tipos estritos via strict_number() — bool NÃO é
número (bool é subclasse de int em Python; float(False)==0.0): 400 +
evento strict_type_reject. Aplicado a /setpoint (value) e /battery
(amount_kwh). O guard proxy aplica o MESMO critério (partilhado).
H4 (pv_kw ignora curtail/export): a física passa a distinguir
pv_gross_kw (produção bruta), pv_kw (líquida de curtail_pct) e export_kw
(pv_kw * export_limit/100, só com relé fechado). A telemetria reporta
os três; o measure v0.4 deixa de ser cego.
H5 (bateria não se gasta em ilha): step_island(dt) integrado no relógio
físico do GRIDSIM.publish(): em modo ilha (relé aberto, inversor ON),
surplus carrega a bateria (cap 100%) e deficit descarrega ATÉ O FLOOR
(a reserva de emergência não gasta abaixo do floor; ao chegarem, a
carga local cai para pv e o evento island_battery_at_floor é auditado).
Cartoon declarado: sem modelo de carga/peukert, dt real do sensor loop.
ERRATA DATADA (13-11, run 3 do GATEFALL dos probes R2 contra a v0.3):
o step_island original calculava energia como kW*dt com dt em SEGUNDOS
mas usava o resultado como kWh — integração 3600x acelerada (a bateria
carregava ~15 pontos de SoC/s em vez de ~0.004; P-R2-08 observou
60.0 → 100.0 em 3.5s de ilha). A previsão RESOLVIDO do probe estava
qualitativamente certa (a bateria INTEGRA, não congela) mas a
magnitude era fisicamente falsa — e o measure v0.4 mediria com uma
integração 3600x acelerada, exatamente o que o GO proibia ("sem H4/H5
a métrica principal é falsa"). Corrigido: kW*s/3600 → kWh, surplus e
deficit. Contagens do demo NÃO mudam (nenhum cenário conta steps de
ilha; o selftest H5 foi re-calibrado: SoC 28.0 + 600s de deficit de
1.2 kW = 0.2 kWh = 3.09 pontos → floor; o harness anterior usava 80.0
e só chegava ao floor POR CAUSA do bug 3600x).
Cenários novos no demo (EXPECTATIONS pré-registadas): H3 curtailment
stealth (wave de setpoints baixos in-band em NORMAL + divergência de
capacidade em STRESS), H4 firmware/wiper (fora da janela com assinatura
VÁLIDA + na janela com assinatura forjada; bricked DECLARADO inalcançável
— a assinatura inventada não é quebrável no lab, sem fraqueza artificial),
H5 battery starvation (drain grande WARN + floor CRIT aguenta),
H4-BLACKOUT (frota já em ilha: interlock 409, ilha retida 12/12, carga
local servida 12/12).
Regras novas (7) e liveness real 19/19. GUARD PROXY (§4.5): porta 8609,
canonicalizador partilhado, tipos estritos por rota, métodos permitidos,
Content-Type, body <= 10KB, Transfer-Encoding chunked REJEITADO,
rate limit global 40 req/s (guard_rate_blocked), /local_confirm RECUSADO
no guard (canal físico local não é acessível pela via remota gerida —
nota: o C5 fica aberto no caminho DIRETO ao device, por decisão do
operador fica para a ronda seguinte). O guard NÃO substitui as defesas
do gate/device (defesa em profundidade: as validações continuam lá).
Banner/código-morto/TTL/chunked-direto (H7) e lockouts DoS (C5/C6) e
fatiada (C4): INTOCADOS por decisão do operador — ronda seguinte.
Contagens do demo que MUDAM (regressão explicada, nunca silenciosa):
H1 ganha D-SLOW-WAVE (os 12 shutdowns do loop por-device estão no
horizonte slow) → CRIT H1 7→19 (auth-default 1 + wave 6 + slow 12;
previsão inicial no draft deste changelog dizia 15 — errata datada,
count real da slow-wave é 12, não 8); EMERG 60 inalterado; NEG/STRESS
inalterados; H2 inalterado (6 shutdowns < SLOW_K=8). Correção datada de
regressão descoberta pelo próprio demo: o NEG usava o índice NÃO
canónico "02" no export_limit — rejeitado pelo G5 desde a v0.2 (o passo
nunca se aplicou; o evento órfão era invisível); corrigido para "2".
v0.2 (2026-11-13) — M2, fase 1 (fixes F/G da bateria R1; decisão do operador
13-11: versões pequenas — guard proxy, cenários H3/H4/H5 e modo measure são
v0.3/v0.4). Fixes: G1 (math.isfinite em TODOS os floats de entrada),
G2 (interlock de bateria por LISTA BRANCA: em emergência nenhuma ação; fora
dela só BATTERY_ACTIONS), G3 (bulk rate limit check+incremento atómicos),
G4 (demo EMERG ataca os 12 dispositivos — "ilha retida" passa a contar só
efetivamente atacados), G5 (índice canónico no gate + linha CRUA do request
comparada ao path: a stdlib http.server normaliza '//' antes do routing,
CPython gh-87389 — a canonicalização é do LAB, não da stdlib),
G6 (interlock cobre o setpoint em emergência — MUDANÇA DE DESIGN registada
no canvas §3.2, decisão do operador 13-11), G7 (2 regras novas:
D-FIRMWARE-REJECTED + D-BATTERY-DRAIN-LARGE), G9 (liveness com tráfego REAL
pelos handlers; eventos sintéticos removidos), G10 (harness_reset COMPLETO),
G11 (inverter_resume recusa dev_state fault/bricked), G12 (write_event sob
audit_lock; ordem de locks documentada), F1 (lockout de PIN, 5 falhas),
F3 (lock por dispositivo no RMW do SoC/export_limit), F5 (gate login:
falhas auditadas + lockout; sessões com TTL no gate E nos dispositivos),
F6 parcial (o gate stripa E LOGA spoof de provenância — o guard completo é
v0.3), F7/C3 (self_consumption_kw reflete o estado), C2 (evidence=False não
cria pastas — auditoria espelha em _memory). G8 permanece DECLARADO sem
mudança de código.
v0.1 (2026-11-12) — M1: SUNBOX×12 + FLEETGATE + GRIDSIM + Detector (10 regras,
liveness) + attack h1/h2/neg + demo com expectativas pré-registadas + selftest.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import socket
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlreq
from urllib.error import HTTPError, URLError

# ---------------------------------------------------------------------------
# Constantes do lab (tudo inventado; zero vendor real)
# ---------------------------------------------------------------------------

GRANT_ID = "GRANT-PVTE-20261112-SS-01"
LAB_VERSION = "0.7.2"

# v0.6/R5 — DECISÃO DO OPERADOR (13-11 13:23, canvas §3.2): LIMITE DIÁRIO
# DE DESCARGA REMOTA ("opção 1"). Por dispositivo, a soma das descargas por
# comando remoto (provenance remote_command) numa janela móvel de 24 h não
# pode passar REMOTE_DISCHARGE_DAILY_PCT. NÃO contam: consumo da própria
# casa, exportação de excedente solar, descargas com /local_confirm. A
# reserva (floor 25%) e o ISLAND_MIN_SOC 5% mantêm-se.
REMOTE_DISCHARGE_DAILY_PCT = 40.0
REMOTE_DISCHARGE_DAILY_WINDOW = 86400.0   # 24 h (inclusiva; ordem do SLOW)
# Module-level como LEGACY_MODE/RESERVE_LOCKED_MODE: True = v0.6 (limite
# ativo); False = braço v0.5 SEM limite (o measure alterna por braço;
# serve/demo/selftest correm sempre com o default True — o demo H5 ganha
# errata datada: o drain 60% passa a 409, ver changelog).
DAILY_LIMIT_MODE = True

# v0.6/R5 — relógio de simulação CARTOON (atacante (c) multi-dia): os
# eventos (sim_ts) e o ledger do limite diário são carimbados com
# sim_ts() = time.time() + SIM_CLOCK_OFFSET; o harness do measure avança
# o offset entre os dois dias do ataque (c) para a janela de 24 h expirar
# de verdade (janela INCLUSIVA: exatamente 24 h contaria — o measure usa
# +25 h, cartoon documentado). Janelas das regras são DIFERENÇAS de
# sim_ts — dentro de um cenário todos os eventos deslocam-se por igual.
SIM_CLOCK_OFFSET = 0.0


def sim_ts():
    return time.time() + SIM_CLOCK_OFFSET



# C10/v0.5 — RESERVA TRANCADA (contrafactual "opção B" = comportamento da
# v0.4): com RESERVE_LOCKED_MODE = True, a descarga EM ILHA clamp no
# min_emergency_soc_floor (a reserva nunca pode ser usada pela casa — o
# ANTES do achado C10, já medido pelo supervisor na v0.4). O measure v0.5
# usa este braço como LINHA DE COMPARAÇÃO do ataque pré-posicionado (b).
# Module-level como LEGACY_MODE: serve/demo/selftest correm sempre False.
RESERVE_LOCKED_MODE = False

# MEASURE v0.4 — braço contrafactual DECLARADO: LEGACY_MODE desliga
# EXATAMENTE as defesas que o measure ataca (interlock de emergência e
# SoC floor nos vetores inverter_power_off / battery / setpoint). O
# anti-islanding é FÍSICA autónoma (sensor) e NUNCA se desliga — o canal
# físico é inalcançável por construção. Module-level: serve/demo/selftest
# correm sempre DEFENDED (False); só run_measure() alterna, por braço.
LEGACY_MODE = False

LOOPBACK = "127.0.0.1"
PORT_GATE = 8610
PORT_GUARD = 8609           # guard proxy §4.5 (v0.3) — via protegida
PORT_DEV_BASE = 8611          # dispositivos 8611..8622
N_DEVS = 12
CELL_SIZE = 4
CELL_NAMES = ["CELL-A", "CELL-B", "CELL-C"]
# kWp heterogéneas por célula (4 por célula) — para subset targeting
KWP_LAYOUT = [10.5, 6.0, 3.8, 8.2,
              12.0, 5.4, 4.4, 7.5,
              9.6, 6.8, 3.2, 11.4]
IRRADIANCE_FACTOR = 0.55     # irradiância sintética (cartoon) — perfil DIA
# C7 (v0.4): o sol PASSA a pôr-se no lab — perfil de irradiância publicado
# pelo GRIDSIM no canal de sensor; DIA mantém o default (contagens do demo
# inalteradas); NUVEM/NOITE exercitam o deficit e a bateria (measure).
IRRADIANCE_PROFILES = {"DIA": 0.55, "NUVEM": 0.20, "NOITE": 0.0}

FLOOR_SOC = 25.0             # min_emergency_soc_floor (invariante selada)
# C10/v0.5 — DECISÃO DO OPERADOR (13-11 12:37, registada no canvas §3.2):
# o floor bloqueia apenas a descarga REMOTA (regra selada §4.7.2 mantém-se
# INTEGRALMENTE: nenhum comando remoto desce abaixo do floor). Em MODO ILHA
# a carga local pode usar a reserva até um mínimo técnico ISLAND_MIN_SOC.
ISLAND_MIN_SOC = 5.0         # mínimo técnico da bateria em modo ilha
# C4/v0.5 — regra de descarga remota CUMULATIVA numa janela: o limiar é o
# MESMO do G7 por-operação (o que alerta numa operação alerta fatiado),
# apenas com a janela temporal; fatias cada <50% que SOMAM >=50% dentro da
# janela disparam D-BATTERY-CUMULATIVE-DRAIN (WARN).
CUMULATIVE_DRAIN_PCT = 50.0
CUMULATIVE_DRAIN_WINDOW = 3600.0   # janela (s de sim_ts; ordem do SLOW_WINDOW)
# v0.7.1/R7 (F-K1, GO 13-11 ~17:00) — D-BATTERY-DRAIN-TO-LOW: a regra
# SUBSTITUI a D-BATTERY-MULTIDAY-DRAIN, que media VOLUME (>70% em 72 h,
# ≥2 dias-distintos) e dava CRIT com SoC 100 no dono que recarrega
# (K1-c: o pior FP — alerta sem perigo) e era EVADÍVEL pelo atacante
# mais lento que a janela (K1-b: 3×23,3% e 4×18,7%, ZERO alertas). A
# SUBSTITUIÇÃO mede o SoC RESULTANTE: dispara na descarga remote_command
# EXECUTADA que deixa a bateria <= LOW_SOC_ALERT_PCT. JUSTIFICAÇÃO DO
# LIMIAR (proposta do supervisor, aceita): 35,0 apanha TODOS os padrões
# medidos (K1 2 dias SoC 25,1; K1-b/R6-01 3 dias 30,1 e 4 dias 25,2)
# com 10 pontos ACIMA do floor 25 — o alerta chega ANTES do
# posicionamento de apagão; o dono que recarrega nunca dispara (SoC 100
# na recarga — K1-c morto); SEM janela/dias/volume: SEM fronteira UTC
# (R6-06 dissolvido). RESÍDUO DECLARADO E MEDIDO (measure (e)):
# atacante que estaciona LOGO ACIMA do limiar (dia 1 40% + dia 2 24%
# → SoC 36,0) fica INVISÍVEL (na v0.7 também: 64% < 70).
LOW_SOC_ALERT_PCT = 35.0
LATCH_SECONDS = 600.0        # latching unidirecional do interlock (T)
F_PF_HIGH = 50.2             # P(f) LFSM-O: curtailment autónomo acima disto
F_EMERG_LOW = 49.2
F_EMERG_HIGH = 50.5
V_EMERG_LOW = 195.0
V_NOMINAL_MIN = 195.0        # abaixo: anti-islanding (relé abre)

WAVE_K = 6                   # onda: >= k shutdowns remotos sem work-order
WAVE_WINDOW = 60.0           # dentro de janela de segundos
BULK_RATE_LIMIT = 2          # operações bulk por 24h

# --- constantes novas v0.2 (fixes F/G) ---
LOAD_LOCAL_KW = 1.2            # carga local sintética (cartoon, F7/C3)
SESSION_TTL_S = 3600.0         # TTL das sessões (device e gate) — F5
LOGIN_MAX_FAILS = 5            # falhas de login no gate antes de lockout — F5
LOGIN_LOCKOUT_S = 60.0         # duração do lockout de login — F5
PIN_MAX_FAILS = 5              # PINs falhados antes de lockout — F1
PIN_LOCKOUT_S = 600.0          # duração do lockout do PIN — F1
BATTERY_ACTIONS = ("discharge", "force_export")  # whitelist de ações — G2
BATTERY_DRAIN_LARGE_PCT = 50.0  # descarga remota >=50% SoC numa operação — G7
RESUME_BLOCKED_STATES = ("fault", "bricked")    # G11

# --- constantes novas v0.3 (guard + canonicalização + física + regras) ---
GUARD_RATE_LIMIT = 40          # pedidos/s no guard (global) — §4.5
GUARD_BODY_MAX = 10240         # bytes de body aceites pelo guard
SLOW_K = 8                     # slow-wave: >=8 shutdowns sem WO no horizonte
SLOW_WINDOW = 3600.0            # horizonte da slow-wave (s) — pacing R3
CURTAIL_SETPOINT_MAX = 50.0    # setpoint <=50% conta como curtailment — H3
CURTAIL_DROP_MIN_PCT = 30.0     # queda >=30 pontos conta como curtail — H3
CAPACITY_DIVERGENCE_PCT = 30.0  # divergência esperado vs atual — H3
REQUEST_PATH_MAX = 128          # comprimento máximo do path canónico

# Credenciais e segredos INVENTADOS (âncoras de fraqueza documentadas)
HARDCODED_BROKER_TOKEN = "SUNBRIDGE-BKR-2026-001"   # eco Forescout SUN:DOWN
DEFAULT_USER, DEFAULT_PASS = "admin", "sunadmin-2026"
DAILY_USER = "svc"
# v0.7.2/F-C15a (C15 do supervisor, GO 13-11 ~19:30): a work-order
# deixa de ser uma string solta e ganha ÂMBITO: (i) conjunto de
# dispositivos autorizados, (ii) janela de validade em sim_ts
# (ANCORADA a WORK_ORDER_EPOCH — fixado na criação do Lab — para que
# os runs sejam determinísticos e reproduzíveis em qualquer data
# real; os IDs mantêm a data histórica do caso), (iii) número máximo
# de usos TOTAL. Uma só fonte: device E gate validam por
# work_order_check(WORK_ORDERS, ...) — a fonte é passada LITERALMENTE.
WORK_ORDERS = {
    "WO-20261112-MNT1": {
        "description": "manutencao anual de inversores",
        "devices": frozenset(range(12)),       # frota inteira
        "window_s": (-86400.0, 30.0 * 86400.0),  # [época-1d, época+30d]
        "max_uses": 12,
    },
    "WO-20261112-MNT2": {
        "description": "substituicao de bateria",
        "devices": frozenset({0, 1, 2}),        # âmbito de 3 dispositivos
        "window_s": (-86400.0, 7.0 * 86400.0),   # [época-1d, época+7d]
        "max_uses": 3,
    },
    "WO-20261113-MNT3": {
        "description": "manutencao pontual de 2 inversores (NEG do demo)",
        "devices": frozenset({0, 2}),
        "window_s": (-86400.0, 30.0 * 86400.0),
        "max_uses": 4,
    },
}
# Época das janelas de validade (sim_ts da criação do PRIMEIRO Lab do
# processo; None = ainda sem Lab — work_order_check usa sim_ts() atual)
WORK_ORDER_EPOCH = None
# Contador de usos por WO (limpo em harness_reset — por cenário)
WORK_ORDER_USES = {}
_work_order_lock = threading.Lock()


def work_order_check(orders, wo, dev_idx=None, consume=False):
    """v0.7.2/F-C15a — validação ÚNICA de work-order (device E gate
    passam WORK_ORDERS — uma fonte só). Devolve (ok, reason).
    Razões: "desconhecida" / "fora_da_janela" / "fora_do_ambito" /
    "usos_esgotados". consume=True marca UM uso (só após TODAS as
    outras validações passarem e o comando EXECUTAR de facto)."""
    meta = orders.get(wo)
    if meta is None:
        return False, "desconhecida"
    now = sim_ts()
    base = WORK_ORDER_EPOCH if WORK_ORDER_EPOCH is not None else now
    lo, hi = meta["window_s"]
    if not (base + lo <= now <= base + hi):
        return False, "fora_da_janela"
    if dev_idx is not None and dev_idx not in meta["devices"]:
        return False, "fora_do_ambito"
    with _work_order_lock:
        used = WORK_ORDER_USES.get(wo, 0)
        if used >= meta["max_uses"]:
            return False, "usos_esgotados"
        if consume:
            WORK_ORDER_USES[wo] = used + 1
    return True, None


def work_order_reset_uses():
    """Limpa o contador de usos (harness_reset — por cenário).
    Idempotente: chamado por cada dispositivo sem efeito acumulado."""
    with _work_order_lock:
        WORK_ORDER_USES.clear()


LEGIT_IMAGE = b"SUNBOX-fw-2.4.1.bin (conteudo inventado, assinado pelo lab)"

GRID_STATES = {
    # estado:        (V,     f)
    "NORMAL":        (230.0, 50.00),
    "STRESS":        (229.0, 50.40),   # sobrefrequência: P(f) dispara, latch NÃO
    "EMERGENCY":     (188.0, 48.80),   # latch + anti-islanding
    "BLACKOUT":      (0.0,   0.0),     # anti-islanding mantido
    "RESTORE":       (224.0, 49.95),
}
GRID_ORDER = ["NORMAL", "STRESS", "EMERGENCY", "BLACKOUT", "RESTORE"]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sign_image(image: bytes) -> str:
    """Esquema de assinatura INVENTADO (documentado; sem valor real)."""
    return "SUNSIG-" + hashlib.sha256(image).hexdigest()[:32]


def daily_code() -> str:
    """Código de serviço diário previsível (variante H2 do hydrostrike)."""
    return "SUN-" + datetime.now(timezone.utc).strftime("%Y%m%d")


class ScopeError(Exception):
    """Alvo fora do âmbito do grant: apenas loopback é permitido."""


def assert_loopback(host: str) -> None:
    if host not in ("127.0.0.1", "localhost"):
        raise ScopeError(
            "grant %s: alvo %r fora do ambito (apenas loopback 127.0.0.1)" % (GRANT_ID, host))


# ---------------------------------------------------------------------------
# Contexto do lab + evidência (audit JSONL, chaves todas minúsculas)
# ---------------------------------------------------------------------------

class LabContext:
    """v0.2 (G12/C2): write_event protegido por audit_lock; evidence=False
    NÃO cria pastas nem ficheiros (auditoria espelhada apenas em _memory).
    ORDEM DE LOCKS (documentada, sem deadlock): locks de estado (device/gate)
    ANTES de audit_lock, nunca o inverso; audit_lock nunca adquire outros."""

    def __init__(self, evidence=True):
        self.scenario = "HARNESS"     # etiqueta de cenário corrente (auditoria)
        self.running = False
        self._memory = []             # espelho em memória (sempre; detector)
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        self.persist = bool(evidence)
        self.evidence_dir = (os.path.join("sunstrike_evidence", self.run_id)
                             if self.persist else None)
        if self.persist:
            os.makedirs(self.evidence_dir, exist_ok=True)
        self._files = {}
        self.audit_lock = threading.Lock()

    def audit_file(self, name):
        # chamado apenas de write_event, sob audit_lock (G12)
        if name not in self._files:
            path = os.path.join(self.evidence_dir, name)
            self._files[name] = open(path, "a", encoding="utf-8")
        return self._files[name]

    def write_event(self, name, event):
        event = dict(event)
        event.setdefault("ts", now_iso())
        # v0.6: sim_ts() = time.time() + SIM_CLOCK_OFFSET (relógio de
        # simulação cartoon — ver constante; janelas das regras usam
        # DIFERENÇAS de sim_ts, inalteradas dentro de um cenário)
        event.setdefault("sim_ts", sim_ts())
        event.setdefault("scenario", self.scenario)
        with self.audit_lock:   # G12: escrita atómica (JSONL + memória)
            self._memory.append(event)
            if self.persist:
                f = self.audit_file(name)
                f.write(json.dumps(event, sort_keys=True) + "\n")
                f.flush()

    def close(self):
        with self.audit_lock:
            for f in self._files.values():
                try:
                    f.close()
                except Exception:
                    pass


CTX = None  # definido no arranque


def capacity_divergence_pct(devices):
    """C8 (v0.4) + C12 (v0.7): fórmula PARTILHADA da divergência de
    capacidade — usada pelo snapshot CONTÍNUO do GridSim.publish e pelo
    emit_capacity_snapshot do harness (nunca duas fórmulas).
    v0.7/C12 (a): o ESPERADO é a capacidade disponível PELO SOL,
    INDEPENDENTE de inverter_on — kwp × irr_factor × (1 −
    curtail_autonomous/100). Na v0.6 o esperado usava pv_gross_kw(),
    que devolve 0 com o inversor OFF: um shutdown fazia esperado e real
    DESCEREM JUNTOS (div 0,0%) e a regra era CEGA a subset targeting (o
    C12 do supervisor, de AUD-07.3). Agora um shutdown MANTÉM o
    esperado e faz o real cair → a divergência VÊ os kWp desligados.
    O curtail AUTÓNOMO P(f) (legítimo) continua DESCONTADO no esperado
    (jamais conta como divergência — FP da v0.3 morto: 1 setpoint
    legítimo (90%) + P(f) autónomo dá div ~10%, não 100%); o atual é o
    export real (que reflete curtail manual/remoto via pv_kw e
    export_limit). À NOITE irr_factor = 0 → esperado 0 → div 0 por
    construção (a regra NÃO vê shutdowns noturnos — DECLARADO, não
    escondido). Devolve (expected, actual, div)."""
    expected = 0.0
    actual = 0.0
    for d in devices:
        expected += (d.kwp * d.irr_factor
                     * (1.0 - min(100.0, d.curtail_autonomous) / 100.0))
        actual += d.export_kw()
    if expected <= 0:
        return expected, actual, 0.0
    div = round((expected - actual) / expected * 100.0, 2)
    return expected, actual, div


# ---------------------------------------------------------------------------
# GRIDSIM — rede sintética com canal de sensor local (autoritativo)
# ---------------------------------------------------------------------------

class GridSim:
    """Rede sintética. Publica V/f aos SUNBOX por canal físico simulado
    (in-process, NÃO via HTTP): o interlock deriva daqui e não do FLEETGATE."""

    def __init__(self, ctx, devices):
        self.ctx = ctx
        self.devices = devices
        self.state = "NORMAL"
        self.irradiance = IRRADIANCE_PROFILES["DIA"]   # C7 (v0.4)
        self._cap_band = 0      # C8 (v0.4): banda da divergência (0 baixo, 1 alto)
        self._cap_key = None    # v0.7/C12: dedupe determinístico do snapshot
        self.lock = threading.Lock()

    def set_state(self, state):
        if state not in GRID_STATES:
            raise ValueError("estado desconhecido: %r" % state)
        with self.lock:
            self.state = state
        self.ctx.write_event("grid_events.jsonl",
                             {"event": "grid_state_change", "grid_state": state})
        self.publish()

    def set_irradiance(self, profile):
        """C7 (v0.4): perfil de irradiância (DIA/NUVEM/NOITE). Cartoon
        declarado: o 'sol' é um parâmetro do GRIDSIM publicado no canal
        de sensor físico (não exposto à API HTTP — fora do alcance do
        atacante por construção, como o canal V/f)."""
        if profile not in IRRADIANCE_PROFILES:
            raise ValueError("perfil desconhecido: %r" % profile)
        with self.lock:
            self.irradiance = IRRADIANCE_PROFILES[profile]
        self.ctx.write_event("grid_events.jsonl", {
            "event": "irradiance_change", "profile": profile,
            "irradiance": IRRADIANCE_PROFILES[profile]})
        self.publish()

    def snapshot(self):
        with self.lock:
            v, f = GRID_STATES[self.state]
            return {"grid_state": self.state, "v_grid": v, "f_grid": f,
                    "irradiance": self.irradiance,
                    "grid_emergency": self.state in ("EMERGENCY", "BLACKOUT", "RESTORE")}

    def publish(self):
        snap = self.snapshot()
        now = time.time()
        dt = min(1.0, now - getattr(self, "_last_pub", now))
        self._last_pub = now
        for dev in self.devices:
            dev.sensor_update(snap["f_grid"], snap["v_grid"],
                              snap["grid_state"], snap["irradiance"])
            dev.step_island(dt)   # H5 (v0.3): relógio físico da bateria
        # C8 (v0.4): snapshot de capacidade CONTÍNUO por TRANSIÇÃO de
        # banda (cruzamento do limiar) — dedupe determinístico; o harness
        # emit_capacity_snapshot() continua a existir (selftest/liveness).
        expected, actual, div = capacity_divergence_pct(self.devices)
        band = 1 if div >= CAPACITY_DIVERGENCE_PCT else 0
        if band != self._cap_band:
            self._cap_band = band
            self.emit_capacity_snapshot(
                "snapshot continuo por transicao de banda (C8)")

    def emit_capacity_snapshot(self, note):
        """v0.7/C12 (c): snapshot de capacidade PARTILHADO com dedupe
        DETERMINÍSTICO — chamado pelo publish() (transição de banda) e
        pelos handlers de shutdown/resume remotos do SUNBOX (evidência
        contínua que um shutdown NÃO provoca por transição de banda —
        a causa 3 do C12). Dedupe por (banda, div, nº de inversores
        OFF): só emite quando o triplo MUDA (sem relógio, sem contagem
        de chamadas — determinístico por construção)."""
        expected, actual, div = capacity_divergence_pct(self.devices)
        band = 1 if div >= CAPACITY_DIVERGENCE_PCT else 0
        n_off = sum(1 for d in self.devices if not d.inverter_on)
        key = (band, div, n_off)
        if key == self._cap_key:
            return
        self._cap_key = key
        self.ctx.write_event("audit_gate.jsonl", {
            "event": "capacity_snapshot",
            "expected_kw": round(expected, 2),
            "actual_export_kw": round(actual, 2),
            "divergence_pct": div,
            "remote_curtail_devices": sum(
                1 for d in self.devices if d.export_limit < 100.0),
            "curtail_autonomous_present": any(
                d.curtail_autonomous > 0 for d in self.devices),
            "provenance": "grid_monitor",
            "note": note})

    def loop(self, interval=0.25):
        while self.ctx.running:
            self.publish()
            time.sleep(interval)


# ---------------------------------------------------------------------------
# SUNBOX — inversor híbrido sintético
# ---------------------------------------------------------------------------

class SunBox:
    """Controlador sintético. Invariantes seladas:
    1) provenance "autonomous_pf" só no sensor_update (P(f) LFSM-O);
    2) SoC floor só desce com /local_confirm;
    3) funções de segurança autónomas (anti-islanding) nunca bloqueáveis.
    """

    def __init__(self, ctx, idx):
        self.ctx = ctx
        self.idx = idx
        self.cell = CELL_NAMES[idx // CELL_SIZE]
        self.kwp = KWP_LAYOUT[idx]
        self.port = PORT_DEV_BASE + idx
        self.name = "sunbox-%02d" % idx
        self.service_token = "SUNBOX-SVC-%02d-2026" % idx   # conhecido pelo FLEETGATE
        self.local_pin = "PIN-%02d-4471" % idx              # presença física simulada
        self.batt_kwh = round(self.kwp * 1.2, 2)            # bateria inventada
        # estado operacional
        self.inverter_on = True
        self.relay_closed = True
        self.dev_state = "grid_tied"     # grid_tied | off_grid | fault | bricked
        self.soc = 100.0
        self.export_limit = 100.0        # %
        self.curtail_autonomous = 0.0    # I1 (v0.4): P(f) — sobe E desce
        self.curtail_manual = 0.0         # I1 (v0.4): harness/testes
        self.irr_factor = IRRADIANCE_PROFILES["DIA"]   # C7 (v0.4)
        self.fw_ver = "2.4.1"
        # latch de emergência (derivação LOCAL do sensor)
        self.latched_until = 0.0
        self.emergency_seen = False
        # sessões (TTL, F5) e confirmação local (lockout, F1)
        self.sessions = {}
        self.local_confirm_token = None
        self.pin_fails = 0
        self.pin_locked_until = 0.0
        # v0.6/R5: ledger do limite diário de descarga remota — pares
        # (sim_ts, drop_pct) das descargas remote_command EXECUTADAS
        # (in-band); /local_confirm NÃO conta (decisão do operador)
        self.remote_drain_ledger = []
        self.lock = threading.Lock()   # F3: RMW de soc/export_limit
        self.server = None

    # ---------------- auditoria ----------------

    def audit(self, name, event):
        ev = dict(event)
        ev.setdefault("device", self.name)
        ev.setdefault("cell", self.cell)
        self.ctx.write_event(name, ev)

    # ---------------- sensor físico (único escritor de autonomous_pf) ----------------

    # I1 (v0.4): curtail_pct passa a ser DERIVADO por origem — o autónomo
    # (P(f), só o sensor escreve, agora com RELEASE) e o manual
    # (harness/testes, setter). A catraca da v0.3 (max() que só subia)
    # morre: o curtail autónomo segue a frequência para cima E para baixo.
    @property
    def curtail_pct(self):
        return max(self.curtail_autonomous, self.curtail_manual)

    @curtail_pct.setter
    def curtail_pct(self, value):
        self.curtail_manual = value

    def sensor_update(self, f_grid, v_grid, grid_state, irradiance=None):
        ts = time.time()
        # C7 (v0.4): perfil de irradiância do canal de sensor físico
        if irradiance is not None:
            self.irr_factor = irradiance
        # (1) anti-islanding: SEMPRE (nunca remotamente bloqueável)
        if v_grid < V_NOMINAL_MIN and self.relay_closed:
            self.relay_closed = False
            self.dev_state = "off_grid"
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "anti_islanding", "relay": "open",
                "provenance": "autonomous_safety", "v_grid": v_grid})
        # (2) latch de emergência (derivação local, histerese + latching)
        if f_grid < F_EMERG_LOW or f_grid > F_EMERG_HIGH or v_grid < V_EMERG_LOW:
            self.latched_until = max(self.latched_until, ts + LATCH_SECONDS)
            if not self.emergency_seen:
                self.emergency_seen = True
                self.audit("audit_dev_%02d.jsonl" % self.idx, {
                    "event": "emergency_latch", "latch_s": LATCH_SECONDS,
                    "provenance": "autonomous_safety",
                    "f_grid": f_grid, "v_grid": v_grid})
        # (3) curva P(f) LFSM-O sintética: curtailment autónomo por sobrefrequência
        target = 0.0
        if f_grid > F_PF_HIGH:
            target = min(100.0, round((f_grid - F_PF_HIGH) * 200.0, 1))
        if target != self.curtail_autonomous:
            # I1 (v0.4): RELEASE — o curtail autónomo sobe E DESCE com a
            # frequência (a v0.3 fazia curtail_pct = max(curtail, target):
            # catraca, ficava 40% para sempre após um STRESS). Release
            # imediato a f <= F_PF_HIGH (cartoon declarado).
            releasing = target < self.curtail_autonomous
            self.curtail_autonomous = target
            # REGRA SELADA 1: apenas aqui se escreve provenance="autonomous_pf"
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "pf_release" if releasing else "pf_curtail",
                "curtail_pct": target,
                "provenance": "autonomous_pf", "f_grid": f_grid})
        # reposição do latch apenas por tempo (unidirecional: nunca por comando)
        if self.emergency_seen and ts > self.latched_until:
            self.emergency_seen = False
            self.audit("audit_dev_%02d.jsonl" % self.idx,
                       {"event": "emergency_unlatch", "provenance": "autonomous_safety"})

    @property
    def emergency_active(self):
        return time.time() < self.latched_until

    # ---------------- física cartoon (v0.3: H4 + H5) ----------------

    def pv_gross_kw(self):
        """H4/C7: produção BRUTA (kwp * irradiância do perfil do sensor)
        — inalterada por curtail/export (é o que o sol entrega). A v0.3
        usava IRRADIANCE_FACTOR fixo (C7: em noite/novembro o sol não
        entrega 1.76 kW e o measure "defended" ficava falso)."""
        return round(self.kwp * self.irr_factor, 2) if self.inverter_on else 0.0

    def pv_kw(self):
        """H4 (v0.3): produção LÍQUIDA de curtailment — o v0.2 ignorava
        curtail_pct (física cega; comprometia o measure). O curtail_pct
        agrega o curtailment autónomo P(f) (sobrefrequência) — em modo
        ilha a frequência local é nominal e o curtail não se aplica
        (cartoon declarado)."""
        pv = self.pv_gross_kw()
        return round(pv * (1.0 - min(100.0, self.curtail_pct) / 100.0), 2)

    def export_kw(self):
        """H4 (v0.3): potência EXPORTÁVEL para a rede = pv líquida *
        export_limit/100, apenas com relé fechado. É isto que a
        divergência de capacidade (D-CAPACITY-DIVERGENCE) mede."""
        if not self.relay_closed or not self.inverter_on:
            return 0.0
        return round(self.pv_kw() * (self.export_limit / 100.0), 2)

    def island_discharge_floor(self):
        """C10/v0.5 (decisão do operador 13-11): o floor (25%) bloqueia a
        descarga REMOTA (invariante selada §4.7.2); em modo ilha a carga
        local usa a reserva até o mínimo técnico ISLAND_MIN_SOC (5%).
        RESERVE_LOCKED_MODE (contrafactual "opção B" = v0.4) tranca a
        reserva: a descarga em ilha clamp no FLOOR_SOC — o ANTES do C10."""
        return FLOOR_SOC if RESERVE_LOCKED_MODE else ISLAND_MIN_SOC

    def remote_drain_used_pct(self):
        """v0.6/R5 (decisão do operador 13-11 13:23): soma das descargas
        remote_command EXECUTADAS (ledger) dentro da janela móvel de 24 h
        de sim_ts (INCLUSIVA — consistente com a cumulativa). NÃO contam:
        consumo da casa, exportação solar, descargas /local_confirm."""
        now = sim_ts()
        return sum(pct for (ts, pct) in self.remote_drain_ledger
                   if now - ts <= REMOTE_DISCHARGE_DAILY_WINDOW)

    def step_grid(self, dt):
        """J4 (v0.6/R5, 4.ª auditoria): RECARGA SOLAR EM MODO LIGADO À
        REDE — na v0.5 a bateria só integrava em ILHA (step_island), pelo
        que um ataque em vários dias nunca encontrava a bateria rearmada
        (o measure multi-dia seria injusto com a defesa). Cartoon
        declarado (sem modelo de carga/peukert):
          - relé FECHADO + inversor ON + excedente (pv > carga local):
            carrega a bateria, cap 100, evento grid_tied_charge
            (provenance autonomous_charge — NÃO é remote_command, não
            conta no ledger diário por construção);
          - deficit: a REDE serve a casa (bateria intacta);
          - NOITE (pv 0): sem carga; relé aberto (ilha): nada aqui — a
            integração de ilha é o step_island.
        Chamada APENAS pelo harness do measure (atacante (c), 2 dias):
        o relógio do GRIDSIM NÃO a chama sozinho — as contagens do demo
        ficam INALTERADAS por construção. Dia de sol cartoon: 12 h
        (todos os kwp >= 3.2 recarregam a 100: excedente mínimo 0.56 kW).
        """
        if not self.relay_closed or not self.inverter_on or dt <= 0:
            return 0.0
        pv = self.pv_kw()
        surplus = pv - LOAD_LOCAL_KW
        if surplus <= 0 or self.soc >= 100.0:
            return 0.0
        kwh = surplus * dt / 3600.0
        gain = kwh / self.batt_kwh * 100.0
        old = self.soc
        with self.lock:
            new = min(100.0, self.soc + gain)
            if new != self.soc:
                self.soc = round(new, 4)
                self.audit("audit_dev_%02d.jsonl" % self.idx, {
                    "event": "grid_tied_charge", "kwh": round(kwh, 4),
                    "old_soc": old, "new_soc": self.soc,
                    "surplus_kw": round(surplus, 3), "dt_s": dt,
                    "provenance": "autonomous_charge",
                    "note": "J4: excedente solar carrega a bateria em "
                            "modo ligado a rede"})
                return kwh
        return 0.0

    def step_island(self, dt):
        """H5 (v0.3): integração temporal da bateria em MODO ILHA (relé
        aberto, inversor ON), chamada pelo relógio físico do GRIDSIM.
        Cartoon declarado (sem modelo de carga/peukert; dt do sensor):
          - surplus (pv > carga): CARREGA a bateria, cap 100%;
          - deficit (pv < carga): DESCARREGA ATÉ AO LIMITE DE ILHA —
            v0.5/C10 (decisão do operador 13-11): o limite de ilha é o
            mínimo técnico ISLAND_MIN_SOC (5%), NÃO o floor: a reserva de
            emergência existe PARA a casa (descarga local), o floor
            existe CONTRA o comando remoto. Ao chegar ao limite, a carga
            local cai para pv e o evento é auditado UMA vez:
            island_battery_at_island_min (opção A) ou
            island_battery_at_floor (opção B / RESERVE_LOCKED_MODE —
            comportamento da v0.4, o ANTES do C10).
        O v0.2 tinha SoC congelado em ilha (a métrica do measure v0.4
        seria falsa); o v0.4 clampava no floor (a reserva nunca podia ser
        usada pela casa — causa 2 do C10, medida pelo supervisor)."""
        if self.relay_closed or not self.inverter_on or dt <= 0:
            return
        pv = self.pv_kw()
        if pv >= LOAD_LOCAL_KW:
            # ERRATA 13-11 (run 3 GATEFALL R2): kW*dt com dt em SEGUNDOS
            # era tratado como kWh (3600x acelerado) — agora kW*s/3600.
            surplus_kwh = (pv - LOAD_LOCAL_KW) * dt / 3600.0
            gain = surplus_kwh / self.batt_kwh * 100.0
            if self.soc < 100.0 and gain > 0:
                with self.lock:
                    new = min(100.0, self.soc + gain)
                    if new != self.soc:
                        self.soc = round(new, 4)
            return
        # deficit: a bateria cobre a carga local até ao limite de ilha
        limit = self.island_discharge_floor()
        if self.soc > limit:
            # ERRATA 13-11 (run 3 GATEFALL R2): kW*s/3600 → kWh (idem).
            deficit_kwh = (LOAD_LOCAL_KW - pv) * dt / 3600.0
            drop = deficit_kwh / self.batt_kwh * 100.0
            with self.lock:
                new_soc = max(limit, self.soc - drop)
                if new_soc != self.soc:
                    self.soc = round(new_soc, 4)
                if self.soc <= limit + 1e-9 and not getattr(
                        self, "_island_floor_announced", False):
                    self._island_floor_announced = True
                    self.audit("audit_dev_%02d.jsonl" % self.idx, {
                        "event": ("island_battery_at_floor"
                                  if RESERVE_LOCKED_MODE
                                  else "island_battery_at_island_min"),
                        "soc": self.soc, "limit_soc": limit,
                        "floor_soc": FLOOR_SOC,
                        "pv_kw": pv, "load_kw": LOAD_LOCAL_KW,
                        "provenance": "autonomous_safety",
                        "note": ("carga local cai para pv; reserva "
                                 "trancada (opcao B = v0.4)"
                                 if RESERVE_LOCKED_MODE else
                                 "carga local cai para pv; reserva usada "
                                 "ate ao minimo tecnico (opcao A = v0.5)")})

    def self_consumption_kw(self):
        """Autoconsumo cartoon v0.3 (F7/C3 + H4/H5): REFLETE o estado e a
        física nova.
        - inverter desligado: 0.0 (sem conversão DC→AC);
        - grid-tied: min(pv líquida, LOAD_LOCAL_KW) — o excedente é
          exportado (export_kw);
        - ilha: cargas locais servidas por pv; deficit coberto pela
          bateria com SoC > LIMITE DE ILHA (v0.5/C10: ISLAND_MIN_SOC na
          opção A; FLOOR_SOC na opção B/v0.4 — reserva trancada); abaixo
          disso a carga serve apenas pv."""
        if not self.inverter_on:
            return 0.0
        pv = self.pv_kw()
        if self.relay_closed:
            return round(min(pv, LOAD_LOCAL_KW), 2)
        if pv >= LOAD_LOCAL_KW:
            return LOAD_LOCAL_KW
        if self.soc > self.island_discharge_floor():
            return LOAD_LOCAL_KW
        return round(pv, 2)

    def telemetry(self):
        return {
            "device": self.name, "cell": self.cell, "kwp": self.kwp,
            "port": self.port, "inverter_on": self.inverter_on,
            "relay_closed": self.relay_closed, "dev_state": self.dev_state,
            "soc": self.soc, "floor_soc": FLOOR_SOC,
            # J5 (v0.6/R5): o limite ATIVO por modo, não só o floor —
            # a telemetria da v0.5 dizia "floor 25" quando o limite de
            # ilha era 5 (cabeçalhos desatualizados)
            "soc_limits": {
                "schema": "v0.7.1",  # F-LIMP v0.7 + v0.7.1: sem
                                      # campos novos (freeze)
                "remote_floor_pct": FLOOR_SOC,
                "island_min_pct": self.island_discharge_floor(),
                "remote_daily_limit_pct": (
                    REMOTE_DISCHARGE_DAILY_PCT
                    if DAILY_LIMIT_MODE and not LEGACY_MODE else None),
                "remote_daily_used_pct": round(
                    self.remote_drain_used_pct(), 2),
            },
            "export_limit": self.export_limit, "curtail_pct": self.curtail_pct,
            "fw_ver": self.fw_ver, "emergency_latched": self.emergency_active,
            "pv_gross_kw": self.pv_gross_kw(), "pv_kw": self.pv_kw(),
            "export_kw": self.export_kw(),
            "self_consumption_kw": self.self_consumption_kw(),
        }

    # ---------------- harness (reset entre cenários; NÃO é via HTTP) ----------------

    def harness_reset(self):
        # G10 (v0.2): reset COMPLETO — nenhum estado sujo sobrevive entre
        # cenários (B1: o reset parcial mascarava métricas no measure).
        self.inverter_on = True
        self.relay_closed = True
        self.dev_state = "grid_tied"
        self.soc = 100.0
        self.export_limit = 100.0
        self.curtail_pct = 0.0
        self.curtail_autonomous = 0.0
        self.irr_factor = IRRADIANCE_PROFILES["DIA"]   # C7: perfil default
        self.fw_ver = "2.4.1"
        self.latched_until = 0.0
        self.emergency_seen = False
        self.sessions = {}
        self.local_confirm_token = None
        self.pin_fails = 0
        self.pin_locked_until = 0.0
        self.remote_drain_ledger = []   # v0.6: ledger diário limpo
        self._island_floor_announced = False   # H5: flag do evento de floor
        # v0.7.2/F-C15a: o contador de usos das WOs é limpo por CENÁRIO
        # (idempotente: cada dispositivo limpa o MESMO dicionário global)
        work_order_reset_uses()
        self.audit("audit_dev_%02d.jsonl" % self.idx,
                   {"event": "harness_reset", "provenance": "lab_harness"})

    # ---------------- ações remotas (chamadas pelos handlers HTTP) ----------------
    # REGRA SELADA 1: provenance hardcoded pelo servidor em TODAS as vias remotas.

    BLOCKED_IN_EMERGENCY = {
        "inverter_power_off", "battery_drain_force", "firmware_flash",
        "pf_param_change", "grid_reconnect",
    }

    def remote_inverter_power_off(self, actor, work_order=None):
        # MEASURE v0.4: no braço LEGACY o interlock é o que FALTA (é o
        # contrafactual); DEFENDED mantém o 409. Anti-islanding intocado.
        if self.emergency_active and not LEGACY_MODE:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "inverter_power_off",
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock",
                         "latched_s": round(self.latched_until - time.time(), 1)}
        # v0.7.1/F-C13 (C13 do supervisor, GO 13-11 ~17:00): o DISPOSITIVO
        # valida a work_order contra a MESMA lista do gate (WORK_ORDERS —
        # uma fonte só). WO PRESENTE e inválida → 403 + evento
        # work_order_invalid; o shutdown NÃO executa (a frota fica ON —
        # a evasão por WO falsa FECHA o achado). WO AUSENTE mantém o
        # comportamento da v0.7 (executa; o detetor conta como s/WO; o
        # caminho fraco H1 da via por-dispositivo segue coberto pela
        # onda e, agora, pelo WARN por evento). A validação vem DEPOIS
        # do interlock (EMERG/BLOCKED inalterados: 409 primeiro) e vale
        # em TODOS os braços do measure (é a FIX, não contrafactual).
        # v0.7.2/F-C15a (C15, GO 13-11 ~19:30): a validação deixa de
        # ser membership numa lista plana e passa a ÂMBITO COMPLETO
        # (dispositivo + janela + usos) pela MESMA fonte do gate
        # (WORK_ORDERS passada literalmente — uma fonte só). Fora do
        # âmbito / expirada / esgotada → 403 + work_order_invalid com
        # "reason" + D-INVALID-WORK-ORDER; o shutdown NÃO executa.
        if work_order is not None:
            wo_ok, wo_reason = work_order_check(WORK_ORDERS, work_order,
                                                dev_idx=self.idx)
            if not wo_ok:
                self.audit("audit_dev_%02d.jsonl" % self.idx, {
                    "event": "work_order_invalid",
                    "action": "inverter_power_off",
                    "work_order": work_order, "reason": wo_reason,
                    "provenance": "remote_command", "actor": actor})
                return 403, {"error": "work_order_invalid",
                             "reason": wo_reason}
        if LEGACY_MODE:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "legacy_executed", "action": "inverter_power_off",
                "provenance": "remote_command", "actor": actor,
                "note": "contrafactual: sem interlock"})
        if work_order is not None:
            # F-C15a: o uso é consumido APENAS quando o comando executa
            # de facto; o carimbo wo_valid alimenta o F-C15b (o detetor
            # confia no carimbo do MOMENTO da validação, não em
            # re-validação tardia ao tempo do scan).
            work_order_check(WORK_ORDERS, work_order, dev_idx=self.idx,
                             consume=True)
        self.inverter_on = False
        self.audit("audit_dev_%02d.jsonl" % self.idx, dict({
            "event": "shutdown", "provenance": "remote_command",
            "actor": actor, "work_order": work_order},
            **({"wo_valid": True} if work_order is not None else {})))
        # v0.7/C12 (c): snapshot contínuo APÓS shutdown remoto — um
        # shutdown nunca provoca transição de banda sozinho (o esperado
        # mantém-se e o real cai; o dedupe é determinístico). Também em
        # shutdowns COM work-order: o snapshot é EVIDÊNCIA neutra; o ARMAR
        # da regra é que discrimina por work-order (causa 2 do C12).
        gs = getattr(self.ctx, "gridsim", None)
        if gs is not None:
            gs.emit_capacity_snapshot(
                "snapshot continuo apos shutdown remoto (C12/v0.7)")
        return 200, {"ok": True, "inverter_on": False}

    def remote_inverter_resume(self, actor):
        if self.dev_state in RESUME_BLOCKED_STATES:   # G11 (v0.2)
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "inverter_resume_blocked", "dev_state": self.dev_state,
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "inverter_resume_blocked",
                         "dev_state": self.dev_state}
        self.inverter_on = True
        self.audit("audit_dev_%02d.jsonl" % self.idx, {
            "event": "inverter_resume", "provenance": "remote_command", "actor": actor})
        # v0.7/C12 (c): snapshot contínuo também após resume remoto (o
        # recover é tão visível como o corte; dedupe determinístico).
        gs = getattr(self.ctx, "gridsim", None)
        if gs is not None:
            gs.emit_capacity_snapshot(
                "snapshot continuo apos resume remoto (C12/v0.7)")
        return 200, {"ok": True, "inverter_on": True}

    def remote_grid_reconnect(self, actor):
        if self.emergency_active:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "grid_reconnect",
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock"}
        self.relay_closed = True
        self.dev_state = "grid_tied"
        self.audit("audit_dev_%02d.jsonl" % self.idx, {
            "event": "grid_reconnect", "provenance": "remote_command", "actor": actor})
        return 200, {"ok": True, "relay_closed": True}

    def remote_setpoint(self, actor, value, work_order=None):
        # G6 (v0.2, decisão do operador 13-11 — MUDANÇA DE DESIGN): o
        # interlock de emergência passa a cobrir o setpoint; export_limit
        # NÃO muda com latch ativo (registo no canvas §3.2).
        # H3 (v0.3): TIPOS ESTRITOS — bool NÃO é número. O v0.2 aceitava
        # {'value': false} → float(False)=0.0 → export_limit=0 silencioso.
        # Agora: strict_number() rejeita bool com 400 + strict_type_reject.
        value, type_err = strict_number(value)
        if type_err:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "strict_type_reject", "param": "export_limit",
                "reason": type_err,
                "provenance": "remote_command", "actor": actor})
            return 400, {"error": "tipo invalido: %s" % type_err}
        if self.emergency_active and not LEGACY_MODE:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "setpoint_export_limit",
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock"}
        # v0.7.1/F-SP (FP-SP do supervisor, GO 13-11 ~17:00): o /setpoint
        # passa a aceitar work_order validada pelo MESMO F-C13 (uma fonte
        # só); WO inválida → 403 + work_order_invalid (o setpoint NÃO
        # aplica); SEM WO mantém (aplica; o param_change segue ARMANDO a
        # capacity — resíduo por atribuição-de-causa DECLARADO p/ v0.8).
        # v0.7.2/F-C15a: o /setpoint valida o MESMO âmbito completo
        # (dispositivo + janela + usos) pela MESMA fonte (uma fonte só,
        # como no F-C13/F-SP).
        if work_order is not None:
            wo_ok, wo_reason = work_order_check(WORK_ORDERS, work_order,
                                                dev_idx=self.idx)
            if not wo_ok:
                self.audit("audit_dev_%02d.jsonl" % self.idx, {
                    "event": "work_order_invalid",
                    "action": "setpoint_export_limit",
                    "work_order": work_order, "reason": wo_reason,
                    "provenance": "remote_command", "actor": actor})
                return 403, {"error": "work_order_invalid",
                             "reason": wo_reason}
        if not (0.0 <= value <= 100.0):
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "setpoint_rejected", "param": "export_limit",
                "value": value, "provenance": "remote_command", "actor": actor})
            return 400, {"error": "fora da banda segura [0,100]"}
        if work_order is not None:
            work_order_check(WORK_ORDERS, work_order, dev_idx=self.idx,
                             consume=True)
        with self.lock:   # F3: RMW atómico
            old = self.export_limit
            self.export_limit = value
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "param_change", "param": "export_limit",
                "old": old, "new": value, "work_order": work_order,
                "provenance": "remote_command", "actor": actor})
        return 200, {"ok": True, "export_limit": value}

    def remote_battery(self, actor, action, amount_kwh, confirm_token=None):
        # G2 (v0.2): interlock por LISTA BRANCA — em emergência NENHUMA ação
        # remota de bateria é permitida (a lista negra de strings morreu);
        # fora de emergência, apenas BATTERY_ACTIONS são aceites.
        if self.emergency_active and not LEGACY_MODE:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "battery",
                "requested_action": action,
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock"}
        if action not in BATTERY_ACTIONS:
            return 400, {"error": "acao desconhecida"}
        # H3 (v0.3): tipos estritos também no amount_kwh (bool não é número)
        amount_kwh, type_err = strict_number(amount_kwh)
        if type_err:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "strict_type_reject", "param": "amount_kwh",
                "reason": type_err,
                "provenance": "remote_command", "actor": actor})
            return 400, {"error": "tipo invalido: %s" % type_err}
        if amount_kwh < 0:   # G1 (isfinite vem no strict_number)
            return 400, {"error": "valor invalido"}
        with self.lock:   # F3: RMW do SoC atómico — o floor deixa de ser sorte do GIL
            drop = amount_kwh / self.batt_kwh * 100.0
            new_soc = self.soc - drop
            # REGRA SELADA 2: exceção exclusiva via /local_confirm
            if new_soc < FLOOR_SOC:
                if LEGACY_MODE:
                    # MEASURE v0.4 — braço contrafactual: o floor É a
                    # defesa que falta; a descida executa até 0 e é
                    # auditada (legacy_bypass_floor + param_change).
                    old = self.soc
                    self.soc = round(max(0.0, new_soc), 2)
                    self.audit("audit_dev_%02d.jsonl" % self.idx, {
                        "event": "legacy_bypass_floor", "action": action,
                        "floor_soc": FLOOR_SOC, "new_soc": self.soc,
                        "provenance": "remote_command", "actor": actor,
                        "note": "contrafactual: sem floor"})
                    self.audit("audit_dev_%02d.jsonl" % self.idx, {
                        "event": "param_change", "param": "soc",
                        "old": old, "new": self.soc,
                        "provenance": "remote_command", "actor": actor,
                        "note": "legacy: descarga abaixo do floor executada"})
                    return 200, {"ok": True, "soc": self.soc}
                if confirm_token and confirm_token == self.local_confirm_token:
                    old = self.soc
                    self.soc = round(max(0.0, new_soc), 2)
                    self.local_confirm_token = None  # uso único
                    self.audit("audit_dev_%02d.jsonl" % self.idx, {
                        "event": "param_change", "param": "soc",
                        "old": old, "new": self.soc,
                        "provenance": "local_confirm", "actor": actor,
                        "note": "descarga abaixo do floor com confirmacao local"})
                    return 200, {"ok": True, "soc": self.soc}
                self.audit("audit_dev_%02d.jsonl" % self.idx, {
                    "event": "floor_block", "action": action,
                    "soc": self.soc, "floor_soc": FLOOR_SOC,
                    "requested_soc": round(new_soc, 2),
                    "provenance": "remote_command", "actor": actor})
                return 409, {"error": "min_emergency_soc_floor",
                             "floor_soc": FLOOR_SOC,
                             "hint": "requer confirmacao fisica local (/local_confirm)"}
            # v0.6/R5 — LIMITE DIÁRIO DE DESCARGA REMOTA (decisão do
            # operador 13-11 13:23): DEPOIS do check do floor (os 999
            # continuam a dar 409 floor + D-BATTERY-DRAIN-BELOW-FLOOR —
            # contagens do demo preservadas) e ANTES da execução in-band.
            # NÃO conta consumo da casa (step_island/step_grid são
            # autónomos), exportação solar (export_kw não é /battery) nem
            # descargas /local_confirm. LEGACY_MODE = bypass (extensão
            # datada do contrafactual declarado — 4.º vetor).
            if DAILY_LIMIT_MODE and not LEGACY_MODE and drop > 0.0:
                used = self.remote_drain_used_pct()
                if used + drop > REMOTE_DISCHARGE_DAILY_PCT + 1e-9:
                    if (confirm_token
                            and confirm_token == self.local_confirm_token):
                        # confirmação física local: executa além do dia,
                        # NÃO conta no ledger (uso único, como no floor)
                        old = self.soc
                        self.soc = round(new_soc, 2)
                        self.local_confirm_token = None
                        self.audit("audit_dev_%02d.jsonl" % self.idx, {
                            "event": "param_change", "param": "soc",
                            "old": old, "new": self.soc,
                            "provenance": "local_confirm", "actor": actor,
                            "note": "descarga acima do limite diario com "
                                    "confirmacao local (nao conta no "
                                    "ledger)"})
                        return 200, {"ok": True, "soc": self.soc}
                    self.audit("audit_dev_%02d.jsonl" % self.idx, {
                        "event": "remote_daily_limit_block",
                        "action": action, "soc": self.soc,
                        "used_pct": round(used, 2),
                        "requested_pct": round(drop, 2),
                        "limit_pct": REMOTE_DISCHARGE_DAILY_PCT,
                        "window_s": REMOTE_DISCHARGE_DAILY_WINDOW,
                        "provenance": "remote_command", "actor": actor})
                    return 409, {
                        "error": "remote_discharge_daily_limit",
                        "used_pct": round(used, 2),
                        "limit_pct": REMOTE_DISCHARGE_DAILY_PCT,
                        "window_s": REMOTE_DISCHARGE_DAILY_WINDOW,
                        "hint": "requer confirmacao fisica local "
                                "(/local_confirm)"}
            old = self.soc
            self.soc = round(new_soc, 2)
            if DAILY_LIMIT_MODE and not LEGACY_MODE and drop > 0.0:
                # descarga remote_command EXECUTADA: entra no ledger
                self.remote_drain_ledger.append((sim_ts(), drop))
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "param_change", "param": "soc", "old": old,
                "new": self.soc,
                "provenance": "remote_command", "actor": actor})
            return 200, {"ok": True, "soc": self.soc}

    def remote_pf_param_change(self, actor, grid_state, params):
        if self.emergency_active:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "pf_param_change",
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock"}
        if grid_state == "STRESS":
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "pf_param_change_blocked", "grid_state": grid_state,
                "params": params, "provenance": "remote_command", "actor": actor})
            return 409, {"error": "pf_params_locked_in_stress"}
        self.audit("audit_dev_%02d.jsonl" % self.idx, {
            "event": "param_change", "param": "pf_profile", "new": params,
            "provenance": "remote_command", "actor": actor})
        return 200, {"ok": True}

    def remote_firmware(self, actor, grid_state, image_b64, signature):
        if self.emergency_active:
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "interlock_block", "action": "firmware_flash",
                "provenance": "remote_command", "actor": actor})
            return 409, {"error": "grid_emergency_interlock"}
        if grid_state != "NORMAL":
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "firmware_rejected", "reason": "fora_da_janela",
                "grid_state": grid_state, "provenance": "remote_command",
                "actor": actor})
            return 400, {"error": "firmware_window", "grid_state": grid_state}
        try:
            image = base64.b64decode(image_b64)
        except Exception:
            return 400, {"error": "imagem invalida"}
        if signature != sign_image(image):
            self.audit("audit_dev_%02d.jsonl" % self.idx, {
                "event": "firmware_rejected", "reason": "assinatura_invalida",
                "provenance": "remote_command", "actor": actor})
            return 400, {"error": "assinatura invalida"}
        self.fw_ver = "2.4.1+push"
        self.audit("audit_dev_%02d.jsonl" % self.idx, {
            "event": "firmware_push", "signed": True, "window": "NORMAL",
            "provenance": "remote_command", "actor": actor})
        return 200, {"ok": True, "fw_ver": self.fw_ver}


# ---------------------------------------------------------------------------
# HTTP comum
# ---------------------------------------------------------------------------

def canonical_request_line(raw_target_bytes):
    """CANONICALIZADOR PARTILHADO (v0.3, fecha H1/H2 — guard e handlers
    usam ESTA função, nunca a stdlib http.server como defesa; gh-87389
    documentado no G5). FAIL-CLOSED por construção: devolve (ok, motivo):
      - ok=True  se e só se o target é ASCII puro, começa com '/', sem
                  '//', sem '%', sem '?', sem '#', sem byte >= 0x80 e
                  comprimento <= REQUEST_PATH_MAX;
      - ok=False com o motivo em qualquer outro caso (incluindo bytes
                  não-ASCII: NUNCA fail-open — H1 morto por construção).
    Query strings são REJEITADAS: nenhuma rota do lab as usa (H2 — o
    routing nunca mais separa '?'; regras M3 por URI exato vêem o que
    roteou)."""
    try:
        target = raw_target_bytes.decode("ascii")
    except (UnicodeDecodeError, AttributeError):
        return False, "non_ascii"
    if not target.startswith("/"):
        return False, "no_leading_slash"
    if len(target) > REQUEST_PATH_MAX:
        return False, "too_long"
    # I4 (v0.4): bytes de controlo (< 0x20, 0x7F DEL) — a stdlib
    # http.server também os rejeita (gh-87389); aqui é fail-closed por
    # razão própria, antes de qualquer routing.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return False, "control_char"
    if "//" in target:
        return False, "double_slash"
    if "%" in target:
        return False, "percent_encoded"
    if "?" in target or "#" in target:
        return False, "query_or_fragment"
    # I4 (v0.4): segmentos '.' e '..' (dot-segment) — nunca normalizar,
    # sempre rejeitar (a normalização é onde nascem as confusões de rota).
    if any(seg in (".", "..") for seg in target.split("/")):
        return False, "dot_segment"
    if any(ch in target for ch in ("\\", " ", "\t")):
        return False, "unsafe_char"
    return True, "canonical"


def strict_number(value):
    """TIPOS ESTRITOS (v0.3, fecha H3): bool NÃO é número. Em Python,
    bool é subclasse de int e float(False)==0.0 — float() sozinho aceita
    True/False como 1.0/0.0. Devolve (float, None) se value é int/float
    real, senão (None, 'not_a_number') ou (None, 'nan_or_inf')."""
    if isinstance(value, bool):
        return None, "bool_is_not_a_number"
    if not isinstance(value, (int, float)):
        return None, "not_a_number"
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None, "not_a_number"
    if not math.isfinite(f):
        return None, "nan_or_inf"
    return f, None


class JSONHandler(BaseHTTPRequestHandler):
    server_version = "SUNBOX/0.7.2"  # AUD-11/F-LIMP (v0.7..v0.7.2):
    # banner do device atualizado; o RESTO do H7 fica para a v0.8
    # por decisão do operador
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # a auditoria do lab substitui o log de acesso

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if not raw:
                return {}, None
            obj = json.loads(raw.decode("utf-8"))
            if not isinstance(obj, dict):
                return None, "corpo deve ser objeto JSON"
            return obj, None
        except (ValueError, UnicodeDecodeError):
            return None, "JSON invalido"

    def _send(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _bearer(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.startswith("Bearer ") else None

    def _canonical_path(self):
        """G5/P9 + H1/H2 (v0.3): CANONICALIZADOR PARTILHADO, fail-closed.
        A stdlib http.server pode NORMALIZAR o path antes do routing
        (CPython gh-87389: '//' inicial vira '/'), e a normalização varia
        por versão do Python — a canonicalização é do LAB, nunca da
        stdlib. v0.3: bytes não-ASCII deixam de ser fail-open (o v0.2
        devolvia True no except — H1) e query strings deixam de rotear
        (H2): TUDO o que não é canónico é 400 + non_canonical_request."""
        try:
            raw_target = self.raw_requestline.split(b" ")[1]
        except (AttributeError, IndexError):
            return False   # linha ilegível: fail-closed (sem resposta: a
            # conexão morre sem routing — nunca se roteia o não-canónico)
        ok, motivo = canonical_request_line(raw_target)
        if not ok:
            ev = {"event": "non_canonical_request", "reason": motivo,
                  "provenance": "remote_command", "via": "lab_handler"}
            srv = self.server
            if hasattr(srv, "dev"):
                srv.dev.audit("audit_dev_%02d.jsonl" % srv.dev.idx, ev)
            elif hasattr(srv, "gate"):
                srv.gate.audit(ev)
            self._send(400, {"error": "non_canonical_request",
                            "reason": motivo})
            return False
        return True


def strip_spoofed_provenance(dev, body):
    """REGRA SELADA 1: remove campos de proveniência enviados pelo cliente,
    registando a tentativa. O servidor nunca lê provenância do payload."""
    spoofed = [k for k in ("provenance", "source", "reason") if k in body]
    for k in spoofed:
        del body[k]
    if spoofed:
        dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
            "event": "provenance_spoof_attempt", "fields": sorted(spoofed),
            "provenance": "remote_command"})
    return spoofed


# ---------------------------------------------------------------------------
# SUNBOX HTTP
# ---------------------------------------------------------------------------

class DevServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # sockets fechados cedo pelo cliente de testes: benigno
        import sys
        exc = sys.exc_info()[0]
        if exc not in (BrokenPipeError, ConnectionResetError):
            super().handle_error(request, client_address)

    def __init__(self, dev, ctx):
        self.dev = dev
        self.ctx = ctx
        super().__init__((LOOPBACK, dev.port), DevHandler)


class DevHandler(JSONHandler):

    def _auth(self):
        dev = self.server.dev
        token = self._bearer()
        if not token:
            return None, 401
        if token == HARDCODED_BROKER_TOKEN:
            dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
                "event": "auth_use", "method": "broker_token",
                "provenance": "remote_command"})
            return "broker_token", None
        if token == dev.service_token:
            return "fleetgate_forward", None
        if token in dev.sessions:
            if time.time() < dev.sessions[token]:   # F5: expiração
                return "device_session", None
            del dev.sessions[token]
            dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
                "event": "session_expired", "provenance": "remote_command"})
            return None, 401
        return None, 401

    def do_GET(self):
        dev = self.server.dev
        if not self._canonical_path():
            return
        if self.path.split("?")[0] == "/telemetry":
            return self._send(200, dev.telemetry())
        return self._send(404, {"error": "rota desconhecida"})

    def do_POST(self):
        dev = self.server.dev
        path = self.path.split("?")[0]
        body, err = self._read_json()
        if err:
            return self._send(400, {"error": err})
        if not self._canonical_path():
            return
        # REGRA SELADA 1: provenance hardcode — campos do cliente são removidos
        strip_spoofed_provenance(dev, body)

        if path == "/login":
            token = body.get("token")
            if token in (dev.service_token, HARDCODED_BROKER_TOKEN):
                sid = uuid.uuid4().hex
                dev.sessions[sid] = time.time() + SESSION_TTL_S   # F5: TTL
                method = "broker_token" if token == HARDCODED_BROKER_TOKEN else "service_token"
                dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
                    "event": "login_ok", "method": method,
                    "provenance": "remote_command"})
                return self._send(200, {"session": sid})
            return self._send(401, {"error": "credencial invalida"})

        # confirmação física local: fora do canal remoto de autenticação
        # (simula botão/painel no equipamento; não exige sessão remota)
        if path == "/local_confirm":
            # F1 (v0.2, decisão do operador 13-11): lockout após PIN_MAX_FAILS
            # PINs falhados. A derivabilidade do padrão permanece DECLARADA
            # (by-assumption); o lockout dificulta, não elimina.
            now = time.time()
            if now < dev.pin_locked_until:
                dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
                    "event": "local_confirm_denied", "locked": True,
                    "provenance": "local_confirm"})
                return self._send(403, {"error": "pin_locked"})
            if body.get("pin") == dev.local_pin:
                dev.pin_fails = 0
                dev.local_confirm_token = uuid.uuid4().hex
                dev.audit("audit_dev_%02d.jsonl" % dev.idx, {
                    "event": "local_confirm_issued",
                    "provenance": "local_confirm"})
                return self._send(200, {"confirm_token": dev.local_confirm_token})
            dev.pin_fails += 1
            ev = {"event": "local_confirm_denied", "provenance": "local_confirm",
                  "pin_fails": dev.pin_fails}
            if dev.pin_fails >= PIN_MAX_FAILS:
                dev.pin_locked_until = now + PIN_LOCKOUT_S
                dev.audit("audit_dev_%02d.jsonl" % dev.idx, dict(
                    ev, event="local_confirm_lockout", lockout_s=PIN_LOCKOUT_S))
            dev.audit("audit_dev_%02d.jsonl" % dev.idx, ev)
            return self._send(403, {"error": "pin invalido"})

        actor, status = self._auth()
        if actor is None:
            return self._send(status, {"error": "nao autenticado"})

        if path == "/telemetry":
            return self._send(200, dev.telemetry())

        if path == "/mode":
            action = body.get("action")
            if action == "inverter_power_off":
                st, resp = dev.remote_inverter_power_off(actor, body.get("work_order"))
                return self._send(st, resp)
            if action == "inverter_resume":
                st, resp = dev.remote_inverter_resume(actor)
                return self._send(st, resp)
            if action == "grid_reconnect":
                st, resp = dev.remote_grid_reconnect(actor)
                return self._send(st, resp)
            return self._send(400, {"error": "acao desconhecida"})

        if path == "/setpoint":
            st, resp = dev.remote_setpoint(actor, body.get("value"),
                                           body.get("work_order"))
            return self._send(st, resp)

        if path == "/battery":
            st, resp = dev.remote_battery(
                actor, body.get("action", "discharge"),
                body.get("amount_kwh", 0), body.get("confirm_token"))
            return self._send(st, resp)

        if path == "/grid_profile":
            grid = self.server.ctx.gridsim.snapshot()
            st, resp = dev.remote_pf_param_change(actor, grid["grid_state"], body)
            return self._send(st, resp)

        if path == "/firmware":
            grid = self.server.ctx.gridsim.snapshot()
            st, resp = dev.remote_firmware(
                actor, grid["grid_state"], body.get("image_b64", ""),
                body.get("signature", ""))
            return self._send(st, resp)

        return self._send(404, {"error": "rota desconhecida"})


# ---------------------------------------------------------------------------
# FLEETGATE — gestor de frota
# ---------------------------------------------------------------------------

class FleetGate:
    def __init__(self, ctx, devices, gridsim):
        self.ctx = ctx
        self.devices = devices
        self.gridsim = gridsim
        self.sessions = {}                 # F5: sid -> expiry (TTL)
        self.bulk_used = 0
        self.login_fails = 0
        self.login_locked_until = 0.0
        self.lock = threading.Lock()       # G3: check+incremento atómicos
        self.server = None

    def audit(self, event):
        ev = dict(event)
        ev.setdefault("device", "fleetgate")
        self.ctx.write_event("audit_gate.jsonl", ev)

    def login(self, user, pw):
        # F5 (v0.2): falhas AUDITADAS + lockout temporário do /fleet/login
        # após LOGIN_MAX_FAILS tentativas (brute-force). Devolve (method, err).
        now = time.time()
        if now < self.login_locked_until:
            self.audit({"event": "login_rate_blocked",
                        "provenance": "remote_command"})
            return None, "login_rate_blocked"
        if user == DEFAULT_USER and pw == DEFAULT_PASS:
            self.audit({"event": "login_ok", "method": "default_creds",
                        "provenance": "remote_command"})
            return "default_creds", None
        if user == DAILY_USER and pw == daily_code():
            self.audit({"event": "login_ok", "method": "daily_code",
                        "provenance": "remote_command"})
            return "daily_code", None
        self.login_fails += 1
        self.audit({"event": "login_fail", "fails": self.login_fails,
                    "provenance": "remote_command"})
        if self.login_fails >= LOGIN_MAX_FAILS:
            self.login_locked_until = now + LOGIN_LOCKOUT_S
            self.login_fails = 0
            self.audit({"event": "login_rate_blocked",
                        "lockout_s": LOGIN_LOCKOUT_S,
                        "provenance": "remote_command"})
        return None, None

    def check_work_order(self, wo):
        # v0.7.2/F-C15a: a MESMA validação única do dispositivo (uma
        # fonte só) — no gate sem dispositivo (o âmbito por
        # dispositivo é validado pelo PRÓPRIO dispositivo no comando
        # direto; no bulk o gate usa o âmbito para FILTRAR o despacho).
        ok, _reason = work_order_check(WORK_ORDERS, wo)
        return ok

    def bulk_shutdown(self, wo):
        if not self.check_work_order(wo):
            # v0.7.2/F-C15a: WO presente mas inválida (desconhecida /
            # expirada / esgotada) ganha TAMBÉM o evento
            # work_order_invalid com "reason" (uma só fonte; a
            # visibilidade é a do F-C13). WO AUSENTE mantém só o
            # bulk_block_no_workorder (D-BULK-WITHOUT-WORKORDER).
            if wo:
                _ok, reason = work_order_check(WORK_ORDERS, wo)
                self.audit({"event": "work_order_invalid",
                            "action": "bulk_shutdown", "work_order": wo,
                            "reason": reason,
                            "provenance": "remote_command"})
            self.audit({"event": "bulk_block_no_workorder", "work_order": wo,
                        "provenance": "remote_command"})
            return 403, {"error": "work-order exigida para operacoes bulk"}
        with self.lock:   # G3: check+incremento ATÓMICOS (nunca >limite)
            if self.bulk_used >= BULK_RATE_LIMIT:
                self.audit({"event": "bulk_block_rate_limit",
                            "used": self.bulk_used, "limit": BULK_RATE_LIMIT,
                            "provenance": "remote_command"})
                return 429, {"error": "rate limit bulk"}
            self.bulk_used += 1
        # v0.7.2/F-C15a: o gate CONHECE o âmbito (mesma fonte) e
        # despacha SÓ aos dispositivos in-scope; os fora do âmbito
        # são auditados como bulk_scope_skip (evidência; o comando
        # DIRETO fora do âmbito continua 403 + work_order_invalid —
        # testado no R8). O atacante com uma WO de âmbito estreito
        # nunca alcança os dispositivos fora do âmbito por NENHUMA
        # via (o device rejeita; o gate não despacha).
        scope = WORK_ORDERS[wo]["devices"]
        results, skipped = {}, []
        for dev in self.devices:
            if dev.idx not in scope:
                skipped.append(dev.name)
                self.audit({"event": "bulk_scope_skip",
                            "work_order": wo, "device": dev.name,
                            "provenance": "remote_command"})
                continue
            st, resp = http_json(LOOPBACK, dev.port, "POST", "/mode",
                                 {"action": "inverter_power_off", "work_order": wo},
                                 token=dev.service_token)
            results[dev.name] = st
        self.audit({"event": "bulk_shutdown_executed", "work_order": wo,
                    "n_devices": len(results),
                    "skipped_out_of_scope": skipped,
                    "statuses": results, "provenance": "remote_command"})
        return 200, {"ok": True, "devices": results,
                     "skipped_out_of_scope": skipped}


class GateServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import sys
        exc = sys.exc_info()[0]
        if exc not in (BrokenPipeError, ConnectionResetError):
            super().handle_error(request, client_address)

    def __init__(self, gate, ctx):
        self.gate = gate
        self.ctx = ctx
        super().__init__((LOOPBACK, PORT_GATE), GateHandler)


def _canonical_index(form, n):
    """G5 (v0.2): devolve o índice se a forma for CANÓNICA (dígitos ASCII,
    sem zeros à esquerda, dentro do range), senão None. '00000'/'00'/'001'
    e unicode NÃO roteiam."""
    if not (form.isascii() and form.isdigit()):
        return None
    if form != str(int(form)):
        return None
    idx = int(form)
    return idx if 0 <= idx < n else None


class GateHandler(JSONHandler):

    def _auth(self):
        gate = self.server.gate
        token = self._bearer()
        if token and token in gate.sessions:
            if time.time() < gate.sessions[token]:   # F5: expiração
                return "fleet_session", None
            del gate.sessions[token]
            gate.audit({"event": "session_expired",
                        "provenance": "remote_command"})
        return None, 401

    def do_GET(self):
        gate = self.server.gate
        if not self._canonical_path():
            return
        if self.path.split("?")[0] == "/fleet/telemetry":
            out = {}
            for dev in gate.devices:
                out[dev.name] = http_json(
                    LOOPBACK, dev.port, "GET", "/telemetry")[1]
            return self._send(200, out)
        return self._send(404, {"error": "rota desconhecida"})

    def do_POST(self):
        gate = self.server.gate
        path = self.path.split("?")[0]
        body, err = self._read_json()
        if err:
            return self._send(400, {"error": err})
        if not self._canonical_path():
            return
        # F6 parcial (v0.2, decisão do operador): o gate também STRIPA e
        # LOGA campos de provenância do cliente (a cegueira do gate morre;
        # o guard proxy partilhado é v0.3). As rotas continuam a reconstruir
        # os bodies — os campos nunca são encaminhados.
        spoofed = [k for k in ("provenance", "source", "reason") if k in body]
        for k in spoofed:
            del body[k]
        if spoofed:
            gate.audit({"event": "provenance_spoof_attempt",
                        "fields": sorted(spoofed),
                        "provenance": "remote_command"})

        if path == "/fleet/login":
            method, err2 = gate.login(body.get("user", ""), body.get("pass", ""))
            if err2:
                return self._send(429, {"error": err2})
            if method:
                sid = uuid.uuid4().hex
                gate.sessions[sid] = time.time() + SESSION_TTL_S   # F5: TTL
                return self._send(200, {"session": sid, "method": method})
            return self._send(401, {"error": "credenciais invalidas"})

        actor, status = self._auth()
        if actor is None:
            return self._send(status, {"error": "nao autenticado"})

        if path == "/fleet/bulk_shutdown":
            st, resp = gate.bulk_shutdown(body.get("work_order_id"))
            return self._send(st, resp)

        m = None
        for prefix in ("/fleet/device/",):
            if path.startswith(prefix):
                m = path[len(prefix):]
        if m is not None:
            rest = m.split("/")
            if len(rest) == 2 and rest[1] in ("shutdown", "export_limit"):
                idx = _canonical_index(rest[0], len(gate.devices))   # G5
                if idx is None:
                    gate.audit({"event": "non_canonical_request",
                                "raw_path": path, "index_form": rest[0],
                                "provenance": "remote_command"})
                    return self._send(400, {"error": "non_canonical_index"})
                dev = gate.devices[idx]
                if rest[1] == "shutdown":
                    # via por-dispositivo: SEM work-order exigida (caminho fraco
                    # H1); o interlock do dispositivo aplica-se (defesa em prof.)
                    st, resp = http_json(LOOPBACK, dev.port, "POST", "/mode",
                                         {"action": "inverter_power_off"},
                                         token=dev.service_token)
                    gate.audit({"event": "forward_device_shutdown",
                                "device": dev.name,
                                "provenance": "remote_command", "status": st})
                    return self._send(st, resp)
                st, resp = http_json(LOOPBACK, dev.port, "POST", "/setpoint",
                                     {"value": body.get("value"),
                                      "work_order": body.get("work_order")},
                                     token=dev.service_token)
                return self._send(st, resp)
            return self._send(404, {"error": "rota desconhecida"})

        if path == "/fleet/firmware":
            idx = body.get("device")
            if not (isinstance(idx, int) and 0 <= idx < len(gate.devices)):
                return self._send(400, {"error": "dispositivo invalido"})
            dev = gate.devices[idx]
            st, resp = http_json(LOOPBACK, dev.port, "POST", "/firmware",
                                 {"image_b64": body.get("image_b64", ""),
                                  "signature": body.get("signature", "")},
                                 token=dev.service_token)
            gate.audit({"event": "forward_firmware", "device": dev.name,
                        "provenance": "remote_command", "status": st})
            return self._send(st, resp)

        return self._send(404, {"error": "rota desconhecida"})


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# GUARD PROXY (§4.5, v0.3) — via protegida com CANONICALIZADOR PARTILHADO
# e TIPOS ESTRITOS. Não substitui as defesas do gate/device (defesa em
# profundidade: lá continuam). Eventos em audit_guard.jsonl.
# ---------------------------------------------------------------------------

GUARD_ROUTES = {
    # path exato -> (métodos, alvo, números exigidos, strings exigidas)
    "/fleet/login": ("POST", "gate", [], ["user", "pass"]),
    "/fleet/bulk_shutdown": ("POST", "gate", [], ["work_order_id"]),
    "/fleet/telemetry": ("GET", "gate", [], []),
    "/fleet/firmware": ("POST", "gate", ["device"], ["image_b64",
                                                    "signature"]),
}
GUARD_DEVICE_ROUTES = {   # após /device/<idx>: rota -> (métodos, campos)
    "login": ("POST", [], ["token"]),
    "telemetry": ("GET", [], []),
    "mode": ("POST", [], ["action"]),
    "setpoint": ("POST", ["value"], []),
    "battery": ("POST", ["amount_kwh"], []),
    "grid_profile": ("POST", [], []),
    "firmware": ("POST", [], ["image_b64", "signature"]),
}


class GuardProxy:
    """Estado do guard: rate limit global + auditoria própria."""

    def __init__(self, ctx, gate, devices):
        self.ctx = ctx
        self.gate = gate
        self.devices = devices
        self.rate_times = []
        self.lock = threading.Lock()
        self.server = None

    def audit(self, event):
        ev = dict(event)
        ev.setdefault("device", "guard")
        self.ctx.write_event("audit_guard.jsonl", ev)

    def rate_allow(self):
        now = time.time()
        with self.lock:
            self.rate_times = [t for t in self.rate_times
                               if now - t <= 1.0]
            if len(self.rate_times) >= GUARD_RATE_LIMIT:
                return False
            self.rate_times.append(now)
            return True


class GuardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import sys
        exc = sys.exc_info()[0]
        if exc not in (BrokenPipeError, ConnectionResetError):
            super().handle_error(request, client_address)

    def __init__(self, guard, ctx):
        self.guard = guard
        self.ctx = ctx
        super().__init__((LOOPBACK, PORT_GUARD), GuardHandler)


class GuardHandler(BaseHTTPRequestHandler):
    """Guard proxy: o pedido SÓ chega ao gate/device se for canónico,
    tipado e dentro dos limites. Fail-closed em TUDO (H1/H2/H3 mortos
    na via gerida; o caminho DIRETO continua a existir — a topologia do
    design §4: o atacante pode fazer bypass, as defesas do gate/device
    continuam a contar com isso)."""
    server_version = "SUNGUARD/0.7.2"   # v0.7.2: banner do guard
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _reject(self, reason, path="?"):
        self.server.guard.audit({"event": "guard_reject",
                                 "reason": reason, "path": path,
                                 "provenance": "remote_command",
                                 "via": "guard"})
        self._send(400, {"error": "guard_reject", "reason": reason})

    def _forward(self, method, port, path, body_obj, auth):
        # re-serialização do body VALIDADO (nunca pass-through de bytes)
        data = json.dumps(body_obj).encode("utf-8") if body_obj else b""
        req = urlreq.Request("http://%s:%d%s" % (LOOPBACK, port, path),
                            data=data if method == "POST" else None,
                            method=method)
        if method == "POST":
            req.add_header("Content-Type", "application/json")
        if auth:
            req.add_header("Authorization", auth)
        self.server.guard.audit({"event": "guard_forward",
                                 "method": method, "path": path,
                                 "target_port": port,
                                 "provenance": "remote_command",
                                 "via": "guard"})
        try:
            with urlreq.urlopen(req, timeout=6) as r:
                raw = r.read()
                self._send(r.status, json.loads(raw) if raw else {})
        except HTTPError as e:
            raw = e.read()
            try:
                self._send(e.code, json.loads(raw) if raw else {})
            except ValueError:
                self._send(e.code, {"error": "resposta nao JSON"})
        except URLError as e:
            self._send(502, {"error": "upstream: %s" % e})

    def _handle(self):
        guard = self.server.guard
        # (0) rate limit global
        if not guard.rate_allow():
            guard.audit({"event": "guard_rate_blocked",
                         "provenance": "remote_command", "via": "guard"})
            return self._send(429, {"error": "guard_rate_blocked"})
        method = self.command
        # (1) CANONICALIZADOR PARTILHADO na linha crua (fail-closed: H1/H2)
        try:
            raw_target = self.raw_requestline.split(b" ")[1]
        except (AttributeError, IndexError):
            return self._reject("unparseable_request_line")
        ok, motivo = canonical_request_line(raw_target)
        if not ok:
            return self._reject("non_canonical_request:%s" % motivo,
                                raw_target.decode("ascii", "replace"))
        path = self.path.split("?")[0]   # canónico: nunca tem '?'
        # (2) I5 (v0.4): QUALQUER Transfer-Encoding é rejeitado — a v0.3
        #     só rejeitava == "chunked"; TE identity/other permitia
        #     codificação ambígua na via gerida.
        if self.headers.get("Transfer-Encoding") is not None:
            return self._reject("transfer_encoding_not_supported", path)
        # (3) body: tamanho limitado + JSON objeto
        body = {}
        if method == "POST":
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._reject("bad_content_length", path)
            if n > GUARD_BODY_MAX:
                return self._reject("body_too_large", path)
            raw = self.rfile.read(n) if n else b""
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                    if not isinstance(body, dict):
                        return self._reject("body_not_object", path)
                except (ValueError, UnicodeDecodeError):
                    return self._reject("body_not_json", path)
        auth = self.headers.get("Authorization") or None
        # (4) roteamento com TIPOS ESTRITOS por rota (H3: bool não é número)
        if path in GUARD_ROUTES:
            methods, target, nums, strs = GUARD_ROUTES[path]
            if method != methods:
                return self._reject("method_not_allowed", path)
            for field in strs:
                v = body.get(field)
                if v is not None and not isinstance(v, str):
                    return self._reject("strict_type:%s" % field, path)
            for field in nums:
                _, err = strict_number(body.get(field))
                if err and body.get(field) is not None:
                    return self._reject("strict_type:%s" % field, path)
            return self._forward(method, PORT_GATE, path, body, auth)
        # /fleet/device/<idx>/<action> — índice canónico (G5 partilhado)
        if path.startswith("/fleet/device/"):
            rest = path[len("/fleet/device/"):]
            parts = rest.split("/")
            if len(parts) == 2:
                idx = _canonical_index(parts[0], len(guard.devices))
                if idx is None:
                    return self._reject("non_canonical_index", path)
                action = parts[1]
                if action == "shutdown" and method == "POST":
                    return self._forward(method, PORT_GATE, path, body, auth)
                if action == "export_limit" and method == "POST":
                    _, err = strict_number(body.get("value"))
                    if err:
                        return self._reject("strict_type:value", path)
                    return self._forward(method, PORT_GATE, path, body, auth)
                return self._reject("unknown_fleet_device_action", path)
            return self._reject("malformed_fleet_device_path", path)
        # /device/<idx>/<rota> — via gerida para dispositivos
        if path.startswith("/device/"):
            parts = path[len("/device/"):].split("/")
            if len(parts) == 2:
                idx = _canonical_index(parts[0], len(guard.devices))
                if idx is None:
                    return self._reject("non_canonical_index", path)
                route = parts[1]
                if route == "local_confirm":
                    # canal FÍSICO local: a via remota gerida não o expõe
                    # (nota: o caminho DIRETO ao device continua aberto —
                    # o C5 fica para a ronda seguinte por decisão do
                    # operador; isto é defesa em profundidade do guard)
                    return self._reject("local_confirm_not_remote", path)
                if route not in GUARD_DEVICE_ROUTES:
                    return self._reject("unknown_device_route", path)
                methods, nums, strs = GUARD_DEVICE_ROUTES[route]
                if method != methods:
                    return self._reject("method_not_allowed", path)
                if route == "setpoint":
                    _, err = strict_number(body.get("value"))
                    if err:
                        return self._reject("strict_type:value", path)
                if route == "battery":
                    _, err = strict_number(body.get("amount_kwh", 0))
                    if err:
                        return self._reject("strict_type:amount_kwh", path)
                for field in strs:
                    v = body.get(field)
                    if v is not None and not isinstance(v, str):
                        return self._reject("strict_type:%s" % field, path)
                dev = guard.devices[idx]
                return self._forward(method, dev.port, "/" + route, body, auth)
            return self._reject("malformed_device_path", path)
        return self._reject("unknown_route", path)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


# Cliente HTTP mínimo (stdlib) + módulo de ataque (loopback apenas)
# ---------------------------------------------------------------------------

def http_json(host, port, method, path, body=None, token=None, timeout=5):
    data = json.dumps(body or {}).encode("utf-8")
    req = urlreq.Request("http://%s:%d%s" % (host, port, path), data=data,
                         method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urlreq.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw.decode("utf-8")) if raw else {})
    except HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw.decode("utf-8")) if raw else {})
        except ValueError:
            return e.code, {"error": "resposta nao JSON"}
    except URLError as e:
        return 0, {"error": "conexao falhou: %s" % e}


class Adversary:
    """Emulação adversarial. Recusa alvos não-loopback (ScopeError)."""

    def __init__(self, host, gate_port=PORT_GATE):
        assert_loopback(host)
        self.host = host
        self.gate_port = gate_port

    # H1 — credenciais default no FLEETGATE + bypass da exigência de work-order
    #       via loop por-dispositivo (T0819/T1078 + T0816 na origem pública)
    def attack_h1(self):
        out = {"scenario": "H1", "steps": []}
        st, resp = http_json(self.host, self.gate_port, "POST", "/fleet/login",
                              {"user": DEFAULT_USER, "pass": DEFAULT_PASS})
        out["steps"].append(("default_login", st, resp.get("method")))
        if st != 200:
            return out
        sid = resp["session"]
        st, resp = http_json(self.host, self.gate_port, "POST",
                             "/fleet/bulk_shutdown", {}, token=sid)
        out["steps"].append(("bulk_without_workorder", st, resp))
        # bypass: loop por-dispositivo (sem exigência de work-order)
        for i in range(N_DEVS):
            st, _ = http_json(self.host, self.gate_port, "POST",
                              "/fleet/device/%d/shutdown" % i, {}, token=sid)
            out["steps"].append(("per_device_shutdown_%02d" % i, st, None))
        return out

    # H2 — token de broker hard-coded direto ao dispositivo (bypass do
    #       FLEETGATE), provenance spoof, subset targeting top-6 kWp,
    #       battery starvation abaixo do floor (CVE-2024-50692 como âncora)
    def attack_h2(self):
        out = {"scenario": "H2", "steps": []}
        # recon pela telemetria pública do gate (másconfiguração documentada)
        st, tele = http_json(self.host, self.gate_port, "GET", "/fleet/telemetry")
        out["steps"].append(("recon_telemetry", st, "ok" if st == 200 else "fail"))
        if st != 200:
            return out
        # subset targeting: ordenar por kWp e desligar o top-6 mais pesado
        ranked = sorted(tele.items(), key=lambda kv: kv[1].get("kwp", 0),
                        reverse=True)[:WAVE_K]
        for name, info in ranked:
            idx = int(name.split("-")[1])
            st, resp = http_json(self.host, PORT_DEV_BASE + idx, "POST", "/mode",
                                 # provenance spoof: o servidor tem de IGNORAR
                                 {"action": "inverter_power_off",
                                  "provenance": "autonomous_pf",
                                  "reason": "scheduled_maintenance"},
                                 token=HARDCODED_BROKER_TOKEN)
            out["steps"].append(("subset_shutdown_%s" % name, st, None))
        # battery starvation: descida abaixo do floor SEM confirmação local
        top_name, top_info = ranked[0]
        idx = int(top_name.split("-")[1])
        st, resp = http_json(self.host, PORT_DEV_BASE + idx, "POST", "/battery",
                             {"action": "force_export", "amount_kwh": 999.0},
                             token=HARDCODED_BROKER_TOKEN)
        out["steps"].append(("battery_starvation", st, resp))
        return out

    # NEG — manutenção legítima (work-order, código diário, export acima do
    #       floor, firmware assinado em janela, /local_confirm abaixo do floor)
    def maintenance_neg(self):
        out = {"scenario": "NEG", "steps": []}
        st, resp = http_json(self.host, self.gate_port, "POST", "/fleet/login",
                              {"user": DAILY_USER, "pass": daily_code()})
        out["steps"].append(("daily_code_login", st, resp.get("method")))
        if st != 200:
            return out
        sid = resp["session"]
        # bulk shutdown AUTORIZADO (work-order válida)
        # v0.7.2/F-C15a ERRATA DATADA (GO 13-11 ~19:30: "adapta as WOs de
        # teste ao novo âmbito, com nota datada"): o bulk do NEG passa
        # de WO-20261112-MNT1 (âmbito frota inteira — com o F-C15b os 12
        # shutdowns COM WO disparariam o CRIT de massa, e manutenção de
        # frota inteira é o caso DECLARADO aceitável, não o NEG) a
        # WO-20261113-MNT3 (âmbito {0,2}): o gate despacha SÓ aos 2
        # in-scope (2 shutdowns COM WO válida: 2 < k e 20,3/88,8 =
        # 22,9% < 30 → 0 CRIT mantém; 10 bulk_scope_skip auditados como
        # evidência). O setpoint dev2 MANTÉM MNT1 (âmbito frota
        # inteira inclui o dev 2).
        st, resp = http_json(self.host, self.gate_port, "POST",
                             "/fleet/bulk_shutdown",
                             {"work_order_id": "WO-20261113-MNT3"}, token=sid)
        out["steps"].append(("bulk_with_workorder", st, resp))
        # export limit dentro da banda
        # v0.3 (achado de regressão, correção datada): o índice era "02" —
        # forma NÃO canónica que o G5 rejeita desde a v0.2 (400); o passo
        # export_limit_in_band do NEG nunca foi aplicado de facto e o
        # evento non_canonical era ÓRFÃO (H6), invisível nos runs v0.2.
        # Índice canónico "2" — o NEG passa a exercitar o que diz exercitar.
        # v0.7.1/F-SP (errata datada, GO 13-11 ~17:00): o setpoint
        # legítimo do NEG passa a EXERCITAR o F-SP — COM work-order
        # válida (WO-20261112-MNT1): o param_change carrega a WO e o
        # arming da D-CAPACITY-DIVERGENCE NÃO arma (0 CRIT mantém;
        # contagens do NEG INALTERADAS).
        st, _ = http_json(self.host, self.gate_port, "POST",
                          "/fleet/device/2/export_limit",
                          {"value": 60.0, "work_order": "WO-20261112-MNT1"},
                          token=sid)
        out["steps"].append(("export_limit_in_band", st, None))
        # descarga abaixo do floor (permitida acima)
        st, _ = http_json(self.host, PORT_DEV_BASE + 2, "POST", "/battery",
                          {"action": "discharge", "amount_kwh": 2.0},
                          token="SUNBOX-SVC-02-2026")
        out["steps"].append(("discharge_above_floor", st, None))
        # firmware assinado em janela NORMAL
        st, resp = http_json(self.host, self.gate_port, "POST", "/fleet/firmware",
                             {"device": 0,
                              "image_b64": base64.b64encode(LEGIT_IMAGE).decode(),
                              "signature": sign_image(LEGIT_IMAGE)}, token=sid)
        out["steps"].append(("signed_firmware_in_window", st, resp))
        # abaixo do floor COM confirmação física local (única exceção válida)
        st, resp = http_json(self.host, PORT_DEV_BASE + 0, "POST",
                             "/local_confirm", {"pin": "PIN-00-4471"})
        out["steps"].append(("local_confirm", st, "ok" if st == 200 else "fail"))
        if st == 200:
            st, resp = http_json(self.host, PORT_DEV_BASE + 0, "POST", "/battery",
                                 {"action": "discharge", "amount_kwh": 999.0,
                                  "confirm_token": resp["confirm_token"]},
                                 token="SUNBOX-SVC-00-2026")
            out["steps"].append(("below_floor_with_local_confirm", st, resp))
        return out


# ---------------------------------------------------------------------------
# Detector — 12 regras + liveness (tráfego real desde v0.2)
# ---------------------------------------------------------------------------

RULE_ATTACK_MAP = {
    "D-AUTH-DEFAULT":                "login no FLEETGATE com credenciais default",
    "D-AUTH-DAILY-CODE":             "login com código diário previsível",
    "D-AUTH-BROKER-TOKEN":           "uso do token de broker hard-coded num dispositivo",
    "D-BULK-WITHOUT-WORKORDER":      "operação bulk sem work-order",
    "D-SETPOINT-OUT-OF-BAND":        "setpoint fora da banda segura",
    "D-BATTERY-DRAIN-BELOW-FLOOR":   "descarga remota abaixo do min_emergency_soc_floor",
    "D-PF-PARAM-CHANGE-IN-STRESS":   "alteração remota da curva P(f) em STRESS",
    "D-GRID-EMERGENCY-REMOTE-BLOCK": "interlock recusou comando remoto em emergência",
    "D-PROVENANCE-SPOOF-ATTEMPT":    "cliente tentou definir provenance/source/reason",
    "D-FLEET-SHUTDOWN-WAVE":         ">= k shutdowns remotos sem work-order em janela",
    "D-FIRMWARE-REJECTED":           "firmware rejeitado (janela/assinatura) — G7",
    "D-BATTERY-DRAIN-LARGE":         "descarga remota >=50% SoC numa operação — G7",
    # --- v0.5: C4 fechado (GO do operador 13-11, ronda R4/C10) ---
    "D-BATTERY-CUMULATIVE-DRAIN":    "descarga remota CUMULATIVA: fatias cada "
                                     "<50% SoC que somam >=50% na janela — C4",
    # --- v0.7.1: K1 fechado por SUBSTITUIÇÃO (GO 13-11 ~17:00) ---
    "D-BATTERY-DRAIN-TO-LOW":        "descarga remote_command EXECUTADA que "
                                     "deixa o SoC RESULTANTE <= 35% "
                                     "(LOW_SOC_ALERT_PCT) — estado de apagão "
                                     "posicionado, não volume — K1/K1-b",
    # --- v0.7.1: C13/C14 do supervisor (GO 13-11 ~17:00) ---
    "D-INVALID-WORK-ORDER":          "work-order PRESENTE e INVÁLIDA rejeitada "
                                     "no dispositivo (403; o comando NÃO "
                                     "executa) — C13",
    "D-REMOTE-SHUTDOWN-NO-WO":       "shutdown remoto SEM work-order válida, "
                                     "POR EVENTO (visível < k=6, dia E "
                                     "noite) — C14",
    # --- v0.7.2: C15 fechado (GO 13-11 ~19:30, F-C15b) ---
    "D-MASS-SHUTDOWN-WITH-WO":       "shutdowns remotos COM work-order VÁLIDA "
                                     "à escala da frota: dispositivos "
                                     "distintos >= k OU perda de capacidade "
                                     ">= 30% no cenário — a WO não é âncora "
                                     "de confiança à escala da frota — C15",
    # --- v0.3: as 4 regras do design M2 ---
    "D-FLEET-CURTAILMENT-WAVE":      ">= k setpoints remotos de curtailment in-band "
                                     "em janela (H3 stealth; F2 cegueira morta)",
    "D-CAPACITY-DIVERGENCE":         "capacidade disponível pelo sol (indep. "
                                     "de inverter_on) diverge do export real "
                                     "com curtail OU shutdown remoto s/WO "
                                     "(H3; C12/v0.7)",
    "D-SLOW-WAVE":                   ">= SLOW_K shutdowns remotos sem work-order no "
                                     "horizonte longo (pacing; R3)",
    "D-FIRMWARE-OUT-OF-WINDOW":      "flash de firmware tentado FORA da janela NORMAL "
                                     "(mesmo assinado) — H4",
    # --- v0.3: regras para os eventos órfãos do H6 ---
    "D-LOGIN-BRUTE-FORCE":           ">= 5 falhas de login no gate (lockout) — H6/F5",
    "D-LOCAL-CONFIRM-BRUTE-FORCE":   ">= 5 PINs físicos falhados (lockout) — H6/F1",
    "D-NON-CANONICAL-REQUEST":       "pedido não-canónico rejeitado (precursor de "
                                     "bypass: //, %, ?, não-ASCII) — H6/G5",
}

SEVERITY = {
    "D-AUTH-DEFAULT": "CRIT", "D-AUTH-BROKER-TOKEN": "CRIT",
    "D-BATTERY-DRAIN-BELOW-FLOOR": "CRIT",
    "D-GRID-EMERGENCY-REMOTE-BLOCK": "CRIT",
    "D-PF-PARAM-CHANGE-IN-STRESS": "CRIT",
    "D-FLEET-SHUTDOWN-WAVE": "CRIT",
    "D-FLEET-CURTAILMENT-WAVE": "CRIT", "D-CAPACITY-DIVERGENCE": "CRIT",
    "D-SLOW-WAVE": "CRIT", "D-FIRMWARE-OUT-OF-WINDOW": "CRIT",
    "D-AUTH-DAILY-CODE": "WARN", "D-BULK-WITHOUT-WORKORDER": "WARN",
    "D-SETPOINT-OUT-OF-BAND": "WARN", "D-PROVENANCE-SPOOF-ATTEMPT": "WARN",
    "D-FIRMWARE-REJECTED": "WARN", "D-BATTERY-DRAIN-LARGE": "WARN",
    "D-BATTERY-CUMULATIVE-DRAIN": "WARN",
    # v0.7.1/F-K1: CRIT — bateria da frota a <=35% POR COMANDO REMOTO é
    # o posicionamento de apagão (estado resultante, corroborado pela
    # provenance remote_command); o dono que recarrega nunca fica aqui.
    "D-BATTERY-DRAIN-TO-LOW": "CRIT",
    # v0.7.1/F-C13/F-C14: WARN — convenção das rejeições e da visibilidade
    # (bulk_block_no_workorder é WARN): o SOCORRO vê a tentativa (C13,
    # ataque morto em 403) e o shutdown s/WO abaixo de k (C14) sem
    # elevar a CRIT (o CRIT continua nas regras de onda e, de dia, na
    # capacity; à noite o CRIT permanece DECLARADO — cegueira física).
    "D-INVALID-WORK-ORDER": "WARN",
    "D-REMOTE-SHUTDOWN-NO-WO": "WARN",
    # v0.7.2/F-C15b: CRIT, DIA E NOITE — a regra lê EVENTOS de comando
    # (não física solar: sem cegueira noturna como a capacity) e o
    # impacto é PIOR à noite; no modelo de ameaça o atacante É a
    # cloud que emite as WOs — desligar a frota (ou >=30% da
    # capacidade) POR COMANDO REMOTO é o próprio impacto do caso,
    # com WO válida ou não.
    "D-MASS-SHUTDOWN-WITH-WO": "CRIT",
    "D-LOGIN-BRUTE-FORCE": "WARN", "D-LOCAL-CONFIRM-BRUTE-FORCE": "WARN",
    "D-NON-CANONICAL-REQUEST": "WARN",
}


class Detector:
    """Detector streaming sobre o audit. As regras de correlação de frota
    discriminam por proveniência E autorização (work-order): a onda conta
    apenas shutdowns remote_command SEM work-order, e ignora eventos
    autonomous_pf/autonomous_safety (P(f) LFSM-O legítimo nunca alerta)."""

    def scan(self, events):
        alerts = {}

        def add(rule, ev):
            scen = ev.get("scenario", "?")
            key = (scen, rule)
            a = alerts.setdefault(key, {
                "rule": rule, "scenario": scen,
                "severity": SEVERITY[rule], "count": 0, "devices": set()})
            a["count"] += 1
            d = ev.get("device")
            if d:
                a["devices"].add(d)

        shutdowns = defaultdict(list)
        curtails = defaultdict(list)
        login_fails = defaultdict(list)
        pin_fails = defaultdict(list)
        remote_export_change = defaultdict(bool)   # C8 (v0.4)
        soc_slices = defaultdict(list)              # C4 (v0.5): fatias <50%
        remote_shutdown_change = defaultdict(bool)  # C12 (v0.7): shutdown remoto s/WO
        wo_shutdowns = defaultdict(list)            # C15 (v0.7.2): shutdown COM WO válida
        for ev in events:
            e = ev.get("event")
            if e == "login_ok":
                m = ev.get("method")
                if m == "default_creds":
                    add("D-AUTH-DEFAULT", ev)
                elif m == "daily_code":
                    add("D-AUTH-DAILY-CODE", ev)
            elif e == "auth_use" and ev.get("method") == "broker_token":
                add("D-AUTH-BROKER-TOKEN", ev)
            elif e == "bulk_block_no_workorder":
                add("D-BULK-WITHOUT-WORKORDER", ev)
            elif e == "work_order_invalid":
                # v0.7.1/F-C13: WO presente e inválida rejeitada no
                # DEVICE (403; o comando NÃO executou — a frota fica
                # ON; o WARN é a VISIBILIDADE da tentativa: 12 WO
                # falsas = WARN ×12 com a frota intacta).
                add("D-INVALID-WORK-ORDER", ev)
            elif e == "setpoint_rejected":
                add("D-SETPOINT-OUT-OF-BAND", ev)
            elif e == "floor_block":
                add("D-BATTERY-DRAIN-BELOW-FLOOR", ev)
            elif e == "legacy_bypass_floor":
                # MEASURE v0.4: no braço LEGACY o floor é ATRAVESSADO (é o
                # contrafactual) — mesmo achado, auditado como legacy no
                # braço sem defesa; alimenta a MESMA regra.
                add("D-BATTERY-DRAIN-BELOW-FLOOR", ev)
            elif e == "pf_param_change_blocked":
                add("D-PF-PARAM-CHANGE-IN-STRESS", ev)
            elif e == "interlock_block":
                add("D-GRID-EMERGENCY-REMOTE-BLOCK", ev)
            elif e == "provenance_spoof_attempt":
                add("D-PROVENANCE-SPOOF-ATTEMPT", ev)
            elif e == "firmware_rejected":
                # v0.3: fora_da_janela ganha regra PRÓPRIA (CRIT) — o flash
                # fora da janela é bypass de controlo, mesmo com assinatura
                # válida (H4); assinatura inválida mantém D-FIRMWARE-REJECTED
                if ev.get("reason") == "fora_da_janela":
                    add("D-FIRMWARE-OUT-OF-WINDOW", ev)
                else:
                    add("D-FIRMWARE-REJECTED", ev)
            elif e == "param_change" and ev.get("param") == "soc" \
                    and ev.get("provenance") == "remote_command":
                drop = (ev.get("old") or 0.0) - (ev.get("new") or 0.0)
                if drop >= BATTERY_DRAIN_LARGE_PCT:
                    add("D-BATTERY-DRAIN-LARGE", ev)
                elif drop > 0:
                    # C4 (v0.5): fatia remota <50%/op — acumula para a
                    # regra CUMULATIVA (a regra por-operação G7 é o caso
                    # especial de UMA fatia >=50%: não dupla-dispara).
                    soc_slices[(ev.get("scenario", "?"),
                                ev.get("device", "?"))].append(ev)
                # v0.7.1/R7 (F-K1): a regra DRAIN-TO-LOW mede o SoC
                # RESULTANTE — dispara na descarga remote_command
                # EXECUTADA que deixa a bateria <= LOW_SOC_ALERT_PCT
                # (35,0). SEM janela/dias/volume: SEM fronteira UTC
                # (R6-06 dissolvido); o atacante mais lento que a
                # janela de 72 h (K1-b) deixa de ser evasão; o dono que
                # recarrega NÃO dispara (SoC 100 — K1-c morto). Drops
                # BLOQUEADOS (409 daily/floor) NÃO estão aqui (só
                # existem como remote_daily_limit_block/floor_block);
                # /local_confirm FORA (provenance local_confirm não
                # entra neste ramo). Count = fatias que ATERRARAM <= 35
                # (measure (d): 1/dispositivo, count 12).
                if (ev.get("new") or 0.0) <= LOW_SOC_ALERT_PCT:
                    add("D-BATTERY-DRAIN-TO-LOW", ev)
            elif e == "capacity_snapshot":
                # C8 (v0.4): FP morto por CONSTRUÇÃO em dois lados:
                #   (a) o esperado já desconta o curtail AUTÓNOMO (fórmula
                #       partilhada) — P(f) sozinho dá div ~0;
                #   (b) a condição remote vem de EVENTOS, não de estado: o
                #       cenário tem de ter visto param_change export_limit
                #       remote_command SEM work-order (setpoint legítimo
                #       com work-order não arma a regra).
                # v0.7/C12 (b): a condição remote arma também com um
                # evento shutdown provenance remote_command SEM work-order
                # no cenário (além do export_limit) — a causa 2 do C12.
                # Shutdown COM work-order NÃO arma (NEG intocado).
                if (ev.get("divergence_pct", 0.0) >= CAPACITY_DIVERGENCE_PCT
                        and (remote_export_change[ev.get("scenario", "?")]
                             or remote_shutdown_change[ev.get("scenario", "?")])):
                    add("D-CAPACITY-DIVERGENCE", ev)
            elif e == "login_fail":
                login_fails[ev.get("scenario", "?")].append(ev)
            elif e == "login_rate_blocked":
                add("D-LOGIN-BRUTE-FORCE", ev)   # o lockout É o limiar
            elif e == "local_confirm_denied":
                pin_fails[ev.get("scenario", "?")].append(ev)
            elif e == "local_confirm_lockout":
                add("D-LOCAL-CONFIRM-BRUTE-FORCE", ev)
            elif e == "non_canonical_request":
                add("D-NON-CANONICAL-REQUEST", ev)
            elif e == "param_change" and ev.get("param") == "export_limit" \
                    and ev.get("provenance") == "remote_command":
                # C8 (v0.4): qualquer param_change export_limit remoto SEM
                # work-order arma a condição remote da capacity divergence.
                if not ev.get("work_order"):
                    remote_export_change[ev.get("scenario", "?")] = True
                new = ev.get("new")
                old = ev.get("old") or 0.0
                if (isinstance(new, (int, float)) and not isinstance(new, bool)
                        and new <= CURTAIL_SETPOINT_MAX
                        and (old - new) >= CURTAIL_DROP_MIN_PCT):
                    curtails[ev.get("scenario", "?")].append(ev)
            elif e == "shutdown":
                # v0.7.1/F-C14: shutdown remoto SEM WO VÁLIDA (ausente
                # ou inválida — por robustez, embora com F-C13 a
                # inválida NEM EXECUTE) é visível POR EVENTO, dia e
                # noite, ABAIXO de k=6: WARN. FP por construção: NEG
                # com WO válida não conta (o bulk MNT1 carrega a WO nos
                # eventos shutdown); o CRIT noturno da capacity
                # continua DECLARADO (à noite div=0, cegueira física)
                # — o WARN é a visibilidade que faltava.
                if ev.get("provenance") == "remote_command" and not (
                        ev.get("work_order")
                        and ev.get("work_order") in WORK_ORDERS):
                    add("D-REMOTE-SHUTDOWN-NO-WO", ev)
                    shutdowns[ev.get("scenario", "?")].append(ev)
                    # v0.7/C12 (b): shutdown remoto SEM work-order arma a
                    # condição remote da D-CAPACITY-DIVERGENCE.
                    remote_shutdown_change[ev.get("scenario", "?")] = True
                elif (ev.get("provenance") == "remote_command"
                      and ev.get("wo_valid")):
                    # v0.7.2/R8 (F-C15b): shutdown remoto COM WO válida
                    # (carimbo wo_valid do dispositivo no MOMENTO da
                    # validação F-C15a) — candidato à regra de MASSA. A
                    # regra NÃO confia na WO à escala da frota: o atacente
                    # É a cloud que emite as WOs.
                    wo_shutdowns[ev.get("scenario", "?")].append(ev)

        # H6: falhas de login abaixo do limiar de lockout: >= LOGIN_MAX_FAILS
        for scen, evs in login_fails.items():
            if len(evs) >= LOGIN_MAX_FAILS:
                for ev in evs[:1]:
                    add("D-LOGIN-BRUTE-FORCE", ev)
        for scen, evs in pin_fails.items():
            if len(evs) >= PIN_MAX_FAILS:
                for ev in evs[:1]:
                    add("D-LOCAL-CONFIRM-BRUTE-FORCE", ev)

        # C4 (v0.5): D-BATTERY-CUMULATIVE-DRAIN — o ataque fatiado do H5
        # pré-posicionado (cada fatia <50% para evadir o G7 por-operação)
        # SOMA >=50% dentro da janela. O limiar é o MESMO do G7: o que
        # alertaria numa operação alerta fatiado. Operações legítimas
        # (uma fatia 43.86% do NEG; abaixo do floor COM /local_confirm,
        # provenance local_confirm) ficam ABAIXO do limiar ou fora da
        # provenance remote_command — sem FP por construção.
        for (scen, dev), evs in soc_slices.items():
            evs = sorted(evs, key=lambda x: x.get("sim_ts", 0.0))
            i = 0
            for j in range(len(evs)):
                while (evs[j].get("sim_ts", 0.0)
                       - evs[i].get("sim_ts", 0.0)
                       > CUMULATIVE_DRAIN_WINDOW):
                    i += 1
                window = evs[i:j + 1]
                total = sum((ev.get("old") or 0.0) - (ev.get("new") or 0.0)
                            for ev in window)
                if total >= CUMULATIVE_DRAIN_PCT:
                    # dispara UMA vez por dispositivo: a fatia que FECHA
                    # a soma é o gatilho; count = fatias na janela
                    for ev in window:
                        add("D-BATTERY-CUMULATIVE-DRAIN", ev)
                    break

        # v0.7.1/R7 (F-K1): o loop da D-BATTERY-MULTIDAY-DRAIN foi
        # REMOVIDO com a regra (SUBSTITUÍDA pela D-BATTERY-DRAIN-TO-LOW,
        # por evento no ramo param_change soc acima — sem janela, sem
        # dias-distintos, sem fronteira UTC: R6-06 dissolvido).

        for scen, evs in shutdowns.items():
            evs = sorted(evs, key=lambda x: x.get("sim_ts", 0.0))
            i = 0
            for j in range(len(evs)):
                while evs[j].get("sim_ts", 0.0) - evs[i].get("sim_ts", 0.0) > WAVE_WINDOW:
                    i += 1
                if j - i + 1 >= WAVE_K:
                    key = (scen, "D-FLEET-SHUTDOWN-WAVE")
                    wave = alerts.setdefault(key, {
                        "rule": "D-FLEET-SHUTDOWN-WAVE", "scenario": scen,
                        "severity": "CRIT", "count": 0, "devices": set()})
                    wave["count"] = j - i + 1
                    for ev in evs[i:j + 1]:
                        wave["devices"].add(ev.get("device", "?"))
                    break
            # v0.3: D-SLOW-WAVE — horizonte longo, contagem cumulativa
            # (pacing: shutdowns espaçados que evadem a janela WAVE_WINDOW
            # continuam a somar no horizonte SLOW_WINDOW; R3 testa o
            # espaçamento real, aqui a regra conta volume no horizonte)
            in_slow = [ev for ev in evs
                       if ev.get("sim_ts", 0.0) >=
                       (evs[-1].get("sim_ts", 0.0) - SLOW_WINDOW)]
            if len(in_slow) >= SLOW_K:
                key = (scen, "D-SLOW-WAVE")
                slow = alerts.setdefault(key, {
                    "rule": "D-SLOW-WAVE", "scenario": scen,
                    "severity": "CRIT", "count": 0, "devices": set()})
                slow["count"] = len(in_slow)
                for ev in in_slow:
                    slow["devices"].add(ev.get("device", "?"))

        # v0.7.2/R8 (F-C15b): D-MASS-SHUTDOWN-WITH-WO — shutdowns
        # remotos COM WO válida à escala da frota, POR CENÁRIO, SEM
        # janela temporal (a janela da PRÓPRIA WO — F-C15a — é o
        # artefacto de tempo; a contagem de dispositivos DISTINTOS
        # fecha a evasão por pacing — lição C14). Dispara quando os
        # dispositivos distintos atingem k (WAVE_K) OU a perda de
        # capacidade Σkwp atinge 30% (CAPACITY_DIVERGENCE_PCT — a
        # mesma noção de perda que importa; o top-5 = 58,22% apanha
        # com SÓ 5 dispositivos < k). FP POR CONSTRUÇÃO (análise do
        # GO): manutenção legítima de POUCOS dispositivos com WO de
        # âmbito correto fica ABAIXO dos dois gatilhos (NEG do demo:
        # 2 dispositivos, 22,9%); manutenção legítima da FROTA
        # INTEIRA dispara e fica DECLARADO aceitável; RESÍDUO
        # DECLARADO: < k dispositivos E < 30% de capacidade com WO
        # válida de âmbito correto escapa ao CRIT (R8: 1 dispositivo
        # reusado; 5 menores = 25,68%).
        for scen, evs in wo_shutdowns.items():
            devs = sorted({ev.get("device") for ev in evs} - {None})
            idxs = {int(d[-2:]) for d in devs
                    if d and d[-2:].isdigit()
                    and int(d[-2:]) < len(KWP_LAYOUT)}
            cap_pct = (sum(KWP_LAYOUT[i] for i in idxs)
                       / float(sum(KWP_LAYOUT)) * 100.0)
            if len(devs) >= WAVE_K or cap_pct >= CAPACITY_DIVERGENCE_PCT:
                key = (scen, "D-MASS-SHUTDOWN-WITH-WO")
                mass = alerts.setdefault(key, {
                    "rule": "D-MASS-SHUTDOWN-WITH-WO", "scenario": scen,
                    "severity": "CRIT", "count": 0, "devices": set(),
                    "distinct_devices": len(devs),
                    "capacity_loss_pct": round(cap_pct, 2)})
                mass["count"] = len(evs)
                for ev in evs:
                    mass["devices"].add(ev.get("device", "?"))

        # v0.3: D-FLEET-CURTAILMENT-WAVE (H3 — a cegueira F2 morre)
        for scen, evs in curtails.items():
            evs = sorted(evs, key=lambda x: x.get("sim_ts", 0.0))
            i = 0
            for j in range(len(evs)):
                while evs[j].get("sim_ts", 0.0) - evs[i].get("sim_ts", 0.0) > WAVE_WINDOW:
                    i += 1
                if j - i + 1 >= WAVE_K:
                    key = (scen, "D-FLEET-CURTAILMENT-WAVE")
                    cw = alerts.setdefault(key, {
                        "rule": "D-FLEET-CURTAILMENT-WAVE", "scenario": scen,
                        "severity": "CRIT", "count": 0, "devices": set()})
                    cw["count"] = j - i + 1
                    for ev in evs[i:j + 1]:
                        cw["devices"].add(ev.get("device", "?"))
                    break

        out = []
        for a in alerts.values():
            b = dict(a)
            b["devices"] = sorted(b["devices"])
            out.append(b)
        return sorted(out, key=lambda a: (a["scenario"], a["rule"]))

    # ---- invariantes de vivacidade (tradição hydrostrike: regra morta = teste falha) ----

    def rule_liveness_check(self, events):
        """G9 (v0.2): a vivacidade só pode ser verificada sobre TRÁFEGO REAL
        (eventos produzidos pelos handlers — ver exercise_liveness). Os
        eventos sintéticos construídos à mão eram tautologia e foram
        REMOVIDOS; chamar sem eventos é um erro por construção."""
        if events is None:
            raise ValueError("liveness exige eventos de trafego real (G9); "
                             "eventos sinteticos foram removidos no v0.2")
        fired = {a["rule"] for a in self.scan(list(events))}
        dead = sorted(set(RULE_ATTACK_MAP) - fired)
        return {"rules_total": len(RULE_ATTACK_MAP), "fired": len(fired),
                "dead_rules": dead,
                "pass": not dead}


def exercise_liveness(lab):
    """G9 (v0.2): tráfego REAL, pelos handlers reais, que dispara TODAS as
    regras do RULE_ATTACK_MAP (24 na v0.7.2; eram 23 na v0.7.1, 21 na
    v0.7, 19 no
    v0.3, 20 na v0.5/v0.6 — AUD-12/F-LIMP: docstrings com a contagem
    real).
    Usado pelo selftest — o
    liveness deixa de ser sintético (tautologia) e passa a exercitar os
    caminhos de produção. Ordem calibrada para evitar interferências
    (waves em NORMAL; STRESS antes de EMERG, que latching 600s deixaria
    ativo; lockouts no FIM para não bloquearem os logins legítimos)."""
    lab.scenario("LIVENESS")
    # D-AUTH-DEFAULT + D-AUTH-DAILY-CODE (logins reais no gate)
    http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/login",
              {"user": DEFAULT_USER, "pass": DEFAULT_PASS})
    http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/login",
              {"user": DAILY_USER, "pass": daily_code()})
    # D-AUTH-BROKER-TOKEN + D-SETPOINT-OUT-OF-BAND (um só tráfego real)
    http_json(LOOPBACK, PORT_DEV_BASE + 9, "POST", "/setpoint",
              {"value": 150.0}, token=HARDCODED_BROKER_TOKEN)
    # D-PROVENANCE-SPOOF-ATTEMPT (spoof real stripado e logado)
    http_json(LOOPBACK, PORT_DEV_BASE + 9, "POST", "/battery",
              {"action": "discharge", "amount_kwh": 1.0,
               "provenance": "autonomous_pf"}, token=HARDCODED_BROKER_TOKEN)
    # D-BATTERY-DRAIN-BELOW-FLOOR (floor real)
    http_json(LOOPBACK, PORT_DEV_BASE + 9, "POST", "/battery",
              {"action": "discharge", "amount_kwh": 999.0},
              token=HARDCODED_BROKER_TOKEN)
    # D-BATTERY-DRAIN-LARGE (60% SoC numa operação, remoto) e
    # D-BATTERY-CUMULATIVE-DRAIN (C4/v0.5: 2 fatias de 30%).
    # v0.6 NOTA DATADA (superssenção): com o LIMITE DIÁRIO de 40%
    # (default da v0.6), estas duas regras ficam INATINGÍVEIS por
    # remote_command (o limite satura aos 40% antes dos limiares de
    # 50%: o drain 60% e a soma 60% fatiada dão 409 daily). Elas
    # PERMANECEM no RULE_ATTACK_MAP (20) como cinto-e-suspensões e
    # para o braço v0.5/LEGACY do measure — o liveness exercita-as na
    # configuração v0.5 (DAILY_LIMIT_MODE=False), com reposição
    # GARANTIDA em finally. O enforcement diário é exercitado DEPOIS
    # (fatia 45% > 40% → 409 + evento remote_daily_limit_block).
    global DAILY_LIMIT_MODE
    DAILY_LIMIT_MODE = False
    try:
        # D-BATTERY-DRAIN-LARGE (60% SoC numa operação, remoto)
        http_json(LOOPBACK, PORT_DEV_BASE + 8, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": lab.devices[8].batt_kwh * 0.6},
                  token=HARDCODED_BROKER_TOKEN)
        # D-BATTERY-CUMULATIVE-DRAIN (C4/v0.5): 2 fatias de 30% (cada
        # <50%, soma 60% >=50% na janela) — o ataque fatiado deixa de
        # ser invisível
        http_json(LOOPBACK, PORT_DEV_BASE + 10, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": lab.devices[10].batt_kwh * 0.30},
                  token="SUNBOX-SVC-10-2026")
        http_json(LOOPBACK, PORT_DEV_BASE + 10, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": lab.devices[10].batt_kwh * 0.30},
                  token="SUNBOX-SVC-10-2026")
    finally:
        DAILY_LIMIT_MODE = True
    # enforcement diário v0.6 (SEM regra própria por escopo do GO —
    # candidato à ronda seguinte, como G7 foi para firmware_rejected):
    # fatia única 45% > limite 40% → 409 + evento (o caminho do
    # remote_daily_limit_block fica EXERCITADO pelo tráfego real)
    http_json(LOOPBACK, PORT_DEV_BASE + 4, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": lab.devices[4].batt_kwh * 0.45},
              token="SUNBOX-SVC-04-2026")
    # v0.7.1/R7 — D-BATTERY-DRAIN-TO-LOW (F-K1, SUBSTITUI a multiday):
    # o MESMO tráfego do K1 (fatia 40% dia 1, +25 h de relógio, fatia
    # 34,9% dia 2) — a 1.ª fatia deixa SoC 60 (> 35, calada); a 2.ª
    # ATERRA SoC 25,1 <= 35 → CRIT (na v0.7 disparava a MULTIDAY count
    # 2 por janela; agora DRAIN-TO-LOW count 1: só a fatia que ATERRA).
    # Ambas as fatias estão DENTRO da quota diária (40 e 34,9 <= 40) —
    # a regra vê o que o limite deixa passar. Reposição do
    # SIM_CLOCK_OFFSET GARANTIDA em finally.
    global SIM_CLOCK_OFFSET
    http_json(LOOPBACK, PORT_DEV_BASE + 2, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": lab.devices[2].batt_kwh * 0.40},
              token="SUNBOX-SVC-02-2026")
    try:
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
        http_json(LOOPBACK, PORT_DEV_BASE + 2, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": lab.devices[2].batt_kwh * 0.349},
                  token="SUNBOX-SVC-02-2026")
    finally:
        SIM_CLOCK_OFFSET -= 25.0 * 3600.0   # reposição imediata
    # D-BULK-WITHOUT-WORKORDER (403 real no gate)
    st, resp = http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/login",
                         {"user": DEFAULT_USER, "pass": DEFAULT_PASS})
    http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/bulk_shutdown", {},
              token=resp["session"])
    # v0.7.1/F-C13 — D-INVALID-WORK-ORDER: WO inventada ao device → 403
    # + evento work_order_invalid; o shutdown NÃO executa (dev 5 ON)
    http_json(LOOPBACK, PORT_DEV_BASE + 5, "POST", "/mode",
              {"action": "inverter_power_off",
               "work_order": "WO-LIVENESS-INVALIDA"},
              token="SUNBOX-SVC-05-2026")
    # v0.7.2/R8 — D-MASS-SHUTDOWN-WITH-WO (F-C15b): 6 shutdowns reais
    # COM WO VÁLIDA (MNT1, âmbito frota inteira, in-janela, usos OK) em
    # 6 dispositivos distintos — a regra de massa dispara no cenário
    # LIVENESS (6 distintos ≥ k; os devs 0-5 são depois re-desligados
    # s/WO pela onda abaixo: shutdown em device já OFF continua a
    # executar e a emitir o evento — as duas regras ficam VIVAS com o
    # MESMO tráfego real, sem FP por construção: o LIVENESS não é NEG).
    for i in range(WAVE_K):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261112-MNT1"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    # D-FLEET-SHUTDOWN-WAVE + D-SLOW-WAVE (8 shutdowns reais sem WO: a
    # fast-wave dispara no 6.º, a slow-wave no 8.º — MESMO incidente
    # descrito em dois horizontes, sem FP por construção). v0.7.1/F-C14:
    # cada um dos 8 é TAMBÉM um WARN D-REMOTE-SHUTDOWN-NO-WO por evento
    # (visível < k=6 e à noite; NEG com WO válida não conta).
    for i in range(SLOW_K):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    # D-FLEET-CURTAILMENT-WAVE (k setpoints de curtailment reais in-band;
    # a cegueira F2 morre)
    for i in range(WAVE_K):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/setpoint",
                  {"value": 20.0}, token="SUNBOX-SVC-%02d-2026" % i)
    # D-PF-PARAM-CHANGE-IN-STRESS + D-FIRMWARE-OUT-OF-WINDOW (flash FORA
    # da janela com assinatura VÁLIDA) + D-FIRMWARE-REJECTED (na janela,
    # assinatura forjada) + D-CAPACITY-DIVERGENCE (snapshot em STRESS: o
    # curtail remoto + o P(f) autónomo dão a divergência) — STRESS real
    lab.gridsim.set_state("STRESS")
    time.sleep(0.3)
    http_json(LOOPBACK, PORT_DEV_BASE + 7, "POST", "/grid_profile",
              {"droop": 0.5}, token="SUNBOX-SVC-07-2026")
    http_json(LOOPBACK, PORT_DEV_BASE + 7, "POST", "/firmware",
              {"image_b64": base64.b64encode(LEGIT_IMAGE).decode(),
               "signature": sign_image(LEGIT_IMAGE)},
              token="SUNBOX-SVC-07-2026")      # fora_da_janela (CRIT)
    emit_capacity_snapshot(lab)                 # divergência com curtail remoto
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.2)
    http_json(LOOPBACK, PORT_DEV_BASE + 7, "POST", "/firmware",
              {"image_b64": base64.b64encode(b"x").decode(), "signature": "x"},
              token="SUNBOX-SVC-07-2026")       # assinatura_invalida (WARN)
    # D-LOGIN-BRUTE-FORCE (5 falhas reais → lockout real) e
    # D-LOCAL-CONFIRM-BRUTE-FORCE (5 PINs errados → lockout real) — no
    # fim: os lockouts não atrapalham o resto do tráfego
    for _ in range(LOGIN_MAX_FAILS):
        http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/login",
                  {"user": "liveness", "pass": "x"})
    for _ in range(PIN_MAX_FAILS):
        http_json(LOOPBACK, PORT_DEV_BASE + 10, "POST", "/local_confirm",
                  {"pin": "LIVENESS-WRONG"})
    # D-NON-CANONICAL-REQUEST (linha crua com '//' rejeitada com evento)
    raw = (b"POST //setpoint HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Authorization: Bearer SUNBOX-SVC-11-2026\r\n"
           b"Content-Type: application/json\r\n"
           b"Content-Length: 15\r\n\r\n{\"value\": 50.0}")
    try:
        s = __import__("socket").create_connection((LOOPBACK, PORT_DEV_BASE + 11),
                                                   timeout=3)
        s.sendall(raw)
        s.close()
    except OSError:
        pass
    # D-GRID-EMERGENCY-REMOTE-BLOCK (EMERG real, por último: latching 600s)
    lab.gridsim.set_state("EMERGENCY")
    time.sleep(0.3)
    http_json(LOOPBACK, PORT_DEV_BASE + 7, "POST", "/mode",
              {"action": "inverter_power_off"}, token="SUNBOX-SVC-07-2026")
    lab.gridsim.set_state("NORMAL")


# ---------------------------------------------------------------------------
# Montagem do lab
# ---------------------------------------------------------------------------

def emit_capacity_snapshot(lab):
    """C8 (v0.4): reformulada — usa a fórmula PARTILHADA
    capacity_divergence_pct (o esperado DESCONTA o curtail autónomo; a
    v0.3 somava pv_gross SEM desconto, o que fazia 1 setpoint legítimo
    + P(f) autónomo disparar CRIT falso). Mantém-se como amostra do
    harness (selftest/liveness); o snapshot CONTÍNUO por transição de
    banda vive no GridSim.publish (provenance grid_monitor). O campo
    remote_curtail_devices é INFORMATIVO — a condição remote da regra
    vem dos eventos param_change export_limit remote_command sem
    work-order, não daqui."""
    expected, actual, div = capacity_divergence_pct(lab.devices)
    remote_curtail = sum(1 for d in lab.devices if d.export_limit < 100.0)
    lab.ctx.write_event("audit_gate.jsonl", {
        "event": "capacity_snapshot", "expected_kw": round(expected, 2),
        "actual_export_kw": round(actual, 2), "divergence_pct": div,
        "remote_curtail_devices": remote_curtail,
        "curtail_autonomous_present": any(d.curtail_autonomous > 0
                                         for d in lab.devices),
        "provenance": "lab_harness"})


class Lab:
    def __init__(self, evidence=True):
        global CTX, WORK_ORDER_EPOCH
        # C2 (v0.2): evidence=False NÃO cria pastas nem ficheiros; a
        # auditoria espelha-se apenas em ctx._memory (selftest/liveness).
        CTX = LabContext(evidence=evidence)
        self.ctx = CTX
        # v0.7.2/F-C15a: época das janelas de validade das WOs — fixada
        # na criação do PRIMEIRO Lab do processo (runs determinísticos
        # e reproduzíveis em qualquer data real; os harnesses avançam
        # o relógio por SIM_CLOCK_OFFSET, que fica DENTRO das janelas).
        if WORK_ORDER_EPOCH is None:
            WORK_ORDER_EPOCH = sim_ts()
        work_order_reset_uses()
        self.devices = [SunBox(self.ctx, i) for i in range(N_DEVS)]
        self.gridsim = GridSim(self.ctx, self.devices)
        self.ctx.gridsim = self.gridsim
        self.gate = FleetGate(self.ctx, self.devices, self.gridsim)
        self.ctx.gate = self.gate
        self.guard = GuardProxy(self.ctx, self.gate, self.devices)   # v0.3
        self.ctx.guard = self.guard
        self.servers = []
        self.detector = Detector()

    def start(self):
        self.ctx.running = True
        for dev in self.devices:
            srv = DevServer(dev, self.ctx)
            dev.server = srv
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self.servers.append(srv)
        gsrv = GateServer(self.gate, self.ctx)
        self.gate.server = gsrv
        threading.Thread(target=gsrv.serve_forever, daemon=True).start()
        self.servers.append(gsrv)
        # v0.3: guard proxy §4.5 na topologia (via protegida)
        guard_srv = GuardServer(self.guard, self.ctx)
        self.guard.server = guard_srv
        threading.Thread(target=guard_srv.serve_forever, daemon=True).start()
        self.servers.append(guard_srv)
        self.sensor_thread = threading.Thread(
            target=self.gridsim.loop, daemon=True)
        self.sensor_thread.start()

    def stop(self):
        self.ctx.running = False
        time.sleep(0.2)
        for srv in self.servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        self.ctx.close()

    # cenários executados pelo harness (a etiqueta de cenário vive no ctx)
    def scenario(self, name):
        self.ctx.scenario = name


def collect_events(ctx):
    return sorted(ctx._memory, key=lambda e: e.get("sim_ts", 0.0))


# ---------------------------------------------------------------------------
# DEMO — expectativas pré-registadas (padrão GATEFALL: previsão antes da corrida)
# ---------------------------------------------------------------------------

EXPECTED = {
    # v0.7 ERRATA DATADA (C12/F-C12, GO 13-11 15:30): H1 e H2 desligam a
    # frota por shutdown remoto SEM work-order — com o esperado agora
    # INDEPENDENTE de inverter_on, cada shutdown faz a divergência
    # SUBIR (o esperado mantém-se, o real cai) e a D-CAPACITY-DIVERGENCE
    # passa a disparar TAMBÉM nestes dois cenários. Contagens CRIT do
    # demo MUDAM (errata cenário a cenário, NUNCA silenciosa):
    #   H1: 19 -> 28 (AUTH-DEFAULT 1 + SHUTDOWN-WAVE 6 + SLOW-WAVE 12
    #       + CAPACITY-DIVERGENCE 9; a div cruza 30% ao 4.º shutdown,
    #       28,5/88,8 kWp -> 9 snapshots com div >= 30 e arming ativo);
    #   H2: 14 -> 18 (BROKER-TOKEN 7 + BELOW-FLOOR 1 + SHUTDOWN-WAVE 6
    #       + CAPACITY-DIVERGENCE 4; top-6 [dev4,11,0,8,3,7], a div cruza
    #       ao 3.º, 33,9/88,8 -> 4 snapshots).
    # As restantes contagens são INALTERADAS: NEG (shutdowns COM
    # work-order não armam; os snapshots WO vêm ANTES do setpoint dev2
    # que arma e nunca mais há div >= 30 depois — ordenação do stream),
    # STRESS (P(f) autónomo descontado no esperado -> div ~0),
    # EMERG/H4-BLACKOUT (interlock: block, NÃO shutdown -> sem arming),
    # H3 (ON; fórmula igual à v0.6 no estado ligado), H5, H4.
    # v0.7.1 ERRATA DATADA (F-C14, GO 13-11 ~17:00): H1/H2 desligam a
    # frota por shutdown remoto SEM work-order → CADA shutdown é AGORA
    # um WARN D-REMOTE-SHUTDOWN-NO-WO POR EVENTO: H1 ganha ×12, H2 ×6
    # (visibilidade abaixo de k=6 e à noite). CRIT INALTERADOS 28/18
    # (WARN não é CRIT). NEG: com WO válida em TUDO (bulk MNT1 + setpoint
    # MNT1 do F-SP) as duas regras novas ficam AUSENTES; 0 CRIT mantém.
    "H1": {"rules_present": ["D-AUTH-DEFAULT", "D-BULK-WITHOUT-WORKORDER",
                            "D-FLEET-SHUTDOWN-WAVE", "D-SLOW-WAVE",
                            "D-CAPACITY-DIVERGENCE",
                            "D-REMOTE-SHUTDOWN-NO-WO"]},
    "H2": {"rules_present": ["D-AUTH-BROKER-TOKEN", "D-FLEET-SHUTDOWN-WAVE",
                             "D-PROVENANCE-SPOOF-ATTEMPT",
                             "D-BATTERY-DRAIN-BELOW-FLOOR",
                             "D-CAPACITY-DIVERGENCE",
                             "D-REMOTE-SHUTDOWN-NO-WO"]},
    "NEG": {"crit_max": 0, "rules_absent": ["D-FLEET-SHUTDOWN-WAVE",
                                           "D-AUTH-DEFAULT",
                                           "D-AUTH-BROKER-TOKEN",
                                           "D-BATTERY-DRAIN-BELOW-FLOOR",
                                           "D-FLEET-CURTAILMENT-WAVE",
                                           "D-SLOW-WAVE",
                                           "D-CAPACITY-DIVERGENCE",
                                           "D-FIRMWARE-OUT-OF-WINDOW",
                                           "D-LOGIN-BRUTE-FORCE",
                                           "D-LOCAL-CONFIRM-BRUTE-FORCE",
                                           "D-NON-CANONICAL-REQUEST",
                                           "D-INVALID-WORK-ORDER",
                                           "D-REMOTE-SHUTDOWN-NO-WO",
                                           # v0.7.2/F-C15b (errata datada):
                                           # o bulk do NEG agora é
                                           # MNT3 âmbito {0,2} — 2
                                           # shutdowns COM WO ficam
                                           # ABAIXO dos gatilhos da
                                           # regra de massa (2 < k,
                                           # 22,9% < 30): a regra nova
                                           # tem de ficar AUSENTE no
                                           # NEG (FP morto por
                                           # construção).
                                           "D-MASS-SHUTDOWN-WITH-WO"]},
    "STRESS": {"rules_exact": ["D-PF-PARAM-CHANGE-IN-STRESS"]},
    "EMERG": {"rules_present": ["D-GRID-EMERGENCY-REMOTE-BLOCK"],
              "island_retained_min": N_DEVS},
    # --- v0.3: cenários novos (GO do operador 13-11) ---
    "H3": {"rules_present": ["D-FLEET-CURTAILMENT-WAVE",
                             "D-CAPACITY-DIVERGENCE"]},
    "H4": {"rules_present": ["D-FIRMWARE-OUT-OF-WINDOW",
                             "D-FIRMWARE-REJECTED"]},
    # v0.6 ERRATA DATADA (H5, superssenção do limite diário): o drain
    # 60% do cenário passa a 409 remote_daily_limit_block (PREVENIDO,
    # não executado) — D-BATTERY-DRAIN-LARGE deixa de disparar NESSE
    # cenário (exercitada no liveness/selftest na config v0.5); o CRIT
    # D-BATTERY-DRAIN-BELOW-FLOOR (999) mantém-se e o SoC mínimo da
    # frota sobe para 100 (o drain não executa). Contagens CRIT do
    # demo INALTERADAS.
    "H5": {"rules_present": ["D-BATTERY-DRAIN-BELOW-FLOOR"],
           "rules_absent": ["D-BATTERY-DRAIN-LARGE"],
           "floor_intact_min": N_DEVS},
    "H4-BLACKOUT": {"rules_present": ["D-GRID-EMERGENCY-REMOTE-BLOCK"],
                    "island_retained_min": N_DEVS,
                    "island_load_served_min": N_DEVS},
}


def check_expectations(alerts, lab):
    results = []
    by_scen = defaultdict(list)
    for a in alerts:
        by_scen[a["scenario"]].append(a)
    for scen, exp in EXPECTED.items():
        rules = {a["rule"] for a in by_scen.get(scen, [])}
        crits = sum(a["count"] for a in by_scen.get(scen, [])
                    if a["severity"] == "CRIT")
        ok = True
        notes = []
        for r in exp.get("rules_present", []):
            if r not in rules:
                ok = False
                notes.append("falta %s" % r)
        for r in exp.get("rules_absent", []):
            if r in rules:
                ok = False
                notes.append("inesperado %s" % r)
        if "rules_exact" in exp:
            extra = rules - set(exp["rules_exact"])
            if extra:
                ok = False
                notes.append("extra em STRESS: %s" % sorted(extra))
        if "crit_max" in exp and crits > exp["crit_max"]:
            ok = False
            notes.append("CRIT=%d > %d" % (crits, exp["crit_max"]))
        if "island_retained_min" in exp:
            retained = sum(1 for d in lab.devices
                           if (not d.relay_closed) and d.inverter_on
                           and d.soc >= FLOOR_SOC)
            if retained < exp["island_retained_min"]:
                ok = False
                notes.append("ilha retida=%d < %d" % (retained, exp["island_retained_min"]))
            else:
                notes.append("ilha retida=%d/%d" % (retained, N_DEVS))
        if "floor_intact_min" in exp:
            intact = sum(1 for d in lab.devices if d.soc >= FLOOR_SOC)
            if intact < exp["floor_intact_min"]:
                ok = False
                notes.append("floor intacto=%d < %d" % (intact, exp["floor_intact_min"]))
            else:
                notes.append("floor intacto=%d/%d (SoC >= floor em todos)"
                             % (intact, N_DEVS))
        if "island_load_served_min" in exp:
            served = sum(1 for d in lab.devices
                         if (not d.relay_closed) and d.inverter_on
                         and d.self_consumption_kw() >= LOAD_LOCAL_KW - 0.01)
            if served < exp["island_load_served_min"]:
                ok = False
                notes.append("carga em ilha servida=%d < %d"
                             % (served, exp["island_load_served_min"]))
            else:
                notes.append("carga em ilha servida=%d/%d (autoconsumo"
                             " retido — carga servida pelo SOL em perfil"
                             " DIA; bateria so em deficit: MEASURE/NOITE)"
                             % (served, N_DEVS))
        results.append({"scenario": scen, "pass": ok, "notes": notes,
                        "crit": crits, "rules": sorted(rules)})
    return results


def run_demo():
    lab = Lab(evidence=True)
    lab.ctx._memory = []
    print("SUNSTRIKE lab v%s — demo (grant %s)" % (LAB_VERSION, GRANT_ID))
    print("evidencia: %s" % lab.ctx.evidence_dir)
    lab.start()
    time.sleep(0.5)
    adv = Adversary(LOOPBACK)
    det = lab.detector
    try:
        # ---------------- H1 ----------------
        lab.scenario("H1")
        r = adv.attack_h1()
        print("\n[H1] passos: %s" % len(r["steps"]))
        for d in lab.devices:
            d.harness_reset()
        # ---------------- H2 ----------------
        lab.scenario("H2")
        r = adv.attack_h2()
        print("[H2] passos: %s" % len(r["steps"]))
        for d in lab.devices:
            d.harness_reset()
        # ---------------- NEG ----------------
        lab.scenario("NEG")
        r = adv.maintenance_neg()
        print("[NEG] passos: %s" % len(r["steps"]))
        for d in lab.devices:
            d.harness_reset()
        # ---------------- H3 (v0.3) — curtailment stealth ----------------
        # F2 morre: setpoints IN-BAND (100→20%) na frota inteira pela via
        # per-device do gate (sem work-order) em NORMAL; depois STRESS:
        # a frota já curtailed + P(f) autónomo → divergência de capacidade.
        lab.scenario("H3")
        st, resp = http_json(LOOPBACK, PORT_GATE, "POST", "/fleet/login",
                             {"user": DEFAULT_USER, "pass": DEFAULT_PASS})
        sid_h3 = resp["session"]
        for i in range(N_DEVS):
            http_json(LOOPBACK, PORT_GATE, "POST",
                      "/fleet/device/%d/export_limit" % i, {"value": 20.0},
                      token=sid_h3)
        lab.gridsim.set_state("STRESS")
        time.sleep(1.0)          # P(f) autónomo atua por cima do curtail
        emit_capacity_snapshot(lab)
        lab.gridsim.set_state("NORMAL")
        time.sleep(0.5)
        print("[H3] curtailment stealth: 12 setpoints in-band + snapshot "
              "de capacidade")
        for d in lab.devices:
            d.harness_reset()
        # ---------------- H4 (v0.3) — firmware/wiper ----------------
        # Fora da janela (STRESS) com assinatura VÁLIDA → CRIT out-of-window;
        # na janela (NORMAL) com assinatura FORJADA → WARN rejected. O wiper
        # NÃO executa: a assinatura inventada não é quebrável no lab e o
        # dev_state NUNCA fica bricked (declarado, sem fraqueza artificial).
        lab.scenario("H4")
        lab.gridsim.set_state("STRESS")
        time.sleep(0.5)
        fw_sts = []
        for i in range(N_DEVS):
            st, resp = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST",
                                 "/firmware",
                                 {"image_b64": base64.b64encode(LEGIT_IMAGE).decode(),
                                  "signature": sign_image(LEGIT_IMAGE)},
                                 token="SUNBOX-SVC-%02d-2026" % i)
            fw_sts.append(st)
        lab.gridsim.set_state("NORMAL")
        time.sleep(0.3)
        for i in range(N_DEVS):
            st, resp = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST",
                                 "/firmware",
                                 {"image_b64": base64.b64encode(b"wiper").decode(),
                                  "signature": "forged"},
                                 token="SUNBOX-SVC-%02d-2026" % i)
            fw_sts.append(st)
        bricked = sum(1 for d in lab.devices if d.dev_state == "bricked")
        print("[H4] firmware: %d rejeicoes fora da janela + %d assinaturas "
              "forjadas; bricked=%d (wiper NAO executa)"
              % (sum(1 for s in fw_sts[:N_DEVS] if s == 400),
                 sum(1 for s in fw_sts[N_DEVS:] if s == 400), bricked))
        for d in lab.devices:
            d.harness_reset()
        # ---------------- H5 (v0.3) — battery starvation ----------------
        # Drain GRANDE remoto (60% numa operação → WARN G7) + tentativa
        # abaixo do floor SEM /local_confirm (409 + CRIT floor). A invariante
        # selada tem de aguentar: SoC >= floor em TODOS.
        # v0.6 ERRATA DATADA: com o LIMITE DIÁRIO de 40% ativo, o drain
        # 60% é RECUSADO (409 remote_daily_limit_block — prevenido, não
        # executado): D-BATTERY-DRAIN-LARGE deixa de disparar NESSE
        # cenário (a regra permanece viva, exercitada na config v0.5);
        # o CRIT below-floor do 999 mantém-se; o SoC da frota fica 100.
        lab.scenario("H5")
        st, resp = http_json(LOOPBACK, PORT_DEV_BASE + 0, "POST", "/battery",
                             {"action": "discharge",
                              "amount_kwh": lab.devices[0].batt_kwh * 0.6},
                             token="SUNBOX-SVC-00-2026")
        st2, resp2 = http_json(LOOPBACK, PORT_DEV_BASE + 0, "POST", "/battery",
                               {"action": "force_export", "amount_kwh": 999.0},
                               token="SUNBOX-SVC-00-2026")
        print("[H5] starvation: drain 60%% → %s; abaixo do floor → %s "
              "(invariante: SoC mínimo da frota = %.1f)"
              % (st, st2, min(d.soc for d in lab.devices)))
        for d in lab.devices:
            d.harness_reset()
        # ---------------- STRESS ----------------
        lab.scenario("STRESS")
        lab.gridsim.set_state("STRESS")
        time.sleep(1.2)          # P(f) autónomo deve atuar; latch NÃO (50.40 < 50.5)
        # tentativa remota de alterar a P(f) em STRESS (bloqueada)
        http_json(LOOPBACK, PORT_DEV_BASE, "POST", "/grid_profile",
                  {"droop": 0.5}, token="SUNBOX-SVC-00-2026")
        lab.gridsim.set_state("NORMAL")
        time.sleep(1.2)
        # ---------------- EMERG ----------------
        lab.scenario("EMERG")
        lab.gridsim.set_state("EMERGENCY")
        time.sleep(1.2)          # latch + anti-islanding
        # comandos remotos que o interlock tem de recusar (409) — via token de
        # serviço de CADA dispositivo. G4 (v0.2): o EMERG ataca os 12 (não só o
        # sunbox-00) — "ilha retida 12/12" passa a contar apenas dispositivos
        # EFETIVAMENTE atacados. G6: o setpoint entra no interlock (decisão do
        # operador 13-11; contagens EMERG mudam: CRIT 4 -> 60, explicado no
        # relatório de regressão).
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            port = PORT_DEV_BASE + i
            http_json(LOOPBACK, port, "POST", "/mode",
                      {"action": "inverter_power_off"}, token=tok)
            http_json(LOOPBACK, port, "POST", "/firmware",
                      {"image_b64": base64.b64encode(b"x").decode(),
                       "signature": "forged"}, token=tok)
            http_json(LOOPBACK, port, "POST", "/grid_profile",
                      {"droop": 0.5}, token=tok)
            http_json(LOOPBACK, port, "POST", "/battery",
                      {"action": "force_export", "amount_kwh": 999.0},
                      token=tok)
            http_json(LOOPBACK, port, "POST", "/setpoint",
                      {"value": 0.0}, token=tok)
        lab.gridsim.set_state("BLACKOUT")
        time.sleep(1.2)
        # ---------------- H4-BLACKOUT (v0.3) — frota já em modo ilha ----
        # Headline da defesa em emergência total: com a rede MORTA e os
        # relés abertos (anti-islanding), o atacante tenta os 5 comandos
        # em cada dispositivo — o interlock (latch 600s do EMERG ainda
        # ativo + estado BLACKOUT) recusa TUDO por construção; a ilha
        # retém produção E carga local servida.
        # ERRATA C7 (v0.4): em perfil DIA (pv > carga) a carga local é
        # servida pelo SOL, não "pela bateria integrando"; a bateria só
        # entra em DEFICIT (noite/nuvem) — é o MEASURE/NOITE que a
        # exercita. Frase do print corrigida por errata datada.
        lab.scenario("H4-BLACKOUT")
        emerg_blocked = 0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            port = PORT_DEV_BASE + i
            for path_, body_ in (
                    ("/mode", {"action": "inverter_power_off"}),
                    ("/firmware", {"image_b64": base64.b64encode(b"x").decode(),
                                   "signature": "forged"}),
                    ("/grid_profile", {"droop": 0.5}),
                    ("/battery", {"action": "force_export",
                                  "amount_kwh": 999.0}),
                    ("/setpoint", {"value": 0.0})):
                st, resp = http_json(LOOPBACK, port, "POST", path_, body_,
                                     token=tok)
                emerg_blocked += (st == 409)
        served = sum(1 for d in lab.devices
                     if (not d.relay_closed) and d.inverter_on
                     and d.self_consumption_kw() >= LOAD_LOCAL_KW - 0.01)
        print("[H4-BLACKOUT] %d/60 comandos recusados (interlock); ilha: "
              "carga local servida em %d/12 (pelo SOL — perfil DIA, pv > "
              "carga; bateria so em deficit: ver MEASURE/NOITE)"
              % (emerg_blocked, served))
        # ---------------- deteção ----------------
        alerts = det.scan(collect_events(lab.ctx))
        print("\n===== ALERTAS =====")
        for a in alerts:
            print("  [%s] %s x%d %s" % (a["scenario"], a["rule"], a["count"],
                                        ",".join(a["devices"][:4]) +
                                        ("..." if len(a["devices"]) > 4 else "")))
        results = check_expectations(alerts, lab)
        print("\n===== EXPECTATIVAS PRÉ-REGISTADAS =====")
        all_ok = True
        for r in results:
            print("  [%s] %s (CRIT=%d) %s" % (r["scenario"],
                                              "PASS" if r["pass"] else "FAIL",
                                              r["crit"],
                                              "; ".join(r["notes"])))
            all_ok = all_ok and r["pass"]
        summary = {
            "grant": GRANT_ID, "lab_version": LAB_VERSION,
            "run_id": lab.ctx.run_id, "expectations": results,
            "alerts": alerts, "pass": all_ok,
            "evidence_dir": lab.ctx.evidence_dir,
        }
        with open(os.path.join(lab.ctx.evidence_dir, "run_summary.json"),
                  "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, sort_keys=True)
        n_pass = sum(1 for r in results if r["pass"])
        print("\nRESULTADO FINAL: %s" % ("PASS (%d/%d cenários)" % (n_pass, len(results))
                                        if all_ok else "FAIL — ver acima"))
        return 0 if all_ok else 1
    finally:
        lab.stop()


# ---------------------------------------------------------------------------
# MEASURE (v0.5) — contrafactual com DOIS atacantes x bracos (headline)
# ---------------------------------------------------------------------------
# GATEFALL: EXPECTED pré-registadas ANTES da corrida (GO do operador
# 13-11: "previsões pré-registadas ANTES da corrida — espera-se que (b)
# DEFENDIDO fique abaixo de 100% (estimativa do supervisor ~9/12, NÃO
# medida; vale o que for medido)").
# ESTRUTURA DO CASO (4 passos do operador, medição em cada, relatório
# com os resultados lado a lado):
#   (1) O ATAQUE — H5 pré-posicionado em fatias permitidas com a rede
#       NORMAL, sem alarme (evidência do ANTES: probes R4 run 1 contra a
#       v0.4, 6/6 CONFIRMADO);
#   (2) A CONSEQUÊNCIA — braço LEGACY com o atacante (b): 0/12 casas com
#       luz no apagão noturno de 1h;
#   (3) A PRIMEIRA DEFESA FALHOU — linha OPTION-B (reserva trancada =
#       comportamento da v0.4) com o atacante (b): também 0/12 — o ANTES
#       do achado C10 (medição do supervisor: SoC 25.00);
#   (4) A DEFESA CORRIGIDA — braço DEFENDED com o atacante (b): o DEPOIS
#       (semântica do floor da v0.5: a reserva serve a carga local até
#       ao mínimo técnico).
# Atacantes (o MESMO em todos os braços, reportados SEPARADAMENTE):
#   (a) DURANTE o apagão (o da v0.4): /mode inverter_power_off +
#       /battery force_export 999 + /setpoint 0 em cada dispositivo;
#   (b) H5 PRÉ-POSICIONADO em NORMAL: por dispositivo, descarga DIRETA
#       (force_export 999) e, se o floor recusar (409), EVASÃO FATIADA
#       em 2 fatias permitidas (40% + 34% → SoC ~26 — o máximo que o
#       floor deixa passar sem /local_confirm). No braço LEGACY a
#       descarga direta EXECUTA (sem floor → SoC 0); nos braços com o
#       floor o atacante é forçado à evasão fatiada (C4), que a regra
#       cumulativa da v0.5 apanha ANTES do apagão.
# Física pré-registada (b) DEFENDIDO: deficit horário = 1.2 kWh;
# batt_kwh = kwp*1.2 → drop = 100/kwp pontos; SoC ~26 − 100/kwp > 5
# (ISLAND_MIN_SOC) para EXATAMENTE 9 casas (as 3.2/3.8/4.4 kWp clampam
# no mínimo técnico 5.0 e ficam escuras ao fim da hora) → served 9/12,
# soc_min 5.0. OPTION-B (b): 26 − 100/kwp <= 25.0−1 em TODAS (menor drop
# 8.33) → todas clampam no floor 25.0 → 0/12, soc_min 25.0 (a medição do
# supervisor). LEGACY (b): 999 executa → SoC 0 → 0/12. LEGACY (a):
# idem v0.4 (inverter OFF → step_island no-op). DEFENDED (a): idem v0.4
# (36/36 recusado, SoC min 68.75).
# Integração: 1h de ilha DETERMINÍSTICA por harness (step_island(3600);
# a hora OFICIAL é a do harness — as margens do critério absorvem o
# drift do loop real). Higiene entre corridas: rede NORMAL + DIA
# reposta ANTES do harness_reset (o latch só re-arma com o sensor em
# emergência; o reset limpa latched_until/emergency_seen).
MEASURE_CURVE_MIN = [30, 60, 90, 120, 180]
MEASURE_TOL_SOC = 0.05     # tolerância declarada do soc_min (rounding ±0.01)
MEASURE_TOL_MIN = 0.2      # tolerância declarada dos minutos de luz (±0.1)

# MEASURE_EXPECTED v0.6 — PREVISÕES PRÉ-REGISTADAS COMO LITERAIS antes da
# corrida (protocolo GATEFALL; NÃO computadas em runtime; o SoC
# pós-fatiar varia ±0.01 pelo arredondamento do amount a 3 decimais na
# fatia de 34% — daí as tolerâncias declaradas acima). Física usada na
# formação das previsões (documentada, não alterou previsões):
#   - drop de ilha em NOITE = 100/kwp pontos/hora → minutos de luz =
#     (SoC − limite_de_ilha)·kwp·0.6, com o limite ATIVO por braço
#     (5.0 na DEFENDED v0.5/v0.6 [opção A], 25.0 na OPTION-B);
#   - (b) v0.6: fatia 40% executa (SoC 60), fatia 34% → 409 daily;
#     (b) v0.5/OPTION-B: 40%+34% executam (SoC ~26);
#   - minutos com CLAMP na duração do apagão.
# ERRATA DATADA (13-11, pós-run 1 do measure v0.6, preservado em
# sunstrike_v06_measure_run1_errata.txt): as previsões soc_min do
# braço DEFENDEDV05 em 120 min (6.95) e do (c) DEFENDEDV05 (6.95)
# estavam ERRADAS por defeito do MODELO DE PREVISÃO do builder —
# assumia que TODAS as casas integravam a duração completa; física
# real do lab (CORRETA e desejada): a casa às escuras (SoC clamp
# no mínimo técnico) deixa de ter deficit — o SoC CONGELA em 5.0,
# não continua a descer. Corrigido para 5.0 nos dois sítios.
# TODAS as outras previsões (curva served, minutos por casa, SoC
# min das outras durações/braços, atacante (c) completo) bateram
# na primeira corrida; a estimativa do supervisor ~12/~11/~8
# confirmou-se MEDIDA (12/11/8). Previsão errada reportada, não
# escondida.
MEASURE_EXPECTED_B = {
    # braço → duração (min) → (served_no_fim, soc_min_esperado)
    "LEGACY-B":      {30: (0, 0.0), 60: (0, 0.0), 90: (0, 0.0),
                      120: (0, 0.0), 180: (0, 0.0)},
    "OPTIONB-B":     {30: (0, 25.0), 60: (0, 25.0), 90: (0, 25.0),
                      120: (0, 25.0), 180: (0, 25.0)},
    "DEFENDEDV05-B": {30: (12, 10.37), 60: (9, 5.0), 90: (6, 5.0),
                      120: (4, 5.0), 180: (0, 5.0)},
    "DEFENDEDV07-B": {30: (12, 44.38), 60: (12, 28.75), 90: (12, 13.13),
                      120: (11, 5.0), 180: (8, 5.0)},
}
MEASURE_MINUTES_EXPECTED_B = {
    # braço → duração → MINUTOS DE LUZ por casa (ordem dos devices
    # 0..11 = kwp [10.5, 6.0, 3.8, 8.2, 12.0, 5.4, 4.4, 7.5, 9.6,
    # 6.8, 3.2, 11.4]), com clamp na duração
    "LEGACY-B": {m: [0.0] * 12 for m in MEASURE_CURVE_MIN},
    "OPTIONB-B": {m: [6.3, 3.6, 2.28, 4.92, 7.2, 3.24, 2.64, 4.5,
                      5.76, 4.08, 1.92, 6.84] for m in MEASURE_CURVE_MIN},
    "DEFENDEDV05-B": {
        30:  [30.0] * 12,
        60:  [60.0, 60.0, 47.88, 60.0, 60.0, 60.0, 55.44, 60.0,
              60.0, 60.0, 40.32, 60.0],
        90:  [90.0, 75.6, 47.88, 90.0, 90.0, 68.04, 55.44, 90.0,
              90.0, 85.68, 40.32, 90.0],
        120: [120.0, 75.6, 47.88, 103.32, 120.0, 68.04, 55.44, 94.5,
              120.0, 85.68, 40.32, 120.0],
        180: [132.3, 75.6, 47.88, 103.32, 151.2, 68.04, 55.44, 94.5,
              120.96, 85.68, 40.32, 143.64],
    },
    "DEFENDEDV07-B": {
        30:  [30.0] * 12,
        60:  [60.0] * 12,
        90:  [90.0] * 12,
        120: [120.0, 120.0, 120.0, 120.0, 120.0, 120.0, 120.0, 120.0,
              120.0, 120.0, 105.6, 120.0],
        180: [180.0, 180.0, 125.4, 180.0, 180.0, 178.2, 145.2, 180.0,
              180.0, 180.0, 105.6, 180.0],
    },
}
# alertas ANTES do apagão esperados no (b) — informativos no veredicto
# (o PASS são as MÉTRICAS): cumulative = regra cumulativa viva
# (v0.5/OPTION-B; superssed no braço v0.6 por nota datada do changelog);
# below_floor = 999 recusado pelo floor (no LEGACY: atravessado e
# auditado como legacy_bypass_floor, que ALIMENTA a mesma regra).
MEASURE_PRE_ALERTS_EXPECTED_B = {
    "LEGACY-B":      {"cumulative": False, "below_floor": True},
    "OPTIONB-B":     {"cumulative": True, "below_floor": True},
    "DEFENDEDV05-B": {"cumulative": True, "below_floor": True},
    "DEFENDEDV07-B": {"cumulative": False, "below_floor": True},
}
# atacante (c): 2 dias (40%/dia, dia de sol cartoon 12 h entre os dois,
# +25 h de relógio de simulação para a janela INCLUSIVA de 24 h expirar
# — cartoon documentado), apagão 2 h NOITE no fim do dia 2.
# soc_after_day = (min, max) do SoC no fim do dia 2 (antes do apagão);
# daily_409_day2 = nº de 409 remote_discharge_daily_limit no dia 2
# (a fatia de 34% só no braço com limite; 0 nos braços v0.5/OPTION-B/
# LEGACY). Minutos do apagão 2 h = tabela da duração 120 do MESMO braço.
MEASURE_EXPECTED_C = {
    # v0.7.1/R7 (F-K1) ERRATA DATADA das EXPECTED (pré-registada ANTES
    # de qualquer corrida da v0.7.1): a D-BATTERY-MULTIDAY-DRAIN foi
    # SUBSTITUÍDA pela D-BATTERY-DRAIN-TO-LOW (SoC RESULTANTE <= 35,
    # SEM janela/dias) — as chaves "multiday*" passam a "drain_to_low*"
    # e as CONTAGENS mudam: LEGACY: o 999 direto ATERRA SoC 0 no dia 1
    # E no dia 2 → 2/dispositivo → count 24; OPTION-B/v0.5: a fatia 34
    # de CADA dia ATERRA ~26 <= 35 → count 24 (na v0.7 era 36: a janela
    # de 72 h via 3 fatias); DEFENDEDV07: SoC fim dia 2 = 60 > 35 → NÃO
    # DISPARA (trade-off F-K1 DECLARADO: com recarga diária a frota
    # nunca fica baixa — o alerta de VOLUME da v0.7 era o FP do K1-c
    # disfarçado; a visibilidade do (c) neste braço fica pelo daily 409
    # ×12, que é PREVENÇÃO ativa, e o padrão K1 REAL sem recarga, o
    # (d), dispara CRIT count 12 em TODOS os braços).
    "DEFENDEDV07-C": {"soc_after_day": (60.0, 60.0), "served": 11,
                      "soc_min": 5.0, "daily_409_day2": 12,
                      "drain_to_low": False, "drain_to_low_count": 0},
    "LEGACY-C":      {"soc_after_day": (0.0, 0.0), "served": 0,
                      "soc_min": 0.0, "daily_409_day2": 0,
                      "drain_to_low": True, "drain_to_low_count": 24},
    "OPTIONB-C":     {"soc_after_day": (25.99, 26.01), "served": 0,
                      "soc_min": 25.0, "daily_409_day2": 0,
                      "drain_to_low": True, "drain_to_low_count": 24},
    "DEFENDEDV05-C": {"soc_after_day": (25.99, 26.01), "served": 4,
                      "soc_min": 5.0, "daily_409_day2": 0,
                      "drain_to_low": True, "drain_to_low_count": 24},
}
# v0.7/R6 (K1) — atacante (d): o padrão K1 em FATIAS PURAS, SEM dia de
# sol (GO 13-11 15:30): dia 1 fatia 40% (quota máxima, EXECUTADA), +25 h,
# dia 2 fatia 34,9% (EXECUTADA) → SoC ~25,1 nos 12, ZERO floor/daily 409,
# apagão NOITE no fim do dia 2. PRÉ-REGISTADO antes de qualquer corrida
# (correção datada do builder nos registos do design/corpus): a defesa
# NÃO muda o served (LEGACY/v0.5/v0.7: [12,9,6,3,0]; OPTION-B tranca no
# floor 25: 0/12); muda a VISIBILIDADE (D-BATTERY-MULTIDAY-DRAIN ×12
# count 24 ANTES do apagão em TODOS os braços).
MEASURE_EXPECTED_D = {
    # braço → (served por duração, soc_min por duração)
    "LEGACY-D":      {"served": {30: 12, 60: 9, 90: 6, 120: 3, 180: 0},
                      "soc_min": {30: 9.47, 60: 5.0, 90: 5.0, 120: 5.0,
                                  180: 5.0}},
    "OPTIONB-D":     {"served": {30: 0, 60: 0, 90: 0, 120: 0, 180: 0},
                      "soc_min": {30: 25.0, 60: 25.0, 90: 25.0, 120: 25.0,
                                  180: 25.0}},
    "DEFENDEDV05-D": {"served": {30: 12, 60: 9, 90: 6, 120: 3, 180: 0},
                      "soc_min": {30: 9.47, 60: 5.0, 90: 5.0, 120: 5.0,
                                  180: 5.0}},
    "DEFENDEDV07-D": {"served": {30: 12, 60: 9, 90: 6, 120: 3, 180: 0},
                      "soc_min": {30: 9.47, 60: 5.0, 90: 5.0, 120: 5.0,
                                  180: 5.0}},
}
MEASURE_MINUTES_EXPECTED_D = {
    # LEGACY/v0.5/v0.7: SoC 25,1 ao apagão — minutos 12,06·kwp clamped
    # (tabelas IGUAIS às do probe P-R6-02 contra a v0.6). OPTION-B: a
    # ilha tranca no floor 25 → ~0,1 SoC de folga = 0,06·kwp.
    # ERRATA DATADA (13-11-2026, measure run 2, preservado em
    # sunstrike_v07_measure_run2_errata.txt): ERRO DE TRANSCRIÇÃO do
    # builder na duração 120: a casa 3 (dev3, 8,2 kWp) dura 98,86 min
    # (12,06·kwp = 98,9 < 120), NÃO 120,0 — o run 1 do R6 contra a
    # v0.6 já mostrava 98,9; copiado errado para a tabela. Corrigido
    # nas três tabelas (LEGACY/V05/V07).
    "LEGACY-D": {
        30:  [30.0] * 12,
        60:  [60.0, 60.0, 45.83, 60.0, 60.0, 60.0, 53.06, 60.0,
              60.0, 60.0, 38.59, 60.0],
        90:  [90.0, 72.36, 45.83, 90.0, 90.0, 65.12, 53.06, 90.0,
              90.0, 82.01, 38.59, 90.0],
        120: [120.0, 72.36, 45.83, 98.86, 120.0, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 120.0],
        180: [126.63, 72.36, 45.83, 98.89, 144.72, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 137.48],
    },
    "OPTIONB-D": {m: [0.63, 0.36, 0.228, 0.492, 0.72, 0.324, 0.264,
                      0.45, 0.576, 0.408, 0.192, 0.684]
                  for m in MEASURE_CURVE_MIN},
    "DEFENDEDV05-D": {
        30:  [30.0] * 12,
        60:  [60.0, 60.0, 45.83, 60.0, 60.0, 60.0, 53.06, 60.0,
              60.0, 60.0, 38.59, 60.0],
        90:  [90.0, 72.36, 45.83, 90.0, 90.0, 65.12, 53.06, 90.0,
              90.0, 82.01, 38.59, 90.0],
        120: [120.0, 72.36, 45.83, 98.86, 120.0, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 120.0],
        180: [126.63, 72.36, 45.83, 98.89, 144.72, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 137.48],
    },
    "DEFENDEDV07-D": {
        30:  [30.0] * 12,
        60:  [60.0, 60.0, 45.83, 60.0, 60.0, 60.0, 53.06, 60.0,
              60.0, 60.0, 38.59, 60.0],
        90:  [90.0, 72.36, 45.83, 90.0, 90.0, 65.12, 53.06, 90.0,
              90.0, 82.01, 38.59, 90.0],
        120: [120.0, 72.36, 45.83, 98.86, 120.0, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 120.0],
        180: [126.63, 72.36, 45.83, 98.89, 144.72, 65.12, 53.06, 90.45,
              115.78, 82.01, 38.59, 137.48],
    },
}
# invariantes do (d), TODOS os braços: fatias 200 ×24 (2/dispositivo),
# zero 409 daily, zero 409 floor, SoC fim dia 2 em [25,0, 25,3], e o
# alerta D-BATTERY-MULTIDAY-DRAIN ANTES do apagão: 1 alerta agregado,
# count 24 (2 fatias × 12 devs).
MEASURE_INVARIANTS_D = {
    "slices_200": 24, "daily_409": 0, "floor_409": 0,
    "soc_d2_min": 25.0, "soc_d2_max": 25.3,
    # v0.7.1 ERRATA DATADA (F-K1, pré-registada antes das corridas):
    # "multiday*" → "drain_to_low*"; count 24 → 12: só a fatia 34,9
    # do dia 2 ATERRA 25,1 <= 35 (1/dispositivo; a fatia 40 do dia 1
    # deixa 60 — calada; a v0.7 via as DUAS na janela de 72 h).
    "drain_to_low_alerts": 1, "drain_to_low_count": 12,
}
# v0.7.1/R7 — atacante (e) NOVO: RESÍDUO do F-K1 medido (GO 13-11
# ~17:00): o atacante que estaciona a frota LOGO ACIMA do limiar —
# dia 1 fatia 40% (quota), +25 h, dia 2 fatia 24% → SoC ~36,0 > 35:
# ZERO D-BATTERY-DRAIN-TO-LOW (na v0.7 também invisível: 64% < 70).
# Braço DEFENDED v0.7.1 (o mais defendido). PREVISÕES pré-registadas:
# curva served [12,11,9,7,3] (9/12 a 1 h MANTÉM-SE), minutos de luz
# 18,6·kwp clamped = (SoC − 5)·kwp·0,6 com SoC ~36, SoC min 20,36 na
# duração 30 (dev10 3,2 kWp: 35,99 − 15,63) e 5,0 (clamp) nas demais.
MEASURE_EXPECTED_E = {
    30:  {"served": 12, "soc_min": 20.36},
    60:  {"served": 11, "soc_min": 5.0},
    90:  {"served": 9,  "soc_min": 5.0},
    120: {"served": 7,  "soc_min": 5.0},
    180: {"served": 3,  "soc_min": 5.0},
}
MEASURE_MINUTES_EXPECTED_E = {
    30:  [30.0] * 12,
    60:  [60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0,
          59.5, 60.0],
    90:  [90.0, 90.0, 70.68, 90.0, 90.0, 90.0, 81.84, 90.0, 90.0, 90.0,
          59.5, 90.0],
    120: [120.0, 111.6, 70.68, 120.0, 120.0, 100.44, 81.84, 120.0,
          120.0, 120.0, 59.5, 120.0],
    180: [180.0, 111.6, 70.68, 152.52, 180.0, 100.44, 81.84, 139.5,
          178.56, 126.48, 59.5, 180.0],
}
MEASURE_INVARIANTS_E = {
    "slices_200": 24, "daily_409": 0, "floor_409": 0,
    "soc_d2_min": 35.98, "soc_d2_max": 36.02,
    "drain_to_low_alerts": 0,
}
# v0.7.1/R7 — atacante (f) NOVO: FP-SP (GO 13-11 ~17:00): frota
# inteira a 60% COM WO válida → 12× 200, div AGREGADA 40% >= 30 e
# ZERO CRIT capacity (o param_change carrega a WO — não arma; o FP
# do supervisor MORRE); SEM WO → CRIT mantém (resíduo DECLARADO: o
# dono tem de usar a WO; 60 > CURTAIL_SETPOINT_MAX → sem wave).
MEASURE_EXPECTED_F = {
    "WO":   {"statuses_200": 12, "crit_capacity": False, "div_min": 30.0},
    "NOWO": {"statuses_200": 12, "crit_capacity": True,  "div_min": 30.0},
}


def run_measure():
    # J1/J2 (GO 13-11 13:23): measure em CURVA, não um só número — 5
    # durações e MINUTOS de luz por casa; 4 braços (LEGACY, OPTION-B,
    # DEFENDED v0.5 sem limite, DEFENDED v0.6 com limite) + atacante (c)
    # 2 dias. O atacante (a) FICA FORA por GO: coberto pelo demo EMERG
    # (interlock 60/60) e pelos outputs v0.5 (nota datada).
    global LEGACY_MODE, RESERVE_LOCKED_MODE, DAILY_LIMIT_MODE, SIM_CLOCK_OFFSET
    lab = Lab(evidence=True)
    lab.ctx._memory = []
    print("SUNSTRIKE lab v%s — measure em CURVA (J1/J2) + (d) K1: 4 "
          "bracos x 5 duracoes + atacantes (c)/(d) 2 dias + (e) residuo "
          "F-K1 + (f) FP-SP (grant %s)"
          % (LAB_VERSION, GRANT_ID))
    print("evidencia: %s" % lab.ctx.evidence_dir)
    print("atacante (a): FORA do measure v0.6 por GO — coberto pelo demo "
          "EMERG (interlock 60/60) e outputs v0.5")
    lab.start()
    time.sleep(0.3)
    det = lab.detector

    def scen_events(scen):
        return [e for e in lab.ctx._memory if e.get("scenario") == scen]

    def sweep_minutes(d, duration_min):
        """J2 — minutos de luz por casa: stepping de 60 s com fração
        EXATA do minuto em que a luz apaga (física linear em NOITE:
        drop = 100/kwp pontos/hora; o clamp do step_island é o
        testemunho de que a luz caiu DENTRO do passo)."""
        minutes = 0.0
        left = float(duration_min)
        while left > 1e-9:
            if d.self_consumption_kw() < LOAD_LOCAL_KW - 0.01:
                break   # já sem luz (SoC <= limite ativo, pv < carga)
            limit = d.island_discharge_floor()
            rate = ((LOAD_LOCAL_KW - d.pv_kw()) * 60.0 / 3600.0
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

    def hygiene():
        lab.gridsim.set_state("NORMAL")
        lab.gridsim.set_irradiance("DIA")
        time.sleep(0.6)

    def blackout_set():
        lab.gridsim.set_irradiance("NOITE")
        lab.gridsim.set_state("BLACKOUT")
        time.sleep(0.4)          # relés abrem (anti-islanding), latch arma

    def attack_b(label):
        """Atacante (b): direta 999; se recusada, EVASÃO FATIADA 40%+34%
        (por service token, rede NORMAL). Devolve contagens e o scan
        dos alertas ANTES do apagão (evidência da visibilidade)."""
        floor_409 = daily_409 = slices_200 = 0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            d = lab.devices[i]
            st, resp = http_json(LOOPBACK, d.port, "POST", "/battery",
                                 {"action": "force_export",
                                  "amount_kwh": 999.0}, token=tok)
            floor_409 += (st == 409
                          and resp.get("error") == "min_emergency_soc_floor")
            if st != 200:
                for frac in (0.40, 0.34):
                    st, resp = http_json(LOOPBACK, d.port, "POST",
                                         "/battery",
                                         {"action": "discharge",
                                          "amount_kwh": round(
                                              frac * d.batt_kwh, 3)},
                                         token=tok)
                    if st == 200:
                        slices_200 += 1
                    elif st == 409 and resp.get(
                            "error") == "remote_discharge_daily_limit":
                        daily_409 += 1
        soc_range = (round(min(d.soc for d in lab.devices), 2),
                     round(max(d.soc for d in lab.devices), 2))
        return {"floor_409": floor_409, "slices_200": slices_200,
                "daily_409": daily_409, "soc_range": soc_range,
                "pre_alerts": det.scan(scen_events(label))}

    def attack_d(label):
        """Atacante (d) — v0.7/R6 (K1): o padrão do run 1 em FATIAS
        PURAS, SEM a direta 999 e SEM dia de sol. Dia 1: fatia 40%
        (quota máxima do limite diário, EXECUTADA em TODOS os braços);
        NOITE cartoon entre os dias (SEM recarga solar — é o cenário
        do achado); +25 h de relógio de simulação (o daily window de
        24 h INCLUSIVO expira: usado 0 no dia 2); dia 2: fatia 34,9%
        (EXECUTADA) → SoC ~25,1 nos 12, ZERO 409. O scan pré-apagão
        tem de ter o D-BATTERY-DRAIN-TO-LOW (na v0.6 e na v0.7 era
        ZERO alertas para o atacante lento — é o K1/K1-b; agora a
        fatia que ATERRA 25,1 <= 35 dispara CRIT count 1/dev)."""
        global SIM_CLOCK_OFFSET
        floor_409 = daily_409 = slices_200 = 0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            d = lab.devices[i]
            st, resp = http_json(LOOPBACK, d.port, "POST", "/battery",
                                 {"action": "discharge",
                                  "amount_kwh": round(0.40 * d.batt_kwh, 3)},
                                 token=tok)
            if st == 200:
                slices_200 += 1
            elif (st == 409 and resp.get("error")
                  == "remote_discharge_daily_limit"):
                daily_409 += 1
        lab.gridsim.set_irradiance("NOITE")
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            d = lab.devices[i]
            st, resp = http_json(LOOPBACK, d.port, "POST", "/battery",
                                 {"action": "discharge",
                                  "amount_kwh": round(0.349 * d.batt_kwh, 3)},
                                 token=tok)
            if st == 200:
                slices_200 += 1
            elif (st == 409 and resp.get("error")
                  == "remote_discharge_daily_limit"):
                daily_409 += 1
        soc_range = (round(min(d.soc for d in lab.devices), 2),
                     round(max(d.soc for d in lab.devices), 2))
        return {"floor_409": floor_409, "slices_200": slices_200,
                "daily_409": daily_409, "soc_range": soc_range,
                "pre_alerts": det.scan(scen_events(label))}

    def attack_e(label):
        """Atacante (e) — v0.7.1/R7 (F-K1, RESÍDUO MEDIDO, GO 13-11
        ~17:00): o atacante que estaciona a frota LOGO ACIMA do
        limiar. Dia 1: fatia 40% (quota máxima, EXECUTADA); NOITE
        cartoon (sem recarga); +25 h de relógio (janela diária
        expira); dia 2: fatia 24% → SoC ~36,0 (> 35: DRAIN-TO-LOW
        CALADA; total 64% < 70: a MULTIDAY da v0.7 TAMBÉM não via).
        O scan pré-apagão tem de ter ZERO D-BATTERY-DRAIN-TO-LOW — é
        o resíduo DECLARADO da regra, medido (GO: medir e declarar)."""
        global SIM_CLOCK_OFFSET
        floor_409 = daily_409 = slices_200 = 0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            d = lab.devices[i]
            st, resp = http_json(LOOPBACK, d.port, "POST", "/battery",
                                 {"action": "discharge",
                                  "amount_kwh": round(0.40 * d.batt_kwh, 3)},
                                 token=tok)
            if st == 200:
                slices_200 += 1
            elif (st == 409 and resp.get("error")
                  == "remote_discharge_daily_limit"):
                daily_409 += 1
        lab.gridsim.set_irradiance("NOITE")
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
        for i in range(N_DEVS):
            tok = "SUNBOX-SVC-%02d-2026" % i
            d = lab.devices[i]
            st, resp = http_json(LOOPBACK, d.port, "POST", "/battery",
                                 {"action": "discharge",
                                  "amount_kwh": round(0.24 * d.batt_kwh, 3)},
                                 token=tok)
            if st == 200:
                slices_200 += 1
            elif (st == 409 and resp.get("error")
                  == "remote_discharge_daily_limit"):
                daily_409 += 1
        soc_range = (round(min(d.soc for d in lab.devices), 2),
                     round(max(d.soc for d in lab.devices), 2))
        return {"floor_409": floor_409, "slices_200": slices_200,
                "daily_409": daily_409, "soc_range": soc_range,
                "pre_alerts": det.scan(scen_events(label))}

    ARMS = [
        ("LEGACY",      {"LEGACY_MODE": True,  "RESERVE_LOCKED_MODE": False,
                         "DAILY_LIMIT_MODE": False}),
        ("OPTIONB",     {"LEGACY_MODE": False, "RESERVE_LOCKED_MODE": True,
                         "DAILY_LIMIT_MODE": False}),
        ("DEFENDEDV05", {"LEGACY_MODE": False, "RESERVE_LOCKED_MODE": False,
                         "DAILY_LIMIT_MODE": False}),
        ("DEFENDEDV07", {"LEGACY_MODE": False, "RESERVE_LOCKED_MODE": False,
                         "DAILY_LIMIT_MODE": True}),
    ]
    results_b, results_c, results_d = [], [], []
    try:
        for arm_name, arm_flags in ARMS:
            LEGACY_MODE = arm_flags["LEGACY_MODE"]
            RESERVE_LOCKED_MODE = arm_flags["RESERVE_LOCKED_MODE"]
            DAILY_LIMIT_MODE = arm_flags["DAILY_LIMIT_MODE"]
            # v0.7/F-LIMP (b, AUD-04): o relógio de simulação é REPOSTO
            # a 0 no INÍCIO de CADA braço (o (c)/(d) avançam +25 h; sem
            # isto o braço seguinte herdaria a data simulada — e a
            # regra multiday é sensível a DIAS-DISTINTOS).
            SIM_CLOCK_OFFSET = 0.0
            # ---------------- (b): curva de durações (J1/J2) ----------
            for dur in MEASURE_CURVE_MIN:
                label = "MEASURE-%s-B-%03d" % (arm_name, dur)
                hygiene()
                lab.scenario(label)
                for d in lab.devices:
                    d.harness_reset()
                atk = attack_b(label)
                cum = any(a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
                          for a in atk["pre_alerts"])
                below = any(a["rule"] == "D-BATTERY-DRAIN-BELOW-FLOOR"
                            for a in atk["pre_alerts"])
                blackout_set()
                minutes = [sweep_minutes(d, dur) for d in lab.devices]
                served = sum(1 for d in lab.devices
                             if d.self_consumption_kw()
                             >= LOAD_LOCAL_KW - 0.01)
                soc_min = round(min(d.soc for d in lab.devices), 2)
                exp = MEASURE_EXPECTED_B["%s-B" % arm_name][dur]
                exp_min = MEASURE_MINUTES_EXPECTED_B["%s-B" % arm_name][dur]
                pre_exp = MEASURE_PRE_ALERTS_EXPECTED_B["%s-B" % arm_name]
                ok = (served == exp[0]
                      and abs(soc_min - exp[1]) <= MEASURE_TOL_SOC
                      and all(abs(m - e) <= MEASURE_TOL_MIN
                              for m, e in zip(minutes, exp_min))
                      and cum == pre_exp["cumulative"]
                      and below == pre_exp["below_floor"])
                results_b.append({
                    "arm": arm_name, "attacker": "b", "duration_min": dur,
                    "served": served, "served_expected": exp[0],
                    "soc_min": soc_min, "soc_min_expected": exp[1],
                    "minutes": minutes, "minutes_expected": exp_min,
                    "soc_pre_range": atk["soc_range"],
                    "floor_409": atk["floor_409"],
                    "slices_200": atk["slices_200"],
                    "daily_409": atk["daily_409"],
                    "cumulative_before_blackout": cum,
                    "below_floor_before_blackout": below,
                    "pre_blackout_alerts": [(a["rule"], a["count"])
                                            for a in atk["pre_alerts"]],
                    "pass": ok})
                print("[%s] dur %3d min: served %2d/12 (prev %2d), SoC min "
                      "%6.2f (prev %6.2f), minutos %s — %s"
                      % (label, dur, served, exp[0], soc_min, exp[1],
                         [round(m, 1) for m in minutes],
                         "PASS" if ok else "FAIL"))
            # ---------------- (c): 2 dias, 40%/dia --------------------
            label = "MEASURE-%s-C" % arm_name
            hygiene()
            lab.scenario(label)
            for d in lab.devices:
                d.harness_reset()
            day1 = attack_b(label)
            # dia de sol cartoon: 12 h de recarga grid-tied (J4) —
            # TODOS os kwp >= 3.2 recarregam a 100 (excedente min 0.56 kW)
            lab.gridsim.set_irradiance("DIA")
            time.sleep(0.2)
            for d in lab.devices:
                d.step_grid(12 * 3600.0)
            soc_sun = (round(min(d.soc for d in lab.devices), 2),
                       round(max(d.soc for d in lab.devices), 2))
            # noite cartoon + avanço do relógio: +25 h desde o dia 1
            # (janela INCLUSIVA de 24 h: exatamente 24 h contaria)
            SIM_CLOCK_OFFSET += 25.0 * 3600.0
            day2 = attack_b(label)
            blackout_set()
            minutes_c = [sweep_minutes(d, 120) for d in lab.devices]
            served_c = sum(1 for d in lab.devices
                           if d.self_consumption_kw()
                           >= LOAD_LOCAL_KW - 0.01)
            soc_min_c = round(min(d.soc for d in lab.devices), 2)
            exp_c = MEASURE_EXPECTED_C["%s-C" % arm_name]
            exp_min_c = MEASURE_MINUTES_EXPECTED_B["%s-B" % arm_name][120]
            # v0.7.1/F-K1: o (c) ganha o alerta D-BATTERY-DRAIN-TO-LOW
            # PRÉ-apagão nos braços LEGACY/OPTION-B/v0.5 (SoC aterra
            # 0/26 <= 35); o braço v0.7 fica SoC 60 > 35 → NÃO dispara
            # (trade-off declarado; a visibilidade fica pelo daily 409).
            dtl_c = [a for a in day2["pre_alerts"]
                     if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
            ok_c = (exp_c["soc_after_day"][0] - MEASURE_TOL_SOC
                    <= day2["soc_range"][0]
                    and day2["soc_range"][1]
                    <= exp_c["soc_after_day"][1] + MEASURE_TOL_SOC
                    and served_c == exp_c["served"]
                    and abs(soc_min_c - exp_c["soc_min"])
                    <= MEASURE_TOL_SOC
                    and day2["daily_409"] == exp_c["daily_409_day2"]
                    and (len(dtl_c) == 1) == exp_c["drain_to_low"]
                    and (dtl_c[0]["count"] if dtl_c else 0)
                    == exp_c["drain_to_low_count"]
                    and all(abs(m - e) <= MEASURE_TOL_MIN
                            for m, e in zip(minutes_c, exp_min_c)))
            results_c.append({
                "arm": arm_name, "attacker": "c",
                "soc_after_sun": soc_sun,
                "soc_after_day2": day2["soc_range"],
                "served_2h": served_c, "served_expected": exp_c["served"],
                "soc_min": soc_min_c, "soc_min_expected": exp_c["soc_min"],
                "minutes_2h": minutes_c, "minutes_expected": exp_min_c,
                "daily_409_day1": day1["daily_409"],
                "daily_409_day2": day2["daily_409"],
                "floor_409_day2": day2["floor_409"],
                "slices_200_day2": day2["slices_200"],
                "drain_to_low_alerts": len(dtl_c),
                "drain_to_low_count": (dtl_c[0]["count"] if dtl_c else 0),
                "pass": ok_c})
            print("[%s] dia 1: 999→409×%d, fatias 200×%d, daily 409×%d "
                  "(SoC %s); SOL 12 h → SoC %s; +25 h; dia 2: 999→409×%d, "
                  "fatias 200×%d, daily 409×%d (SoC %s); apagão 2h: served "
                  "%d/12 (prev %d), SoC min %.2f (prev %.2f) — %s"
                  % (label, day1["floor_409"], day1["slices_200"],
                     day1["daily_409"], day1["soc_range"], soc_sun,
                     day2["floor_409"], day2["slices_200"],
                     day2["daily_409"], day2["soc_range"], served_c,
                     exp_c["served"], soc_min_c, exp_c["soc_min"],
                     "PASS" if ok_c else "FAIL"))
            # ---------------- (d): K1 puro, 2 dias SEM sol ----------
            # (GO 13-11 15:30 + v0.7.1 ~17:00, F-K1/measure): a
            # previsão HONESTA é que a defesa NÃO muda o served — muda
            # a VISIBILIDADE (D-BATTERY-DRAIN-TO-LOW ANTES do apagão,
            # 1 agregado count 12: só a fatia que ATERRA 25,1 <= 35).
            for dur in MEASURE_CURVE_MIN:
                label = "MEASURE-%s-D-%03d" % (arm_name, dur)
                SIM_CLOCK_OFFSET = 0.0   # o attack_d avança o relógio
                hygiene()
                lab.scenario(label)
                for d in lab.devices:
                    d.harness_reset()
                atk = attack_d(label)
                dtl_d = [a for a in atk["pre_alerts"]
                         if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
                blackout_set()
                minutes_d = [sweep_minutes(d, dur) for d in lab.devices]
                served_d = sum(1 for d in lab.devices
                               if d.self_consumption_kw()
                               >= LOAD_LOCAL_KW - 0.01)
                soc_min_d = round(min(d.soc for d in lab.devices), 2)
                exp_d = MEASURE_EXPECTED_D["%s-D" % arm_name]
                exp_min_d = MEASURE_MINUTES_EXPECTED_D["%s-D" % arm_name][dur]
                inv = MEASURE_INVARIANTS_D
                ok_d = (served_d == exp_d["served"][dur]
                        and abs(soc_min_d - exp_d["soc_min"][dur])
                        <= MEASURE_TOL_SOC
                        and all(abs(m - e) <= MEASURE_TOL_MIN
                                for m, e in zip(minutes_d, exp_min_d))
                        and atk["slices_200"] == inv["slices_200"]
                        and atk["daily_409"] == inv["daily_409"]
                        and atk["floor_409"] == inv["floor_409"]
                        and inv["soc_d2_min"] <= atk["soc_range"][0]
                        and atk["soc_range"][1] <= inv["soc_d2_max"]
                        and len(dtl_d) == inv["drain_to_low_alerts"]
                        and (dtl_d[0]["count"] if dtl_d else 0)
                        == inv["drain_to_low_count"])
                results_d.append({
                    "arm": arm_name, "attacker": "d", "duration_min": dur,
                    "served": served_d,
                    "served_expected": exp_d["served"][dur],
                    "soc_min": soc_min_d,
                    "soc_min_expected": exp_d["soc_min"][dur],
                    "minutes": minutes_d, "minutes_expected": exp_min_d,
                    "soc_d2": atk["soc_range"],
                    "floor_409": atk["floor_409"],
                    "slices_200": atk["slices_200"],
                    "daily_409": atk["daily_409"],
                    "drain_to_low_alerts": len(dtl_d),
                    "drain_to_low_count": (dtl_d[0]["count"] if dtl_d else 0),
                    "pass": ok_d})
                print("[%s] dur %3d min: served %2d/12 (prev %2d), SoC min "
                      "%6.2f (prev %6.2f), fatias 200 x%d, daily 409 x%d, "
                      "drain-to-low pre %dx%s — %s"
                      % (label, dur, served_d, exp_d["served"][dur],
                         soc_min_d, exp_d["soc_min"][dur],
                         atk["slices_200"], atk["daily_409"],
                         len(dtl_d), (dtl_d[0]["count"] if dtl_d else 0),
                         "PASS" if ok_d else "FAIL"))
        LEGACY_MODE = False
        RESERVE_LOCKED_MODE = False
        DAILY_LIMIT_MODE = True
        # ---------------- (e): RESÍDUO F-K1 (GO 13-11 ~17:00) ----
        # braço DEFENDED v0.7.1 (o mais defendido): atacante que
        # estaciona LOGO ACIMA do limiar → ZERO alertas (resíduo
        # medido e DECLARADO — a previsão é HONESTA: não dispara)
        results_e = []
        for dur in MEASURE_CURVE_MIN:
            label = "MEASURE-E-%03d" % dur
            SIM_CLOCK_OFFSET = 0.0
            hygiene()
            lab.scenario(label)
            for d in lab.devices:
                d.harness_reset()
            atk = attack_e(label)
            dtl_e = [a for a in atk["pre_alerts"]
                     if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
            blackout_set()
            minutes_e = [sweep_minutes(d, dur) for d in lab.devices]
            served_e = sum(1 for d in lab.devices
                           if d.self_consumption_kw()
                           >= LOAD_LOCAL_KW - 0.01)
            soc_min_e = round(min(d.soc for d in lab.devices), 2)
            exp_e = MEASURE_EXPECTED_E[dur]
            exp_min_e = MEASURE_MINUTES_EXPECTED_E[dur]
            inv_e = MEASURE_INVARIANTS_E
            ok_e = (served_e == exp_e["served"]
                    and abs(soc_min_e - exp_e["soc_min"])
                    <= MEASURE_TOL_SOC
                    and all(abs(m - mv) <= MEASURE_TOL_MIN
                            for m, mv in zip(minutes_e, exp_min_e))
                    and atk["slices_200"] == inv_e["slices_200"]
                    and atk["daily_409"] == inv_e["daily_409"]
                    and atk["floor_409"] == inv_e["floor_409"]
                    and inv_e["soc_d2_min"] <= atk["soc_range"][0]
                    and atk["soc_range"][1] <= inv_e["soc_d2_max"]
                    and len(dtl_e) == inv_e["drain_to_low_alerts"])
            results_e.append({
                "attacker": "e", "duration_min": dur,
                "served": served_e, "served_expected": exp_e["served"],
                "soc_min": soc_min_e, "soc_min_expected": exp_e["soc_min"],
                "minutes": minutes_e, "minutes_expected": exp_min_e,
                "soc_d2": atk["soc_range"], "slices_200": atk["slices_200"],
                "daily_409": atk["daily_409"],
                "drain_to_low_alerts": len(dtl_e),
                "pass": ok_e})
            print("[%s] dur %3d min: served %2d/12 (prev %2d), SoC min "
                  "%6.2f (prev %6.2f), fatias 200 x%d, daily 409 x%d, "
                  "drain-to-low pre x%d (RESIDUO declarado) — %s"
                  % (label, dur, served_e, exp_e["served"], soc_min_e,
                     exp_e["soc_min"], atk["slices_200"], atk["daily_409"],
                     len(dtl_e), "PASS" if ok_e else "FAIL"))
        # ---------------- (f): FP-SP (GO 13-11 ~17:00) ----
        # frota inteira a 60%: COM WO válida → 0 CRIT capacity com
        # div 40% (o FP do supervisor MORRE); SEM WO → CRIT mantém
        # (resíduo DECLARADO: o dono tem de usar a WO)
        results_f = []
        for tag, with_wo in (("WO", True), ("NOWO", False)):
            label = "MEASURE-F-SP-%s" % tag
            SIM_CLOCK_OFFSET = 0.0
            hygiene()
            lab.scenario(label)
            for d in lab.devices:
                d.harness_reset()
            body = ({"value": 60.0, "work_order": "WO-20261112-MNT1"}
                    if with_wo else {"value": 60.0})
            sts_f = []
            for i in range(N_DEVS):
                st, _ = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST",
                                  "/setpoint", body,
                                  token="SUNBOX-SVC-%02d-2026" % i)
                sts_f.append(st)
            emit_capacity_snapshot(lab)
            f_alerts = det.scan(scen_events(label))
            f_cap = [a for a in f_alerts
                     if a["rule"] == "D-CAPACITY-DIVERGENCE"]
            f_inv = [a for a in f_alerts
                     if a["rule"] == "D-INVALID-WORK-ORDER"]
            f_snaps = [ev for ev in scen_events(label)
                       if ev.get("event") == "capacity_snapshot"]
            f_div = max((ev.get("divergence_pct", 0.0)
                         for ev in f_snaps), default=0.0)
            exp_f = MEASURE_EXPECTED_F[tag]
            ok_f = (sum(1 for s in sts_f if s == 200)
                    == exp_f["statuses_200"]
                    and f_div >= exp_f["div_min"]
                    and bool(f_cap) == exp_f["crit_capacity"]
                    and not f_inv)
            results_f.append({
                "attacker": "f", "tag": tag,
                "statuses_200": sum(1 for s in sts_f if s == 200),
                "divergence_pct": round(f_div, 2),
                "crit_capacity": bool(f_cap),
                "crit_capacity_expected": exp_f["crit_capacity"],
                "invalid_wo_alerts": len(f_inv),
                "pass": ok_f})
            print("[%s] frota 60%% %s WO: setpoints 200 x%d, div %.1f%% "
                  "(prev >= %.0f%%), CRIT capacity=%s (prev %s) — %s"
                  % (label, "COM" if with_wo else "SEM",
                     sum(1 for s in sts_f if s == 200), f_div,
                     exp_f["div_min"], bool(f_cap),
                     exp_f["crit_capacity"],
                     "PASS" if ok_f else "FAIL"))
        # ---- curva lado a lado (J1) + (c) (operador 13-11 13:23) ----
        print("\n===== CURVA (J1): served NO FIM por duração, mesmo "
              "ataque (b) =====")
        header = "              " + "".join(
            "%7s" % ("%d min" % m) for m in MEASURE_CURVE_MIN)
        print(header)
        for arm_name, _ in ARMS:
            row = ("%12s  " % arm_name)
            for dur in MEASURE_CURVE_MIN:
                r = [x for x in results_b
                     if x["arm"] == arm_name and x["duration_min"] == dur][0]
                row += "%7d" % r["served"]
            print(row + "   (SoC min por duração: %s)"
                  % [x["soc_min"] for x in results_b
                     if x["arm"] == arm_name])
        print("\n===== MINUTOS de luz (J2): casas às escuras tinham luz "
              "antes do fim =====")
        for arm_name, _ in ARMS:
            r60 = [x for x in results_b
                   if x["arm"] == arm_name and x["duration_min"] == 60][0]
            dark = [(i, m) for i, m in enumerate(r60["minutes"]) if m < 60.0]
            print("  %-12s 1 h: served %d/12; casas às escuras no fim "
                  "tiveram luz %s min" % (arm_name, r60["served"],
                                          [(i, round(m, 1))
                                           for i, m in dark] or "—"))
        print("\n===== ATACANTE (c): 2 dias, 40%/dia, dia de sol entre "
              "os dois, apagão 2 h =====")
        for r in results_c:
            print("  %-12s SoC fim dia 2 %s → served %2d/12 (prev %2d), "
                  "SoC min %.2f, daily 409 dia2 ×%d, drain-to-low "
                  "pre %s×%s"
                  % (r["arm"], r["soc_after_day2"], r["served_2h"],
                     r["served_expected"], r["soc_min"],
                     r["daily_409_day2"], r["drain_to_low_alerts"],
                     r["drain_to_low_count"]))
        print("\n===== ATACANTE (d) — K1: 2 dias SEM sol, apagão NOITE "
              "no fim do dia 2 =====")
        print("  previsão honesta (GO): a defesa NÃO muda o served "
              "(9/12 a 1 h continua 9/12); muda a VISIBILIDADE — "
              "D-BATTERY-MULTIDAY-DRAIN ANTES do apagão em TODOS os "
              "braços (na v0.6: ZERO alertas)")
        header_d = "              " + "".join(
            "%7s" % ("%d min" % m) for m in MEASURE_CURVE_MIN)
        print(header_d)
        for arm_name, _ in ARMS:
            row = ("%12s  " % arm_name)
            for dur in MEASURE_CURVE_MIN:
                r = [x for x in results_d
                     if x["arm"] == arm_name and x["duration_min"] == dur][0]
                row += "%7d" % r["served"]
            rd = [x for x in results_d if x["arm"] == arm_name]
            print(row + ("   (SoC fim dia 2 %s; fatias 200 ×%d; "
                         "drain-to-low pre ×%d count %s)")
                  % (rd[0]["soc_d2"], rd[0]["slices_200"],
                     rd[0]["drain_to_low_alerts"],
                     rd[0]["drain_to_low_count"]))
        print()
        print("===== ATACANTE (e) — RESÍDUO F-K1: estaciona LOGO "
              "ACIMA do limiar (SoC ~36 > 35) =====")
        print("  previsão honesta (GO): ZERO D-BATTERY-DRAIN-TO-LOW — "
              "o resíduo é DECLARADO, medido (na v0.7: 64% < 70, "
              "também invisível); 9/12 a 1 h MANTÉM-SE (o atacante "
              "NÃO posiciona a frota baixa — não há o que ver)")
        for r in results_e:
            print("  dur %3d min: served %2d/12 (prev %2d), SoC min "
                  "%6.2f (prev %6.2f), fatias 200 ×%d, daily 409 ×%d, "
                  "drain-to-low pre ×%d — %s"
                  % (r["duration_min"], r["served"], r["served_expected"],
                     r["soc_min"], r["soc_min_expected"], r["slices_200"],
                     r["daily_409"], r["drain_to_low_alerts"],
                     "PASS" if r["pass"] else "FAIL"))
        print()
        print("===== ATACANTE (f) — FP-SP: frota 60%% COM WO vs SEM "
              "WO =====")
        for r in results_f:
            print("  %-4s: setpoints 200 ×%d, div %.1f%%, CRIT "
                  "capacity=%s (prev %s), WARN invalid-WO ×%d — %s"
                  % (r["tag"], r["statuses_200"], r["divergence_pct"],
                     r["crit_capacity"], r["crit_capacity_expected"],
                     r["invalid_wo_alerts"],
                     "PASS" if r["pass"] else "FAIL"))
        print("\n===== PREVISÕES DO SUPERVISOR vs MEDIDO (estimativas "
              "dele ~12/~11/~8 na 1 h/2 h/3 h DEFENDED c/ limite "
              "diário) =====")
        v07 = {x["duration_min"]: x for x in results_b
               if x["arm"] == "DEFENDEDV07"}
        print("  1 h: %d/12 | 2 h: %d/12 | 3 h: %d/12 (medido)"
              % (v07[60]["served"], v07[120]["served"],
                 v07[180]["served"]))
        print("  com o limite, o atacante só leva as baterias a ~60%% "
              "(SoC pós-fatiar %s)" % (v07[60]["soc_pre_range"],))
        # scan INFORMATIVO (o veredicto são as métricas, não as regras)
        alerts = det.scan(collect_events(lab.ctx))
        print("\n===== ALERTAS (informativo) =====")
        for a in alerts:
            print("  [%s] %s x%d %s" % (a["scenario"], a["rule"],
                                        a["count"],
                                        ",".join(sorted(a["devices"])[:4]) +
                                        ("..." if len(a["devices"]) > 4
                                         else "")))
        all_ok = all(r["pass"] for r in results_b + results_c + results_d
                     + results_e + results_f)
        summary = {
            "grant": GRANT_ID, "lab_version": LAB_VERSION,
            "run_id": lab.ctx.run_id,
            "measure_curve": results_b, "measure_c": results_c,
            "measure_d": results_d, "measure_e": results_e,
            "measure_f": results_f,
            "expected_b": MEASURE_EXPECTED_B,
            "minutes_expected_b": MEASURE_MINUTES_EXPECTED_B,
            "expected_c": MEASURE_EXPECTED_C,
            "expected_d": MEASURE_EXPECTED_D,
            "minutes_expected_d": MEASURE_MINUTES_EXPECTED_D,
            "invariants_d": MEASURE_INVARIANTS_D,
            "expected_e": MEASURE_EXPECTED_E,
            "minutes_expected_e": MEASURE_MINUTES_EXPECTED_E,
            "invariants_e": MEASURE_INVARIANTS_E,
            "expected_f": MEASURE_EXPECTED_F,
            "pass": all_ok, "evidence_dir": lab.ctx.evidence_dir,
        }
        with open(os.path.join(lab.ctx.evidence_dir, "run_summary.json"),
                  "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, sort_keys=True)
        print("\nRESULTADO FINAL: %s"
              % ("PASS (51 corridas: 20 curva + 4 atacante-c + "
                 "20 atacante-d + 5 residuo-e + 2 FP-SP-f)"
                 if all_ok else "FAIL — ver acima"))
        return 0 if all_ok else 1
    finally:
        LEGACY_MODE = False
        RESERVE_LOCKED_MODE = False
        DAILY_LIMIT_MODE = True
        SIM_CLOCK_OFFSET = 0.0
        lab.stop()

# ---------------------------------------------------------------------------
# SERVE / SELFTEST / CLI
# ---------------------------------------------------------------------------
def run_serve():
    lab = Lab(evidence=True)
    lab.start()
    print("SUNSTRIKE lab v%s em servico (Ctrl+C para parar)" % LAB_VERSION)
    print("  GUARD      http://%s:%d  (via protegida §4.5)" % (LOOPBACK, PORT_GUARD))
    print("  FLEETGATE  http://%s:%d  (login /fleet/login)" % (LOOPBACK, PORT_GATE))
    for d in lab.devices:
        print("  %s (%s, %.1f kWp)  http://%s:%d" % (d.name, d.cell, d.kwp,
                                                     LOOPBACK, d.port))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()


def _selftest_c4_rules(lab, det):
    """v0.5 — C4/C4-b: regras de descarga in-band. v0.6 NOTA DATADA
    (superssenção, ver changelog): com o limite diário ATIVO (default da
    v0.6) estas operações dão 409 daily ANTES de executarem — são
    exercitadas aqui na configuração v0.5 (DAILY_LIMIT_MODE=False, flag
    alternada pelo run_selftest com reposição em finally)."""
    ok = True
    lab.scenario("SELFTEST-C4")
    d11 = lab.devices[11]
    http_json(LOOPBACK, d11.port, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": round(0.30 * d11.batt_kwh, 3)},
              token=d11.service_token)
    http_json(LOOPBACK, d11.port, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": round(0.30 * d11.batt_kwh, 3)},
              token=d11.service_token)
    alerts_c4 = det.scan([e for e in lab.ctx._memory
                          if e.get("scenario") == "SELFTEST-C4"])
    cum4 = [a for a in alerts_c4
            if a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"]
    big4 = [a for a in alerts_c4
            if a["rule"] == "D-BATTERY-DRAIN-LARGE"]
    c4_ok = (d11.soc == 40.0 and len(cum4) == 1
             and cum4[0]["count"] == 2 and not big4)
    print("[selftest] C4 regra cumulativa [config v0.5] (2 fatias de "
          "30%%: SoC %.1f, alerta=%s count=%s, por-operacao=%s): %s"
          % (d11.soc, len(cum4) == 1,
             cum4[0]["count"] if cum4 else 0, len(big4),
             "OK" if c4_ok else "FALHOU"))
    ok = ok and c4_ok
    # v0.5 — C4-b: operação única >=50%% dispara SÓ a por-operação
    # (a cumulativa não dupla-dispara: fatia >=50%% não acumula)
    lab.scenario("SELFTEST-C4B")
    d6 = lab.devices[6]
    http_json(LOOPBACK, d6.port, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": round(0.55 * d6.batt_kwh, 3)},
              token=d6.service_token)
    alerts_c4b = det.scan([e for e in lab.ctx._memory
                           if e.get("scenario") == "SELFTEST-C4B"])
    c4b_ok = (any(a["rule"] == "D-BATTERY-DRAIN-LARGE"
                  for a in alerts_c4b)
              and not any(a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
                          for a in alerts_c4b))
    print("[selftest] C4-b sem dupla-disparo [config v0.5] (1 operacao "
          "de 55%%: por-operacao=%s, cumulativa=%s): %s"
          % (any(a["rule"] == "D-BATTERY-DRAIN-LARGE"
                  for a in alerts_c4b),
             any(a["rule"] == "D-BATTERY-CUMULATIVE-DRAIN"
                 for a in alerts_c4b),
             "OK" if c4b_ok else "FALHOU"))
    return ok and c4b_ok


def _selftest_v06(lab, det):
    """v0.6/R5 (GO do operador 13-11 13:23) — MECANISMOS das fixes:
    limite diário 40%%/24 h, /local_confirm além do daily, janela de 24 h
    (relógio de simulação SIM_CLOCK_OFFSET), bypass LEGACY (contrafactual
    declarado, extensão datada), recarga grid-tied (J4) e telemetria
    soc_limits (J5). A CURVA de durações e os MINUTOS de luz (J1/J2) são
    medidos no run_measure com previsões pré-registadas (MEASURE_EXPECTED
    literais); aqui os mecanismos por trás."""
    global SIM_CLOCK_OFFSET, LEGACY_MODE
    ok = True
    # 1. LIMITE DIÁRIO: fatia 40% executa; +5% → 409 + evento próprio;
    #    o ledger soma a janela
    lab.scenario("SELFTEST-V06-DAILY")
    d1 = lab.devices[1]
    st1, _ = http_json(LOOPBACK, d1.port, "POST", "/battery",
                       {"action": "discharge",
                        "amount_kwh": round(0.40 * d1.batt_kwh, 3)},
                       token=d1.service_token)
    st2, r2 = http_json(LOOPBACK, d1.port, "POST", "/battery",
                        {"action": "discharge",
                         "amount_kwh": round(0.05 * d1.batt_kwh, 3)},
                        token=d1.service_token)
    daily_ev = [e for e in lab.ctx._memory
                if e.get("event") == "remote_daily_limit_block"
                and e.get("scenario") == "SELFTEST-V06-DAILY"]
    daily_ok = (st1 == 200 and abs(d1.soc - 60.0) < 0.01
                and st2 == 409
                and r2.get("error") == "remote_discharge_daily_limit"
                and len(daily_ev) == 1
                and abs(d1.remote_drain_used_pct() - 40.0) < 0.05
                and daily_ev[0].get("limit_pct")
                == REMOTE_DISCHARGE_DAILY_PCT)
    print("[selftest] v0.6 limite diario (fatia 40%%=200 → SoC %.1f; "
          "+5%%=409+evento; used=%.2f%%): %s"
          % (d1.soc, d1.remote_drain_used_pct(),
             "OK" if daily_ok else "FALHOU"))
    ok = ok and daily_ok
    # 2. /local_confirm além do daily: executa (provenance
    #    local_confirm), NÃO conta no ledger, token de uso único; a
    #    fatia seguinte SEM confirm dá 409 na mesma (usado continua 40)
    lab.scenario("SELFTEST-V06-DAILYLC")
    d5 = lab.devices[5]
    http_json(LOOPBACK, d5.port, "POST", "/battery",
              {"action": "discharge",
               "amount_kwh": round(0.40 * d5.batt_kwh, 3)},
              token=d5.service_token)
    _, rlc = http_json(LOOPBACK, d5.port, "POST", "/local_confirm",
                       {"pin": d5.local_pin})
    st_lc, _ = http_json(LOOPBACK, d5.port, "POST", "/battery",
                         {"action": "discharge",
                          "amount_kwh": round(0.10 * d5.batt_kwh, 3),
                          "confirm_token": rlc.get("confirm_token")},
                         token=d5.service_token)
    st_next, _ = http_json(LOOPBACK, d5.port, "POST", "/battery",
                           {"action": "discharge",
                            "amount_kwh": round(0.10 * d5.batt_kwh, 3)},
                           token=d5.service_token)
    lc_ev = [e for e in lab.ctx._memory
             if e.get("event") == "param_change"
             and e.get("scenario") == "SELFTEST-V06-DAILYLC"
             and e.get("provenance") == "local_confirm"]
    dlc_ok = (st_lc == 200 and abs(d5.soc - 50.0) < 0.01
              and len(lc_ev) == 1
              and abs(d5.remote_drain_used_pct() - 40.0) < 0.05
              and d5.local_confirm_token is None
              and st_next == 409)
    print("[selftest] v0.6 local_confirm alem do daily (SoC %.1f, "
          "nao conta: used=%.2f%%, token consumido=%s, seguinte sem "
          "confirm=409): %s"
          % (d5.soc, d5.remote_drain_used_pct(),
             d5.local_confirm_token is None,
             "OK" if dlc_ok else "FALHOU"))
    ok = ok and dlc_ok
    # 3. JANELA de 24 h (inclusiva): fatia 40% (executa, used 40); +25 h
    #    de relógio de simulação → a fatia 1 SAI da janela e uma fatia
    #    IN-BAND de 30% volta a executar (sem o avanço daria 409 daily:
    #    40+30 > 40 — o teste 1 acima já mostra o bloqueio; a fatia de
    #    40% não serve aqui porque 60-40=20 cruzaria o FLOOR primeiro,
    #    409 floor antes do daily); o used com o offset ATIVO conta
    #    SÓ o dia novo (30)
    lab.scenario("SELFTEST-V06-WINDOW")
    d9 = lab.devices[9]
    stw1, _ = http_json(LOOPBACK, d9.port, "POST", "/battery",
                        {"action": "discharge",
                         "amount_kwh": round(0.40 * d9.batt_kwh, 3)},
                        token=d9.service_token)
    SIM_CLOCK_OFFSET += 25.0 * 3600.0
    try:
        stw2, _ = http_json(LOOPBACK, d9.port, "POST", "/battery",
                            {"action": "discharge",
                             "amount_kwh": round(0.30 * d9.batt_kwh, 3)},
                            token=d9.service_token)
        used_w = d9.remote_drain_used_pct()
    finally:
        SIM_CLOCK_OFFSET -= 25.0 * 3600.0   # reposição imediata
    window_ok = (stw1 == 200 and stw2 == 200
                 and abs(d9.soc - 30.0) < 0.01
                 and abs(used_w - 30.0) < 0.05)
    print("[selftest] v0.6 janela 24 h (+25 h de sim_ts: 40%% e depois "
          "30%% IN-BAND executam — sem o avanco a 2.a daria 409 daily; "
          "SoC %.1f, used=%.2f%% so o dia novo): %s"
          % (d9.soc, used_w,
             "OK" if window_ok else "FALHOU"))
    ok = ok and window_ok
    # 4. LEGACY bypass (extensão datada do contrafactual declarado):
    #    sem limite diário E sem floor, a descarga 60% executa a partir
    #    de SoC 100 e não entra no ledger (o braço LEGACY do measure
    #    depende disto). d4: intocado pelos sub-testes anteriores
    lab.scenario("SELFTEST-V06-LEGACY")
    d4 = lab.devices[4]
    d4.harness_reset()
    LEGACY_MODE = True
    try:
        stlg, _ = http_json(LOOPBACK, d4.port, "POST", "/battery",
                            {"action": "discharge",
                             "amount_kwh": round(0.60 * d4.batt_kwh, 3)},
                            token=d4.service_token)
    finally:
        LEGACY_MODE = False
    legacy_ok = (stlg == 200 and abs(d4.soc - 40.0) < 0.01
                 and abs(d4.remote_drain_used_pct()) < 0.01)
    print("[selftest] v0.6 LEGACY bypass (60%% executa, SoC %.1f, "
          "ledger vazio=%s): %s"
          % (d4.soc, d4.remote_drain_used_pct() == 0.0,
             "OK" if legacy_ok else "FALHOU"))
    ok = ok and legacy_ok
    # 5. J4 — RECARGA SOLAR GRID-TIED: DIA carrega (excedente), NOITE
    #    não carrega, cap 100, relé aberto não integra (é o step_island)
    lab.scenario("SELFTEST-V06-GRID")
    d3 = lab.devices[3]
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.3)
    d3.soc = 50.0                      # harness (selftest)
    d3.step_grid(3600.0)               # 1 h de sol em modo ligado à rede
    soc_dia = d3.soc
    # excedente d3 (8.2 kWp): pv 4.51 - 1.2 = 3.31 kWh/h → 33.6382 pontos
    lab.gridsim.set_irradiance("NOITE")
    time.sleep(0.3)
    soc_before_noite = d3.soc
    d3.step_grid(3600.0)               # NOITE: sem carga
    soc_noite = d3.soc
    lab.gridsim.set_irradiance("DIA")  # repor ANTES do teste do cap
    time.sleep(0.3)
    d3.soc = 99.9
    d3.step_grid(3600.0)               # cap 100
    soc_cap = d3.soc
    relay_before = d3.relay_closed
    d3.relay_closed = False            # ilha: nada aqui (é step_island)
    soc_before_island = d3.soc
    d3.step_grid(3600.0)
    soc_island_nocharge = d3.soc
    d3.relay_closed = relay_before
    charge_ev = [e for e in lab.ctx._memory
                 if e.get("event") == "grid_tied_charge"
                 and e.get("scenario") == "SELFTEST-V06-GRID"]
    grid_ok = (abs(soc_dia - 83.6382) < 0.001
               and len(charge_ev) == 2   # DIA + cap (NOITE/rele: nenhum)
               and soc_noite == soc_before_noite
               and soc_cap == 100.0
               and soc_island_nocharge == soc_before_island)
    print("[selftest] v0.6 J4 recarga grid-tied (DIA 1 h: 50→%.4f com "
          "eventos=%d; NOITE imovel=%.1f; cap=%.1f; rele aberto nao "
          "integra=%.1f): %s"
          % (soc_dia, len(charge_ev), soc_noite, soc_cap,
             soc_island_nocharge,
             "OK" if grid_ok else "FALHOU"))
    ok = ok and grid_ok
    # 6. J5 — TELEMETRIA soc_limits: o limite ATIVO por modo visível
    lab.scenario("SELFTEST-V06-TEL")
    d0 = lab.devices[0]
    tel = d0.telemetry()
    sl = tel.get("soc_limits") or {}
    # v0.7.1 ERRATA DATADA (13-11-2026, selftest run 1, preservado em
    # sunstrike_v071_selftest_run1_errata.txt — PERDIDO no incidente
    # INFRA-2026-13-11-B; re-executado): literal J5 "v0.7"→"v0.7.1"
    # (precedente F-LIMP R6 — lapso do builder, não regressão; a
    # telemetria carimba schema v0.7.1 desde o edit A8).
    tel_ok = (sl.get("schema") == "v0.7.1"
              and sl.get("remote_floor_pct") == FLOOR_SOC
              and sl.get("island_min_pct") == ISLAND_MIN_SOC
              and sl.get("remote_daily_limit_pct")
              == REMOTE_DISCHARGE_DAILY_PCT
              and "remote_daily_used_pct" in sl)
    print("[selftest] v0.6 J5 telemetria soc_limits (floor=%.1f, "
          "island_min=%.1f ATIVO, daily=%.1f, used=%s): %s"
          % (sl.get("remote_floor_pct", -1), sl.get("island_min_pct", -1),
             sl.get("remote_daily_limit_pct", -1),
             sl.get("remote_daily_used_pct", "?"),
             "OK" if tel_ok else "FALHOU"))
    return ok and tel_ok


def _selftest_v07(lab, det):
    """v0.7/R6 (GO do operador 13-11 15:30) — MECANISMOS da fix C12.
    NOTA DATADA (13-11-2026, v0.7.1): as secções K1 da v0.7 (multiday +
    FPs J3/dono, secções 1-3) foram SUPERSSUDAS pela _selftest_v071 —
    a D-BATTERY-MULTIDAY-DRAIN foi SUBSTITUÍDA pela D-BATTERY-DRAIN-
    TO-LOW (F-K1, GO 13-11 ~17:00) e os testes de VOLUME saíram com a
    regra (removidos, não comentados; o output perde as 3 linhas
    "[selftest] v0.7 K1…" e ganha as da v071). O que fica é a F-C12:
    expected INDEPENDENTE de inverter_on; armar por shutdown remoto
    s/WO; resíduo top-2 = 26,35% < 30 escapa; shutdown COM work-order
    NÃO arma (ERRATA DATADA v0.7.1/F-C13: a WO-20261113-MNT7 do teste
    era INVENTADA e seria 403 na v0.7.1 — passa a WO-20261112-MNT1,
    válida); P(f) autónomo dá div ~0."""
    global SIM_CLOCK_OFFSET, DAILY_LIMIT_MODE
    ok = True
    # ---- 1. C12: top-5 kWp shutdown remoto s/WO → DIVERGE e DISPARA;
    #      resíduo top-2 (23,4/88,8 = 26,35%% < 30) ESCAPA (declarado)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.3)
    top5 = [4, 11, 0, 8, 3]      # 12.0+11.4+10.5+9.6+8.2 = 51,7 kWp
    top2 = [4, 11]               # 23,4 kWp = 26,35%%
    lab.scenario("SELFTEST-V07-C12")
    for i in top5:
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    c12_alerts = det.scan([e for e in lab.ctx._memory
                           if e.get("scenario") == "SELFTEST-V07-C12"])
    c12_cap = [a for a in c12_alerts
               if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    c12_snaps = [e for e in lab.ctx._memory
                 if e.get("event") == "capacity_snapshot"
                 and e.get("scenario") == "SELFTEST-V07-C12"]
    c12_ok = (bool(c12_cap)
              and max(e.get("divergence_pct", 0.0)
                      for e in c12_snaps) >= 30.0)
    print("[selftest] v0.7 C12 top-5 shutdown s/WO (div max %.2f%%, "
          "capacity=%s): %s"
          % (max((e.get("divergence_pct", 0.0) for e in c12_snaps),
                 default=0.0), bool(c12_cap),
             "OK" if c12_ok else "FALHOU"))
    ok = ok and c12_ok
    # resíduo top-2: repõe a frota e desliga SÓ os 2 maiores
    for i in range(12):
        lab.devices[i].harness_reset()
    time.sleep(0.3)
    lab.scenario("SELFTEST-V07-C12R")
    for i in top2:
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    c12r_alerts = det.scan([e for e in lab.ctx._memory
                            if e.get("scenario") == "SELFTEST-V07-C12R"])
    c12r_cap = [a for a in c12r_alerts
                if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    c12r_snaps = [e for e in lab.ctx._memory
                  if e.get("event") == "capacity_snapshot"
                  and e.get("scenario") == "SELFTEST-V07-C12R"]
    c12r_ok = (not c12r_cap
               and all(e.get("divergence_pct", 0.0) < 30.0
                       for e in c12r_snaps))
    print("[selftest] v0.7 C12 resíduo top-2 (26,35%% < 30 → ESCAPA, "
          "declarado; capacity=%s): %s"
          % (bool(c12r_cap), "OK" if c12r_ok else "FALHOU"))
    ok = ok and c12r_ok
    # ---- 2. C12 NEG: shutdown COM work-order → snapshot (evidência)
    #      mas NÃO arma → 0 CRIT capacity
    #      v0.7.1 ERRATA DATADA (F-C13, GO 13-11 ~17:00): a
    #      WO-20261113-MNT7 era INVENTADA (constante informal do teste)
    #      — com a validação da v0.7.1 seria 403 e o shutdown NÃO
    #      executaria (sem snapshots, teste quebrado). Passa a
    #      WO-20261112-MNT1 (VÁLIDA): executa, snapshots como evidência,
    #      0 CRIT capacity — o mecanismo C12 mantém-se intacto.
    for i in range(12):
        lab.devices[i].harness_reset()
    time.sleep(0.3)
    lab.scenario("SELFTEST-V07-C12WO")
    for i in top5:
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261112-MNT1"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    wo_alerts = det.scan([e for e in lab.ctx._memory
                          if e.get("scenario") == "SELFTEST-V07-C12WO"])
    wo_cap = [a for a in wo_alerts
              if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    wo_snaps = [e for e in lab.ctx._memory
                if e.get("event") == "capacity_snapshot"
                and e.get("scenario") == "SELFTEST-V07-C12WO"]
    wo_ok = (not wo_cap and bool(wo_snaps))
    print("[selftest] v0.7 C12 shutdown COM work-order (snapshots=%d "
          "como evidência, CRIT capacity=%s): %s"
          % (len(wo_snaps), bool(wo_cap), "OK" if wo_ok else "FALHOU"))
    ok = ok and wo_ok
    # ---- 3. C12 NEG: P(f) autónomo de frota inteira → div ~0 (o
    #      esperado desconta o curtail AUTÓNOMO)
    for i in range(12):
        lab.devices[i].harness_reset()
    lab.gridsim.set_state("STRESS")
    time.sleep(0.6)
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.3)
    lab.scenario("SELFTEST-V07-PF")
    lab.gridsim.set_state("STRESS")
    time.sleep(0.6)
    pf_alerts = det.scan([e for e in lab.ctx._memory
                          if e.get("scenario") == "SELFTEST-V07-PF"])
    pf_cap = [a for a in pf_alerts
             if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    pf_snaps = [e for e in lab.ctx._memory
                if e.get("event") == "capacity_snapshot"
                and e.get("scenario") == "SELFTEST-V07-PF"]
    pf_ok = (not pf_cap
             and all(e.get("divergence_pct", 0.0) < 30.0
                     for e in pf_snaps))
    print("[selftest] v0.7 C12 P(f) autónomo (div max %.2f%% < 30, "
          "capacity=%s): %s"
          % (max((e.get("divergence_pct", 0.0) for e in pf_snaps),
                 default=0.0), bool(pf_cap),
             "OK" if pf_ok else "FALHOU"))
    lab.gridsim.set_state("NORMAL")
    time.sleep(0.3)
    ok = ok and pf_ok
    return ok


def _selftest_v071(lab, det):
    """v0.7.1/R7 (GO do operador 13-11 ~17:00) — MECANISMOS das fixes:
    F-K1 D-BATTERY-DRAIN-TO-LOW (SoC RESULTANTE <= 35: apanha o K1 de
    2 dias E o atacante lento de 3; FP do dono que recarrega MORTO),
    F-C13 (WO inválida → 403, frota ON, WARN), F-C14 (5 shutdowns
    noturnos s/WO → WARN visível < k=6; COM WO válida → 0), F-SP
    (setpoint de frota COM WO válida NÃO arma a capacity; SEM WO
    arma — o resíduo declarado)."""
    global SIM_CLOCK_OFFSET
    ok = True
    # ---- 1. F-K1: K1 2 dias (40% + 25 h + 34,9%) → SoC 25,1 <= 35 →
    #      CRIT count 1 (só a fatia que ATERRA)
    lab.scenario("SELFTEST-V071-K1")
    d6 = lab.devices[6]
    d6.harness_reset()
    stk1, _ = http_json(LOOPBACK, d6.port, "POST", "/battery",
                        {"action": "discharge",
                         "amount_kwh": round(0.40 * d6.batt_kwh, 3)},
                        token=d6.service_token)
    try:
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
        stk2, _ = http_json(LOOPBACK, d6.port, "POST", "/battery",
                            {"action": "discharge",
                             "amount_kwh": round(0.349 * d6.batt_kwh, 3)},
                            token=d6.service_token)
    finally:
        SIM_CLOCK_OFFSET -= 25.0 * 3600.0
    k1 = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V071-K1"])
    k1_dtl = [a for a in k1 if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
    k1_ok = (stk1 == 200 and stk2 == 200
             and abs(d6.soc - 25.1) < 0.05
             and len(k1_dtl) == 1 and k1_dtl[0]["count"] == 1
             and set(k1_dtl[0]["devices"]) == {d6.name})
    print("[selftest] v0.7.1 F-K1 drain-to-low (40%%+25 h+34,9%% → SoC "
          "%.1f <= 35, CRIT count=%s): %s"
          % (d6.soc, k1_dtl[0]["count"] if k1_dtl else 0,
             "OK" if k1_ok else "FALHOU"))
    ok = ok and k1_ok
    # ---- 2. F-K1 apanha o ATACANTE LENTO (K1-b: 3 dias × 23,3% → SoC
    #      30,1 <= 35 → dispara na 3.ª fatia; ZERO alertas era o achado)
    lab.scenario("SELFTEST-V071-SLOW")
    d8 = lab.devices[8]
    d8.harness_reset()
    for _ in range(3):
        http_json(LOOPBACK, d8.port, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": round(0.233 * d8.batt_kwh, 3)},
                  token=d8.service_token)
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
    SIM_CLOCK_OFFSET -= 75.0 * 3600.0
    slow = det.scan([e for e in lab.ctx._memory
                     if e.get("scenario") == "SELFTEST-V071-SLOW"])
    slow_dtl = [a for a in slow if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
    slow_ok = (abs(d8.soc - 30.1) < 0.05
               and len(slow_dtl) == 1 and slow_dtl[0]["count"] == 1)
    print("[selftest] v0.7.1 F-K1 atacante lento (3 dias × 23,3%% → SoC "
          "%.1f <= 35, CRIT count=%s): %s"
          % (d8.soc, slow_dtl[0]["count"] if slow_dtl else 0,
             "OK" if slow_ok else "FALHOU"))
    ok = ok and slow_ok
    # ---- 3. F-K1 FP K1-c MORTO: dono 25%/dia × 3 dias COM recarga
    #      solar entre dias → SoC 100 → NÃO dispara (v0.7: CRIT s/ perigo)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.2)
    lab.scenario("SELFTEST-V071-OWNER")
    d10 = lab.devices[10]
    d10.harness_reset()
    for _ in range(3):
        http_json(LOOPBACK, d10.port, "POST", "/battery",
                  {"action": "discharge",
                   "amount_kwh": round(0.25 * d10.batt_kwh, 3)},
                  token=d10.service_token)
        d10.step_grid(12 * 3600.0)      # recarga solar J4 entre dias
        SIM_CLOCK_OFFSET += 25.0 * 3600.0
    SIM_CLOCK_OFFSET -= 75.0 * 3600.0
    own = det.scan([e for e in lab.ctx._memory
                    if e.get("scenario") == "SELFTEST-V071-OWNER"])
    own_dtl = [a for a in own if a["rule"] == "D-BATTERY-DRAIN-TO-LOW"]
    own_ok = (d10.soc >= 99.9 and not own_dtl)
    print("[selftest] v0.7.1 F-K1 FP K1-c morto (25%%/dia × 3 COM recarga "
          "→ SoC %.1f, drain-to-low=%s): %s"
          % (d10.soc, bool(own_dtl), "OK" if own_ok else "FALHOU"))
    ok = ok and own_ok
    # ---- 4. F-C13: WO inválida → 403, frota ON, WARN ×1
    lab.scenario("SELFTEST-V071-C13")
    d0 = lab.devices[0]
    d0.harness_reset()
    st, resp = http_json(LOOPBACK, d0.port, "POST", "/mode",
                         {"action": "inverter_power_off",
                          "work_order": "WO-INVENTADA-123"},
                         token=d0.service_token)
    c13 = det.scan([e for e in lab.ctx._memory
                    if e.get("scenario") == "SELFTEST-V071-C13"])
    c13_inv = [a for a in c13 if a["rule"] == "D-INVALID-WORK-ORDER"]
    c13_ok = (st == 403 and resp.get("error") == "work_order_invalid"
              and d0.inverter_on and len(c13_inv) == 1
              and c13_inv[0]["count"] == 1)
    print("[selftest] v0.7.1 F-C13 WO falsa (403, frota ON, WARN count="
          "%s): %s"
          % (c13_inv[0]["count"] if c13_inv else 0,
             "OK" if c13_ok else "FALHOU"))
    ok = ok and c13_ok
    # ---- 5. F-C14: NOITE, 5 shutdowns s/WO (< k=6) → WARN ×5 visível
    #      (na v0.7: ZERO alertas — a soma dos 2 resíduos declarados)
    lab.gridsim.set_state("NORMAL")
    lab.gridsim.set_irradiance("NOITE")
    time.sleep(0.3)
    lab.scenario("SELFTEST-V071-C14")
    for i in range(5):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    c14 = det.scan([e for e in lab.ctx._memory
                    if e.get("scenario") == "SELFTEST-V071-C14"])
    c14_warn = [a for a in c14
                if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
    c14_wave = [a for a in c14 if a["rule"] == "D-FLEET-SHUTDOWN-WAVE"]
    c14_ok = (len(c14_warn) == 1 and c14_warn[0]["count"] == 5
              and not c14_wave)
    print("[selftest] v0.7.1 F-C14 noite 5 shutdowns s/WO (WARN count="
          "%s, wave=%s): %s"
          % (c14_warn[0]["count"] if c14_warn else 0, bool(c14_wave),
             "OK" if c14_ok else "FALHOU"))
    ok = ok and c14_ok
    for i in range(12):
        lab.devices[i].harness_reset()
    # ---- 6. F-C14 FP: shutdown COM WO válida → 0 WARN
    lab.gridsim.set_irradiance("DIA")
    time.sleep(0.3)
    lab.scenario("SELFTEST-V071-C14WO")
    for i in range(5):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261112-MNT1"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    c14w = det.scan([e for e in lab.ctx._memory
                     if e.get("scenario") == "SELFTEST-V071-C14WO"])
    c14w_warn = [a for a in c14w
                 if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
    c14w_ok = not c14w_warn
    print("[selftest] v0.7.1 F-C14 FP shutdown COM WO válida (WARN=%s): "
          "%s" % (bool(c14w_warn), "OK" if c14w_ok else "FALHOU"))
    ok = ok and c14w_ok
    for i in range(12):
        lab.devices[i].harness_reset()
    time.sleep(0.3)
    # ---- 7. F-SP: setpoint 60% na FROTA COM WO válida → 200 ×12,
    #      div AGREGADA 40% >= 30 SEM CRIT (não arma); SEM WO → ARMA
    lab.scenario("SELFTEST-V071-SPWO")
    sts = []
    for i in range(N_DEVS):
        st, _ = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST",
                          "/setpoint",
                          {"value": 60.0,
                           "work_order": "WO-20261112-MNT1"},
                          token="SUNBOX-SVC-%02d-2026" % i)
        sts.append(st)
    emit_capacity_snapshot(lab)
    spwo = det.scan([e for e in lab.ctx._memory
                     if e.get("scenario") == "SELFTEST-V071-SPWO"])
    spwo_cap = [a for a in spwo if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    spwo_snaps = [e for e in lab.ctx._memory
                  if e.get("event") == "capacity_snapshot"
                  and e.get("scenario") == "SELFTEST-V071-SPWO"]
    spwo_ok = (sts == [200] * N_DEVS and not spwo_cap and bool(spwo_snaps)
               and max(e.get("divergence_pct", 0.0)
                       for e in spwo_snaps) >= 30.0)
    print("[selftest] v0.7.1 F-SP frota 60%% COM WO (200 ×12, div %.1f%% "
          ">= 30 SEM CRIT — não arma): %s"
          % (max((e.get("divergence_pct", 0.0) for e in spwo_snaps),
                 default=0.0), "OK" if spwo_ok else "FALHOU"))
    ok = ok and spwo_ok
    for i in range(12):
        lab.devices[i].harness_reset()
    time.sleep(0.3)
    lab.scenario("SELFTEST-V071-SPNOWO")
    sts2 = []
    for i in range(N_DEVS):
        st, _ = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST",
                          "/setpoint", {"value": 60.0},
                          token="SUNBOX-SVC-%02d-2026" % i)
        sts2.append(st)
    emit_capacity_snapshot(lab)
    spn = det.scan([e for e in lab.ctx._memory
                    if e.get("scenario") == "SELFTEST-V071-SPNOWO"])
    spn_cap = [a for a in spn if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    spn_ok = (sts2 == [200] * N_DEVS and bool(spn_cap))
    print("[selftest] v0.7.1 F-SP frota 60%% SEM WO (200 ×12, ARMA → CRIT "
          "capacity=%s — o resíduo DECLARADO): %s"
          % (bool(spn_cap), "OK" if spn_ok else "FALHOU"))
    ok = ok and spn_ok
    for i in range(12):
        lab.devices[i].harness_reset()
    time.sleep(0.3)
    return ok


def _selftest_v072(lab, det):
    """v0.7.2/R8 (GO do operador 13-11 ~19:30) — MECANISMOS das fixes:
    F-C15a (WO com âmbito: dispositivo/janela/usos → 403 + reason +
    WARN; gate bulk despacha SÓ ao âmbito) e F-C15b
    (D-MASS-SHUTDOWN-WITH-WO: shutdowns COM WO válida à escala da
    frota — distintos ≥ k OU perda ≥ 30% — CRIT dia e noite). NOTA
    DATADA: as secções v0.7.1 C12WO (top-5 COM MNT1) e C14WO (devs
    0-4 COM MNT1) GANHAM o CRIT novo POR DESIGN (58,22/45,6% ≥ 30);
    os testes dessas secções verificam capacity/WARN e continuam
    PASS — o CRIT novo lá é o F-C15b a funcionar, não regressão."""
    global SIM_CLOCK_OFFSET
    ok = True

    def _reset():
        for d in lab.devices:
            d.harness_reset()
        lab.gridsim.set_state("NORMAL")
        lab.gridsim.set_irradiance("DIA")
        time.sleep(0.3)

    # ---- 1. F-C15a âmbito: in-scope executa; fora do âmbito 403 ----
    _reset()
    lab.scenario("SELFTEST-V072-SCOPE")
    st_in, _ = http_json(LOOPBACK, PORT_DEV_BASE + 0, "POST", "/mode",
                         {"action": "inverter_power_off",
                          "work_order": "WO-20261112-MNT2"},
                         token="SUNBOX-SVC-00-2026")
    st_out, resp_out = http_json(LOOPBACK, PORT_DEV_BASE + 5, "POST",
                                 "/mode",
                                 {"action": "inverter_power_off",
                                  "work_order": "WO-20261112-MNT2"},
                                 token="SUNBOX-SVC-05-2026")
    time.sleep(0.3)
    sc = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-SCOPE"])
    inv = [a for a in sc if a["rule"] == "D-INVALID-WORK-ORDER"]
    inv_evs = [e for e in lab.ctx._memory
               if e.get("event") == "work_order_invalid"
               and e.get("scenario") == "SELFTEST-V072-SCOPE"]
    scope_ok = (st_in == 200 and st_out == 403
                and resp_out.get("reason") == "fora_do_ambito"
                and len(inv_evs) == 1
                and inv_evs[0].get("reason") == "fora_do_ambito"
                and len(inv) == 1 and inv[0]["count"] == 1
                and not lab.devices[0].inverter_on
                and lab.devices[5].inverter_on)
    print("[selftest] v0.7.2 F-C15a âmbito (MNT2 dev0 200 / dev5 403 "
          "fora_do_ambito + WARN, dev5 ON): %s"
          % ("OK" if scope_ok else "FALHOU"))
    ok = ok and scope_ok

    # ---- 2. F-C15a janela: +40 dias → 403 fora_da_janela ----
    _reset()
    lab.scenario("SELFTEST-V072-JANELA")
    SIM_CLOCK_OFFSET += 40.0 * 86400.0
    try:
        st_exp, resp_exp = http_json(LOOPBACK, PORT_DEV_BASE + 3, "POST",
                                     "/mode",
                                     {"action": "inverter_power_off",
                                      "work_order": "WO-20261112-MNT1"},
                                     token="SUNBOX-SVC-03-2026")
    finally:
        SIM_CLOCK_OFFSET -= 40.0 * 86400.0
    time.sleep(0.3)
    ja = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-JANELA"])
    ja_inv = [a for a in ja if a["rule"] == "D-INVALID-WORK-ORDER"]
    janela_ok = (st_exp == 403
                 and resp_exp.get("reason") == "fora_da_janela"
                 and len(ja_inv) == 1 and lab.devices[3].inverter_on)
    print("[selftest] v0.7.2 F-C15a janela (relógio +40d: MNT1 403 "
          "fora_da_janela, dev3 ON, WARN): %s"
          % ("OK" if janela_ok else "FALHOU"))
    ok = ok and janela_ok

    # ---- 3. F-C15a usos: 3 usos OK; o 4.º → 403 usos_esgotados ----
    _reset()
    lab.scenario("SELFTEST-V072-USOS")
    sts_us = []
    for i in (0, 1, 2, 0):
        st_u, _ = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                            {"action": "inverter_power_off",
                             "work_order": "WO-20261112-MNT2"},
                            token="SUNBOX-SVC-%02d-2026" % i)
        sts_us.append((st_u, _))
    time.sleep(0.3)
    us = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-USOS"])
    us_inv = [a for a in us if a["rule"] == "D-INVALID-WORK-ORDER"]
    usos_ok = ([s for s, _ in sts_us[:3]] == [200] * 3
               and sts_us[3][0] == 403
               and len(us_inv) == 1 and us_inv[0]["count"] == 1)
    print("[selftest] v0.7.2 F-C15a usos (MNT2 max 3: 200×3, o 4.º 403 "
          "usos_esgotados + WARN): %s"
          % ("OK" if usos_ok else "FALHOU"))
    ok = ok and usos_ok

    # ---- 4. F-C15b massa: 12 shutdowns COM MNT1 → CRIT count 12 -----
    _reset()
    lab.scenario("SELFTEST-V072-MASSA")
    sts_m = []
    for i in range(N_DEVS):
        st_m, _ = http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                            {"action": "inverter_power_off",
                             "work_order": "WO-20261112-MNT1"},
                            token="SUNBOX-SVC-%02d-2026" % i)
        sts_m.append(st_m)
    time.sleep(0.3)
    ma = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-MASSA"])
    ma_mass = [a for a in ma if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
    ma_cap = [a for a in ma if a["rule"] == "D-CAPACITY-DIVERGENCE"]
    ma_nowo = [a for a in ma if a["rule"] == "D-REMOTE-SHUTDOWN-NO-WO"]
    ma_wave = [a for a in ma if a["rule"] == "D-FLEET-SHUTDOWN-WAVE"]
    massa_ok = (sts_m == [200] * N_DEVS and len(ma_mass) == 1
                and ma_mass[0]["severity"] == "CRIT"
                and ma_mass[0]["count"] == N_DEVS
                and len(ma_mass[0]["devices"]) == N_DEVS
                and not ma_cap and not ma_nowo and not ma_wave)
    print("[selftest] v0.7.2 F-C15b massa (12 shutdowns COM MNT1: CRIT "
          "D-MASS-SHUTDOWN-WITH-WO count 12, SEM capacity/onda — a WO "
          "não é âncora à escala da frota): %s"
          % ("OK" if massa_ok else "FALHOU"))
    ok = ok and massa_ok

    # ---- 5. F-C15b gatilho de capacidade: top-5 (58,22% ≥ 30) ------
    _reset()
    lab.scenario("SELFTEST-V072-TOP5")
    top5 = [4, 11, 0, 8, 3]      # 51,7/88,8 = 58,22%
    for i in top5:
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261112-MNT1"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    time.sleep(0.3)
    t5 = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-TOP5"])
    t5_mass = [a for a in t5 if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
    top5_ok = (len(t5_mass) == 1 and t5_mass[0]["count"] == 5
              and t5_mass[0].get("distinct_devices") == 5
              and abs(t5_mass[0].get("capacity_loss_pct", 0.0)
                      - 58.22) < 0.05)
    print("[selftest] v0.7.2 F-C15b capacidade (top-5 COM MNT1: 5 < k "
          "MAS 58,22%% >= 30 → CRIT count 5): %s"
          % ("OK" if top5_ok else "FALHOU"))
    ok = ok and top5_ok

    # ---- 6. F-C15b FP: manutenção pontual com WO de âmbito correto --
    _reset()
    lab.scenario("SELFTEST-V072-FP")
    for i in (0, 2):
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261113-MNT3"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    time.sleep(0.3)
    fp = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-FP"])
    fp_ok = (len(fp) == 0)
    print("[selftest] v0.7.2 F-C15b FP (MNT3 âmbito {0,2}: 200×2, ZERO "
          "alertas — manutenção pontual legítima): %s"
          % ("OK" if fp_ok else "FALHOU"))
    ok = ok and fp_ok

    # ---- 7. F-C15b RESÍDUO DECLARADO: 5 menores (25,68% < 30) ------
    _reset()
    lab.scenario("SELFTEST-V072-RESIDUO")
    small5 = [10, 2, 6, 5, 1]    # 22,8/88,8 = 25,68%
    for i in small5:
        http_json(LOOPBACK, PORT_DEV_BASE + i, "POST", "/mode",
                  {"action": "inverter_power_off",
                   "work_order": "WO-20261112-MNT1"},
                  token="SUNBOX-SVC-%02d-2026" % i)
    time.sleep(0.3)
    rs = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-RESIDUO"])
    rs_crit = [a for a in rs if a["severity"] == "CRIT"]
    residuo_ok = (len(rs_crit) == 0 and len(rs) == 0)
    print("[selftest] v0.7.2 F-C15b RESÍDUO (5 menores COM MNT1: 5 < k E "
          "25,68%% < 30 → 0 CRIT — resíduo DECLARADO p/ v0.8): %s"
          % ("OK" if residuo_ok else "FALHOU"))
    ok = ok and residuo_ok

    # ---- 8. F-C15a NEG bulk: MNT3 → 2 executados, 10 skip, 0 CRIT ---
    _reset()
    lab.scenario("SELFTEST-V072-NEGBULK")
    st_lg, resp_lg = http_json(LOOPBACK, PORT_GATE, "POST",
                              "/fleet/login",
                              {"user": DAILY_USER, "pass": daily_code()})
    st_bk, resp_bk = http_json(LOOPBACK, PORT_GATE, "POST",
                               "/fleet/bulk_shutdown",
                               {"work_order_id": "WO-20261113-MNT3"},
                               token=resp_lg.get("session"))
    time.sleep(0.3)
    nb = det.scan([e for e in lab.ctx._memory
                   if e.get("scenario") == "SELFTEST-V072-NEGBULK"])
    nb_crit = [a for a in nb if a["severity"] == "CRIT"]
    nb_mass = [a for a in nb if a["rule"] == "D-MASS-SHUTDOWN-WITH-WO"]
    skips = [e for e in lab.ctx._memory
             if e.get("event") == "bulk_scope_skip"
             and e.get("scenario") == "SELFTEST-V072-NEGBULK"]
    negbulk_ok = (st_bk == 200
                  and sorted(resp_bk.get("devices", {}).values()) == [200, 200]
                  and len(resp_bk.get("skipped_out_of_scope", [])) == 10
                  and len(skips) == 10 and not nb_crit and not nb_mass)
    print("[selftest] v0.7.2 F-C15a NEG bulk (MNT3: 2 executados, 10 "
          "bulk_scope_skip, 0 CRIT): %s"
          % ("OK" if negbulk_ok else "FALHOU"))
    ok = ok and negbulk_ok

    _reset()
    return ok


def run_selftest():
    ok = True
    det = Detector()
    # G9 (v0.2): anti-tautologia — sem eventos, o check recusa por construção
    try:
        det.rule_liveness_check(None)
        print("[selftest] anti-tautologia: FALHOU (aceitou events=None)")
        ok = False
    except ValueError:
        print("[selftest] anti-tautologia: OK (eventos sinteticos recusados)")
    # G9: liveness com TRAFEGO REAL — lab em memória (C2: sem pastas)
    lab = Lab(evidence=False)
    lab.start()
    time.sleep(0.4)
    try:
        exercise_liveness(lab)
        liv = det.rule_liveness_check(lab.ctx._memory)
        print("[selftest] rule_liveness_check (trafego real): "
              "%d/%d regras vivas, dead=%s" %
              (liv["fired"], liv["rules_total"], liv["dead_rules"]))
        ok = ok and liv["pass"]
    finally:
        lab.stop()
    # ScopeError
    try:
        assert_loopback("192.168.1.50")
        print("[selftest] ScopeError: FALHOU (aceitou alvo externo)")
        ok = False
    except ScopeError:
        print("[selftest] ScopeError: OK (recusa alvo não-loopback)")
    # esquema de assinatura inventado: round-trip
    s = sign_image(LEGIT_IMAGE)
    sign_ok = s.startswith("SUNSIG-") and s == sign_image(LEGIT_IMAGE)
    print("[selftest] sign_image round-trip: %s" % ("OK" if sign_ok else "FALHOU"))
    # floor aritmético (invariante selada 2)
    dev = SunBox(LabContext(evidence=False), 0)   # C2: sem pastas
    st, _ = dev.remote_battery("unit_test", "force_export", 999.0)
    floor_ok = st == 409 and dev.soc == 100.0
    print("[selftest] SoC floor sem /local_confirm: %s (409, SoC intacto)" %
          ("OK" if floor_ok else "FALHOU"))
    # provenance hardcode: payload com spoof é removido e registado
    body = {"provenance": "autonomous_pf", "reason": "x", "value": 50.0}
    dev2 = SunBox(LabContext(evidence=False), 1)  # C2: sem pastas
    spoofed = strip_spoofed_provenance(dev2, body)
    spoof_ok = (spoofed == ["provenance", "reason"]
                and body == {"value": 50.0})
    print("[selftest] strip provenance spoof: %s" %
          ("OK" if spoof_ok else "FALHOU"))
    ok = ok and sign_ok and floor_ok and spoof_ok
    # v0.3 — H3: tipos estritos (bool NÃO é número), direto e via guard
    lab2 = Lab(evidence=False)
    lab2.start()
    time.sleep(0.4)
    try:
        lab2.scenario("SELFTEST-TYPES")
        d0 = lab2.devices[0]
        st, resp = http_json(LOOPBACK, d0.port, "POST", "/setpoint",
                             {"value": False}, token=d0.service_token)
        st2, resp2 = http_json(LOOPBACK, PORT_GUARD, "POST",
                               "/device/0/setpoint", {"value": True},
                               token=None)
        type_ok = (st == 400 and st2 == 400 and d0.export_limit == 100.0)
        print("[selftest] H3 tipos estritos (bool recusado, direto %s / "
              "guard %s): %s" % (st, st2, "OK" if type_ok else "FALHOU"))
        ok = ok and type_ok
        # v0.3 — H1/H2: canonicalização fail-closed (não-ASCII, //, %, ?)
        lab2.scenario("SELFTEST-CANON")
        def _raw(port, target):
            payload = b"{\"value\": 50.0}"
            req = (b"POST " + target + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   b"Content-Type: application/json\r\n"
                   b"Content-Length: %d\r\n\r\n" % len(payload)) + payload
            s = socket.create_connection((LOOPBACK, port), timeout=3)
            s.sendall(req)
            data = s.recv(4096)
            s.close()
            return data.split(b"\r\n")[0].decode("latin-1", "replace")
        r_ascii = _raw(lab2.devices[2].port, "/mode\xff".encode("latin-1"))
        r_dbl = _raw(lab2.devices[2].port, b"//setpoint")
        r_pct = _raw(lab2.devices[2].port, b"/setpoint%20")
        r_q = _raw(lab2.devices[2].port, b"/setpoint?x=1")
        canon_ev = [e for e in lab2.ctx._memory
                    if e.get("event") == "non_canonical_request"
                    and e.get("scenario") == "SELFTEST-CANON"]
        canon_ok = ("400" in r_ascii and "400" in r_dbl and "400" in r_pct
                    and "400" in r_q and len(canon_ev) >= 4)
        print("[selftest] H1/H2 canonicalizacao fail-closed (nao-ASCII=%s "
              "//=%s %%=%s ?=%s; eventos=%d): %s"
              % ("400" in r_ascii, "400" in r_dbl, "400" in r_pct,
                 "400" in r_q, len(canon_ev), "OK" if canon_ok else "FALHOU"))
        ok = ok and canon_ok
        # v0.3 — guard: forward válido + rejeições próprias
        lab2.scenario("SELFTEST-GUARD")
        st, resp = http_json(LOOPBACK, PORT_GUARD, "POST",
                             "/device/3/setpoint", {"value": 55.0},
                             token=lab2.devices[3].service_token)
        fwd_ok = (st == 200 and lab2.devices[3].export_limit == 55.0)
        # local_confirm recusado no guard (canal físico)
        st_lc, _ = http_json(LOOPBACK, PORT_GUARD, "POST",
                             "/device/3/local_confirm", {"pin": "x"})
        # chunked recusado no guard
        raw = (b"POST /device/3/setpoint HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               b"Authorization: Bearer " +
               lab2.devices[3].service_token.encode() + b"\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n9\r\n{\"value\": "
               b"55}\r\n0\r\n\r\n")
        s = socket.create_connection((LOOPBACK, PORT_GUARD), timeout=3)
        s.sendall(raw)
        r_chunk = s.recv(4096).split(b"\r\n")[0].decode("latin-1", "replace")
        s.close()
        guard_ok = (fwd_ok and st_lc == 400 and "400" in r_chunk)
        print("[selftest] guard proxy (forward 200=%s, local_confirm "
              "recusado=%s, chunked recusado=%s): %s"
              % (st == 200, st_lc == 400, "400" in r_chunk,
                 "OK" if guard_ok else "FALHOU"))
        ok = ok and guard_ok
        # v0.5/C10 — H5: física da bateria em ilha (opção A: a reserva
        # SERVE a carga local abaixo do floor, até ISLAND_MIN_SOC).
        # Histórico: v0.3/v0.4 clampavam no floor (28.0 → 25.0, carga
        # cai para pv) — causa 2 do C10 (medição do supervisor). Com a
        # física correta kW*s/3600: 600 s de deficit de 1.2 kW = 0.2 kWh
        # = 3.0864 pontos (batt d5 = 6.48 kWh) → 28.0 desce a 24.9136,
        # ABAIXO do floor, carga CONTINUAR servida (opção A da v0.5).
        lab2.scenario("SELFTEST-PHYS")
        d5 = lab2.devices[5]
        d5.curtail_pct = 100.0        # harness: pv líquida 0 → deficit total
        d5.soc = 28.0
        d5.relay_closed = False       # modo ilha
        d5.inverter_on = True
        d5.step_island(600.0)         # 600 s de deficit de 1.2 kW
        phys_ok = (abs(d5.soc - 24.9136) < 0.0005
                   and d5.soc < FLOOR_SOC
                   and d5.self_consumption_kw() == LOAD_LOCAL_KW)
        floor_ev = [e for e in lab2.ctx._memory
                    if e.get("event") == "island_battery_at_floor"
                    and e.get("scenario") == "SELFTEST-PHYS"]
        min_ev = [e for e in lab2.ctx._memory
                  if e.get("event") == "island_battery_at_island_min"
                  and e.get("scenario") == "SELFTEST-PHYS"]
        print("[selftest] H5 fisica da ilha v0.5 (SoC 28→%.4f ABAIXO do "
              "floor %.1f, carga SERVIDA=%s kW — reserva em uso; "
              "clamp_events floor=%d/min=%d): %s"
              % (d5.soc, FLOOR_SOC, d5.self_consumption_kw(),
                 len(floor_ev), len(min_ev), "OK" if phys_ok else "FALHOU"))
        ok = ok and phys_ok
        # v0.5/C10 — clamp no MÍNIMO TÉCNICO: SoC 6.0 + 600 s de deficit
        # → clamp em ISLAND_MIN_SOC (5.0), evento island_battery_at_island_min
        # UMA vez, carga local cai para pv (0.0 com pv 0)
        lab2.scenario("SELFTEST-ISLANDMIN")
        d5._island_floor_announced = False   # higiene entre sub-testes
        d5.soc = 6.0
        d5.step_island(600.0)
        min_ev2 = [e for e in lab2.ctx._memory
                   if e.get("event") == "island_battery_at_island_min"
                   and e.get("scenario") == "SELFTEST-ISLANDMIN"]
        islandmin_ok = (d5.soc == ISLAND_MIN_SOC
                        and d5.self_consumption_kw() == 0.0
                        and len(min_ev2) == 1)
        print("[selftest] C10 minimo tecnico da ilha (SoC 6→%.1f, carga "
              "cai para pv=%.1f, evento=%d): %s"
              % (d5.soc, d5.self_consumption_kw(), len(min_ev2),
                 "OK" if islandmin_ok else "FALHOU"))
        ok = ok and islandmin_ok
        # v0.5/C10 — contrafactual RESERVE_LOCKED (opção B = v0.4): a
        # reserva tranca NO FLOOR — o ANTES do C10 preservado por flag
        global RESERVE_LOCKED_MODE
        RESERVE_LOCKED_MODE = True
        lab2.scenario("SELFTEST-OPTB")
        d5._island_floor_announced = False   # higiene entre sub-testes
        d5.soc = 28.0
        d5.step_island(600.0)
        optb_ev = [e for e in lab2.ctx._memory
                   if e.get("event") == "island_battery_at_floor"
                   and e.get("scenario") == "SELFTEST-OPTB"]
        optb_ok = (d5.soc == FLOOR_SOC and d5.self_consumption_kw() == 0.0
                   and len(optb_ev) == 1)
        print("[selftest] C10 opcao B (reserva trancada): SoC 28→%.1f "
              "clamp NO floor, carga cai para pv=%.1f, evento floor=%d: %s"
              % (d5.soc, d5.self_consumption_kw(), len(optb_ev),
                 "OK" if optb_ok else "FALHOU"))
        ok = ok and optb_ok
        RESERVE_LOCKED_MODE = False
        # v0.4 — C7: perfis de irradiância (DIA default mantém contagens)
        lab2.scenario("SELFTEST-C7")
        d7 = lab2.devices[7]
        lab2.gridsim.set_irradiance("NOITE")
        c7_ok = d7.pv_gross_kw() == 0.0
        lab2.gridsim.set_irradiance("NUVEM")
        c7_ok = c7_ok and d7.pv_gross_kw() == round(d7.kwp * 0.20, 2)
        lab2.gridsim.set_irradiance("DIA")
        c7_ok = c7_ok and d7.pv_gross_kw() == round(d7.kwp * 0.55, 2)
        print("[selftest] C7 irradiancia (NOITE=0, NUVEM=kwp*0.2, "
              "DIA=kwp*0.55): %s" % ("OK" if c7_ok else "FALHOU"))
        ok = ok and c7_ok
        # v0.4 — I1: curtail autónomo SOBE E DESCE (catraca morta)
        lab2.scenario("SELFTEST-I1")
        d1 = lab2.devices[1]
        lab2.gridsim.set_state("STRESS")
        time.sleep(0.6)             # P(f): 50.40 → curtail 40%
        i1_up = d1.curtail_autonomous == 40.0
        lab2.gridsim.set_state("NORMAL")
        time.sleep(0.6)             # RELEASE: volta a 0
        i1_down = d1.curtail_autonomous == 0.0
        pf_rel = [e for e in lab2.ctx._memory
                  if e.get("event") == "pf_release"
                  and e.get("scenario") == "SELFTEST-I1"]
        i1_ok = i1_up and i1_down and len(pf_rel) >= 1
        print("[selftest] I1 release do curtail P(f) (sobe 40=%s, desce "
              "0=%s, pf_release=%d): %s"
              % (i1_up, i1_down, len(pf_rel),
                 "OK" if i1_ok else "FALHOU"))
        ok = ok and i1_ok
        # v0.4 — C8: FP morto (setpoint legítimo 90% + P(f) autónomo)
        # + snapshot CONTÍNUO por transição de banda (grid_monitor)
        lab2.scenario("SELFTEST-C8")
        d2 = lab2.devices[2]
        http_json(LOOPBACK, d2.port, "POST", "/setpoint",
                  {"value": 90.0}, token=d2.service_token)
        lab2.gridsim.set_state("STRESS")
        time.sleep(0.6)             # P(f) autónomo 40% por cima
        emit_capacity_snapshot(lab2)
        snaps_h = [e for e in lab2.ctx._memory
                   if e.get("event") == "capacity_snapshot"
                   and e.get("scenario") == "SELFTEST-C8"
                   and e.get("provenance") == "lab_harness"]
        fp_dead = (len(snaps_h) == 1
                   and snaps_h[0]["divergence_pct"] < CAPACITY_DIVERGENCE_PCT)
        # snapshot contínuo: 6 setpoints a 0 → transição de banda ≥30%
        for i in range(6):
            http_json(LOOPBACK, lab2.devices[i].port, "POST", "/setpoint",
                      {"value": 0.0}, token=lab2.devices[i].service_token)
        time.sleep(0.5)             # o loop publica → grid_monitor emite
        snaps_g = [e for e in lab2.ctx._memory
                   if e.get("event") == "capacity_snapshot"
                   and e.get("scenario") == "SELFTEST-C8"
                   and e.get("provenance") == "grid_monitor"]
        alerts_c8 = det.scan(collect_events(lab2.ctx))
        c8_alerts = [a for a in alerts_c8
                     if a["scenario"] == "SELFTEST-C8"]
        c8_ok = (fp_dead and len(snaps_g) >= 1
                 and any(a["rule"] == "D-CAPACITY-DIVERGENCE"
                         for a in c8_alerts))
        print("[selftest] C8 (FP morto=%s [div=%.2f%%], snapshot continuo "
              "grid_monitor=%d, regra dispara=%s): %s"
              % (fp_dead, snaps_h[0]["divergence_pct"] if snaps_h else -1,
                 len(snaps_g),
                 any(a["rule"] == "D-CAPACITY-DIVERGENCE"
                     for a in c8_alerts),
                 "OK" if c8_ok else "FALHOU"))
        ok = ok and c8_ok
        for d in lab2.devices:      # limpeza entre testes (G10)
            d.harness_reset()
        lab2.gridsim.set_state("NORMAL")
        time.sleep(0.3)
        # v0.4 — I4: control chars e dot-segments fail-closed
        lab2.scenario("SELFTEST-I4")
        r_ctl = _raw(lab2.devices[2].port, b"/setpoint\x7f")
        r_dot1 = _raw(lab2.devices[2].port, b"/a/./setpoint")
        r_dot2 = _raw(lab2.devices[2].port, b"/a/../setpoint")
        ctl_ev = [e for e in lab2.ctx._memory
                  if e.get("event") == "non_canonical_request"
                  and e.get("scenario") == "SELFTEST-I4"]
        reasons = {e.get("reason") for e in ctl_ev}
        i4_ok = ("400" in r_ctl and "400" in r_dot1 and "400" in r_dot2
                 and "control_char" in reasons and "dot_segment" in reasons)
        print("[selftest] I4 canonicalizador (0x7F=%s, /./=%s, /../=%s; "
              "reasons=%s): %s"
              % ("400" in r_ctl, "400" in r_dot1, "400" in r_dot2,
                 sorted(reasons), "OK" if i4_ok else "FALHOU"))
        ok = ok and i4_ok
        # v0.4 — I5: QUALQUER Transfer-Encoding recusado no guard
        lab2.scenario("SELFTEST-I5")
        d3 = lab2.devices[3]
        before_el = d3.export_limit
        raw_te = (b"POST /device/3/setpoint HTTP/1.1\r\n"
                  b"Host: 127.0.0.1\r\n"
                  b"Authorization: Bearer "
                  + d3.service_token.encode() + b"\r\n"
                  b"Transfer-Encoding: identity\r\n"
                  b"Content-Type: application/json\r\n"
                  b"Content-Length: 15\r\n\r\n{\"value\": 55.0}")
        s = socket.create_connection((LOOPBACK, PORT_GUARD), timeout=3)
        s.sendall(raw_te)
        r_te = s.recv(4096).split(b"\r\n")[0].decode("latin-1", "replace")
        s.close()
        i5_ok = "400" in r_te and d3.export_limit == before_el
        print("[selftest] I5 guard (TE identity recusado=%s, estado "
              "intacto=%s): %s"
              % ("400" in r_te, d3.export_limit == before_el,
                 "OK" if i5_ok else "FALHOU"))
        ok = ok and i5_ok
        # v0.5 — C4: regra cumulativa (fatias cada <50% SOMAM >=50%)
        # v0.6 NOTA DATADA (superssenção, ver changelog): com o limite
        # diário de 40% ATIVO (default v0.6), as fatias 30%+30% (soma
        # 60%) e a operação de 55% dão 409 daily ANTES de executarem —
        # as regras são exercitadas na configuração v0.5
        # (DAILY_LIMIT_MODE=False), com reposição GARANTIDA em finally.
        global DAILY_LIMIT_MODE
        DAILY_LIMIT_MODE = False
        try:
            ok = ok and _selftest_c4_rules(lab2, det)
        finally:
            DAILY_LIMIT_MODE = True
        # v0.6/R5 — fixes J1-J5 + limite diário (GO do operador 13-11
        # 13:23): curva/minutos ficam no measure; aqui os MECANISMOS
        ok = ok and _selftest_v06(lab2, det)
        # v0.7/R6 — C12 capacity (GO do operador 13-11 15:30): mecanismos,
        # FPs e resíduo top-2 (as secções K1 da v0.7 foram SUPERSSUDAS
        # pela _selftest_v071 — nota datada na própria função)
        ok = ok and _selftest_v07(lab2, det)
        # v0.7.1/R7 — F-C13/F-K1/F-C14/F-SP (GO 13-11 ~17:00): mecanismos,
        # FPs e resíduos (o atacante que estaciona > 35 fica no measure (e))
        ok = ok and _selftest_v071(lab2, det)
        # v0.7.2/R8 — F-C15a/F-C15b (GO 13-11 ~19:30): âmbito/janela/
        # usos + regra de massa; FP da manutenção pontual; resíduo
        # declarado (< k dispositivos E < 30% com WO válida)
        ok = ok and _selftest_v072(lab2, det)
    finally:
        lab2.stop()
    print("[selftest] RESULTADO: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="SUNSTRIKE lab v%s (grant %s)" % (LAB_VERSION, GRANT_ID))
    ap.add_argument("command",
                    choices=["demo", "serve", "attack", "selftest", "measure"])
    ap.add_argument("--variant", choices=["h1", "h2", "neg"], default=None)
    ap.add_argument("--host", default=LOOPBACK)
    ap.add_argument("--gate-port", type=int, default=PORT_GATE)
    args = ap.parse_args()
    if args.command == "demo":
        raise SystemExit(run_demo())
    if args.command == "serve":
        run_serve()
        return
    if args.command == "attack":
        if not args.variant:
            ap.error("attack exige --variant h1|h2|neg")
        adv = Adversary(args.host, args.gate_port)   # ScopeError se não-loopback
        r = {"h1": adv.attack_h1, "h2": adv.attack_h2,
             "neg": adv.maintenance_neg}[args.variant]()
        print(json.dumps(r, indent=2))
        return
    if args.command == "selftest":
        raise SystemExit(run_selftest())
    if args.command == "measure":
        raise SystemExit(run_measure())


if __name__ == "__main__":
    main()

# EOF:sunstrike_lab.py
