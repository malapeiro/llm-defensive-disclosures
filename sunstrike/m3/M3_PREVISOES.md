# M3_PREVISOES — SUNSTRIKE — deteção externa (Suricata + Sigma)

Escritas em 14-11-2026 (~16:00), ANTES de qualquer corrida dos cenários M3 e
ANTES de qualquer pcap/log existir. Nunca mudam depois. O run oficial é
SEMPRE o run 1, feito pelo supervisor (Suricata 7.0.3 + Sigma via SQLite;
o operador corre Suricata 8.0.8 no Mac sobre os mesmos pcaps).

Lab alvo: v0.7.5 SELADA — sha256 `5162964f2df283fd6ed0a1a4d53f8b3650f491b4
892e24abb198494b7abcb441`. O gerador `m3_cenarios.py` recusa correr contra
qualquer outro hash.

Cenários (um por invocação, `python3 -I m3_cenarios.py <cenario>`,
`Lab(evidence=True)` → uma pasta de evidência própria por cenário):

| Cenário | Tráfego gerado |
|---|---|
| NEG | manutenção legítima do demo: login por código diário, bulk MNT3 (âmbito {0,2}), export_limit 60% com WO MNT1, descarga 2 kWh, firmware assinado em janela, /local_confirm + descarga abaixo do floor COM token |
| H1 | credenciais default no gate, bulk SEM work-order (403), loop por-dispositivo: 12× POST /fleet/device/N/shutdown |
| H2 | recon /fleet/telemetry, 6× POST /mode (broker token + spoof de provenance) no top-6 kWp, force_export 999 (409 floor) |
| H3 | login default, 12× export_limit 20% s/WO pela via per-device, STRESS + tentativa /grid_profile (409 pf), snapshot de capacidade |
| H4 | STRESS: 12× firmware assinado fora da janela (400); NORMAL: 12× firmware com assinatura forjada (403) |
| H5 | descarga 60% (409 limite diário), force_export 999 (409 floor) no dev 0 |
| NONCANON | login diário via guard (canónico), 5 logins falhados no gate (lockout), 5 pedidos não-canónicos crus no gate, 1 não-canónico + TE + body grande + rota desconhecida no guard, 6 PINs falhados, /mode com WO falsa (403), /setpoint 150 (400) |
| MASS | login por código diário, bulk_shutdown COM WO MNT1 (âmbito frota inteira → 12 shutdowns executados) |
| SLOW | login por código diário, 8× POST /fleet/device/N/shutdown espaçados 65 s REAIS (pacing visível no pcap E no sim_ts; > WAVE_WINDOW 60 s, < SLOW_WINDOW 3600 s) |
| EMERG | EMERGENCY no GRIDSIM; 5 comandos remotos no dev 0 (mode/battery/setpoint/firmware/grid_profile), todos recusados pelo interlock (409) — cenário EXTRA (mínimos do GO não cobrem esta regra; "mínimos" ≠ fechados) |

NOTA: cada pedido do lab é um fluxo TCP novo (stdlib urllib sem keep-alive)
→ contagens previstas = 1 alerta por pedido/resposta.

## A. Suricata (`sunstrike_m3.rules`, sid 9100001-9100020) × cenários

| sid | Regra M3 (msg) | NEG | H1 | H2 | H3 | H4 | H5 | NONCANON | MASS | SLOW | EMERG |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 9100001 | D-AUTH-DEFAULT | não | SIM ×1 | não | SIM ×1 | não | não | não | não | não | não |
| 9100002 | D-AUTH-BROKER-TOKEN | não | não | SIM ×7 | não | não | não | não | não | não | não |
| 9100003 | D-BULK-WITHOUT-WORKORDER | não | SIM ×1 | não | não | não | não | não | não | não | não |
| 9100004 | D-REMOTE-SHUTDOWN-NO-WO | não | SIM ×12 | SIM ×6 | não | não | não | não | não | SIM ×8 | SIM ×1 (FP declarado) |
| 9100005 | D-FLEET-SHUTDOWN-WAVE | não | SIM ×1 | SIM ×1 | não | não | não | não | não | NÃO (pacing 65 s > 60 s) | não |
| 9100006 | D-SLOW-WAVE | não | SIM ×1 | NÃO (6 < 8) | não | não | não | não | não | SIM ×1 | não |
| 9100007 | D-MASS-SHUTDOWN-WITH-WO | não | não | não | não | não | não | não | SIM ×1 | não | não |
| 9100008 | D-FLEET-CURTAILMENT-WAVE | não | não | não | SIM ×1 | não | não | não | não | não | não |
| 9100009 | D-MASS-CURTAILMENT | não | não | não | SIM ×1 (duplo alerta declarado, como no lab) | não | não | não | não | não | não |
| 9100010 | D-BATTERY-DRAIN-BELOW-FLOOR | não | não | SIM ×1 | não | não | SIM ×1 | não | não | não | não |
| 9100011 | D-PROVENANCE-SPOOF-ATTEMPT | não | não | SIM ×6 | não | não | não | não | não | não | não |
| 9100012 | D-NON-CANONICAL-REQUEST | não | não | não | não | não | não | SIM ×6 (5 gate + 1 guard) | não | não | não |
| 9100013 | D-LOGIN-BRUTE-FORCE | não | não | não | não | não | não | SIM ×1 | não | não | não |
| 9100014 | D-LOCAL-CONFIRM-BRUTE-FORCE | não | não | não | não | não | não | SIM ×1 (no 5.º) | não | não | não |
| 9100015 | D-INVALID-WORK-ORDER | não | não | não | não | não | não | SIM ×1 | não | não | não |
| 9100016 | D-SETPOINT-OUT-OF-BAND | não | não | não | não | não | não | SIM ×1 | não | não | não |
| 9100017 | D-PF-PARAM-CHANGE-IN-STRESS | não | não | não | SIM ×1 | não | não | não | não | não | não |
| 9100018 | D-GRID-EMERGENCY-REMOTE-BLOCK | não | não | não | não | não | não | não | não | não | SIM ×5 |
| 9100019 | D-FIRMWARE-OUT-OF-WINDOW | não | não | não | não | SIM ×12 | não | não | não | não | não |
| 9100020 | D-FIRMWARE-REJECTED | não | não | não | não | SIM ×12 | não | não | não | não | não |

**NEG tem de dar ZERO alertas Suricata** — verificação linha a linha:
login diário (sem "sunadmin-2026"), bulk COM WO (resposta 200 sem a
string de erro; pcre da massa exige sunbox-00..05 consecutivos no
`devices` — o bulk MNT3 só despacha {0,2}), export_limit 60% (1 pedido <
threshold 6), descargas sem force_export e com execução 200 (sem a
string do floor), firmware assinado em janela (200), /local_confirm com
PIN certo (200). Nenhum body contém provenance/source/reason. Nenhum
pedido não-canónico.

Falsos positivos DECLARADOS (previstos, não escondidos):
- 9100004 em EMERG: o pedido `/mode inverter_power_off` s/WO é VISTO na
  rede, mas o interlock recusa (409) — o lab NÃO gera evento shutdown.
  Regra request-based não vê a execução. (1 alerta, declarado.)
- 9100008/9100009 não verificam o VALOR do setpoint (≤50%/≤25%): contam
  qualquer `export_limit`/`setpoint`. NEG fica abaixo do threshold (1);
  manutenção legítima de frota inteira a ≤50% DISPARARIA (o mesmo FP
  declarado do lab no MNT1 frota-inteira).

## B. Sigma (`sigma/*.yml`, 18 regras) × cenários

| Regra Sigma | NEG | H1 | H2 | H3 | H4 | H5 | NONCANON | MASS | SLOW | EMERG |
|---|---|---|---|---|---|---|---|---|---|---|
| D-AUTH-DEFAULT | não | SIM (1) | não | SIM (1) | não | não | não | não | não | não |
| D-AUTH-BROKER-TOKEN | não | não | SIM (7 auth_use) | não | não | não | não | não | não | não |
| D-BULK-WITHOUT-WORKORDER | não | SIM (1) | não | não | não | não | não | não | não | não |
| D-SETPOINT-OUT-OF-BAND | não | não | não | não | não | não | SIM (1) | não | não | não |
| D-BATTERY-DRAIN-BELOW-FLOOR | não | não | SIM (1) | não | não | SIM (1) | não | não | não | não |
| D-PF-PARAM-CHANGE-IN-STRESS | não | não | não | SIM (1) | não | não | não | não | não | não |
| D-GRID-EMERGENCY-REMOTE-BLOCK | não | não | não | não | não | não | não | não | não | SIM (5) |
| D-PROVENANCE-SPOOF-ATTEMPT | não | não | SIM (6) | não | não | não | não | não | não | não |
| D-FIRMWARE-REJECTED | não | não | não | não | SIM (12) | não | não | não | não | não |
| D-FIRMWARE-OUT-OF-WINDOW | não | não | não | não | SIM (12) | não | não | não | não | não |
| D-BATTERY-DRAIN-LARGE | não | não | NÃO (0 — nenhum param_change soc remoto; o 999 dá floor_block) | não | não | NÃO (0 — o 60% dá 409 daily, o 999 dá floor_block) | não | não | não | não |
| D-BATTERY-DRAIN-TO-LOW | não | não | NÃO (0) | não | não | NÃO (0) | não | não | não | não |
| D-INVALID-WORK-ORDER | não | não | não | não | não | não | SIM (1) | não | não | não |
| D-REMOTE-SHUTDOWN-NO-WO | não (WO presente) | SIM (12) | SIM (6) | não | não | não | não | NÃO (shutdowns COM WO — work_order não é NULL) | SIM (8) | não (interlock: sem evento shutdown) |
| D-CAPACITY-DIVERGENCE | não (div < 30) | SIM (≥1 snapshot ≥30) | SIM (≥1) | SIM (≥1) | não (STRESS: P(f) descontado, div ~0) | não | não | SIM (≥1) **FP DECLARADO** (sem arming — ver C) | SIM (≥1; o lab TAMBÉM dispara — shutdowns s/WO armam) | não (relay aberto → esperado 0 → div 0) |
| D-LOGIN-BRUTE-FORCE | não | não | não | não | não | não | SIM (1) | não | não | não |
| D-LOCAL-CONFIRM-BRUTE-FORCE | não | não | não | não | não | não | SIM (1) | não | não | não |
| D-NON-CANONICAL-REQUEST | não | não | não | não | não | não | SIM (5 diretos + 1 guard_reject non_canonical*) | não | não | não |

**NEG tem de dar ZERO alertas Sigma** — os únicos eventos "sensíveis" do
NEG são: login_ok daily_code (SEM regra M3 — ver C), shutdown COM WO
(work_order não é NULL), param_change export_limit COM WO (sem regra),
param_change soc remoto de descarga 2 kWh (new ~97,6 > 50), firmware_push
(sem regra), local_confirm_issued (sem regra), param_change soc
provenance **local_confirm** (excluído pela seleção), capacity_snapshot
com div < 30.

## C. Expressibilidade das 26 regras do detetor do lab

| Regra do lab | Suricata | Sigma | Porquê |
|---|---|---|---|
| D-AUTH-DEFAULT | SIM | SIM | credenciais default visíveis no body do POST /fleet/login; evento login_ok method=default_creds |
| D-AUTH-DAILY-CODE | — | EXPRESSÁVEL MAS EXCLUÍDA | login_ok method=daily_code é detectável em Sigma, mas o NEG autentica por código diário: incluí-la quebraria o requisito NEG=0. LACUNA DECLARADA — a visibilidade fica no WARN do detetor interno |
| D-AUTH-BROKER-TOKEN | SIM | SIM | token hard-coded no header Authorization; eventos login_ok/auth_use method=broker_token |
| D-BULK-WITHOUT-WORKORDER | SIM | SIM | resposta 403 com string própria; evento bulk_block_no_workorder |
| D-SETPOINT-OUT-OF-BAND | SIM | SIM | resposta 400 "fora da banda segura"; evento setpoint_rejected |
| D-BATTERY-DRAIN-BELOW-FLOOR | SIM | SIM | resposta 409 "min_emergency_soc_floor"; evento floor_block (+ legacy_bypass_floor do contrafactual) |
| D-PF-PARAM-CHANGE-IN-STRESS | SIM | SIM | o estado STRESS não é visível na rede, mas a RECUSA (409 pf_params_locked_in_stress) só ocorre nele; evento pf_param_change_blocked |
| D-GRID-EMERGENCY-REMOTE-BLOCK | SIM | SIM | resposta 409 grid_emergency_interlock; evento interlock_block |
| D-PROVENANCE-SPOOF-ATTEMPT | SIM | SIM | campos provenance/source/reason no body; evento próprio |
| D-FLEET-SHUTDOWN-WAVE | APROX | NÃO | threshold Suricata 6/60 s conta PEDIDOS por src, não dispositivos DISTINTOS na janela (8 shutdowns no mesmo inversor = onda falsa); correlação de janela não é expressível em Sigma |
| D-FIRMWARE-REJECTED | SIM | SIM | resposta 403 "assinatura invalida"; evento firmware_rejected reason=assinatura_invalida |
| D-BATTERY-DRAIN-LARGE | NÃO | APROX | SoC é estado interno (invisível na rede); Sigma não faz aritmética (old−new≥50) — aproximação por new ≤ 50 |
| D-BATTERY-CUMULATIVE-DRAIN | NÃO | NÃO | soma de fatias em janela deslizante por dispositivo — correlação temporal não expressível em nenhuma das duas |
| D-BATTERY-DRAIN-TO-LOW | NÃO | APROX | SoC resultante invisível na rede; Sigma: new ≤ 35 com provenance remote_command (drop>0 não verificável) |
| D-INVALID-WORK-ORDER | SIM | SIM | resposta 403 work_order_invalid; evento próprio |
| D-REMOTE-SHUTDOWN-NO-WO | SIM | SIM | pedido por-dispositivo s/WO (pcre com lookahead negativo); evento shutdown work_order IS NULL |
| D-MASS-SHUTDOWN-WITH-WO | APROX | NÃO | Suricata vê a RESPOSTA do bulk com ≥6 dispositivos no `devices` (massa executada), mas não vê kWp nem a união de canais por cenário; contagem/correlação não é expressível em Sigma |
| D-FLEET-CURTAILMENT-WAVE | APROX | NÃO | threshold 6/60 s sobre pedidos export_limit/setpoint; o VALOR (≤50%) não é verificado; correlação não expressível em Sigma |
| D-CAPACITY-DIVERGENCE | NÃO | APROX | divergência é física/estado (esperado vs real) — invisível na rede; Sigma: divergence_pct ≥ 30 SEM a condição de arming (correlação) → FP DECLARADO no MASS |
| D-SLOW-WAVE | APROX | NÃO | threshold 8/3600 s conta pedidos por src, não distintos; correlação não expressível em Sigma |
| D-FIRMWARE-OUT-OF-WINDOW | SIM | SIM | resposta 400 firmware_window; evento firmware_rejected reason=fora_da_janela |
| D-LOGIN-BRUTE-FORCE | SIM | SIM | resposta 429 login_rate_blocked; evento próprio (o lockout É o limiar) |
| D-LOCAL-CONFIRM-BRUTE-FORCE | SIM | SIM | 5× resposta 403 "pin invalido" com threshold 5/600 s; evento local_confirm_lockout |
| D-NON-CANONICAL-REQUEST | SIM | SIM | linha de pedido crua (//, %, ?, #, dot-segment, não-ASCII) na rede; eventos non_canonical_request + guard_reject non_canonical* |
| D-MASS-CURTAILMENT | APROX | NÃO | threshold 6/3600 s; valor ≤25% e kWp não verificados; correlação não expressível em Sigma |
| D-BATTERY-PARKED-DRAIN | NÃO | NÃO | acumulador com défice líquido e rearme por episódio — estado interno por (cenário, dispositivo), invisível na rede e não expressível em Sigma |

## D. Previsão INFORMATIVA do detetor INTERNO do lab por cenário

(não é alvo do run M3; serve de comparação — o detetor interno lê o audit,
não a rede)

| Cenário | Alertas internos esperados |
|---|---|
| NEG | D-AUTH-DAILY-CODE ×1 (WARN; é o porquê de a regra ficar EXCLUÍDA do M3) — ZERO CRIT |
| H1 | D-AUTH-DEFAULT, D-BULK-WITHOUT-WORKORDER, D-REMOTE-SHUTDOWN-NO-WO ×12, D-FLEET-SHUTDOWN-WAVE, D-SLOW-WAVE, D-MASS-SHUTDOWN-WITH-WO, D-CAPACITY-DIVERGENCE |
| H2 | D-AUTH-BROKER-TOKEN ×7, D-PROVENANCE-SPOOF-ATTEMPT ×6, D-REMOTE-SHUTDOWN-NO-WO ×6, D-FLEET-SHUTDOWN-WAVE, D-MASS-SHUTDOWN-WITH-WO, D-BATTERY-DRAIN-BELOW-FLOOR, D-CAPACITY-DIVERGENCE |
| H3 | D-AUTH-DEFAULT, D-FLEET-CURTAILMENT-WAVE, D-MASS-CURTAILMENT, D-CAPACITY-DIVERGENCE, D-PF-PARAM-CHANGE-IN-STRESS |
| H4 | D-FIRMWARE-OUT-OF-WINDOW ×12, D-FIRMWARE-REJECTED ×12 |
| H5 | D-BATTERY-DRAIN-BELOW-FLOOR ×1 (o drain 60% dá 409 daily — sem DRAIN-LARGE) |
| NONCANON | D-LOGIN-BRUTE-FORCE, D-LOCAL-CONFIRM-BRUTE-FORCE, D-NON-CANONICAL-REQUEST ×6, D-INVALID-WORK-ORDER, D-SETPOINT-OUT-OF-BAND |
| MASS | D-MASS-SHUTDOWN-WITH-WO (12 distintos ≥ k E 100% kWp) — capacity NÃO dispara (shutdowns COM WO não armam) |
| SLOW | D-REMOTE-SHUTDOWN-NO-WO ×8, D-SLOW-WAVE (8 distintos em 3600 s), D-CAPACITY-DIVERGENCE (arming por shutdown s/WO) — onda rápida NÃO (pacing 65 s) |
| EMERG | D-GRID-EMERGENCY-REMOTE-BLOCK ×5 |

## Pontos a validar

- `suricata -T` NÃO foi corrido neste ambiente (sem binário Suricata
  disponível): a sintaxe foi escrita para Suricata 7.0.3/8.0.8 (regras
  tcp + flow + content/pcre + threshold, sem keywords que exijam config
  de portas HTTP — matching sobre o stream TCP reassemblado). O run 1
  oficial valida o carregamento; se uma regra não carregar, o run 1
  preserva-se e a correção é errata datada.
- Contagens previstas assumem 1 alerta por pedido/resposta (fluxo novo
  por pedido no lab) e que o Suricata não fragmenta os bodies
  (Content-Length < MTU na maioria; o image_b64 do firmware ~100 B).
- O pcre do D-MASS-SHUTDOWN-WITH-WO depende da ordem de serialização do
  json.dumps do lab (`devices` em ordem de inserção dev0..dev11) —
  a confirmar no run 1 (o bulk MNT1 do MASS e o MNT3 do NEG discriminam
  os dois casos).
- O threshold `track by_src` conta por HOST (o lab tem um só cliente
  127.0.0.1): equivalente a por-operador AQUI; não transfere para
  topologia real multi-cliente.
- Mapeamento ATT&CK no metadata/references é PROVISÓRIO (reconfirmado no
  M5): T0819/T1078 (creds), T0816 (device restart/shutdown), T0879
  (modify parameter), T0814 (system firmware), T1485 (data destruction),
  T1110 (brute force), T1693.001/.002 (âncoras do caso).
- D-AUTH-DAILY-CODE: lacuna DECLARADA do M3 (ver C) — o requisito NEG=0
  força a exclusão; decisão do supervisor em M5 se abre exceção com
  allowlist de janelas de manutenção.

## Errata E-M3-1 (14-11, datada, ~16:45)

Run 1 oficial do supervisor (14-11 ~16:00) PRESERVADO: `suricata -T` falhou
em 7.0.3 e 8.0.8 — 11 regras não carregaram (9100003, 9100007, 9100010,
9100013-9100020): todas as regras servidor→cliente tinham `-> any (`
sem a PORTA de destino (sintaxe de regra incompleta — cabeçalho exige
`src -> dst porta`).

Correção: criado `sunstrike_m3_v0.1.1.rules` = cópia de
`sunstrike_m3.rules` com UMA só mudança nessas 11 linhas:
`-> any (` passa a `-> any any (`. Mais NADA: nem lógica, nem conteúdos
(contents/pcre), nem thresholds, nem sids, nem revs — verificado por
diff (11 pares de linhas, só o cabeçalho de porta). O ficheiro original
`sunstrike_m3.rules` NÃO se altera nem se apaga (run 1 preservado).

As PREVISÕES NÃO MUDAM: a porta de destino `any` não altera o
comportamento pretendido (o lab só fala com o cliente loopback; as
regras já restringiam por `flow:established,to_client` e por conteúdo).
A tabela A continua a valer para o v0.1.1 nos mesmos termos.
