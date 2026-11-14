# README M3 — SUNSTRIKE — deteção externa (Suricata + Sigma)

Entrega M3 (supervisor, 14-11-2026). Lab v0.7.5 CONGELADO (sha256
`5162964f2df283fd6ed0a1a4d53f8b3650f491b4892e24abb198494b7abcb441`) —
o M3 só acrescenta ficheiros novos dentro de `m3/`; nada do lab foi
alterado. Previsões fixadas em `M3_PREVISOES.md` ANTES de qualquer
corrida; o run oficial é o run 1 do supervisor.

## Ficheiros

| Ficheiro | Conteúdo |
|---|---|
| `m3_cenarios.py` | gerador de cenários — UM por invocação, `Lab(evidence=True)`, importa o lab da mesma pasta (fallback `../v0.7.5/`), recusa qualquer hash que não o da v0.7.5 selada |
| `m3_captura.sh` | wrapper tcpdump à volta de um cenário: `sh m3_captura.sh <iface> <cenario>` (Linux `lo`, macOS `lo0`) |
| `sunstrike_m3.rules` | 20 regras Suricata, sid 9100001-9100020, msg com o ID da regra do lab |
| `sigma/*.yml` | 18 regras Sigma (pySigma 2.x, `logsource: product: sunstrike, service: audit`) |
| `M3_PREVISOES.md` | previsões regra × cenário (fixadas antes do run 1) + expressibilidade das 26 regras do lab |
| `README_M3.md` | este ficheiro |

## Como correr

O lab (`sunstrike_lab.py` v0.7.5) tem de estar na mesma pasta que
`m3_cenarios.py` (ou em `../v0.7.5/` — o script aceita ambos e valida o
hash).

Gerar um cenário com captura (Linux):

```sh
cd m3
sh m3_captura.sh lo H1
```

macOS:

```sh
sh m3_captura.sh lo0 H1
```

Cenários: `NEG H1 H2 H3 H4 H5 NONCANON MASS SLOW EMERG`.
Cada cenário escreve a sua pasta `sunstrike_evidence/<run>/`
(audit_dev_00..11.jsonl, audit_gate.jsonl, grid_events.jsonl,
audit_guard.jsonl quando o guard é usado) e imprime os alertas do detetor
INTERNO do lab (informativo). O cenário SLOW demora ~9 minutos (pacing
real de 65 s entre shutdowns — é isso que o faz ser lento também no pcap).

Validação de sintaxe (antes do run):

```sh
suricata -T -S sunstrike_m3.rules
sigma check sigma/*.yml
```

Sigma → SQL (backend SQLite; o supervisor corre-o sobre a tabela
`events` com as chaves de topo de cada linha JSONL como colunas):

```sh
sigma convert --target sqlite sigma/sunstrike_auth_default.yml
```

Correr o Suricata sobre um pcap:

```sh
suricata -r H1.pcap -S sunstrike_m3.rules -l /tmp/sunstrike_m3_out
```

## O que cada regra deteta

### Suricata (vista de rede, loopback 8609/8610/8611-8622)

- **9100001 D-AUTH-DEFAULT** — `POST /fleet/login` com a senha default no body.
- **9100002 D-AUTH-BROKER-TOKEN** — header `Authorization: Bearer SUNBRIDGE-BKR-2026-001`.
- **9100003 D-BULK-WITHOUT-WORKORDER** — resposta 403 do bulk sem work-order.
- **9100004 D-REMOTE-SHUTDOWN-NO-WO** — pedido de shutdown por-dispositivo
  (via gate) ou `/mode inverter_power_off` SEM work_order no body.
- **9100005 D-FLEET-SHUTDOWN-WAVE** — o mesmo visto ≥6× em 60 s (threshold).
- **9100006 D-SLOW-WAVE** — o mesmo visto ≥8× em 3600 s (threshold).
- **9100007 D-MASS-SHUTDOWN-WITH-WO** — resposta do bulk_shutdown com
  ≥6 dispositivos no `devices` (massa executada, COM ou SEM WO).
- **9100008 D-FLEET-CURTAILMENT-WAVE** — pedidos export_limit/setpoint
  ≥6× em 60 s (valor não verificado).
- **9100009 D-MASS-CURTAILMENT** — idem, ≥6× em 3600 s.
- **9100010 D-BATTERY-DRAIN-BELOW-FLOOR** — resposta 409 do floor.
- **9100011 D-PROVENANCE-SPOOF-ATTEMPT** — campos provenance/source/reason num body.
- **9100012 D-NON-CANONICAL-REQUEST** — linha de pedido com `//`, `%`,
  `?`, `#`, dot-segment ou byte não-ASCII.
- **9100013 D-LOGIN-BRUTE-FORCE** — resposta 429 login_rate_blocked (lockout).
- **9100014 D-LOCAL-CONFIRM-BRUTE-FORCE** — 5× resposta "pin invalido" em 600 s.
- **9100015 D-INVALID-WORK-ORDER** — resposta 403 work_order_invalid.
- **9100016 D-SETPOINT-OUT-OF-BAND** — resposta 400 fora da banda.
- **9100017 D-PF-PARAM-CHANGE-IN-STRESS** — resposta 409 pf_params_locked.
- **9100018 D-GRID-EMERGENCY-REMOTE-BLOCK** — resposta 409 do interlock.
- **9100019 D-FIRMWARE-OUT-OF-WINDOW** — resposta 400 firmware_window.
- **9100020 D-FIRMWARE-REJECTED** — resposta 403 assinatura invalida.

### Sigma (vista de audit, JSONL → tabela `events`)

Cada regra seleciona eventos pelos campos EXATOS dos JSONL (`event`,
`method`, `reason`, `param`, `provenance`, `work_order`, `new`,
`divergence_pct`). Ver cabeçalho de cada `.yml`. As duas regras com
modificadores de comparação (`new|lte`, `divergence_pct|gte`) e a
comparação com `null` (`work_order IS NULL`) foram validadas com o
backend SQLite do pySigma 2.1.

## Limites (declarados, sem suavização)

- **Regras de estado NÃO existem**: massa por kWp, bateria estacionada
  (acumulador com rearme), drain cumulativo em janela e divergência de
  capacidade FÍSICA dependem de estado interno que a rede não vê —
  expressibilidade completa em `M3_PREVISOES.md` §C.
- **Thresholds Suricata contam por src** (o lab tem um cliente só):
  a onda conta PEDIDOS, não dispositivos DISTINTOS — 8 shutdowns ao mesmo
  inversor fabricam uma onda na rede que o lab não daria.
- **Regras request-based vêem a tentativa, não a execução** (9100004 dispara
  em EMERG onde o interlock recusa — FP previsto); regras response-based
  vêem a recusa do lab (mais fiéis, mas cegas se o atacante controlar a
  resposta).
- **D-AUTH-DAILY-CODE fica EXCLUÍDA do M3**: o NEG autentica por código
  diário; incluí-la quebraria o requisito NEG=0. Lacuna declarada.
- **D-CAPACITY-DIVERGENCE em Sigma é aproximação sem arming**: dispara no
  MASS (shutdowns COM WO) onde o lab NÃO dispara — FP previsto.
- **9100007 depende da serialização do json.dumps do lab** (ordem
  dev0..dev11 no `devices`); se mudar, errata datada.
- `suricata -T` não foi corrido neste ambiente (sem binário): validação
  de carregamento no run 1; errata datada se falhar.
- Mapeamento ATT&CK (metadata/references) é provisório — reconfirmado no M5.
- Nada aqui transfere para equipamento real: o lab é sintético, 100%
  loopback, N=12, k e janelas calibrados no sintético.
