# M3 — RUN 1 OFICIAL (supervisor) — resultados

## Suricata (This is Suricata version 7.0.3 RELEASE)

- `suricata -T`: FAIL; regras que NÃO carregam: 11 → 9100003, 9100007, 9100010, 9100013, 9100014, 9100015, 9100016, 9100017, 9100018, 9100019, 9100020

| sid | NEG | H1 | H2 | H3 | H4 | H5 | NONCANON | MASS | SLOW | EMERG |
|---|---|---|---|---|---|---|---|---|---|---|
| 9100001 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100002 | 0 | 0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100003 (não carrega) | 0 | 0 ✗ | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100004 | 0 | 24 ✗ | 6 | 0 | 0 | 0 | 0 | 0 | 16 ✗ | 1 |
| 9100005 | 0 | 4 ✗ | 1 | 0 | 0 | 0 | 0 | 0 | 1 ✗ | 0 |
| 9100006 | 0 | 3 ✗ | 0 | 0 | 0 | 0 | 0 | 0 | 2 ✗ | 0 |
| 9100007 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 |
| 9100008 | 0 | 0 | 0 | 4 ✗ | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100009 | 0 | 0 | 0 | 4 ✗ | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100010 (não carrega) | 0 | 0 | 0 ✗ | 0 | 0 | 0 ✗ | 0 | 0 | 0 | 0 |
| 9100011 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100012 | 0 | 0 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 |
| 9100013 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 |
| 9100014 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 |
| 9100015 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 |
| 9100016 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 |
| 9100017 (não carrega) | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 | 0 | 0 | 0 |
| 9100018 (não carrega) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 ✗ |
| 9100019 (não carrega) | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 | 0 | 0 |
| 9100020 (não carrega) | 0 | 0 | 0 | 0 | 0 ✗ | 0 | 0 | 0 | 0 | 0 |

Suricata: 180/200 células certas; 20 erradas.

## Sigma (pySigma + backend SQLite; tabela `logs` com todas as linhas *.jsonl da evidência do cenário)

| regra | NEG | H1 | H2 | H3 | H4 | H5 | NONCANON | MASS | SLOW | EMERG |
|---|---|---|---|---|---|---|---|---|---|---|
| D-AUTH-DEFAULT | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-AUTH-BROKER-TOKEN | 0 | 0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-BULK-WITHOUT-WORKORDER | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-SETPOINT-OUT-OF-BAND | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| D-BATTERY-DRAIN-BELOW-FLOOR | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| D-PF-PARAM-CHANGE-IN-STRESS | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-GRID-EMERGENCY-REMOTE-BLOCK | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 |
| D-PROVENANCE-SPOOF-ATTEMPT | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-FIRMWARE-REJECTED | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| D-FIRMWARE-OUT-OF-WINDOW | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| D-BATTERY-DRAIN-LARGE | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-BATTERY-DRAIN-TO-LOW | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D-INVALID-WORK-ORDER | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| D-REMOTE-SHUTDOWN-NO-WO | 0 | 12 | 6 | 0 | 0 | 0 | 0 | 0 | 8 | 0 |
| D-CAPACITY-DIVERGENCE | 0 | 9 | 4 | 10 | 0 | 0 | 0 | 9 | 5 | 0 |
| D-LOGIN-BRUTE-FORCE | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| D-LOCAL-CONFIRM-BRUTE-FORCE | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| D-NON-CANONICAL-REQUEST | 0 | 0 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 |

Sigma: 180/180 células certas; 0 erradas.

## NEG (tem de ser zero)
- Suricata: {}
- Sigma: {}

## Previsões erradas (20)
- Suricata 9100003 H1: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100004 H1: previsto «SIM ×12», observado 24
- Suricata 9100004 SLOW: previsto «SIM ×8», observado 16
- Suricata 9100005 H1: previsto «SIM ×1», observado 4
- Suricata 9100005 SLOW: previsto «NÃO (pacing 65 s > 60 s)», observado 1
- Suricata 9100006 H1: previsto «SIM ×1», observado 3
- Suricata 9100006 SLOW: previsto «SIM ×1», observado 2
- Suricata 9100007 MASS: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100008 H3: previsto «SIM ×1», observado 4
- Suricata 9100009 H3: previsto «SIM ×1 (duplo alerta declarado, como no lab)», observado 4
- Suricata 9100010 H2: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100010 H5: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100013 NONCANON: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100014 NONCANON: previsto «SIM ×1 (no 5.º)», observado 0 (não carregou)
- Suricata 9100015 NONCANON: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100016 NONCANON: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100017 H3: previsto «SIM ×1», observado 0 (não carregou)
- Suricata 9100018 EMERG: previsto «SIM ×5», observado 0 (não carregou)
- Suricata 9100019 H4: previsto «SIM ×12», observado 0 (não carregou)
- Suricata 9100020 H4: previsto «SIM ×12», observado 0 (não carregou)

## Hashes dos pcaps de referência
- NEG.pcap `6e97a1427849f91c78b93efaa910fe59c43d167527eebbd685550ed9572a2a2e`
- H1.pcap `8dff7493399a82d4ab28f6969ba5168ef18dd9391e60a7098a666b7cd50dc18b`
- H2.pcap `a86e3bb9353b9ea0951642aec12fbbc32ea5aa04e49d9131708991fad6dc2c60`
- H3.pcap `a246138a7cea0b9c89c93b595d7306d0784a80e434c78807fc55249e941e6b96`
- H4.pcap `acab7d1788d525504b07bf1e6ea46362036bd760615828e650594ebf153036f6`
- H5.pcap `4866db8cb622fb797bd8962d1092f0e64bbea53606aae519313e75a12460f607`
- NONCANON.pcap `3e6b6921df4fa35866d925843bea81185187fae9fccdcba88cb672e52ba36f88`
- MASS.pcap `193c140ebedad54fb9bfd50539084e821307b31481425f0c41b58b4f78bb839e`
- SLOW.pcap `25810fd645f1d5526970f5cc70a81aa9bb450170ce404f90b977822e1ece9be4`
- EMERG.pcap `d6fde828b586aa10e1e7182c68231fce33668f9ea9e955257ae56b6e4b1a7a11`