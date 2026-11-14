# M3 — RUN 2 COMPLEMENTAR (supervisor, 14-11 ~16:50) — regras v0.1.1 (errata E-M3-1, commit 65b6560)

- Diff verificado: só as 11 linhas servidor→cliente, `-> any (` → `-> any any (`; original intacto.
- Suricata 7.0.3: `suricata -T` PASS (0 regras falham).
- Das 11 regras agora carregadas, 10 batem com as previsões (9100003, 9100007, 9100010×2, 9100014–9100020).
- 9100013 (D-LOGIN-BRUTE-FORCE) dá 0 (previsto 1): a string `login_rate_blocked` nunca aparece na rede no cenário NONCANON — o lockout fica registado no audit (o Sigma apanha-o), mas o cenário não faz um pedido depois do lockout, por isso não há resposta 429 para ver. Erro de previsão (análise).
- As 7 células de contagem do run 1 mantêm-se (salto duplo cliente→gate→inversor).
- **9100005 no SLOW é instável**: o mesmo motor, pcap e regras dão 0 ou 1 entre corridas (6 corridas: 1×0, 5×1). A diferença 7.0.3 (1) vs 8.0.8 (2) do run 1 deve ler-se como instabilidade do limiar, não como diferença de versão.
- O run 1 continua a ser o OFICIAL.
