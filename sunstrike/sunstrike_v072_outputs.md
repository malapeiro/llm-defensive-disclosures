# SUNSTRIKE — v0.7.2 — MANIFESTO DE ENTREGA §6 (ronda 8: C15 + F-C15a + F-C15b)

Grant: GRANT-PVTE-20261112-SS-01 · Caso: SUNSTRIKE (solar) · Protocolo: PVTE v5.0
Operador: Sérgio Azevedo (root) · Supervisor: Claude · Auditor: Gemini · BUILDER: GLM 5.3 (Vibe/Mistral)
Data: 13-11-2026 (hora de Lisboa) · GO à v0.7.2: operador 13-11 ~19:30, via supervisor
Regra: entrega §6 e PARAR. NADA da v0.8 nem M3 sem GO.

---

## 1. Índice de ficheiros (hashes 1.ª declaração)

### 1.1 Lab

| ficheiro | versão | sha256 (1.ª) | linhas |
|---|---|---|---|
| sunstrike_lab.py | v0.7.2 (F-C15a + F-C15b) | 1c433df138b90ba8fc7ce8afe28c4298b30206cda00ac38c6e717fd7b40afbd4 | 5930 |
| sunstrike_lab.py.b64 | — | ce45de41c89b6f5ea9de46395eacc268780b4317c0513e03b60b833bdcec3f26 | — |
| sunstrike_lab_v071.py | v0.7.1 PRESERVADA (convenção E10: nome versionado ANTES de o nome genérico receber a versão nova) | 72c894fe579dfc335f9b072995e472d2de943e0bd51fc657a7e7ff0af23d00f7 | 5379 |
| sunstrike_lab_v071.py.b64 | — | 208bdb155b4a727234a685919dd0201fc9918372a8eb84327a7c1b2bf57d3de1 | — |

NOTA (v0.7.1 preservada): o .b64 re-codificado deu hash **208bdb155b…** BYTE-IDÊNTICO ao
declarado no manifesto v0.7.1 §1.1 — prova de preservação byte-exata. O EOF interno diz
`# EOF:sunstrike_lab.py` (nome ORIGINAL do ficheiro da v0.7.1): MANTIDO deliberadamente
para preservar o hash (precedente E10).

### 1.2 Probes (todos multi-target por hash EXATO; SystemExit(2) se o alvo não for reconhecido)

| ficheiro | versão do probe | sha256 (1.ª) | linhas |
|---|---|---|---|
| sunstrike_probes_r8.py | v0.3 (dual V071/V072; errata de rotulagem datada — E-R8-4) | 6313b47a71e7344e39f4cc62b17a80736fd197dc29f161d1a4ea487f447eaec2 | 1134 |
| sunstrike_probes_r8_v011_backup.py | v0.1.1 (alvo V071; o probe DO RUN 1-BIS oficial, PRESERVADO) | a3b4a82af292817c632b3c9397161dabdec34a5898e3023fb1b09f2ecbb885a6 | 715 |
| sunstrike_probes_r7_v071.py | v0.4 (tri V07/V071/V072) | 32b2eec182ca9b91da893c57bebd36beb6dfd29451330802829bdb5070cb980f | 1259 |
| sunstrike_probes_r6.py | v0.5 (quad V06/V07/V071/V072) | a134b5a1f43813cf5425ddbbfe14f9af207bafee316ba0850e3be4037c838b13 | 1189 |
| sunstrike_probes_r5.py | v0.5.2 (penta V05/V06/V07/V071/V072) | 5e6cac19287f16b84b108e250c3a4f638cef8dfd9aa64f0ebfcba5ce9e94a43f | 1136 |
| sunstrike_probes_r4.py | v0.6 (hexa V04/V05/V06/V07/V071/V072) | a336fdfee1737af2997c64ba2b20518ee968cb1b8a23c69c51747f5a61908432 | 1170 |
| sunstrike_probes_r3.py | v0.6 (hepta V03..V072) | 46c8dd23d248385f438fdf4bcb30880b92141e0b834bcf01b701a322f89b954e | 1066 |
| sunstrike_probes_r2.py | v0.9.1 (octa V02..V072; errata de ramo datada) | 4f0b1618202240f97458c0fee450da6a47c6eea7d510a33d88dd58a432969689 | 1298 |

.b64 de cada probe: r8 f02ca351… · r8_v011 043a2533… · r7_v071 9e504166… · r6 7a1f782f… ·
r5 311a0941… · r4 e11ba4c8… · r3 f48d3213… · r2 3ca28b93… (round-trip `cmp` byte-exato 10/10 OK).

### 1.3 Outputs oficiais da v0.7.2

| ficheiro | conteúdo | sha256 (1.ª) |
|---|---|---|
| sunstrike_v072_selftest_output.txt | selftest PASS, liveness 24/24, 39 testes (31 herdados + 8 novos v0.7.2) | fa9aad40183b420879e9f2d6a22fdc8e0dd123a96d687e8a548105284fdfd464 |
| sunstrike_v072_demo_output.txt | demo PASS 9/9 (H1 CRIT=28, H2 CRIT=18, NEG CRIT=0 — contagens INALTERADAS) | ea2143b759144dac1908c94c162e477387a529e41cf400681401fa5cd9c99048 |
| sunstrike_v072_measure_output.txt | measure PASS 51/51 (linhas das corridas idênticas às da v0.7.1) | 2fff5b0de8f3e95dd5a48cf7c2f3a65f4e75da178ee2688186710b4d69a478c8 |
| sunstrike_probes_v071_r8_run1_errata_harness.txt | cópia PRESERVADA do run 1 (errata de harness E-R8-1) | 1f4fa8ec4bea12df4ae1d5bf7e81d4ba551c462c6951b2603d9f242edff410d4 |
| sunstrike_probes_v071_r8_run1.txt | **R8 RUN 1 = GATEFALL OFICIAL** vs v0.7.1 INTOCADA: 9/11 (P-R8-02 errada por defeito de construção do probe; P-R8-04 errada genuína — AMBAS REGISTADAS), RC=1 honesto | 1f4fa8ec4bea12df4ae1d5bf7e81d4ba551c462c6951b2603d9f242edff410d4 |
| sunstrike_probes_v071_r8_run1b.txt | R8 RUN 1B (probe v0.1.1, ordem do P-R8-02 corrigida): 10/11 — PRESERVADO E CITADO, **NÃO oficial** (E-R8-4) | 1c7d1aac5407dce4aa246adbc584b94be5d340d847d610d280f859aa2ed003eb |
| sunstrike_probes_v072_r8_run2.txt | **R8 RUN 2 vs v0.7.2** (probe v0.3): 11/11 (9 RESOLVIDO + 2 DECLARADO), 0 erradas, RC=0 | dda185d15e57a5a165c6cf404feadd5a44fdcce60929690a118aaa62184a7929 |
| sunstrike_probes_v071_r8_recheck.txt | re-check (probe v0.3) vs v0.7.1 INTOCADA: 10/11 — GATEFALL reproduzido | 0f5a90941d7158c190824ec85f6460a6cf8bc1f53bdb2ebd893d7246cceb8255 |
| sunstrike_probes_v072_r8_run2_errata_rotulagem.txt | run 2 produzido pelo probe v0.2 (rótulos antigos) — PRESERVADO como errata de rotulagem (E-R8-4); números idênticos | 0cc43702e7f2eec89df3c641ec20e7dee94a21edfd0fdb4755d31c219da9aafd |
| sunstrike_probes_v071_r8_recheck_errata_rotulagem.txt | re-check produzido pelo probe v0.2 (rótulos antigos) — PRESERVADO (E-R8-4); números idênticos | 8f0a16ceb3bcb5dc3495ecc58bc61f2f1661f302529673a7263a45bffc6af30a |
| sunstrike_probes_v072_r2_output.txt | R2 vs v0.7.2 (não-regressão): 7/7 + 3/3 CONFIRMADO-DECLARADO, 0 erradas, RC=0 | 772495f24cf7e4c9d6fe7667acc027332f259f9099624d815a2b5775071be12f |
| sunstrike_probes_v072_r2_run1_errata_ramo.txt | R2 run 1 (PRESERVADO como errata de ramo do probe: 6/7+3/3, física CORRETA) | 1b15abbaf9417420f8e7535322749a119f806c43efcdc8fea2fb097de9913e1b |
| sunstrike_probes_v072_r3_output.txt | R3 vs v0.7.2: 6/6, 0 erradas, RC=0 | 6600156662f9ba0fc870379ae0b2208e43099db5e77de39e98a251b0b45afe2b |
| sunstrike_probes_v072_r4_output.txt | R4 vs v0.7.2: 6/6, 0 erradas, RC=0 | 637c81315c7741ce7ff7d3af3c60923fb12fc76b238b814fdbcc2432581338c4 |
| sunstrike_probes_v072_r5_output.txt | R5 vs v0.7.2: 6/6, 0 erradas, RC=0 | 716ca72304fbb7a55e6213af0ec32762ded0cf7d10e878f4afb1ead8cae874d7 |
| sunstrike_probes_v072_r6_output.txt | R6 vs v0.7.2: 7/7 (P-R6-07 RESOLVIDO-DECLARADO pré-registado), 0 erradas, RC=0 | 7871656a96c02b84c561698faa8af203189b86039bf6e78bba4089ccdcb48041 |
| sunstrike_probes_v072_r7_output.txt | R7 vs v0.7.2: 8/8 RESOLVIDO, 0 erradas, RC=0 | 046778357c140aead4b35c85a46438254df7339fbadcdf9eba7e9b537eabc7fd |

---

## 2. Verificação (hashes 2.ª declaração + comandos duais)

Cada hash abaixo é a 2.ª declaração, idêntica à 1.ª (§1). Verificar com:

```bash
# Linux
sha256sum sunstrike_lab.py sunstrike_lab_v071.py sunstrike_probes_r8.py \
  sunstrike_probes_r7_v071.py sunstrike_probes_r6.py sunstrike_probes_r5.py \
  sunstrike_probes_r4.py sunstrike_probes_r3.py sunstrike_probes_r2.py
# macOS
shasum -a 256 sunstrike_lab.py sunstrike_lab_v071.py sunstrike_probes_r8.py \
  sunstrike_probes_r7_v071.py sunstrike_probes_r6.py sunstrike_probes_r5.py \
  sunstrike_probes_r4.py sunstrike_probes_r3.py sunstrike_probes_r2.py
```

- sunstrike_lab.py 1c433df138b90ba8fc7ce8afe28c4298b30206cda00ac38c6e717fd7b40afbd4
- sunstrike_lab_v071.py 72c894fe579dfc335f9b072995e472d2de943e0bd51fc657a7e7ff0af23d00f7
- sunstrike_probes_r8.py 6313b47a71e7344e39f4cc62b17a80736fd197dc29f161d1a4ea487f447eaec2
- sunstrike_probes_r7_v071.py 32b2eec182ca9b91da893c57bebd36beb6dfd29451330802829bdb5070cb980f
- sunstrike_probes_r6.py a134b5a1f43813cf5425ddbbfe14f9af207bafee316ba0850e3be4037c838b13
- sunstrike_probes_r5.py 5e6cac19287f16b84b108e250c3a4f638cef8dfd9aa64f0ebfcba5ce9e94a43f
- sunstrike_probes_r4.py a336fdfee1737af2997c64ba2b20518ee968cb1b8a23c69c51747f5a61908432
- sunstrike_probes_r3.py 46c8dd23d248385f438fdf4bcb30880b92141e0b834bcf01b701a322f89b954e
- sunstrike_probes_r2.py 4f0b1618202240f97458c0fee450da6a47c6eea7d510a33d88dd58a432969689

Round-trip b64 (verificado neste turno, `cmp` byte-exato, 10/10 OK — lab, v071, r8, r8_v011, r7, r6, r5, r4, r3, r2):

```bash
for f in sunstrike_lab.py sunstrike_lab_v071.py sunstrike_probes_r8.py \
         sunstrike_probes_r8_v011_backup.py sunstrike_probes_r7_v071.py \
         sunstrike_probes_r6.py sunstrike_probes_r5.py sunstrike_probes_r4.py \
         sunstrike_probes_r3.py sunstrike_probes_r2.py; do
  base64 -d "$f.b64" | cmp - "$f" && echo "RT-OK $f"   # Linux
  # macOS: base64 -D -i "$f.b64" | cmp - "$f"
done
```

EOF: todos os .py desta entrega terminam com `# EOF:<filename>` EXATO, EXCETO (1)
sunstrike_lab_v071.py, que MANTÉM `# EOF:sunstrike_lab.py` para preservar o hash
byte-exato da v0.7.1 (precedente E10), e (2) sunstrike_probes_r8_v011_backup.py, que
mantém `# EOF:sunstrike_probes_r8.py` porque é a CÓPIA PRESERVADA do probe v0.1.1
(exatamente o ficheiro que correu o RUN 1-BIS oficial; hash a3b4a82a… declarado).

---

## 3. Fixes da v0.7.2 (GO vinculativo: probes ANTES, fixes DEPOIS)

- **F-C15a (C15, GRAVE) — WO COM ÂMBITO (uma só fonte)**: WORK_ORDERS passa a
  dicionário com metadados por WO: `devices` (âmbito), `window_s` (janela de validade
  em sim_ts ancorada a WORK_ORDER_EPOCH — fixado na criação do Lab, determinístico e
  reproduzível em qualquer data real), `max_uses` (contador TOTAL com lock). Validação
  ÚNICA `work_order_check(WORK_ORDERS, wo, dev_idx, consume)` — o DISPOSITIVO
  (remote_inverter_power_off E remote_setpoint) e o GATE (check_work_order) chamam a
  MESMA função passando WORK_ORDERS literalmente (uma fonte só, como no F-C13). Fora
  do âmbito / expirada / esgotada / desconhecida → **403 + evento work_order_invalid
  com campo "reason" + D-INVALID-WORK-ORDER (WARN)**; o comando NÃO executa. O gate
  bulk conhece o âmbito (mesma fonte) e despacha SÓ aos in-scope (bulk_scope_skip
  auditado por dispositivo fora do âmbito). Contador limpo em harness_reset (por
  cenário, idempotente). WOs: MNT1 frota inteira/12 usos/30 dias; MNT2 {0,1,2}/3 usos/
  7 dias; MNT3 NOVA {0,2}/4 usos/30 dias (NEG do demo — errata datada E4).
- **F-C15b (C15) — DETEÇÃO QUE NÃO CONFIA NA WO À ESCALA DA FROTA**: regra NOVA
  **D-MASS-SHUTDOWN-WITH-WO (CRIT, DIA E NOITE)** — JUSTIFICAÇÃO da severidade e do
  dia/noite: a regra lê EVENTOS de comando (sem cegueira física noturna como a
  capacity) e o impacto é PIOR à noite; baixar a severidade noturna enfraqueceria
  exatamente quando o dano é maior. Dispara POR CENÁRIO quando shutdowns remotos COM
  WO válida atingem **dispositivos distintos ≥ k (WAVE_K=6) OU perda de capacidade
  Σkwp ≥ 30%** (CAPACITY_DIVERGENCE_PCT — a mesma noção de perda que importa; o top-5
  58,22% apanha com 5 < k). SEM janela temporal: a janela da PRÓPRIA WO (F-C15a) é o
  artefacto de tempo; a contagem de dispositivos DISTINTOS por cenário fecha o pacing
  (lição C14). Conta APENAS shutdowns COM WO válida (carimbo "wo_valid" no evento,
  aditivo — os s/WO já têm a D-FLEET-SHUTDOWN-WAVE CRIT; sem duplo alerta → contagens
  H1/H2 do demo INALTERADAS 28/18). ANÁLISE DE FP (GO): manutenção legítima de POUCOS
  dispositivos com WO de âmbito correto → 0 alertas (MNT3 {0,2}: 2 < k, 22,9% < 30 —
  medido no R8 P-R8-09 e no selftest); manutenção legítima da FROTA INTEIRA → o
  alerta DISPARA e fica DECLARADO aceitável (GO); RESÍDUO MEDIDO E DECLARADO: atacante
  que desliga < k dispositivos com < 30% de capacidade com WO válida de âmbito correto
  ESCAPA (R8 P-R8-03: 1 dispositivo reusado 3×, 11,8%; R8 P-R8-10: 5 menores, 25,68%).
- Banner: SUNBOX/0.7.2 (device) e SUNGUARD/0.7.2 (guard). Liveness: 24/24 (23 +
  D-MASS-SHUTDOWN-WITH-WO; +6 shutdowns COM MNT1 no tráfego real do liveness).

## 4. Erratas datadas (TODAS registadas; NENHUMA silenciosa)

- **E-R8-1 · DEFEITO DE CONSTRUÇÃO do run 1 do R8** (13-11, probe v0.1, output
  1f4fa8ec… PRESERVADO): o cenário P-R8-02 pôs o BLACKOUT ANTES dos shutdowns e o
  INTERLOCK DE EMERGÊNCIA bloqueou-os (409×12, frota ON, 12/12 casas com luz — a
  defesa existente FUNCIONA em BLACKOUT; física do lab CORRETA). A sequência do GO
  é: shutdowns À NOITE em NORMAL e SÓ DEPOIS o blackout (0/12 casas). O run com a
  ordem corrigida (probe v0.1.1, previsão INALTERADA) é o RUN 1B (1c7d1aac…),
  PRESERVADO E CITADO — NÃO oficial (E-R8-4).
- **E-R8-4 · CORREÇÃO DE MÉTODO DO SUPERVISOR (13-11, vinculativa, regra desde a
  R3; probe r8 v0.2 → v0.3; outputs v0.2 PRESERVADOS como
  *_errata_rotulagem.txt)**: o GATEFALL OFICIAL de qualquer ronda é o RUN 1 contra
  o "antes", MESMO COM DEFEITO DE HARNESS/CRITÉRIO do probe (precedentes R3 5/6,
  R5 5/6); o "run 1-bis" da R7 foi EXCEÇÃO só por o run 1 original se ter PERDIDO
  no INFRA-A — não se aplica aqui. LOGO: **GATEFALL OFICIAL R8 = RUN 1 = 9/11**
  (P-R8-02 errada por defeito de construção do probe; P-R8-04 errada genuína —
  AMBAS REGISTADAS). O run com a ordem corrigida passa a **RUN 1B** (10/11),
  PRESERVADO E CITADO, mas NÃO oficial. NENHUM número nem previsão muda — só o
  rótulo de qual corrida é oficial. Correção aplicada IN-PLACE nos rótulos do probe
  r8 (v0.3, errata datada no changedlog), neste manifesto e nos registos; os
  outputs do run 2 e do re-check foram RE-EXECUTADOS com o probe v0.3 (números
  idênticos: 11/11 e 10/11) e os do v0.2 ficam PRESERVADOS como errata de
  rotulagem. NOTA: o changelog do LAB (v0.7.1/v0.7.2) mantém o rótulo antigo
  "run 1-bis = GATEFALL OFICIAL" nas entradas HISTÓRICAS — o lab NÃO foi editado
  (preservação do hash 1c433df1…); ESTA errata SUPERA esse rótulo.
- **E-R8-2 · PREVISÃO ERRADA REGISTADA (P-R8-04, probe do BUILDER)**: no run 1
  (= GATEFALL OFICIAL) e no run 1b contra a v0.7.1, a previsão "ZERO alertas" do
  cenário bulk ESQUECEU a telemetria do
  PRÓPRIO login (credenciais default → D-AUTH-DEFAULT WARN ×1). A substância
  confirmou (200, 12×200, frota OFF, ZERO alertas de shutdown). O cenário NÃO mudou e
  a previsão V071 NÃO foi reescrita para bater: fica REGISTADA como errada nos runs
  V071 (run 1 = GATEFALL OFICIAL 9/11; run 1b e re-checks: 10/11, RC=1 honesto). A
  previsão V072 incorpora a lição (declarado no changedlog do probe v0.2).
- **E-R8-3 · ERRATA DE RAMO do r2** (13-11, probe v0.9 → v0.9.1, output 1b15abba…
  PRESERVADO como sunstrike_probes_v072_r2_run1_errata_ramo.txt): o ramo v0.6+ do
  P-R2-01 não foi estendido a "v0.7.2" e o cenário caiu no ramo v0.2 — a FÍSICA medida
  foi EXATAMENTE a prevista (fatias [200,200,409,409,409], SoC [100→85→70], 3 eventos
  daily). Correção datada IN-PLACE (previsão INALTERADA); re-run = oficial (772495f2…).
- **E4 · NEG do demo/selftest (GO: "adapta as WOs de teste ao novo âmbito, com nota
  datada")**: o bulk do NEG passa de WO-20261112-MNT1 a **WO-20261113-MNT3** (âmbito
  {0,2}): o gate despacha SÓ aos 2 in-scope (2 shutdowns COM WO válida: 2 < k e
  22,9% < 30 → 0 CRIT mantém; 10 bulk_scope_skip auditados); o setpoint dev2 MANTÉM
  MNT1. EXPECTED NEG rules_absent ganha D-MASS-SHUTDOWN-WITH-WO. Contagens do demo
  INALTERADAS (H1=28, H2=18, NEG=0 — os shutdowns do demo são s/WO; verificado 9/9).
- **E5 · schema (errata datada)**: o bloco soc_limits da telemetria NÃO muda na v0.7.2
  e MANTÉM o schema "v0.7.1"; os eventos de AUDITORIA ganham campos ADITIVOS
  (shutdown: "wo_valid"; work_order_invalid: "reason"; bulk: "skipped_out_of_scope").
  O r5 (P-R5-04) continua a verificar "v0.7.1" nos alvos V071 E V072 (nota pré-registada
  no changedlog do r5 v0.5.2). Consumers de auditoria têm de tolerar os campos novos.
- **E6 · selftest/liveness (errata de contagens)**: liveness 23/23 → **24/24** (+1
  regra); selftest ganha a secção _selftest_v072 (8 testes: âmbito in/out, janela
  expirada, usos esgotados, massa 12 → CRIT, top-5 58,22% → CRIT, FP MNT3 → 0 alertas,
  resíduo 5 menores → 0 CRIT declarado, NEG bulk MNT3 → 2+10 skip+0 CRIT); as secções
  v0.7.1 C12WO (top-5 com MNT1) e C14WO (devs 0-4 com MNT1) GANHAM o CRIT novo POR
  DESIGN (58,22/45,6% ≥ 30) — os testes verificam capacity/WARN e continuam PASS (nota
  datada na docstring da _selftest_v072).
- **E7 · ERRATA PEDIDA PELO SUPERVISOR (manifesto v0.7.1)**: o hash do probe
  **sunstrike_probes_r7.py v0.1-bis.2 (21a3fad3…)** — a CORREÇÃO DE CRITÉRIO datada
  que gerou o run 1-BIS (GATEFALL substituto) e o run 1-BIS-B da ronda v0.7.1 — não
  constava do manifesto v0.7.1 (aparecia apenas abreviado no §1.4 como "probes bases
  (r7 21a3fad3…)"). FICA AGORA FORMALMENTE DECLARADO: o ficheiro PRESERVADO em
  artifacts é o probe r7 v0.1-bis.2, sha256 21a3fad3… (16 primeiros hex; declaração
  completa no registo do supervisor), ANTECESSOR do r7 v0.3/v0.3.1/v0.3.2 (d8fa4711…)
  e do atual v0.4 (32b2eec1…). Os runs 1-BIS (0d08b8c0…) e 1-BIS-B (d7a0ec30…)
  produzidos com ele mantêm-se PRESERVADOS e OFICIAIS.
- **E8 · r6 P-R6-07 (não-regressão, pré-registado ANTES do run)**: o top-5 com MNT1
  (58,22% ≥ 30) GANHA o CRIT D-MASS-SHUTDOWN-WITH-WO na v0.7.2 POR DESIGN do GO — o
  cenário que na v0.7.1 era NEG silencioso (200×5, 0 CRIT) passa a RESOLVIDO-DECLARADO
  (200×5, 0 CRIT capacity, 0 WARN, + CRIT novo count 5). A mudança está na lista
  GATEFALL_V072 do r6 v0.5, pré-registada antes da corrida; 7/7, 0 erradas.

---

## 5. GATEFALL por corrida (previsões pré-registadas ANTES de cada uma)

| corrida | alvo | previsões | resultado | output |
|---|---|---|---|---|
| **R8 RUN 1 (probe v0.1) = GATEFALL OFICIAL (E-R8-4)** | v0.7.1 INTOCADA (72c894fe…) | 11× CONFIRMADO | **9/11 — os 3 cenários do GO CONFIRMADOS com os números exatos; P-R8-02 errada POR DEFEITO DE CONSTRUÇÃO do probe (E-R8-1) e P-R8-04 errada genuína (E-R8-2), AMBAS REGISTADAS; RC=1 honesto** | 1f4fa8ec… |
| R8 RUN 1B (probe v0.1.1, ordem do P-R8-02 corrigida) | v0.7.1 INTOCADA (72c894fe…) | 11× CONFIRMADO | 10/11 — PRESERVADO E CITADO, **NÃO oficial** (E-R8-4) | 1c7d1aac… |
| R8 re-check (probe v0.3) | v0.7.1 INTOCADA | 11× CONFIRMADO | 10/11 — GATEFALL reproduzido (P-R8-04 errada registada) | 0f5a9094… |
| **R8 RUN 2 (probe v0.3, GATEFALL_V072 pré-registada ANTES)** | v0.7.2 (1c433df1…) | 9× RESOLVIDO + 2× DECLARADO | **11/11 (9 RESOLVIDO + 2 DECLARADO — resíduos medidos por mandato do GO), 0 erradas, RC=0** | dda185d1… |
| R7 (não-regressão, probe v0.4) | v0.7.2 | 8× RESOLVIDO (herdadas V071; pré-registadas v0.4) | **8/8, 0 erradas, RC=0** | 04677835… |
| R6 (não-regressão, probe v0.5) | v0.7.2 | 6× herdadas + 1× RESOLVIDO-DECLARADO (P-R6-07 pré-registado) | **7/7, 0 erradas, RC=0** | 7871656a… |
| R5 (não-regressão, probe v0.5.2) | v0.7.2 | 6× herdadas (schema "v0.7.1" MANTIDO — pré-registado) | **6/6, 0 erradas, RC=0** | 716ca723… |
| R4 (não-regressão, probe v0.6) | v0.7.2 | 6× herdadas | **6/6, 0 erradas, RC=0** | 637c8131… |
| R3 (não-regressão, probe v0.6) | v0.7.2 | 6× herdadas | **6/6, 0 erradas, RC=0** | 66001566… |
| R2 (não-regressão, probe v0.9.1) | v0.7.2 | 7× RESOLVIDO + 3× CONFIRMADO-DECLARADO (banner SUNBOX/0.7.2 dinâmico) | **7/7 + 3/3, 0 erradas, RC=0** (run 1 com errata de ramo E-R8-3 PRESERVADO) | 772495f2… |

O GATEFALL OFICIAL da R8 é o RUN 1 contra a v0.7.1 INTOCADA (o "antes"), mesmo com o
defeito de construção do probe (E-R8-4, regra de método do supervisor; precedentes
R3 5/6, R5 5/6).
Os GATEFALL oficiais de R2–R7 mantêm-se os RUN 1 de cada ronda contra os ANTES
originais (preservados em artifacts).

### Números-chave do R8 (todos confirmáveis nos outputs)

- **P-R8-01 (C15 replay DIA)**: v0.7.1 → 200×12, frota OFF, ZERO alertas (GO
  confirmado). v0.7.2 → 200×12 (MNT1 in-scope; o fix NÃO bloqueia uso legítimo) MAS
  **CRIT D-MASS-SHUTDOWN-WITH-WO count 12** (12 ≥ k, 100% ≥ 30) — §7 item 8 agora
  VERDADEIRO também para WO válida.
- **P-R8-02 (C15 replay NOITE+BLACKOUT, MNT2)**: v0.7.1 → 200×12, ZERO alertas, 0/12
  casas (GO confirmado). v0.7.2 → **200×3 + 403 fora_do_ambito ×9 + WARN count 9**,
  frota 9/12 ON, 9/12 casas com luz no blackout — o replay à frota com a WO ERRADA
  morre no âMBITO.
- **P-R8-03 (C15 reuso 3×)**: v0.7.1 → 200×5, ZERO alertas (GO confirmado). v0.7.2 →
  200×5 (3 usos ≤ 12), ZERO alertas — **RESÍDUO DECLARADO** (1 dispositivo, 11,8% < 30).
- **P-R8-04 (bulk do gate)**: v0.7.1 → 200, 12×200, frota OFF (previsão errada
  registada: D-AUTH-DEFAULT ×1 do login). v0.7.2 → idem + **CRIT count 12** — o canal
  bulk da cloud também coberto.
- **P-R8-05..08 (propostas do BUILDER)**: âncora vazia confirmada na v0.7.1 (estática;
  MNT2 ×6; +40 dias executa; 4 usos executam) → RESOLVIDO na v0.7.2 (âmbito/janela/
  usos: 403 + reason + WARN; a WO vale EXATAMENTE o seu âmbito, tem PRAZO e usos
  FINITOS).
- **P-R8-09..11 (FP e resíduos, mandato do GO)**: manutenção pontual com MNT3 de
  âmbito correto → 200×2, ZERO alertas (FP morto); 5 menores (25,68% < 30) → 200×5,
  0 CRIT (**RESÍDUO DECLARADO**); top-5 (58,22% ≥ 30) → 200×5 + **CRIT count 5** pelo
  GATILHO DE CAPACIDADE.

### Não-regressões: o que NÃO regrediu

- R7: F-C13 (WO falsa → 403×12 + WARN 12, frota ON), F-K1 (K1-b 3/4 dias DRAIN-TO-LOW
  count 12; K1-c FP morto SoC 100), F-C14 (noite 5 s/WO WARN ×5; 7×61 min WARN ×7),
  F-SP (frota 60% COM WO 0 CRIT div 40; SEM WO ARMA; 6 devs 0 alertas) — 8/8.
- R6: K1 visibilidade (count 12; NUVEM count 5), C12 (top-5 s/WO capacity CRIT +
  WARN 5; top-2 resíduo WARN 2), 3 causas C12, floor (409 + BELOW-FLOOR + DRAIN-TO-LOW
  12), P-R6-07 RESOLVIDO-DECLARADO (E8).
- R5: limite diário 40%/24 h, recarga grid-tied (J4), telemetria soc_limits (schema
  "v0.7.1" MANTIDO — E5), curva com minutos, saturações — regras novas CALADAS.
- R4: limite diário mantém C10 com margem, guardas §4.7.2 VERDES, DRAIN-TO-LOW calada
  (consumo LOCAL em ilha).
- R3: C7/I1/C8/I4/I5 RESOLVIDOS; snap_evs == 1 mantém-se; FP do setpoint legítimo
  mantém-se.
- R2: C4 TRAVADO (fatias [200,200,409,409,409], SoC 70), item (e) do H7 RESOLVIDO
  (banner SUNBOX/0.7.2), C5/C6/H7(a)-(d) DECLARADOS.

---

## 6. Medidas (measure 51/51, PASS — linhas das corridas idênticas às da v0.7.1)

- Curva (b): V07 [12, 12, 12, 11, 8] INALTERADA. (c): SoC fim 60,0; drain-to-low 0×0.
  (d): served [12, 9, 6, 3, 0] IGUAL em todos os braços; DRAIN-TO-LOW ×1 count 12.
  (e) resíduo F-K1: SoC 36,0, ZERO drain alerts (DECLARADO). (f) FP-SP: COM WO →
  200×12, div 40,0%, CRIT capacity=False; SEM WO → CRIT True (resíduo DECLARADO).
- Demo: PASS 9/9 (H1 CRIT=28, H2 CRIT=18, NEG CRIT=0, STRESS=1, EMERG=60, H3=9,
  H4=12, H5=1, H4-BLACKOUT=60; ilha retida 12/12) — CONTAGENS INALTERADAS da v0.7.1
  (errata E4 do NEG: bulk MNT3, 2 executados + 10 skips).
- Selftest: PASS, liveness **24/24**, 31 testes herdados + **8 novos v0.7.2**.

---

## 7. What CANNOT be claimed (resíduos e limites, DECLARADOS)

1. **§7 item 8 CORRIGIDO E FECHADO PARA WO VÁLIDA**: a frase "isto é detetado" é
   AGORA verdadeira para shutdowns à escala da frota COM WO válida (F-C15b: CRIT
   D-MASS-SHUTDOWN-WITH-WO com distintos ≥ k OU perda ≥ 30%, dia E noite) e para WO
   falsa/fora-de-âmbito/expirada/esgotada (F-C15a/F-C13: 403 + WARN). O que fica SÓ
   DECLARADO: < k dispositivos E < 30% de capacidade com WO válida de âmbito correto
   (itens 2 e 6).
2. **RESÍDUO F-C15b MEDIDO (R8 P-R8-03/P-R8-10, mandato do GO)**: atacante que desliga
   < k dispositivos com < 30% da capacidade usando WO válida de âmbito correto ESCAPA
   ao CRIT de massa (1 dispositivo reusado 3× = 11,8%; 5 menores = 25,68%) — DECLARADO
   para a v0.8. Limiar mais baixo = FPs de manutenção legítima de poucos
   dispositivos; k=6/30% ficam JUSTIFICADOS pelos FP medidos (MNT3 {0,2} → 0 alertas).
3. **RESÍDUO escopo-por-uso**: o atacante com uma WO de âmbito LARGO (MNT1 = frota
   inteira) continua a poder desligar a frota INTEIRA (o fix não bloqueia uso
   in-scope) — o que muda é a VISIBILIDADE (CRIT imediato, dia e noite) e o ÂMBITO
   das WOs passa a ser um artefacto de PROVISIONAMENTO auditável (a emissão de WOs de
   frota inteira fica uma decisão visível). DECLARADO.
4. **Manutenção legítima de frota inteira dispara o CRIT novo** (trade-off assumido
   pelo GO: "o alerta é aceitável e fica DECLARADO") — o operador do SOC tem de
   triar o CRIT de massa contra o plano de manutenção; o bulk_scope_skip e o campo
   work_order nos eventos dão o CONTEXTO para triagem.
5. **C14 noturno da capacity CONTINUA DECLARADO** (cegueira física: à noite div=0);
   a visibilidade noturna dos shutdowns é o WARN s/WO (F-C14) + o CRIT de massa
   (F-C15b, COM WO) — os H7 (a)-(d) ficam para a v0.8.
6. **Resíduos herdadas da v0.7.1 (estacionamento 36%, setpoint SEM WO, CRIT noturno
   da capacity, top-2 CRIT-escapa)**: MANTIDOS, DECLARADOS para a v0.8 — o top-2
   (26,35% < 30, 2 < k) continua a escapar ao CRIT de massa TAMBÉM (abaixo dos dois
   gatilhos), mas mantém a visibilidade WARN s/WO quando sem WO.
7. **Guard ≠ gate/device**: o guard do gate e o endpoint do dispositivo continuam
   caminhos DIFERENTES; o F-C15a fecha o âmbito no DISPOSITIVO e no GATE com a mesma
   fonte, mas os abertos H7 (a)-(d) (token sem TTL, /login sem lockout, chunked no
   device, BLOCKED_IN_EMERGENCY morto) ficam para a v0.8.
8. **AUD-03/R6-04 (PIN) e AUD-04/R6-05 (relógio) ficam para a v0.8**; R6-07 e R6-09
   ficam para a v0.8; C5, C6, C9, I2, I3, I6, C11, J3 ficam para a v0.8 (GO).
9. **Física cartoon**: o lab continua uma simulação determinística de propósito; as
   medidas servem para comparar braços, não para prever grids reais. As janelas de
   validade das WOs são ancoradas a WORK_ORDER_EPOCH (sim_ts na criação do Lab) para
   reprodutibilidade — numa implantação real seriam absolutas e com emissão auditada.
10. **SCHEMA**: soc_limits MANTÉM "v0.7.1" (bloco inalterado — E5); os eventos de
    auditoria ganham campos ADITIVOS (wo_valid, reason, skipped_out_of_scope) —
    consumers têm de tolerar campos novos.
11. **MITRE**: TA0101/T0812/T0859 devem ser RECONFIRMADOS antes do M5.
12. **Guard ≠ prova de ausência**: zero erradas em R2–R7 + 11/11 no R8 run 2 é
    evidência de não-regressão e de fix nos cenários EXECUTADOS, não uma prova de
    que nada regrediu ou evadiu fora deles. O P-R8-04 fica REGISTADO como previsão
    errada do BUILDER nos runs V071 (método: nunca se ajusta o probe para bater).

---

## 8. Worklog da ronda (resumo)

1. GO v0.7.2 (operador 13-11 ~19:30, via supervisor): achado C15 (replay de WO
   válida), ordem vinculativa probes ANTES (mínimo: os 3 cenários do GO), fixes
   DEPOIS; errata do manifesto (hash r7 v0.1-bis.2 21a3fad3…).
2. Hashes dos anexos verificados contra o manifesto v0.7.1: TODOS batem (lab
   72c894fe…, r7_v071 d8fa4711…, r6 61774628…, r5 bd761eac…, r4 582ae46b…, r3
   fbeb1bb6…, r2 70c8805d…).
3. Probes R8 (v0.1) com 11 previsões pré-registadas ANTES: 3 do GO + 8 do BUILDER.
   RUN 1 = GATEFALL OFICIAL: 9/11 (P-R8-02 errada por defeito de construção do
   probe, E-R8-1; P-R8-04 errada genuína, E-R8-2 — ambas REGISTADAS). O run com a
   ordem corrigida (probe v0.1.1) = RUN 1B: 10/11, PRESERVADO E CITADO, não
   oficial (E-R8-4). GATEFALL PUBLICADO antes dos fixes.
4. Mecanismos F-C15a/F-C15b pré-registados e justificados ANTES de implementar;
   fixes aplicados ao lab (âmbito/janela/usos + work_order_check única + regra
   D-MASS-SHUTDOWN-WITH-WO + liveness 24 + NEG MNT3 + selftest v072).
5. v0.7.1 preservada como sunstrike_lab_v071.py (byte-exata; .b64 re-codificado
   = 208bdb155b… IDÊNTICO ao manifesto v0.7.1) ANTES de o nome genérico receber a
   v0.7.2 (convenção E10).
6. R8 run 2 (probe v0.2/v0.3 dual, GATEFALL_V072 pré-registada): 11/11 (9 RESOLVIDO
   + 2 DECLARADO), 0 erradas, RC=0. Re-check vs v0.7.1: GATEFALL reproduzido (10/11).
   ERRATA DE ROTULAGEM E-R8-4 (supervisor, regra desde a R3): GATEFALL OFICIAL =
   RUN 1 (9/11); run 1b (10/11) preservado e citado, NÃO oficial; probe r8 v0.3;
   run 2/re-check re-executados (números idênticos); outputs v0.2 preservados.
7. Não-regressões R7 (v0.4 tri) 8/8, R6 (v0.5 quad) 7/7 com P-R6-07
   RESOLVIDO-DECLARADO pré-registado, R5 (v0.5.2 penta) 6/6, R4 (v0.6 hexa) 6/6,
   R3 (v0.6 hepta) 6/6, R2 (v0.9.1 octa) 7/7+3/3 (errata de ramo E-R8-3, run 1
   preservado) — ZERO erradas nos runs oficiais.
8. Selftest PASS liveness 24/24 (+8 testes v0.7.2); demo 9/9 contagens INALTERADAS
   (errata E4 do NEG); measure 51/51 linhas idênticas.
9. b64 + round-trip cmp 10/10 OK; hashes 2×; EOF verificados; este manifesto com a
   errata E7 (r7 v0.1-bis.2 21a3fad3…) pedida pelo supervisor.

Estado: **v0.7.2 ENTREGUE, aguarda verificação do supervisor.** NÃO iniciar v0.8
nem mexer em repos sem GO. M3 só com GO após verificação. FICAM PARA A v0.8 (GO):
C5, C6, C9, H7 (a)-(d), I2, I3, I6, C11, J3, AUD-03 (PIN), AUD-04 (relógio),
R6-07, R6-09 + os resíduos DECLARADOS (estacionamento 36%, setpoint SEM WO, CRIT
noturno da capacity, top-2, e os novos resíduos do F-C15b: < k dispositivos E < 30%
com WO válida).

# EOF:sunstrike_v072_outputs.md
