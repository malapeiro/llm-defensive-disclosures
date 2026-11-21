# RUNBOOK — Minimal event pair, second backend (Elasticsearch)
sigma_t1003_study follow-up · resposta ao comentário do DEV Community (16/11)
v2 (dois venvs) · 2026-11-21 · EMENDA E-01 do PRE_REGISTRATION.md aplica-se

**Escopo:** tudo local no Mac do operador (loopback). Nada sai da máquina. O índice é apagado no fim.
**Divisão de compiladores:** ver EMENDA E-01 — lado SQLite = stack do estudo; lado Elastic = pySigma 1.5.1 (imposição do pip, `pysigma<2.0.0`); colapso do SigmaString verificado nos dois compiladores; P1–P4 inalterados.

## Passo 0 — verificar a transcrição do SQL (1 minuto)
```bash
cd ~/Estudos/Artefactos_de_estudos/sigma_work/minpair
diff v2_compiled.sql ~/Estudos/Clones_de_repos/llm-defensive-disclosures/sigma_t1003_study/compiled_sql/v2_compiled.sql && echo "V2 IDENTICO"
diff v3_compiled.sql ~/Estudos/Clones_de_repos/llm-defensive-disclosures/sigma_t1003_study/compiled_sql/v3_compiled.sql && echo "V3 IDENTICO"
```
Se algum diff falhar: PARAR, reportar à Vibe (errata + re-corrida; não usar resultados).

## Passo 1 — dois venvs (estado atual: JÁ MONTADOS; comandos para reproducibilidade)
```bash
# Python 3.13.18 (o 3.15 não compila o google-re2 — Environment Errata 2, PRE_REGISTRATION.md)
python3.13 -m venv venv_sqlite
venv_sqlite/bin/pip install pysigma==2.0.2 pysigma-backend-sqlite==2.1.1 \
  pysigma-pipeline-sysmon==3.0.0 pysigma-pipeline-windows==3.0.0
venv_sqlite/bin/pip freeze > freeze_sqlite.txt

python3.13 -m venv venv_es
venv_es/bin/pip install pysigma==1.5.1 pysigma-backend-elasticsearch==2.1.1 \
  pysigma-pipeline-sysmon==2.0.0 pysigma-pipeline-windows==2.0.1
venv_es/bin/pip freeze > freeze_es.txt
```
(RUNBOOK Errata 1: a v1 não instalava os pipelines; sem eles o SQL não é byte-identical ao estudo.)

## Passo 2A — lado SQLite (stack do estudo, byte-identity obrigatório)
```bash
cd ~/Estudos/Artefactos_de_estudos/sigma_work/minpair
venv_sqlite/bin/python minpair_sqlite_run.py \
  --rules-dir ~/Estudos/Clones_de_repos/llm-defensive-disclosures/sigma_t1003_study/rules
```
Verificar no output: (a) `byte_identical_to_study_sql` = **true** em v2 E v3; (b) `vs_baseline_prediction_matrix` = **MATCH** em v2 E v3; (c) `sigma_collapse_runtime.matches_single_backslash` = true. Guarda `results_sqlite_mac.json`.

## Passo 2B — lado Elastic (compilação Lucene)
```bash
venv_es/bin/python minpair_es_compile.py \
  --rules-dir ~/Estudos/Clones_de_repos/llm-defensive-disclosures/sigma_t1003_study/rules
```
Verificar: (a) `matches_single_backslash` = true (compilador 1.5.1); (b) no `lucene_query_no_pipeline` da v2, identificar como é que o valor 'ão-nu' `'\\'` foi compilado (âncora da P1 — copiar o excerto para o registo); (c) `index_fields_referenced` tem de ser um subconjunto dos campos dos eventos (TargetImage, GrantedAccess, SourceImage, SourceUser, CallTrace…); (d) as variantes `*_pipelined.json` ficam registadas para o ficheiro, não correm contra este índice a menos que os campos batam. Guarda `results_es_compile.json`, `es_query_v2.json`, `es_query_v3.json`, `es_mapping.json`, `es_bulk.ndjson`.

## Passo 3 — instalar o Elasticsearch (uma só vez)
```bash
brew tap elastic/tap
brew install elastic/tap/elasticsearch-full
brew services start elastic/tap/elasticsearch-full   # aguardar 30–60s
curl -s localhost:9200 | head
```

## Passo 4 — índice fresco + ingestão
```bash
cd ~/Estudos/Artefactos_de_estudos/sigma_work/minpair
curl -s -X DELETE localhost:9200/sigma-minpair
curl -s -X PUT localhost:9200/sigma-minpair -H 'Content-Type: application/json' -d @es_mapping.json
curl -s -X POST localhost:9200/_bulk?refresh=true -H 'Content-Type: application/x-ndjson' --data-binary @es_bulk.ndjson
curl -s 'localhost:9200/sigma-minpair/_count'   # tem de dar count: 4
```

## Passo 5 — as duas corridas (o teste real)
```bash
curl -s -X POST localhost:9200/sigma-minpair/_search -H 'Content-Type: application/json' -d @es_query_v2.json; echo
curl -s -X POST localhost:9200/sigma-minpair/_search -H 'Content-Type: application/json' -d @es_query_v3.json; echo
```
Guardar os outputs completos em `es_results_raw.txt`.
**Leitura contra o pré-registo:** v2 devolve E1 (FP reabre no Elastic = P2), E2 e E4, e NÃO E3; v3 devolve só E4 (P3). Se v2 NÃO devolver E1 = P4: divergência real entre backends — registar tal qual, é o achado novo.

## Passo 6 — limpeza
```bash
curl -s -X DELETE localhost:9200/sigma-minpair
brew services stop elastic/tap/elasticsearch-full   # opcional
```

## Passo 7 — reporte à Vibe
Colar/coller: `results_sqlite_mac.json` + `results_es_compile.json` + `es_results_raw.txt` (+ parte do passo 0 se algo divergir). A Vibe verifica contra P1–P4 e a EMENDA E-01, e prepara a evidência final (publicação só depois da revisão do operador).

## O que não se pode afirmar enquanto isto não correr
- Nada foi ainda demonstrado no Elastic/Lucene: P1–P4 são INFERRED até existir execução real com output registado.
- A matriz SQLite da baseline (results_sqlite_baseline.json, já executada a sério) vale para a reconstrução byte-identical do SQL do estudo em sqlite3 3.46.1; o Passo 2A re-executa no teu Python/venv e regista as versões locais.
