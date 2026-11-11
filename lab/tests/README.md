# Pruebas de requisitos R1–R8

Estas pruebas son **posteriores a la campaña**: no formaron parte de la medición y no modifican los resultados de E1–E3. Se escribieron para cubrir N-18 («pruebas de R1–R6 y R8 sin reportar»).

## Estado (actualizado el 11 de noviembre de 2026)

Se ejecutaron R2, R3, R4, R5, R7/R9 y R8 contra el laboratorio en marcha. R1 se ejecutó a nivel de base de datos el 30/10 y el 5/11; el script de R1 con intentos SSH reales (`r1_ventana.sh`) no se ejecutó. R6 no se ejecutó porque espera 630 s y excede el límite de 5 minutos por comando.

| Requisito | Fecha | Resultado | Salida |
|---|---|---|---|
| R1 (BD) | 2026-10-30 16:23:11 −03:00 | A pasa con GRACE 180 y 600; B pasa con ambos; C falla con 180 y pasa con 600 | `r1_ventana_db_2026-10-30.txt` |
| R1 (BD) | 2026-11-05 21:13:28 −03:00 | Repite el caso C: falla con 180, pasa con 600 | `r1_ventana_db.txt` |
| R1 (SSH real) | — | No ejecutada | `r1_ventana.sh` |
| R2 | 2026-11-11 17:17 UTC | **PASA**: alerts 1→1, pipeline_runs 418→420 | `r2_offset.txt` |
| R3 | 2026-11-11 17:08 UTC | **FALLA**: el nodo Code usa `fs` y `require('fs')`; no cumple R3 | `r3_ingesta.txt` |
| R4 | 2026-11-11 17:24 UTC | **PASA**: la IP no canónica no genera regla; la base rechaza el `inet` inválido | `r4_inyeccion_ip.txt` |
| R5 | 2026-11-11 17:11 UTC | **FALLA en A**: el agente medido bloquea 10.50.0.1; B confirma que no hay tope | `r5_exclusion.txt` |
| R6 | — | **No ejecutada**: espera 630 s (> 5 min) | `r6_ttl_no_ejecutada.txt` |
| R7 / R9 | 2026-11-11 17:09 UTC | **PASA**: 11/11 comprobaciones (10 simuladas + NET.1 con HTTP 401) | `r7_r9_verificacion.txt` |
| R8 | 2026-11-11 17:37 UTC | **FALLA**: no hay alerta de latido; tras reiniciar n8n el disparador programado no se re-registra | `r8_latido.txt` |
| N-14 | 2026-11-11 17:18–17:21 UTC | 10/10 unidades benignas con el patrón SQLi generaron alerta (FP=10) | `benign_e3_sqli.txt` |

## Requisitos previos

```bash
cd <raiz-del-repositorio>
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps
```

Contenedores esperados: `lab-victim`, `lab-attacker`, `lab-n8n`, `lab-postgres`.
Base de datos: `psql -U admin -d security_monitoring` (credenciales del compose; rotarlas antes de publicar).
Flujo: `lab/pipeline-wf.json` importado y activo, con sondeo cada 60 s.

## Cómo se corre cada prueba

```bash
bash lab/tests/r1_ventana.sh
bash lab/tests/r2_offset.sh
bash lab/tests/r3_ingesta.sh
bash lab/tests/r4_inyeccion_ip.sh
bash lab/tests/r5_exclusion.sh
bash lab/tests/r6_ttl.sh
bash lab/tests/r7_r9_enriquecimiento.sh
bash lab/tests/r8_latido.sh
```

Cada script imprime `RESULTADO: PASA`, `RESULTADO: FALLA` o `RESULTADO: NO CONCLUYENTE`, y deja la salida cruda en `lab/results/tests/`. Desde Git Bash en Windows, exportar `MSYS_NO_PATHCONV=1` para que `docker exec` no convierta las rutas `/tmp/...`; los scripts usan `docker exec -i` para pasar los heredocs a Python.

## R1 a nivel de base de datos

- Script: `lab/post_campana/test_r1_ventana.sql`.
- Salidas: `r1_ventana_db_2026-10-30.txt` (30/10) y `r1_ventana_db.txt` (5/11).
- Comando: `docker exec -i lab-postgres psql -U admin -d security_monitoring -v ON_ERROR_STOP=1 < lab/post_campana/test_r1_ventana.sql`.
- Entorno registrado en la salida del 5/11: `now()` = 2026-11-06 00:13:28.003946+00; `version()` = PostgreSQL 15.19.
- Casos: A (5 eventos en 20 s), B (5 eventos en 400 s) y C (5 eventos en 280 s), con `event_ts = ingest_ts`.
- Resultado: A alerta con GRACE 180 y 600; B no alerta con ninguno; C no alerta con 180 y sí con 600.
- `lab/post_campana/pipeline.js` es una copia de `lab/pipeline.js` cuya única diferencia es `GRACE = 600`; no se desplegó ni se usó en una campaña.

`lab/tests/r1_ventana.sh` es distinto: ejecuta intentos SSH reales contra `lab-victim` y no se ejecutó.

## Detalle de los hallazgos

- **R3**: `lab/results/tests/r3_ingesta.txt` registra `NODE_FUNCTION_ALLOW_BUILTIN=fs,...` y las líneas `const fs = require('fs')` del nodo Code. La prueba concluye FALLA porque el flujo depende de `fs` dentro del nodo, que es justamente lo que R3 no admite.
- **R4**: el agente medido responde `200 {"ok": true}` a `10.50.0.99;id`, pero `iptables` rechaza la dirección y no se crea ninguna regla; la base rechaza el `inet` inválido. El agente seguro (`lab/post_campana/block_agent_secure.py`) devuelve 400 para la misma entrada.
- **R5**: el agente medido no tiene lista de exclusión: bloquea 10.50.0.1 (la puerta de enlace) y aplica 10 bloqueos seguidos sin tope. La exclusión existe solo en `lab/pipeline.js`. El agente seguro agrega `EXCLUDE = {"10.50.0.1", "127.0.0.1"}` y responde `skipped=excluded`.
- **R8**: `pipeline_runs` registra contadores, pero no hay latido ni captura de error. Al detener `lab-n8n` durante 180 s no aparece ninguna alerta de latido. Además, en n8n 2.43.6 el disparador `ScheduleTrigger` es `in-memory`: tras reiniciar el contenedor no se re-registra y el flujo deja de correr solo. El webhook persistido sí funciona: `POST http://localhost:5679/webhook/runpipeline` devuelve `{"arm":"f2b",...}`.
- **N-14**: 10 unidades benignas con `GET /?q=union+select+articulos&page=1` desde 10.50.0.230–239 generaron 10 alertas `SQL Injection Pattern` (VP=10, FP=10, FPR=1.00 para esa estrata). El FPR=0.000 de la campaña E3 solo cubre unidades benignas sin el patrón. Las alertas son posteriores a la campaña y no forman parte de `lab/results/*.jsonl`, que es lo que consume `analysis/report_tables.py`.

## Advertencias

- Las pruebas escriben en la base y crean reglas de iptables. **No ejecutarlas durante una campaña** ni sobre un entorno con datos que importen.
- `r4_inyeccion_ip.sh`, `r5_exclusion.sh` y `r6_ttl.sh` pueden dejar reglas si se interrumpen. Para limpiar: `curl http://lab-victim:9000/reset` desde `lab-attacker`, o `docker exec lab-victim iptables -F LABBLOCK`.
- `r8_latido.sh` detiene `lab-n8n` durante 180 s. En n8n 2.43.6 el `ScheduleTrigger` no se re-registra al reiniciar; para reanudar el flujo bajo demanda usar el webhook `POST /webhook/runpipeline`.
- `r7_r9_enriquecimiento.sh` copia `lab/verify_r7_r9.js` y `lab/enrichment.js` a `/tmp/vr7/` y crea `/tmp/vr7/results`; sin `enrichment.js` el script falla con `Cannot find module './enrichment'`.
- Los tiempos de espera suman unos 25 minutos; `r6_ttl.sh` espera más de 600 s.
- Los scripts `lab/tests/*.sh` no se usan para calcular las métricas del capítulo 6. La prueba de R1 a nivel de base de datos se cita en la Tabla 11 con su fecha y su salida.
