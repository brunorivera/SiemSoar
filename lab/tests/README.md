# Pruebas de requisitos R1–R8

Estas pruebas son **posteriores a la campaña**: no formaron parte de la medición y no modifican los resultados de E1–E3. Se escribieron para cubrir las pruebas de R1–R6 y R8 que no se habían reportado.

## Estado (actualizado el 11 de noviembre de 2026)

Se ejecutaron R2, R3, R4, R5, R6, R7/R9 y R8 contra el laboratorio en marcha el 11 de noviembre de 2026, en un lote en segundo plano. R1 se ejecutó a nivel de base de datos el 30/10 y el 5/11; el script de R1 con intentos SSH reales (`r1_ventana.sh`) no se ejecutó. R6 se ejecutó completa (unos 11 minutos) y se informa con su resultado.

| Requisito | Fecha | Resultado | Salida |
|---|---|---|---|
| R1 (BD) | 2026-10-30 16:23:11 −03:00 | A pasa con GRACE 180 y 600; B pasa con ambos; C falla con 180 y pasa con 600 | `r1_ventana_db_2026-10-30.txt` |
| R1 (BD) | 2026-11-05 21:13:28 −03:00 | Repite el caso C: falla con 180, pasa con 600 | `r1_ventana_db.txt` |
| R1 (SSH real) | — | No ejecutada | `r1_ventana.sh` |
| R2 | 2026-11-11 22:08:30 −03:00 | **PASA**: alerts 21→21, pipeline_runs 478→480; no se probó la rotación por inodo | `r2_offset.txt` |
| R3 | 2026-11-11 22:08:30 −03:00 | **FALLA**: el nodo Code usa `fs` y `require('fs')`; no cumple R3 | `r3_ingesta.txt` |
| R4 | 2026-11-11 22:08:33 −03:00 | **PASA**: la IP no canónica no genera regla; la base rechaza el `inet` inválido | `r4_inyeccion_ip.txt` |
| R5 | 2026-11-11 22:10:03 −03:00 | **FALLA en A**: el agente medido bloquea 10.50.0.1; B confirma que no hay tope | `r5_exclusion.txt` |
| R6 | 2026-11-11 22:10:59 −03:00 | **PASA en A y B**: el TTL expira y `/unblock` retira la regla; C documenta que el reinicio borra el estado en memoria y la regla | `r6_ttl.txt` |
| R7 / R9 | 2026-11-11 22:10:35 −03:00 | **PASA**: 11/11 comprobaciones (10 simuladas + NET.1 con HTTP 401) | `r7_r9_verification_2026-11-11.json` |
| R8 | 2026-11-11 22:22:18 −03:00 | **FALLA**: no hay alerta de latido; tras reiniciar n8n el disparador programado no se reanudó (runs 494→494 en 150 s) | `r8_latido.txt` |
| Estrato SQLi benigno | 2026-11-11 22:10:55 −03:00 | 20/20 unidades benignas con el patrón SQLi generaron alerta; 10/20 bloqueos (solo el lote con brazo n8n; FPR 1,00; Wilson [0,839; 1]) | `benign_e3_sqli.txt`, `benign_e3_sqli_n8n.jsonl` |

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
- `lab/post_campana/pipeline.js` es una copia de `lab/pipeline.js` cuyas diferencias con el artefacto medido son `GRACE = 600` y la deduplicación `max(win + 60, GRACE)`; no se desplegó ni se usó en una campaña. `lab/post_campana/pipeline_post_campana.js` conserva el mismo cambio. El detalle está en `lab/post_campana/pipeline.post_campana.diff`.

`lab/tests/r1_ventana.sh` es distinto: ejecuta intentos SSH reales contra `lab-victim` y no se ejecutó.

## Detalle de los hallazgos

- **R3**: `lab/results/tests/r3_ingesta.txt` registra `NODE_FUNCTION_ALLOW_BUILTIN=fs,...` y las líneas `const fs = require('fs')` del nodo Code. La prueba concluye FALLA porque el flujo depende de `fs` dentro del nodo, que es justamente lo que R3 no admite.
- **R4**: el agente medido responde `200 {"ok": true}` a `10.50.0.99;id`, pero `iptables` rechaza la dirección y no se crea ninguna regla; la base rechaza el `inet` inválido. El agente seguro (`lab/post_campana/block_agent_secure.py`) devuelve 400 para la misma entrada.
- **R5**: el agente medido no tiene lista de exclusión: bloquea 10.50.0.1 (la puerta de enlace) y aplica 10 bloqueos seguidos sin tope. La exclusión existe solo en `lab/pipeline.js`. El agente seguro agrega `EXCLUDE = {"10.50.0.1", "127.0.0.1"}` y responde `skipped=excluded`.
- **R8**: `pipeline_runs` registra contadores, pero no hay latido ni captura de error. La prueba del 11/11 detuvo `lab-n8n` durante 180 s: no apareció ninguna alerta de latido (0). Tras reiniciarlo, `pipeline_runs` quedó en 494 (antes 494) y el `ScheduleTrigger` no se reanudó dentro de los 150 s observados (`reanudo_schedule_trigger=no`). El webhook persistido sí funciona: `POST http://localhost:5679/webhook/runpipeline` devuelve `{"arm":"f2b",...}`. La causa probable no se atribuye a una sola hipótesis: el README anterior afirmaba que el `ScheduleTrigger` de n8n 2.43.6 es «in-memory» sin fuente, y una explicación alternativa, compatible con la sección 5.2 del informe, es el despliegue por importación vía API con ajuste de la base SQLite. El hecho medido es que el pipeline deja de sondear en silencio tras un reinicio y que no hay latido que lo advierta.
- **Estrato SQLi benigno**: 20 unidades benignas con `GET /?q=union+select+articulos&page=1` desde 10.50.0.230–249, en dos lotes de diez, generaron 20 alertas `SQL Injection Pattern`; 10/20 bloqueos (solo el lote B, con brazo n8n) (FP=20, FPR=1.00, Wilson [0,839; 1]). El lote A (10.50.0.230–239) se ejecutó con `lab_config.arm='f2b'` (alerta sin bloqueo) y el lote B (10.50.0.240–249) con `arm='n8n'`; el campo `arm` de ambos JSONL registra el argumento de línea de comandos de `benign_e1.py` y por eso dice `"n8n"` también en el lote A. El FPR=0.000 de la campaña E3 solo cubre unidades benignas sin el patrón. Las alertas son posteriores a la campaña y no forman parte de `lab/results/*.jsonl`, que es lo que consume `analysis/report_tables.py`.

## Advertencias

- Las pruebas escriben en la base y crean reglas de iptables. **No ejecutarlas durante una campaña** ni sobre un entorno con datos que importen.
- `r4_inyeccion_ip.sh`, `r5_exclusion.sh` y `r6_ttl.sh` pueden dejar reglas si se interrumpen. Para limpiar: `curl http://lab-victim:9000/reset` desde `lab-attacker`, o `docker exec lab-victim iptables -F LABBLOCK`.
- `r8_latido.sh` detiene `lab-n8n` durante 180 s. En n8n 2.43.6 el `ScheduleTrigger` no se re-registra al reiniciar; para reanudar el flujo bajo demanda usar el webhook `POST /webhook/runpipeline`.
- `r7_r9_enriquecimiento.sh` copia `lab/verify_r7_r9.js` y `lab/enrichment.js` a `/tmp/vr7/` y crea `/tmp/vr7/results`; sin `enrichment.js` el script falla con `Cannot find module './enrichment'`.
- Los tiempos de espera suman unos 30 minutos; `r6_ttl.sh` espera más de 600 s y `r8_latido.sh` detiene n8n 180 s y luego espera 150 s.
- Los scripts `lab/tests/*.sh` no se usan para calcular las métricas del capítulo 6. La prueba de R1 a nivel de base de datos se cita en la Tabla 11 con su fecha y su salida.
