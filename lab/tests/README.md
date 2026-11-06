# Pruebas de requisitos R1–R8

Estas pruebas son **posteriores a la campaña**: no formaron parte de la medición y no modifican los resultados de E1–E3. Se escribieron para cubrir N-18 («pruebas de R1–R6 y R8 sin reportar»).

**Estado.** Los scripts `lab/tests/*.sh` —incluido `r1_ventana.sh`, que ejecuta intentos SSH reales— **no se ejecutaron**. La prueba de R1 a nivel de base de datos (`lab/post_campana/test_r1_ventana.sql`) **se ejecutó el 5 de noviembre de 2026 a las 21:13:28 −03:00 (00:13:28 UTC del 6 de noviembre)** contra el contenedor `lab-postgres`; su salida está en `lab/results/tests/r1_ventana_db.txt` y registra `now()` y `version()` (PostgreSQL 15.19). Esa prueba inserta eventos sintéticos en una transacción y la revierte: no modifica los datos de la campaña ni se usa para calcular las métricas del capítulo 6.

## Requisitos previos

```bash
cd <raiz-del-repositorio>
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps
```

Contenedores esperados: `lab-victim`, `lab-attacker`, `lab-n8n`, `lab-postgres`.
Base de datos: `psql -U admin -d security_monitoring` (credenciales del compose, rotarlas antes de publicar).
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

Cada script imprime `RESULTADO: PASA`, `RESULTADO: FALLA` o `RESULTADO: NO CONCLUYENTE`, y deja la salida cruda en `lab/results/tests/`.

## R1 a nivel de base de datos (ejecutada el 5 de noviembre de 2026)

- Script: `lab/post_campana/test_r1_ventana.sql`.
- Salida: `lab/results/tests/r1_ventana_db.txt`.
- Comando: `docker exec -i lab-postgres psql -U admin -d security_monitoring -v ON_ERROR_STOP=1 < lab/post_campana/test_r1_ventana.sql`.
- Entorno registrado en la salida: `now()` = 2026-11-06 00:13:28.003946+00; `version()` = PostgreSQL 15.19 on x86_64-pc-linux-musl.
- Casos: A (5 eventos en 20 s), B (5 eventos en 400 s) y C (5 eventos en 280 s), con `event_ts = ingest_ts`.
- Resultado: A alerta con GRACE 180 y 600; B no alerta con ninguno; C no alerta con 180 y sí con 600.
- `lab/post_campana/pipeline.js` es una copia de `lab/pipeline.js` cuya única diferencia es `GRACE = 600`; no se desplegó ni se usó en una campaña.

`lab/tests/r1_ventana.sh` es distinto: ejecuta intentos SSH reales contra `lab-victim` y no se ejecutó.

## Matriz de pruebas

| Requisito | Qué se prueba | Resultado esperado según el código medido | Estado |
|---|---|---|---|
| R1 | Ventana deslizante con T < ventana; 5 eventos SSH dentro de 300 s | Dispara. Con los eventos repartidos más de 180 s, la gracia puede impedir la segunda alerta: defecto declarado | Base de datos: ejecutada el 5/11/2026 (`r1_ventana_db.txt`); `r1_ventana.sh` (SSH real): no ejecutada |
| R2 | Offset por archivo e inodo | Dos ciclos sin eventos nuevos no crean alertas | Escrita |
| R3 | Lectura con nodo de archivos o webhook | **No cumple**: requiere `NODE_FUNCTION_ALLOW_BUILTIN` y usa `fs` dentro del nodo Code | Escrita |
| R4 | Validación de IP antes de cualquier comando | El pipeline valida IPv4 canónicas; el agente no valida y no usa shell | Escrita |
| R5 | Lista de exclusión y límite de bloqueos | Excluye 10.50.0.1 y 127.0.0.1; **no hay** límite por tiempo | Escrita |
| R6 | TTL, tope de reglas y desbloqueo | TTL de 600 s en memoria; sin tope; el reinicio borra el estado | Escrita |
| R7 / R9 | Cuota de AbuseIPDB y puntaje como condición | Ya verificado con respuestas simuladas en `lab/verify_r7_r9.js` | Ejecutada en la campaña |
| R8 | Flujo de error y latido | **No cumple**: `pipeline_runs` registra contadores, sin latido ni captura de error | Escrita |

## Advertencias

- Las pruebas escriben en la base y crean reglas de iptables. **No ejecutarlas durante una campaña** ni sobre un entorno con datos que importen.
- `r1_ventana.sh`, `r5_exclusion.sh` y `r6_ttl.sh` dejan reglas de bloqueo si se interrumpen: la limpieza está al final de cada script.
- Los tiempos de espera suman unos 25 minutos en total; `r6_ttl.sh` espera más de 600 s.
- Los scripts `lab/tests/*.sh` no se reportan en el informe como evidencia. La prueba de R1 a nivel de base de datos se cita en la Tabla 11 con su fecha y su salida.
