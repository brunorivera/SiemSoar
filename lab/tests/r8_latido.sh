#!/usr/bin/env bash
# R8 — Flujo de error, reintentos y alerta de latido del propio pipeline.
# Registra la fecha de la corrida, el reinicio de n8n y si el ScheduleTrigger
# reanuda solo. Cada corrida imprime su propia fecha.
set -uo pipefail

PG="docker exec lab-postgres psql -U admin -d security_monitoring -tAc"
OUT=lab/results/tests
mkdir -p "$OUT"

runs_before() { $PG "SELECT count(*) FROM pipeline_runs;" | tr -d '[:space:]'; }
last_run()    { $PG "SELECT coalesce(max(run_ts)::text,'ninguna') FROM pipeline_runs;" | tr -d '[:space:]'; }
alerts()      { $PG "SELECT count(*) FROM alerts WHERE category ILIKE '%heartbeat%' OR category ILIKE '%latido%' OR description ILIKE '%latido%';" | tr -d '[:space:]'; }

echo "R8 | desactivando el flujo"
# Con la CLI de n8n no se puede desactivar un flujo importado; se hace desde la UI
# o se detiene la instancia entera:
docker stop lab-n8n >/dev/null
sleep 10

R0=$(runs_before)
echo "  corridas registradas: $R0 | ultimo run_ts: $(last_run)"
echo "  esperando 180 s para verificar si aparece un latido o una alerta de fallo..."
sleep 180

HB=$(alerts)
echo "  alertas de latido: ${HB:-0}"
printf 'fecha=%s\nruns=%s\nultimo_run_ts=%s\nalertas_latido=%s\n' \
  "$(date -Is)" "$R0" "$(last_run)" "$HB" | tee "$OUT/r8_latido.txt"

echo "R8 | reiniciando n8n a las $(date -Is)"
docker start lab-n8n >/dev/null
sleep 150
R1=$(runs_before)
if [ "${R1:-0}" -gt "${R0:-0}" ]; then RESUMED=si; else RESUMED=no; fi
echo "  corridas tras el reinicio: $R1 (antes: $R0); ScheduleTrigger reanudo: $RESUMED"
printf 'runs_tras_reinicio=%s\nreanudo_schedule_trigger=%s\nfecha_fin=%s\n' \
  "$R1" "$RESUMED" "$(date -Is)" | tee -a "$OUT/r8_latido.txt"

if [ "${HB:-0}" -eq 0 ]; then
  { echo "RESULTADO: FALLA (no existe alerta de latido: un fallo silencioso sigue siendo indistinguible)"
    echo "  Coincide con lo declarado en la Tabla 11 (R8 parcial) y en la seccion 7.2."; } | tee -a "$OUT/r8_latido.txt"
else
  echo "RESULTADO: PASA (hay alerta de latido: actualizar la Tabla 11)" | tee -a "$OUT/r8_latido.txt"
fi
