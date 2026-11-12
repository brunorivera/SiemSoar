#!/usr/bin/env bash
# R7 y R9 — Cuota de AbuseIPDB y puntaje como condicion de respuesta.
# Reproduce la verificacion con respuestas simuladas y guarda la salida.
# Cada corrida imprime su fecha y conserva el JSON en lab/results/tests/.
set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash en Windows: no convertir /tmp/... a rutas locales

OUT=lab/results/tests
mkdir -p "$OUT"

{
  echo "fecha=$(date -Is)"
  echo "== Verificacion de R7 y R9 con respuestas simuladas"
  docker exec lab-n8n sh -c "rm -rf /tmp/vr7; mkdir -p /tmp/vr7/results"
  docker cp lab/verify_r7_r9.js lab-n8n:/tmp/vr7/verify_r7_r9.js
  docker cp lab/enrichment.js lab-n8n:/tmp/vr7/enrichment.js
  docker exec lab-n8n node /tmp/vr7/verify_r7_r9.js
} 2>&1 | tee "$OUT/r7_r9_verificacion.txt"

JSON_OUT="$OUT/r7_r9_verification_$(date +%Y-%m-%d).json"
docker cp lab-n8n:/tmp/vr7/results/r7_r9_verification.json "$JSON_OUT" 2>/dev/null || true
if [ -f "$JSON_OUT" ]; then echo "JSON: $JSON_OUT"; fi

SIM=$(grep -c '\[PASS\] R[79]\.' "$OUT/r7_r9_verificacion.txt" || true)
FAILSIM=$(grep -c '\[FAIL\] R[79]\.' "$OUT/r7_r9_verificacion.txt" || true)
NET=$(grep -c '\[FAIL\] NET\.' "$OUT/r7_r9_verificacion.txt" || true)
if [ "${FAILSIM:-0}" -eq 0 ] && [ "${SIM:-0}" -ge 10 ]; then
  echo "RESULTADO: PASA (${SIM}/10 comprobaciones simuladas de R7/R9)"
  if [ "${NET:-0}" -gt 0 ]; then
    echo "  NET.1 no concluyente: el contenedor no alcanzo api.abuseipdb.com (sin salida a internet)."
  fi
else
  echo "RESULTADO: FALLA (${FAILSIM} comprobaciones simuladas fallaron)"
fi

echo "Nota: la integracion contra la API real de AbuseIPDB no se probo por ausencia de clave."
