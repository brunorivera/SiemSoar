# Correcciones posteriores a la campaña

Estos archivos **no** son el artefacto medido y no deben aplicarse al commit
`38d2d3c` (campaña E1–E3) ni al commit `fc99b02` (repetición de E1) sin una
campaña nueva y un manifiesto nuevo. El artefacto medido se conserva en
`lab/pipeline.js`, `lab/victim/block_agent.py` y `lab/docker-compose.yml`.

## 1. Horizonte de ingesta y deduplicado

`lab/post_campana/pipeline.post_campana.diff` cambia dos cosas:

- `GRACE = 180` → `GRACE = 600`: cubre la ventana de correlación más larga del
  catálogo (600 s de la regla 2).
- Deduplicado de alertas: `win + GRACE + 60` → `max(win + 60, GRACE)`. El margen
  queda en la ventana de la regla más 60 s, pero nunca por debajo del horizonte
  de ingesta. La corrección intermedia `win + 60` dejaba márgenes de 360, 660,
  120, 61 y 61 s: para las reglas 1, 3, 4 y 5 el margen era menor que el TTL de
  bloqueo de 600 s, de modo que una dirección que reincidía después de que el
  agente retiraba el bloqueo seguía suprimida. `max(win + 60, GRACE)` produce
  márgenes de 600, 660, 600, 600 y 600 s: solo la regla 2 supera el TTL, por
  60 s, y ninguna queda por debajo.

Con el dedup original (`win + GRACE + 60`) los márgenes eran 960, 1260, 720, 661
y 661 s: todos superaban el TTL. El efecto de la deduplicación sobre la ventana
efectiva no se midió en la campaña; se declara como comportamiento propuesto del
artefacto, no como resultado experimental. La prueba a nivel de base de datos
`lab/post_campana/test_dedup.sql` (salida en `lab/results/tests/dedup_*.txt`)
verifica los márgenes y el corte en 600 s; tampoco es una medición de campaña.

### Diferencias reales entre las dos copias

`lab/pipeline.js` (artefacto medido) y `lab/post_campana/pipeline.js` difieren
solo en los dos puntos anteriores: `GRACE` (180 → 600) y la expresión del margen
de deduplicación (`win + GRACE + 60` → `max(win + 60, GRACE)`), más los
comentarios asociados. No hay otras diferencias de código. El diff reproducible
es `lab/post_campana/pipeline.post_campana.diff`.

El parche se aplica sobre `lab/pipeline.js` en una copia limpia; el resultado es
el que se conserva en `lab/post_campana/pipeline.js`.

```bash
git apply --check lab/post_campana/pipeline.post_campana.diff
git apply lab/post_campana/pipeline.post_campana.diff
```

Después hay que regenerar `lab/pipeline-wf.json` con `lab/build_workflow.py`,
volver a importar el flujo, ejecutar `lab/tests/` y actualizar el manifiesto. Los
resultados publicados no cambian: la campaña midió el código anterior.

## 2. Agente de bloqueo

`lab/post_campana/block_agent_secure.py` exige `X-Block-Token` en `/block`,
`/unblock`, `/reset` y `/blocked`; no arranca sin `BLOCK_AGENT_TOKEN`; valida
IPv4 y excluye `10.50.0.1` y `127.0.0.1`. Por defecto escucha en
`127.0.0.1:9000`; para que el contenedor n8n lo alcance en una campaña nueva,
definir `BLOCK_AGENT_BIND=0.0.0.0` y aislar el puerto en la red de Docker. El
token no reemplaza el aislamiento de red; `/health` queda sin autenticación.

Verificación: `python lab/post_campana/test_block_agent.py` (6 casos:
`/health`, 401 sin token, 401 con token incorrecto, 400 con IP inválida, 200 con
token válido, `skipped=excluded` para IP excluida). Resultado en
`lab/results/tests/block_agent_secure.txt`.

El pipeline medido no envía el token; para usar el agente seguro en una campaña
nueva hay que añadir el encabezado `X-Block-Token` a la llamada de bloqueo y
regenerar el flujo. El agente seguro no forma parte de la medición publicada.

## 3. Imágenes fijadas por digest

`lab/docker-compose.pinned.yml` es un override para una campaña nueva:

```bash
cp lab/.env.example lab/.env
# editar lab/.env con credenciales nuevas
docker compose --env-file lab/.env \
  -f lab/docker-compose.yml -f lab/docker-compose.pinned.yml up -d
```

`lab/docker-compose.yml` no se modifica: es el archivo que usó la campaña
publicada y su hash figura en los manifiestos. El override fija
`postgres@sha256:f7d23353…` y
`docker.n8n.io/n8nio/n8n@sha256:dd580fe1…`, y exige `POSTGRES_PASSWORD`,
`N8N_ENCRYPTION_KEY` y `BLOCK_AGENT_TOKEN` por entorno.

## 4. Regla 3: ventana de 120 s

`lab/post_campana/rule3_window.sql` lleva `detection_rules.time_window` de la
regla 3 (`Port Scan Detection`) de 60 s a 120 s. La ventana de 60 s igualaba el
período de sondeo del pipeline (60 s), de modo que R1 no podía cumplirse; con
120 s, T < ventana. No se aplica al artefacto medido:
`lab/scripts/seed_rules.sql` no se modifica.

## 5. Unidades benignas de SQLi

Se ejecutó post-campaña, con el brazo `f2b` y con el brazo `n8n`:

- `f2b`: 10 unidades benignas con patrón SQLi (10.50.0.230–239) → 10 alertas
  `SQL Injection Pattern`, sin bloqueos.
- `n8n`: 10 unidades benignas con patrón SQLi (10.50.0.240–249) → 10 alertas y
  10/10 bloqueos (ttl=600), `attack_patterns.is_blocked=10`, agente `/blocked`
  con 10 IPs y 10 líneas BLOCK en `blocks.log`.

Los datos están en `lab/results/benign_e3_sqli.jsonl` (f2b) y
`lab/results/benign_e3_sqli_n8n.jsonl` (n8n); el resumen y la conclusión, en
`lab/results/tests/benign_e3_sqli.txt`. La fila de la Tabla 10 del informe
corresponde al estrato completo de 20 unidades: VP/FN/precisión «—», FP=20, VN=0,
FPR 1,00; 20/20 alertas y 10/20 bloqueos (solo el lote con brazo n8n). No forma parte de `lab/results/*.jsonl` del
manifiesto y no se usa para H3.

## 6. Verificación mínima antes de publicar

```bash
python analysis/report_tables.py
python analysis/t2_metrics_v4.py
python analysis/power_analysis.py
python lab/verify_manifest.py
git diff --check
```

`python lab/verify_manifest.py` debe seguir en 18/18; `report_tables.py` debe
producir la misma salida que la campaña (Tablas 9 y 10), porque lee solo
`lab/results/*.jsonl` y `benign_e2_e3_summary.json`, no la base viva.
