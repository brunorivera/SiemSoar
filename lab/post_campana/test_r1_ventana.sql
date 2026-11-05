-- R1: ventana deslizante y horizonte de ingesta (GRACE).
-- Prueba a nivel de base de datos, posterior a la campana y no medida.
-- Inserta eventos sinteticos en una transaccion y la revierte al final.
--
-- Caso A: 5 eventos en 20 s. Debe alertar con cualquier GRACE.
-- Caso B: 5 eventos en 400 s. No debe alertar: la ventana de 300 s solo
--         contiene los ultimos eventos.
-- Caso C: 5 eventos en 280 s. Debe alertar: los 5 caben en la ventana de 300 s.
--         Con GRACE = 180 s el evento mas antiguo queda fuera del horizonte de
--         ingesta y la regla no alcanza el umbral; con GRACE = 600 s alerta.
--
-- Uso:
--   docker exec -i lab-postgres psql -U admin -d security_monitoring \
--     -v ON_ERROR_STOP=1 < lab/post_campana/test_r1_ventana.sql

BEGIN;

CREATE TEMP TABLE r1_synth (
  case_id  text,
  src_ip   inet,
  event_ts timestamptz,
  ingest_ts timestamptz,
  rule_id  integer,
  rule_name text,
  raw_log  text
);

INSERT INTO r1_synth
SELECT 'A', '10.50.0.240', t, t, 1, 'SSH Brute Force', 'synthetic A'
FROM (VALUES (20),(15),(10),(5),(0)) AS v(age)
CROSS JOIN LATERAL (SELECT now() - make_interval(secs => v.age) AS t) AS x;

INSERT INTO r1_synth
SELECT 'B', '10.50.0.241', t, t, 1, 'SSH Brute Force', 'synthetic B'
FROM (VALUES (400),(300),(200),(100),(0)) AS v(age)
CROSS JOIN LATERAL (SELECT now() - make_interval(secs => v.age) AS t) AS x;

INSERT INTO r1_synth
SELECT 'C', '10.50.0.242', t, t, 1, 'SSH Brute Force', 'synthetic C'
FROM (VALUES (280),(210),(140),(70),(0)) AS v(age)
CROSS JOIN LATERAL (SELECT now() - make_interval(secs => v.age) AS t) AS x;

\echo 'R1 | eventos sinteticos por caso (event_ts = ingest_ts)'
SELECT case_id, count(*) AS events,
       min(now() - event_ts) AS age_max,
       max(now() - event_ts) AS age_min
FROM r1_synth
GROUP BY case_id
ORDER BY case_id;

\echo 'R1 | correlacion con la consulta del pipeline, GRACE 180 vs 600'
SELECT g.grace,
       c.case_id,
       c.expected_alert,
       h.ingested,
       h.in_window,
       CASE WHEN h.in_window >= 5 THEN 1 ELSE 0 END AS observed_alert,
       CASE WHEN (CASE WHEN h.in_window >= 5 THEN 1 ELSE 0 END) = c.expected_alert
            THEN 'PASA' ELSE 'FALLA' END AS result
FROM (VALUES (180),(600)) AS g(grace)
CROSS JOIN (VALUES ('A',1),('B',0),('C',1)) AS c(case_id, expected_alert)
LEFT JOIN LATERAL (
  WITH recent AS (
    SELECT src_ip, event_ts
    FROM r1_synth
    WHERE case_id = c.case_id
      AND rule_id = 1
      AND ingest_ts > now() - make_interval(secs => g.grace)
  ),
  anch AS (
    SELECT src_ip, max(event_ts) AS m FROM recent GROUP BY src_ip
  )
  SELECT
    (SELECT count(*)::int FROM recent) AS ingested,
    (SELECT count(*)::int
       FROM recent r JOIN anch a USING (src_ip)
      WHERE r.event_ts > a.m - interval '300 seconds') AS in_window
) AS h ON true
ORDER BY c.case_id, g.grace;

ROLLBACK;
