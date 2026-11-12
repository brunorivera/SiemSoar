-- Prueba de la deduplicacion post-campana a nivel de base de datos.
-- No forma parte de la campana y no modifica el artefacto medido.
-- Verifica que el margen max(win + 60, GRACE) no suprima una reincidencia
-- posterior al TTL de bloqueo de 600 s.

\timing off
SELECT now() AS fecha_ejecucion, version() AS motor;

CREATE TEMP TABLE dedup_params(rule text, win integer, ttl integer);
INSERT INTO dedup_params VALUES
  ('regla 1', 300, 600),
  ('regla 2', 600, 600),
  ('regla 3', 60, 600),
  ('regla 4', 1, 600),
  ('regla 5', 1, 600);

SELECT rule, win,
       win + 600 + 60 AS margen_anterior,
       GREATEST(win + 60, 600) AS margen_nuevo,
       GREATEST(win + 60, 600) > ttl AS cubre_ttl
FROM dedup_params ORDER BY win DESC;

INSERT INTO alerts(timestamp, severity, category, source_host, source_ip,
                   event_count, description, status)
VALUES (now() - interval '590 seconds', 'low', 'DEDUP TEST', 'lab-test',
        '10.50.0.253', 1, 'prueba dedup post-campana', 'new');

-- Edad 590 s: ambos margenes suprimen (la alerta es mas reciente que el margen).
SELECT 'edad 590 s' AS caso,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (600 || ' seconds')::interval) AS suprime_margen_600,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (660 || ' seconds')::interval) AS suprime_margen_660;

-- Edad 610 s: el margen de 600 s ya no suprime (permite re-alertar tras el TTL).
UPDATE alerts SET timestamp = now() - interval '610 seconds'
WHERE source_ip = '10.50.0.253' AND category = 'DEDUP TEST';
SELECT 'edad 610 s' AS caso,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (600 || ' seconds')::interval) AS suprime_margen_600,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (660 || ' seconds')::interval) AS suprime_margen_660;

-- Edad 650 s: solo el margen de la regla 2 (660 s) sigue suprimiendo.
UPDATE alerts SET timestamp = now() - interval '650 seconds'
WHERE source_ip = '10.50.0.253' AND category = 'DEDUP TEST';
SELECT 'edad 650 s' AS caso,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (600 || ' seconds')::interval) AS suprime_margen_600,
       EXISTS (SELECT 1 FROM alerts WHERE source_ip = '10.50.0.253'
               AND category = 'DEDUP TEST'
               AND timestamp > now() - (660 || ' seconds')::interval) AS suprime_margen_660;

DELETE FROM alerts WHERE source_ip = '10.50.0.253' AND category = 'DEDUP TEST';
