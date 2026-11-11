-- Corrección post-campaña N-12: la regla 3 (Port Scan Detection) tenía
-- time_window = 60 s, igual al período de sondeo del pipeline (60 s).
-- R1 exige T < ventana; se lleva la ventana a 120 s.
-- No se aplica al artefacto medido: lab/scripts/seed_rules.sql no se modifica.
BEGIN;
UPDATE detection_rules
   SET time_window = 120
 WHERE id = 3
   AND name = 'Port Scan Detection';
COMMIT;

SELECT id, name, threshold, time_window, enabled
  FROM detection_rules
 WHERE id = 3;
