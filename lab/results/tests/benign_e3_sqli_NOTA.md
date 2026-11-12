# Nota sobre el estrato benigno con patrón SQLi (N-14)

Fecha: 11 de noviembre de 2026.

## Qué se midió

Veinte unidades benignas de E3 con `GET /?q=union+select+articulos&page=1` desde
10.50.0.230 a 10.50.0.249, en dos lotes de diez, con el flujo de n8n activo.
Evidencia cruda: `lab/results/benign_e3_sqli.jsonl` (lote A) y
`lab/results/benign_e3_sqli_n8n.jsonl` (lote B); resumen en
`lab/results/tests/benign_e3_sqli.txt`.

## Resultado

- Lote A (10.50.0.230–10.50.0.239): 10 alertas `SQL Injection Pattern`, sin bloqueo.
- Lote B (10.50.0.240–10.50.0.249): 10 alertas y 10 bloqueos (`LABBLOCK`, TTL 600 s).
- Total: 20/20 alertas, 20/20 bloqueos con el brazo n8n, FPR 1,00; IC 95 % de
  Wilson [0,839; 1].

## Discrepancia del campo `arm`

El lote A se ejecutó con `lab_config.arm='f2b'` y el lote B con `arm='n8n'`, pero
el campo `arm` de ambos JSONL dice `"n8n"`. No es un error de la campaña: el campo
registra el argumento `--arm` de `lab/benign_e1.py`, no el brazo configurado en el
pipeline. El brazo efectivo se evidencia en la respuesta: el lote A no bloqueó y
el lote B sí. Al final del lote B se ejecutó `/reset` y se restauró
`lab_config.arm='f2b'`.

## Alcance

Estas unidades son posteriores a la campaña y no forman parte de
`lab/results/*.jsonl`, que es lo que consume `analysis/report_tables.py`. El
FPR = 0,000 de E2 y E3 solo cubre unidades benignas sin el patrón; el estrato se
informa por separado en la Tabla 10 y en la sección 7.4 del informe.
