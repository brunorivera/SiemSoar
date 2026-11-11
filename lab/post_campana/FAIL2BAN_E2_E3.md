# Implementación de filtros Fail2ban para E2 y E3 (Post-campaña, no medido)

**Estado:** Diseñado y verificado sintácticamente; **no medido en la campaña**.

El artefacto medido conserva `lab/victim/jail.local` únicamente con la cárcel `[sshd]`.

## 1. Motivación (N-22)
En la campaña ejecutada, Fail2ban solo contó con la cárcel para SSH (`auth.log`), por lo que no se midió en E2 (escaneo de puertos) ni en E3 (inyección SQL). Para documentar el intento de comparación en igualdad de condiciones, se desarrollaron los filtros correspondientes.

## 2. Archivos diseñados
1. `filter_apache_sqli.conf`: Expresión regular sobre logs combinados de Apache que captura patrones de inyección SQL (`UNION SELECT`, `SELECT FROM`, `INSERT INTO`, `DROP TABLE`) tanto con espacios directos como con codificación de URL (`%20`, `+`).
2. `filter_portscan_sensor.conf`: Expresión regular que lee los eventos de caída de paquetes o eventos estructurados emitidos por el sensor en `/var/log/security/alerts.log`.
3. `jail_post_campana.local`: Define las cárceles `[apache-sqli]` (con `maxretry = 1`, `findtime = 1`, `bantime = 300`) y `[portscan-sensor]` (con `maxretry = 20`, `findtime = 60`, `bantime = 300`).

## 3. Verificación
Se verificó sintácticamente la captura de patrones con `test_fail2ban_regex.py`. No se ejecutó en el laboratorio de contenedores por requerir una nueva campaña y un nuevo protocolo de medición. En el informe se declara que en la campaña medida Fail2ban no contó con filtros configurados para Apache ni para el sensor de red.
