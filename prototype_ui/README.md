# Prototipo UI — SIEM & SOAR

Prototipo funcional y autocontenido del pipeline descrito en la tesis
**«Análisis automatizado de registros y detección de anomalías con n8n»**.
Permite demostrar en vivo, durante la defensa, la ingesta de logs, la
correlación por ventana deslizante, la generación de alertas, la deduplicación
y la respuesta activa con TTL y desbloqueo manual.

- **Backend:** Python 3.10+ / FastAPI + SQLite.
- **Frontend:** HTML, CSS y JavaScript puro (sin dependencias ni build).
- **Aislamiento:** este directorio es nuevo. **No modifica** `lab/`, `analysis/`
  ni `Database/`, y no usa PostgreSQL, n8n ni Docker.

---

## 1. Arranque rápido (Windows PowerShell)

Desde la raíz del repositorio `SiemSoar`:

```powershell
cd C:\Users\Usuario\Documents\TestTesis\SiemSoar\prototype_ui

# Opcional pero recomendado: entorno virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt

python run.py
```

Abrir en el navegador:

```text
http://127.0.0.1:8000
```

El backend sirve también el frontend, así que **un solo proceso es suficiente**.
La documentación interactiva de la API queda en
`http://127.0.0.1:8000/docs`.

> Si PowerShell bloquea la activación del entorno virtual:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
>
> Si ya tenés `fastapi` y `uvicorn` instalados, podés omitir el `venv` y ejecutar
> directamente `python -m pip install -r requirements.txt` y `python run.py`.

### Alternativa sin `run.py`

```powershell
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

### Linux / macOS

```bash
cd prototype_ui
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

---

## 2. Qué muestra la pantalla

La vista única está dividida en los cuatro bloques pedidos:

| Bloque | Contenido |
|---|---|
| **1. Panel de simulación** | Botones para inyectar ráfagas SSH, escaneo de puertos, SQLi, login root, abuso de sudo y tráfico benigno; botón para forzar un ciclo; ingesta manual de líneas; prueba de exclusión R5 con `10.50.0.1`. |
| **2. Métricas del pipeline** | Eventos parseados, alertas, ciclos (`pipeline_runs`), IPs bloqueadas, MTTD estimado, líneas recibidas, exclusiones R5, GRACE, TTL y listado de las 5 reglas de la Tabla 7. |
| **3. Alertas y bitácora** | Tabla `alerts` en vivo: timestamp, IP de origen, regla, severidad, cantidad de eventos y estado. |
| **4. Respuesta activa** | IPs bloqueadas con TTL restante (cuenta regresiva), regla que lo motivó y botón **Desbloquear** (R6). |

La interfaz consulta `GET /api/dashboard` cada 2,5 s. La cuenta regresiva del
TTL se actualiza cada segundo en el navegador.

---

## 3. Guion sugerido para la defensa (5–8 minutos)

1. **Estado inicial.** Mostrar que hay 5 reglas cargadas y todos los contadores
   en cero. Señalar las exclusiones R5 (`10.50.0.1`, `127.0.0.1`), GRACE 600 s y
   TTL 600 s.
2. **Fuerza bruta SSH.** Clic en *Simular fuerza bruta SSH*. Se inyectan 5 líneas
   `Failed password ... ssh2`. El ciclo crea **1 alerta `high`** y **1 bloqueo**
   con TTL de 600 s. La alerta pasa a `resuelta` con la nota de auto-bloqueo.
3. **Escaneo de puertos.** Clic en *Simular escaneo de puertos*. Se inyectan 20
   líneas `iptables DROP ... DPT=...`; la regla 3 (20 eventos / 60 s) genera una
   alerta `medium` y su bloqueo.
4. **Inyección SQL.** Clic en *Simular inyección SQL*. Una línea con
   `UNION SELECT` dispara la regla 5 (1 evento / 1 s): alerta `high` y bloqueo.
5. **Login root.** Clic en *Simular login root*. La regla 4 (1 evento / 1 s)
   genera una alerta `critical`; además se registra el evento para la regla 1,
   que no alcanza su umbral de 5.
6. **Abuso de sudo.** Clic en *Simular abuso de sudo*. 10 eventos en 600 s
   disparan la regla 2 y su bloqueo.
7. **Tráfico benigno.** Clic en *Inyectar tráfico benigno*. Se reciben 8 líneas,
   **0 eventos parseados, 0 alertas y 0 bloqueos** (control de falsos positivos).
8. **Exclusión R5.** Clic en *Probar exclusión R5 (10.50.0.1)*. Los 5 eventos se
   contabilizan en `parsed_events`, pero el ciclo informa que la IP fue omitida:
   **no hay alerta ni bloqueo**.
9. **Ciclo manual.** Clic en *Ejecutar ciclo del pipeline* sin nueva ingesta:
   se registra una corrida en `pipeline_runs` y, por la deduplicación
   `max(ventana + 60, GRACE)`, no se repiten alertas de la misma regla/IP.
10. **Desbloqueo R6.** En el bloque 4, pulsar **Desbloquear** sobre una IP. La
    fila desaparece inmediatamente y el evento queda anotado en `alerts`.
11. **Reinicio.** El botón *Reiniciar demo* borra eventos, alertas, corridas y
    bloqueos, pero conserva las 5 reglas.

### Demostrar la expiración del TTL en menos de 10 minutos

El TTL por defecto es 600 s (el de la tesis). Para una demostración corta, se
puede arrancar el backend con un TTL de 60 s:

```powershell
$env:PROTOTYPE_TTL = "60"
python run.py
```

El dashboard mostrará el TTL de 60 s y la IP desaparecerá al expirar. GRACE
también es configurable con `PROTOTYPE_GRACE` (por defecto 600 s).

---

## 4. API REST

| Método | Ruta | Función |
|---|---|---|
| `POST` | `/api/ingest` | Ingesta líneas crudas o genera un escenario (`ssh_bruteforce`, `port_scan`, `sqli`, `root_login`, `sudo_abuse`, `benign`, `custom`). |
| `POST` | `/api/run-cycle` | Ejecuta manualmente parseo → correlación → alerta → decisión de bloqueo → `pipeline_runs`. |
| `GET` | `/api/dashboard` | Métricas, reglas, alertas, bloqueos activos con TTL y últimas corridas. |
| `POST` | `/api/unblock` | Desbloquea una IP y retira la regla activa (R6). |
| `POST` | `/api/reset` | Limpia los datos de demostración y conserva las reglas. |
| `GET` | `/api/rules` | Catálogo de las 5 reglas activas. |
| `GET` | `/api/health` | Estado del backend y conteos de tablas. |

### Ejemplos con PowerShell

```powershell
# Salud
Invoke-RestMethod http://127.0.0.1:8000/api/health | ConvertTo-Json -Depth 6

# Simular fuerza bruta SSH y ejecutar el ciclo en la misma llamada
$body = @{ scenario = "ssh_bruteforce"; run_cycle = $true } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/ingest `
  -Method Post -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8

# Dashboard completo
Invoke-RestMethod http://127.0.0.1:8000/api/dashboard | ConvertTo-Json -Depth 8

# Desbloquear una IP (usar la IP que muestre el dashboard)
$unblock = @{ ip = "203.0.113.10" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/unblock `
  -Method Post -ContentType "application/json" -Body $unblock | ConvertTo-Json
```

### Ejemplos con curl

```bash
curl -s http://127.0.0.1:8000/api/health
curl -s -X POST http://127.0.0.1:8000/api/ingest \
  -H 'Content-Type: application/json' \
  -d '{"scenario":"sqli","run_cycle":true}'
curl -s http://127.0.0.1:8000/api/dashboard
```

### Cuerpo de `/api/ingest`

```json
{
  "scenario": "ssh_bruteforce",
  "source_ip": "203.0.113.50",
  "count": 5,
  "run_cycle": true
}
```

Para ingesta manual:

```json
{
  "scenario": "custom",
  "events": [
    "Nov 13 10:00:00 lab-victim sshd[1234]: Failed password for invalid user admin from 203.0.113.77 port 40001 ssh2"
  ],
  "source": "auth.log",
  "run_cycle": true
}
```

---

## 5. Fidelidad con la tesis

| Elemento de la tesis | Implementación en el prototipo |
|---|---|
| 5 reglas de la Tabla 7 | `detection_rules` sembrada con IDs 1–5: SSH 5/300 s, sudo 10/600 s, port scan 20/60 s, root 1/1 s, SQLi 1/1 s. |
| Esquema de datos | Tablas `detection_rules`, `parsed_events`, `alerts`, `attack_patterns` y `pipeline_runs` (SQLite). Se agrega `blocked_ips` para exponer el TTL. |
| Ventana deslizante (R1) | Consulta SQL anclada al evento más reciente de cada (regla, IP), limitada por el horizonte de ingesta `GRACE`. |
| Deduplicación | Margen `max(ventana + 60, GRACE)` de la corrección post-campaña. |
| Validación de IP (R4) | Regex IPv4 canónica antes de persistir o bloquear. |
| Exclusiones (R5) | `10.50.0.1` y `127.0.0.1` nunca generan alerta ni bloqueo. |
| Respuesta activa (R6) | Bloqueo con TTL 600 s, expiración automática y `POST /api/unblock`. |
| Bitácora de corridas (R8) | Cada ciclo inserta una fila en `pipeline_runs` con líneas, eventos, alertas, duración y disparador. |
| MTTD | Estimado como `timestamp de alerta − primera ocurrencia del evento`; se muestra el promedio de las últimas alertas. |

### Límites declarados del prototipo

- Usa **SQLite**, no PostgreSQL; no reemplaza la medición de las campañas.
- Los logs son **simulados** y el bloqueo es **lógico** (tabla `blocked_ips`);
  no ejecuta `iptables` ni interactúa con n8n.
- La lectura incremental por offset/inodo (R2) no se replica: la ingesta es por
  lote y el horizonte `GRACE` cumple el mismo rol de tolerancia al sondeo.
- El MTTD del prototipo es una **estimación didáctica**, no el MTTD medido en
  las campañas E1–E3.
- El enriquecimiento con AbuseIPDB (R7/R9) no está incluido; la decisión de
  bloqueo se basa en la regla, el umbral y la severidad.

---

## 6. Estructura

```text
prototype_ui/
├── backend/
│   ├── __init__.py
│   ├── app.py          # FastAPI: endpoints + servido del frontend
│   ├── db.py           # esquema SQLite + 5 reglas de la Tabla 7
│   └── engine.py       # parseo, correlación, dedup, bloqueo TTL, dashboard
├── data/
│   └── prototype.db    # se crea en tiempo de ejecución (ignorado por git)
├── frontend/
│   ├── index.html      # vista única con los 4 bloques
│   ├── styles.css      # tema oscuro minimalista, sin librerías
│   └── app.js          # polling, simulación, tablas y cuenta regresiva
├── .gitignore
├── README.md
├── requirements.txt
└── run.py              # lanzador: python run.py
```

---

## 7. Reinicio y resolución de problemas

- **Reiniciar solo los datos:** botón *Reiniciar demo* o
  `Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/reset`.
- **Borrar la base completa:** detener el backend y eliminar
  `prototype_ui/data/prototype.db` (y sus archivos `-wal` / `-shm`). Al arrancar
  se recrea y se vuelven a sembrar las 5 reglas.
- **Puerto ocupado:** ejecutar con otro puerto:
  `python -m uvicorn backend.app:app --port 8001` y abrir
  `http://127.0.0.1:8001`.
- **La interfaz dice «API sin conexión»:** verificar que el backend esté
  corriendo y que la URL sea la misma del servidor. Si se abre el `index.html`
  directamente con `file://`, el frontend apunta a `http://127.0.0.1:8000`;
  conviene usar el servidor integrado.
- **PowerShell no activa el venv:** usar
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` o ejecutar sin
  `venv`.

---

## 8. Verificación rápida del backend

Con el servidor levantado:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health | ConvertTo-Json -Depth 6
```

Salida esperada (conteos pueden variar):

```json
{
  "ok": true,
  "db_path": "...\\prototype_ui\\data\\prototype.db",
  "counts": {
    "detection_rules": 5,
    "parsed_events": 0,
    "alerts": 0,
    "pipeline_runs": 0,
    "blocked_ips": 0
  }
}
```

Prueba funcional mínima sin usar la interfaz:

```powershell
$body = @{ scenario = "ssh_bruteforce"; source_ip = "203.0.113.77"; run_cycle = $true } | ConvertTo-Json
$r = Invoke-RestMethod -Uri http://127.0.0.1:8000/api/ingest -Method Post -ContentType "application/json" -Body $body
$r.cycle | ConvertTo-Json -Depth 8
```

Se espera `alerts_created = 1`, `blocked` con `203.0.113.77` y
`ttl_seconds = 600`. Luego:

```powershell
$u = @{ ip = "203.0.113.77" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/unblock -Method Post -ContentType "application/json" -Body $u
```
