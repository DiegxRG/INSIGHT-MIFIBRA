# InsightVM Pull Integration

Integración para descargar alertas de InsightVM por estrategia `pull`, con snapshot por ejecución, filtros de severidad, reintentos y logs.

Documentacion funcional detallada: [`docs/INSIGHTVM_INTEGRATION_FLOW.md`](docs/INSIGHTVM_INTEGRATION_FLOW.md)

## Inicio rápido (lo principal)

1. Crear y activar un entorno virtual (Recomendado):

En Windows (PowerShell/CMD):
```bash
py -m venv venv
.\venv\Scripts\activate
```

En Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Instalar dependencias:

```bash
py -m pip install -r requirements.txt
```

3. Ejecutar una sola corrida (snapshot):

```bash
py main.py --env-file .env --once
```

4. Ejecutar tests:

```bash
py -m pytest -q
```

## Dónde ver resultados

- Logs:
  - Consola (durante ejecución)
  - Archivo: `logs/integration.log`

- Payloads (en `payloads/`):
  - `raw_api_YYYYmmdd_HHMMSS.json` -> data cruda 1:1 desde API InsightVM.
  - `filtered_YYYYmmdd_HHMMSS.json` -> data filtrada por severidad (por defecto `critical,high`).
  - `prepared_backend_YYYYmmdd_HHMMSS.json` -> artefacto final listo para backend; su lista `alarms` contiene cada payload exacto que se enviaría si `BACKEND_ENABLED=true`.
  - `run_YYYYmmdd_HHMMSS.meta.json` -> metadatos del ciclo (éxito/error, tiempos, conteos).

## Fase actual

Fase actual: validacion del payload final pre-backend.

Avances ya incorporados:

1. `fechaalarma` usa metadata operativa del hallazgo y prioriza `since` cuando InsightVM la expone.
2. el payload final incluye `insightvm_status`.
3. `servidor` usa hostname cuando existe y hace fallback a IP cuando no viene nombre util.
4. `prepared_backend_*.json` es la salida de verdad para revisar exactamente que se enviaria al backend.

## Flujo funcional

1. Baja data desde InsightVM (`/assets`, `/assets/{id}/vulnerabilities`, `/vulnerabilities/{id}`).
2. Si la severidad ya viene en la lista de vulnerabilidades por asset, descarta temprano lo que no coincide para evitar pedir detalles innecesarios.
3. Guarda crudo 1:1 en `raw_api`.
4. Aplica filtro de severidad y guarda resultado operativo en `filtered`.
5. Prepara el payload enriquecido con `asset_id`, `vulnerability_id`, `vulnerability_title`, `severity`, `cvss_score`, `cves`, `source` y lo guarda en `prepared_backend`.
6. Si `BACKEND_ENABLED=true`, envía ese payload preparado al backend (`guarda_alarma.php`).
   Solo se envían hallazgos de severidades configuradas en `ALERT_SEVERITIES` (por defecto: `critical,high`).

## Ejecución continua

Modo servicio (intervalo por defecto: 1 hora):

```bash
py main.py --env-file .env
```

Override de intervalo (ej. 30 min):

```bash
py main.py --env-file .env --interval-seconds 1800
```

## Configuración principal (`.env`)

- `INSIGHTVM_BASE_URL`
- `INSIGHTVM_USER`
- `INSIGHTVM_PASSWORD`
- `INSIGHTVM_TIMEOUT`
- `INSIGHTVM_VERIFY_SSL`
- `PULL_INTERVAL_SECONDS`
- `PAGE_SIZE`
- `MAX_RETRIES`
- `RETRY_BACKOFF_SECONDS`
- `ALERT_SEVERITIES`
- `LOG_LEVEL`
- `LOG_FILE`
- `PAYLOAD_DIR`
- `BACKEND_ENABLED` (true/false)
- `BACKEND_URL` (ej: `https://10.208.232.208/txdxsecure/guarda_alarma.php`)
- `BACKEND_LOCAL`
- `BACKEND_ALARM_TYPE`
- `BACKEND_TIMEOUT`
- `BACKEND_VERIFY_SSL`

Referencia completa: [\.env.example](C:\Users\diego\PROYECTOS\INSIGHT-MIFIBRA\.env.example)

## Integración backend (respuestas esperadas)

La integración envía JSON por `POST` con estos campos:
- `servidor`
- `ip`
- `TipoAlarma`
- `Local`
- `fechaalarma`
- `asset_id`
- `vulnerability_id`
- `vulnerability_title`
- `severity`
- `cvss_score`
- `cves`
- `source`
- `insightvm_status`

Respuestas que maneja:
- Éxito: `{"success": true}`
- Error de campos: `{"success": false, "message": "Campos requeridos faltantes: ..."}`
- Conflicto: `{"success": false, "message": "Ya existe un registro activo ..."}`
- Error BD/general: `{"success": false, "message": "Error en la base de datos"}`

El detalle del envío se registra en `run_*.meta.json` bajo la clave `backend`:
- `sent_ok`
- `conflicts`
- `validation_errors`
- `backend_errors`
