# InsightVM Pull Integration

Integración para descargar alertas de InsightVM por estrategia `pull`, con filtros de severidad, reintentos, logs y persistencia local opcional.

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

3. Ejecutar una sola corrida:

```bash
py main.py --env-file .env --once
```

4. Ejecutar tests:

```bash
py -m pytest -q
```

5. Levantar viewer local de validacion:

```bash
py -m backend.server --payload-dir payloads --frontend-dir frontend --port 8787
```

Luego abrir:

```text
http://127.0.0.1:8787
```

El viewer muestra:

- el snapshot final preparado para backend;
- la proyeccion de ese snapshot sobre las tablas `alarmas` y `detalle_alerta_insightvm`;
- el `run_latest.meta.json`;
- el `filtered_latest.json`.

## Dónde ver resultados

- Logs:
  - Consola (durante ejecución)
  - Archivo: `logs/integration.log`

- Payloads (en `payloads/`):
  - `filtered_latest.json` -> data filtrada y compacta por severidad (por defecto `critical,high`).
  - `prepared_backend_latest.json` -> artefacto final listo para backend; su lista `alarms` contiene cada payload exacto que se enviaría si `BACKEND_ENABLED=true`.
  - `run_latest.meta.json` -> metadatos del último ciclo (éxito/error, tiempos, conteos).
  - `raw_api_YYYYmmdd_HHMMSS.json` -> solo se genera si `PERSIST_RAW_API_DEBUG=true` o si se usa `--persist-raw-api-debug`.

Nota importante:
`raw_api_*` es solo un artefacto de diagnóstico. No participa en el filtrado ni en la preparación del payload backend. Si no se guarda `raw_api_*`, igual se siguen generando normalmente `filtered_latest.json` y `prepared_backend_latest.json`.

Otro detalle importante:
`filtered_latest.json`, `prepared_backend_latest.json` y `run_latest.meta.json` se sobreescriben en cada corrida; no crecen por timestamp. El único artefacto acumulativo por defecto es `raw_api_*` cuando el modo debug está activo. Si no quieres guardar ningún snapshot local en despliegue, usa `PERSIST_PAYLOAD_ARTIFACTS=false`.

## Fase actual

Fase actual: validacion del payload final pre-backend.

Avances ya incorporados:

1. `fechaalarma` usa metadata operativa del hallazgo y prioriza `since` cuando InsightVM la expone.
2. el payload final incluye `finding_id` para relacionar alarma y detalle técnico.
3. `servidor` usa hostname cuando existe y hace fallback a IP cuando no viene nombre util.
4. `prepared_backend_latest.json` es la salida de verdad para revisar exactamente que se enviaria al backend.

## Flujo funcional

1. Baja data desde InsightVM (`/assets`, `/assets/{id}/vulnerabilities`, `/vulnerabilities/{id}`).
2. Si la severidad ya viene en la lista de vulnerabilidades por asset, descarta temprano lo que no coincide para evitar pedir detalles innecesarios.
3. Aplica filtro de severidad y guarda un resultado compacto en `filtered_latest.json`.
4. Prepara el payload enriquecido con `finding_id`, `asset_id`, `vulnerability_id`, `vulnerability_title`, `severity`, `cvss_score`, `cves`, `source` y lo guarda en `prepared_backend`.
5. Si está activo el modo diagnóstico, también persiste `raw_api` para análisis.
6. Si `BACKEND_ENABLED=true`, envía ese payload preparado al backend (`guarda_alarma.php`).
   Solo se envían hallazgos de severidades configuradas en `ALERT_SEVERITIES` (por defecto: `critical,high`).

## Formas de ejecución

Corrida única con copia local normal:

```bash
py main.py --env-file .env --once
```

Qué guarda:
`filtered_latest.json`, `prepared_backend_latest.json` y `run_latest.meta.json`.

Corrida única sin copias locales:

```bash
py main.py --env-file .env --once --no-persist-payloads
```

Qué hace:
envía al backend y no deja snapshots JSON en `payloads/`.

Corrida única en modo debug:

```bash
py main.py --env-file .env --once --persist-raw-api-debug
```

Qué guarda además:
un `raw_api_YYYYmmdd_HHMMSS.json` con la respuesta cruda de InsightVM.

Corrida única sin copias locales pero con debug activado:

```bash
py main.py --env-file .env --once --no-persist-payloads --persist-raw-api-debug
```

Nota:
si usas `--no-persist-payloads`, no se guardará ningún JSON local, así que el flag de debug tampoco dejará `raw_api_*` en disco.

Modo servicio continuo con intervalo del `.env`:

```bash
py main.py --env-file .env
```

Modo servicio continuo con intervalo manual (ej. cada 30 min):

```bash
py main.py --env-file .env --interval-seconds 1800
```

Ejecutar tests:

```bash
py -m pytest -q
```

Recomendación para producción:
si tu plataforma ya tiene scheduler (`cron`, Task Scheduler, Kubernetes CronJob, etc.), lo más simple es ejecutar `py main.py --env-file .env --once --no-persist-payloads` cada domingo a las 09:00.

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
- `PERSIST_PAYLOAD_ARTIFACTS` (true/false)
- `PERSIST_RAW_API_DEBUG` (true/false)
- `BACKEND_ENABLED` (true/false)
- `BACKEND_URL` (ej: `https://10.208.232.208/txdxsecure/guarda_alarma.php`)
- `BACKEND_LOCAL`
- `BACKEND_ALARM_TYPE`
- `BACKEND_TIMEOUT`
- `BACKEND_VERIFY_SSL`

Referencia completa: [`.env.example`](.env.example)

## Integración backend (respuestas esperadas)

La integración envía JSON por `POST` con estos campos:
- `finding_id`
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

Respuestas que maneja:
- Éxito: `{"success": true}`
- Error de campos: `{"success": false, "message": "Campos requeridos faltantes: ..."}`
- Conflicto: `{"success": false, "message": "Ya existe un registro activo ..."}`
- Error BD/general: `{"success": false, "message": "Error en la base de datos"}`

El detalle del envío se registra en `run_latest.meta.json` bajo la clave `backend`:
- `sent_ok`
- `conflicts`
- `validation_errors`
- `backend_errors`

## Política de persistencia

- Corrida exitosa normal: guarda `filtered_latest.json`, `prepared_backend_latest.json` y `run_latest.meta.json`.
- Corrida exitosa en modo debug: además guarda `raw_api_YYYYmmdd_HHMMSS.json`.
- Corrida fallida total: actualiza solo `run_latest.meta.json`.
- Si falla la descarga o transformación local, se conservan los últimos `filtered_latest.json` y `prepared_backend_latest.json` válidos.
- Si `PERSIST_PAYLOAD_ARTIFACTS=false`, no se guarda ningún JSON local en `payloads/`.

## Política de reintentos

- Reintenta solo errores transitorios de descarga desde InsightVM: `429`, `500`, `502`, `503`, `504`, timeout y errores de conexión.
- No reintenta errores definitivos: `401`, `403`, `404` y respuestas inválidas no transitorias.
- El envío `POST` al backend no tiene reintentos automáticos para evitar duplicados.
