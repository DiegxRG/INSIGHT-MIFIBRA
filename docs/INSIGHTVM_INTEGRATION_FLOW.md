# Documentacion del flujo InsightVM -> MiFibra/Txdxsecure

## Finalidad

Este proyecto descarga hallazgos de seguridad desde InsightVM, filtra solo las vulnerabilidades relevantes para la operacion y prepara un payload compatible con el backend de MiFibra/Txdxsecure.

El objetivo operativo es:

1. Identificar equipos afectados en InsightVM.
2. Detectar vulnerabilidades por equipo.
3. Conservar solo severidades configuradas, actualmente `critical` y `high`.
4. Enriquecer cada hallazgo con detalle tecnico minimo.
5. Preparar un JSON limpio para que el backend pueda persistirlo en su base de datos.

## Estado actual

Actualmente el codigo ya implementa lo siguiente:

1. Consulta `assets` desde InsightVM.
2. Consulta `assets/{asset_id}/vulnerabilities` para cada equipo.
3. Aplica filtro temprano por severidad cuando esa severidad ya viene en la lista de vulnerabilidades del asset.
4. Consulta `vulnerabilities/{vulnerability_id}` solo para vulnerabilidades que pasan el filtro o cuando hace falta confirmar severidad/detalle.
5. Normaliza la data a un formato operativo interno.
6. Genera un payload enriquecido listo para backend.
7. Guarda snapshots locales de cada corrida.
8. Solo envia al backend si `BACKEND_ENABLED=true`.

En otras palabras: el proyecto ya esta preparado para bajar la data, filtrarla y dejar el envio listo. Para pruebas controladas se recomienda mantener `BACKEND_ENABLED=false`.

## Flujo funcional implementado

El flujo real del sistema es este:

1. `GET /assets`
2. Tomar `asset_id`, hostname y direccion IP del asset.
3. `GET /assets/{asset_id}/vulnerabilities`
4. Revisar la lista de vulnerabilidades asociadas a ese equipo.
5. Si la referencia de vulnerabilidad ya trae severidad, descartar de inmediato las que no pertenezcan a `ALERT_SEVERITIES`.
6. Solo para vulnerabilidades candidatas, consultar `GET /vulnerabilities/{vulnerability_id}`.
7. Unir datos de equipo + ocurrencia por asset + detalle de vulnerabilidad.
8. Normalizar el hallazgo.
9. Guardar snapshots locales.
10. Si backend esta habilitado, enviar al endpoint configurado.

## Punto exacto del filtro

El filtro recomendado no va antes de bajar `assets`, porque `assets` solo lista equipos.

El filtro tampoco debe esperar hasta el final, porque eso obligaria a pedir detalle de todas las vulnerabilidades.

El punto correcto del filtro es:

1. bajar equipos,
2. bajar la lista de vulnerabilidades de cada equipo,
3. filtrar `critical` y `high`,
4. recien despues bajar el detalle de esas vulnerabilidades filtradas.

Ese enfoque reduce trafico y evita descargar metadata innecesaria.

## Endpoints consumidos

### 1. `GET /assets`

Finalidad:

- Obtener la lista de equipos detectados por InsightVM.

Datos de interes que se extraen:

- `id` -> `asset_id`
- `hostName` / `hostname` / `name` -> nombre del servidor o equipo
- `ip` o `addresses[].ip` -> IP del equipo

Ejemplo conceptual:

```json
{
  "resources": [
    {
      "id": "282",
      "hostName": "OLT-PRUEBA-01",
      "addresses": [
        { "ip": "10.0.0.100" }
      ]
    }
  ]
}
```

### 2. `GET /assets/{asset_id}/vulnerabilities`

Finalidad:

- Obtener la lista de vulnerabilidades asociadas a un equipo especifico.

Datos de interes que pueden venir aqui:

- `id` -> `vulnerability_id`
- `severity` -> usado para filtro temprano
- fechas o metadata de ocurrencia en el asset, si InsightVM las devuelve

Ejemplo conceptual:

```json
{
  "resources": [
    {
      "id": "windows-hotfix-ms03-007",
      "severity": "critical"
    },
    {
      "id": "openssl-low-example",
      "severity": "low"
    }
  ]
}
```

Comportamiento esperado:

- Si la severidad ya viene aqui, `low`, `medium` e `info` se descartan antes de pedir detalle.
- Si no viene severidad, el sistema puede necesitar consultar el detalle para clasificar correctamente.

### 3. `GET /vulnerabilities/{vulnerability_id}`

Finalidad:

- Obtener el detalle tecnico de la vulnerabilidad.

Datos de interes:

- `id`
- `title` o `name`
- `severity`
- `cvss_score` o `cvss.v3.score`
- `cves`
- `riskScore`

Ejemplo conceptual:

```json
{
  "id": "windows-hotfix-ms03-007",
  "title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "severity": "critical",
  "cvss": {
    "v3": {
      "score": 9.8
    }
  },
  "cves": ["CVE-2017-11804"],
  "riskScore": 900
}
```

## Como baja y transforma la data el codigo actual

### Colector

Archivo principal: `insightvm_pull/collector.py`

Responsabilidades:

1. Descargar assets paginados.
2. Consultar vulnerabilidades por asset.
3. Filtrar temprano por severidad cuando es posible.
4. Consultar detalle solo de vulnerabilidades candidatas.
5. Construir una lista interna de `findings`.

Cada `finding` interno queda aproximadamente asi:

```json
{
  "asset_id": "282",
  "asset_ip": "10.0.0.100",
  "asset_hostname": "OLT-PRUEBA-01",
  "vulnerability_id": "windows-hotfix-ms03-007",
  "title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "vulnerability_title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "severity": "critical",
  "cvss": 9.8,
  "cvss_score": 9.8,
  "risk_score": 900,
  "cves": ["CVE-2017-11804"],
  "source": "insightvm",
  "estado": 1,
  "fechaalarma": "2026-05-27 16:10:00"
}
```

### Filtro operativo

Archivo: `insightvm_pull/collector.py`

Funcion relevante: `filter_payload_by_severity(...)`

Uso:

- garantiza que el payload operativo final solo conserve severidades permitidas;
- por defecto: `critical,high`.

### Preparacion de payload para backend

Archivo principal: `insightvm_pull/backend_client.py`

Responsabilidades:

1. Validar campos minimos (`servidor` e `ip`).
2. Transformar el `finding` interno a JSON compatible con backend.
3. Guardar el resultado preparado aunque el backend no este habilitado.
4. Enviar solo si `BACKEND_ENABLED=true`.

## Archivos generados por cada corrida

La carpeta `payloads/` guarda cuatro salidas por ejecucion:

1. `raw_api_YYYYmmdd_HHMMSS.json`
   Contiene respuestas crudas desde InsightVM:
   - paginas de `assets`
   - vulnerabilidades por asset
   - definiciones de vulnerabilidades consultadas

2. `filtered_YYYYmmdd_HHMMSS.json`
   Contiene hallazgos ya filtrados por severidad.

3. `prepared_backend_YYYYmmdd_HHMMSS.json`
   Contiene el JSON final listo para el backend.

4. `run_YYYYmmdd_HHMMSS.meta.json`
   Contiene metadatos de la corrida:
   - exito o error
   - cantidad de assets
   - cantidad de hallazgos
   - cuantos se filtraron
   - datos del envio a backend si aplica

## Formato actual del payload final hacia backend

El payload actual que prepara el codigo para cada hallazgo es este:

```json
{
  "servidor": "OLT-PRUEBA-01",
  "ip": "10.0.0.100",
  "TipoAlarma": "1 - Alarma de seguridad [Critical] - Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "Local": "Txdxsecure",
  "fechaalarma": "2026-05-27 16:10:00",
  "estado": 1,
  "asset_id": "282",
  "vulnerability_id": "windows-hotfix-ms03-007",
  "vulnerability_title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cves": "CVE-2017-11804",
  "source": "insightvm"
}
```

Campos base originalmente requeridos por backend:

- `servidor`
- `ip`
- `TipoAlarma`
- `Local`
- `fechaalarma`

Campos enriquecidos agregados:

- `estado`
- `asset_id`
- `vulnerability_id`
- `vulnerability_title`
- `severity`
- `cvss_score`
- `cves`
- `source`

## Modelo logico recomendado para base de datos

El codigo actual envia un solo JSON enriquecido al endpoint `guarda_alarma.php`. Sin embargo, del lado de base de datos, lo mas ordenado es que el backend lo separe en dos tablas.

### Tabla 1: `alarmas`

Finalidad:

- guardar la cabecera operativa del evento.

Campos sugeridos:

- `id` (PK interna)
- `servidor`
- `ip`
- `TipoAlarma`
- `Local`
- `fechaalarma`
- `estado`
- `source`

Ejemplo logico de fila:

```json
{
  "id": 150,
  "servidor": "OLT-PRUEBA-01",
  "ip": "10.0.0.100",
  "TipoAlarma": "1 - Alarma de seguridad [Critical] - Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "Local": "Txdxsecure",
  "fechaalarma": "2026-05-27 16:10:00",
  "estado": 1,
  "source": "insightvm"
}
```

### Tabla 2: `alarma_vulnerabilidad_detalle`

Finalidad:

- guardar el contexto tecnico asociado a la alarma.

Relacion:

- `alarma_vulnerabilidad_detalle.alarma_id` -> FK hacia `alarmas.id`

Campos sugeridos:

- `id` (PK interna)
- `alarma_id` (FK)
- `asset_id`
- `vulnerability_id`
- `vulnerability_title`
- `severity`
- `cvss_score`
- `cves`

Ejemplo logico de fila:

```json
{
  "id": 900,
  "alarma_id": 150,
  "asset_id": "282",
  "vulnerability_id": "windows-hotfix-ms03-007",
  "vulnerability_title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cves": "CVE-2017-11804"
}
```

## Payload logico para cada tabla

Si el backend decide partir el JSON en dos inserciones, el mapeo recomendado seria este.

### Payload logico para `alarmas`

```json
{
  "servidor": "OLT-PRUEBA-01",
  "ip": "10.0.0.100",
  "TipoAlarma": "1 - Alarma de seguridad [Critical] - Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "Local": "Txdxsecure",
  "fechaalarma": "2026-05-27 16:10:00",
  "estado": 1,
  "source": "insightvm"
}
```

### Payload logico para `alarma_vulnerabilidad_detalle`

```json
{
  "asset_id": "282",
  "vulnerability_id": "windows-hotfix-ms03-007",
  "vulnerability_title": "Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cves": "CVE-2017-11804"
}
```

Nota importante:

- el backend tendria que insertar primero en `alarmas`,
- recuperar el `id` generado,
- e insertar despues en `alarma_vulnerabilidad_detalle` usando `alarma_id` como foreign key.

## Flujo completo esperado hasta envio exitoso

### Etapa 1. Descarga

1. El servicio se ejecuta manualmente o por scheduler.
2. Se conecta a InsightVM usando `INSIGHTVM_BASE_URL`, usuario y password.
3. Descarga `assets` paginados.

### Etapa 2. Descubrimiento por equipo

1. Por cada `asset_id`, consulta `assets/{asset_id}/vulnerabilities`.
2. Obtiene la lista de vulnerabilidades asociadas al equipo.

### Etapa 3. Filtrado

1. Si la lista ya trae `severity`, conserva solo `critical` y `high`.
2. Descarta temprano severidades no requeridas.

### Etapa 4. Enriquecimiento

1. Para cada `vulnerability_id` filtrado, consulta `vulnerabilities/{vulnerability_id}`.
2. Obtiene titulo, CVSS, CVEs y otros datos tecnicos.
3. Une asset + vulnerabilidad del asset + detalle tecnico.

### Etapa 5. Normalizacion

1. Construye un `finding` interno unificado.
2. Genera `filtered_*.json`.
3. Genera `prepared_backend_*.json`.

### Etapa 6. Envio al backend

1. Si `BACKEND_ENABLED=false`, no envia nada y solo deja la evidencia local.
2. Si `BACKEND_ENABLED=true`, hace `POST` a `BACKEND_URL`.
3. El backend responde con uno de estos escenarios:
   - exito,
   - error de validacion,
   - conflicto por registro activo,
   - error general.
4. El resultado queda registrado en `run_*.meta.json`.

## Respuestas esperadas del backend

Casos contemplados actualmente en codigo:

### Exito

```json
{ "success": true }
```

### Error por campos requeridos

```json
{ "success": false, "message": "Campos requeridos faltantes: servidor, ip" }
```

### Conflicto por registro ya existente

```json
{ "success": false, "message": "Ya existe un registro activo ..." }
```

### Error general / base de datos

```json
{ "success": false, "message": "Error en la base de datos" }
```

## Configuracion recomendada para esta fase

Mientras se valida la bajada y estructura del payload, se recomienda:

```env
BACKEND_ENABLED=false
ALERT_SEVERITIES=critical,high
```

Esto permite:

1. bajar la data,
2. filtrarla,
3. revisar el JSON final,
4. corregir formato antes de activar envio real.

## Archivos clave del codigo

- `insightvm_pull/client.py`
  Cliente HTTP para InsightVM.

- `insightvm_pull/collector.py`
  Descarga assets, vulnerabilidades por asset, detalle y aplica filtro temprano.

- `insightvm_pull/backend_client.py`
  Prepara y envia el payload hacia backend.

- `insightvm_pull/scheduler.py`
  Orquesta el ciclo completo de descarga, filtrado, persistencia y envio.

- `insightvm_pull/storage.py`
  Guarda snapshots por ejecucion.

## Limitaciones y siguiente mejora recomendada

Hoy el proyecto filtra temprano usando la severidad que pueda venir en `assets/{asset_id}/vulnerabilities`. Si InsightVM permite filtro directo por query en ese endpoint, la siguiente optimizacion recomendada es mover el filtro al servidor para descargar menos data aun.

Mientras esa capacidad no se confirme, el estado actual ya evita pedir detalle de vulnerabilidades que no pertenecen a `critical` o `high` cuando la severidad viene disponible en la lista por asset.
