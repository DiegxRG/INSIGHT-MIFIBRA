Propuesta de estructura de datos para integracion de alertas InsightVM -> MiFIbra

## 1. Objetivo

El presente documento detalla la estructura de datos que TXDXSecure propone enviar hacia la API de MiFIbra para registrar alertas de ciberseguridad provenientes de InsightVM.

La propuesta considera el envio de un payload JSON completo con la informacion operativa de la alarma y el detalle tecnico del hallazgo.

El objetivo es mantener la estructura actual de alarmas de MiFIbra y complementarla con una tabla adicional de detalle, permitiendo trazabilidad y almacenamiento historico por snapshot.

## 2. Resumen de la propuesta

TXDXSecure enviara un payload JSON completo por cada hallazgo detectado por InsightVM.

La API de MiFIbra podra separar internamente la informacion en dos tablas:

1. `alarmas`
2. `detalle_alerta_insightvm`

Ambas tablas se relacionaran mediante una llave compuesta formada por:

`(finding_id, snapshot_id)`

Donde:

- `finding_id` identifica el hallazgo logico.
- `snapshot_id` identifica el snapshot en el que ese hallazgo fue enviado.

## 3. Identificadores de relacion

### 3.1 `finding_id`

`finding_id` se construye a partir de:

`asset_id + "_" + vulnerability_id`

Ejemplo:

`515_apache-httpd-cve-2024-42516`

Este campo identifica el hallazgo logico asociado a un activo especifico y una vulnerabilidad especifica.

### 3.2 `snapshot_id`

`snapshot_id` identifica el snapshot generado por TXDXSecure.

Todos los hallazgos pertenecientes al mismo snapshot compartiran el mismo valor de `snapshot_id`.

Formato sugerido:

`2026-07-02T11:00:00Z`

`snapshot_id` no reemplaza a `fechaalarma`.

- `fechaalarma`: fecha original de deteccion del hallazgo en InsightVM.
- `snapshot_id`: fecha y hora del snapshot enviado a MiFIbra.

## 4. Flujo funcional de integracion

El flujo propuesto es el siguiente:

1. `GET /assets`
2. Obtencion de `asset_id` y metadata del equipo.
3. `GET /assets/{asset_id}/vulnerabilities`
4. Obtencion de `vulnerability_id` por cada hallazgo.
5. `GET /vulnerabilities/{vulnerability_id}`
6. Obtencion del detalle tecnico del hallazgo.
7. Construccion de `finding_id`.
8. Asignacion de `snapshot_id`.
9. Normalizacion del payload.
10. POST hacia API MiFIbra.
11. Registro en `alarmas` y `detalle_alerta_insightvm`.

## 5. Payload JSON propuesto

Ejemplo de payload completo:

```json
{
  "finding_id": "515_apache-httpd-cve-2024-42516",
  "snapshot_id": "2026-07-02T11:00:00Z",
  "servidor": "Cacti-Cajamarca",
  "ip": "10.208.172.5",
  "TipoAlarma": "Alarma de seguridad de InsightVM x TXDXSecure",
  "Local": "Mi Fibra",
  "fechaalarma": "2026-03-20 20:15:55",
  "asset_id": "515",
  "vulnerability_id": "apache-httpd-cve-2024-42516",
  "vulnerability_title": "Apache HTTPD: CVE-2024-42516: Improper Input Validation",
  "severity": "Critical",
  "cvss_score": 7.5,
  "cves": [
    "CVE-2024-42516"
  ],
  "source": "Rapid7-InsightVM"
}
```

## 6. Estructura de datos enviada por TXDXSecure

| Campo | Tipo JSON | Tipo BD sugerido | Obligatorio | Tabla destino sugerida | Descripcion | Ejemplo |
| --- | --- | --- | --- | --- | --- | --- |
| `finding_id` | string | `VARCHAR(255)` | Si | `alarmas` y `detalle_alerta_insightvm` | Identificador logico del hallazgo. | `515_apache-httpd-cve-2024-42516` |
| `snapshot_id` | string | `VARCHAR(50)` | Si | `alarmas` y `detalle_alerta_insightvm` | Identificador del snapshot generado por TXDXSecure. | `2026-07-02T11:00:00Z` |
| `servidor` | string | `VARCHAR(150)` | Si | `alarmas` | Nombre del servidor o equipo afectado. | `Cacti-Cajamarca` |
| `ip` | string | `VARCHAR(45)` | Si | `alarmas` | Direccion IP del equipo afectado. Soporta IPv4 o IPv6. | `10.208.172.5` |
| `TipoAlarma` | string | `VARCHAR(255)` | Si | `alarmas` | Clasificacion general de la alarma. | `Alarma de seguridad de InsightVM x TXDXSecure` |
| `Local` | string | `VARCHAR(100)` | Si | `alarmas` | Origen o local del reporte. | `Mi Fibra` |
| `fechaalarma` | string | `DATETIME` | Si | `alarmas` | Fecha original de deteccion del hallazgo en InsightVM. Formato sugerido: `YYYY-MM-DD HH:mm:ss`. | `2026-03-20 20:15:55` |
| `asset_id` | string | `VARCHAR(100)` | Si | `detalle_alerta_insightvm` | ID del activo o equipo en InsightVM. | `515` |
| `vulnerability_id` | string | `VARCHAR(255)` | Si | `detalle_alerta_insightvm` | ID tecnico del hallazgo en InsightVM. | `apache-httpd-cve-2024-42516` |
| `vulnerability_title` | string | `VARCHAR(255)` | Si | `detalle_alerta_insightvm` | Nombre legible del hallazgo. | `Apache HTTPD: CVE-2024-42516: Improper Input Validation` |
| `severity` | string | `VARCHAR(50)` | Si | `detalle_alerta_insightvm` | Severidad del hallazgo. Valores esperados inicialmente: `Critical`, `High`. | `Critical` |
| `cvss_score` | number | `DECIMAL(4,1)` | No | `detalle_alerta_insightvm` | Puntaje CVSS asociado al hallazgo. | `7.5` |
| `cves` | array | `JSON` | No | `detalle_alerta_insightvm` | Lista de CVEs asociados al hallazgo. | `["CVE-2024-42516"]` |
| `source` | string | `VARCHAR(50)` | Si | `detalle_alerta_insightvm` | Fuente del hallazgo. | `Rapid7-InsightVM` |

## 7. Distribucion sugerida en tablas

### 7.1 Tabla `alarmas`

Tabla principal existente. Se propone agregar `finding_id` y `snapshot_id` para relacionarla con la tabla adicional y conservar el historico por snapshot.

| Campo | Tipo sugerido | Descripcion |
| --- | --- | --- |
| `finding_id` | `VARCHAR(255)` | Identificador logico del hallazgo. |
| `snapshot_id` | `VARCHAR(50)` | Identificador del snapshot. |
| `servidor` | `VARCHAR(150)` | Servidor o equipo afectado. |
| `ip` | `VARCHAR(45)` | IP del equipo afectado. |
| `TipoAlarma` | `VARCHAR(255)` | Tipo de alarma. |
| `Local` | `VARCHAR(100)` | Origen del reporte. |
| `fechaalarma` | `DATETIME` | Fecha de deteccion del hallazgo en InsightVM. |

Llave primaria sugerida:

```sql
PRIMARY KEY (finding_id, snapshot_id)
```

### 7.2 Tabla `detalle_alerta_insightvm`

Tabla nueva para guardar la informacion tecnica del hallazgo proveniente de InsightVM.

| Campo | Tipo sugerido | Descripcion |
| --- | --- | --- |
| `finding_id` | `VARCHAR(255)` | Relacion con la alarma principal. |
| `snapshot_id` | `VARCHAR(50)` | Relacion con el snapshot principal. |
| `asset_id` | `VARCHAR(100)` | ID del activo en InsightVM. |
| `vulnerability_id` | `VARCHAR(255)` | ID tecnico del hallazgo en InsightVM. |
| `vulnerability_title` | `VARCHAR(255)` | Nombre legible del hallazgo. |
| `severity` | `VARCHAR(50)` | Severidad del hallazgo. |
| `cvss_score` | `DECIMAL(4,1)` | Puntaje CVSS. |
| `cves` | `JSON` | Lista de CVEs asociados. |
| `source` | `VARCHAR(50)` | Fuente del hallazgo. |

Llave primaria sugerida:

```sql
PRIMARY KEY (finding_id, snapshot_id)
```

Llave foranea sugerida:

```sql
FOREIGN KEY (finding_id, snapshot_id)
REFERENCES alarmas (finding_id, snapshot_id)
```

## 8. Llave compuesta y manejo de duplicados

### 8.1 En que consiste la llave compuesta

La llave primaria compuesta propuesta es:

```sql
PRIMARY KEY (finding_id, snapshot_id)
```

Esto significa que un registro no se identifica unicamente por `finding_id`, sino por la combinacion de dos campos:

- `finding_id`: identifica el hallazgo logico.
- `snapshot_id`: identifica el snapshot en el que ese hallazgo fue enviado.

En consecuencia:

- el mismo `finding_id` puede aparecer varias veces en la base de datos;
- cada aparicion representa el mismo hallazgo en un snapshot distinto;
- solo debe rechazarse un registro cuando ya exista la misma combinacion `finding_id + snapshot_id`.

### 8.2 Por que no usar solo `finding_id`

Si la llave primaria fuera solo `finding_id`, el mismo hallazgo no podria volver a insertarse en snapshots posteriores.

Ejemplo:

- Semana 1: `515_apache-httpd-cve-2024-42516`
- Semana 2: `515_apache-httpd-cve-2024-42516`

En un modelo por snapshots, ambos registros deben poder almacenarse porque representan dos fotos distintas del sistema.

Por este motivo, `finding_id` por si solo no es suficiente para identificar un registro historico.

### 8.3 Por que no usar `fechaalarma` como parte de la llave

`fechaalarma` representa la fecha en que InsightVM detecto originalmente la vulnerabilidad.

Ese valor puede mantenerse igual a lo largo de varios snapshots.

Por ello, `fechaalarma` no debe utilizarse para distinguir snapshots. El campo correcto para ese fin es `snapshot_id`.

La relacion logica propuesta es:

`alarmas.(finding_id, snapshot_id) = detalle_alerta_insightvm.(finding_id, snapshot_id)`

En este modelo:

- `finding_id` identifica el hallazgo logico.
- `snapshot_id` identifica el snapshot en el que ese hallazgo fue enviado.
- la combinacion `(finding_id, snapshot_id)` identifica de forma unica cada registro historico.

### 8.4 Como se aplica en las dos tablas

La tabla `alarmas` almacenara la parte operativa del registro y definira la llave primaria compuesta:

```sql
PRIMARY KEY (finding_id, snapshot_id)
```

La tabla `detalle_alerta_insightvm` almacenara la parte tecnica del mismo registro y utilizara la misma llave compuesta para mantener una relacion uno a uno con `alarmas`:

```sql
PRIMARY KEY (finding_id, snapshot_id)
FOREIGN KEY (finding_id, snapshot_id)
REFERENCES alarmas (finding_id, snapshot_id)
```

De esta manera:

- un registro tecnico siempre pertenecera al mismo hallazgo y al mismo snapshot de la tabla principal;
- no existiran detalles huerfanos;
- se conserva el historico sin perder la relacion entre cabecera y detalle.

### 8.5 Ejemplo practico

Supongamos el siguiente hallazgo logico:

`finding_id = 515_apache-httpd-cve-2024-42516`

Ese mismo hallazgo puede llegar en distintos snapshots:

| finding_id | snapshot_id | Interpretacion |
| --- | --- | --- |
| `515_apache-httpd-cve-2024-42516` | `2026-07-02T10:00:00Z` | Snapshot 1 |
| `515_apache-httpd-cve-2024-42516` | `2026-07-09T10:00:00Z` | Snapshot 2 |
| `515_apache-httpd-cve-2024-42516` | `2026-07-16T10:00:00Z` | Snapshot 3 |

Los tres registros son validos porque el `snapshot_id` es diferente.

En cambio, si se intenta insertar nuevamente:

| finding_id | snapshot_id | Resultado |
| --- | --- | --- |
| `515_apache-httpd-cve-2024-42516` | `2026-07-16T10:00:00Z` | Rechazar |

Debe rechazarse porque ya existe exactamente la misma combinacion.

Esto implica que:

- el mismo `finding_id` puede aparecer varias veces si pertenece a snapshots distintos;
- no debe considerarse duplicado cuando cambia `snapshot_id`;
- debe considerarse duplicado cuando ya existe la misma combinacion `(finding_id, snapshot_id)`.

Ejemplo:

| finding_id | snapshot_id | Resultado |
| --- | --- | --- |
| `515_apache-httpd-cve-2024-42516` | `2026-07-02T10:00:00Z` | Insertar |
| `515_apache-httpd-cve-2024-42516` | `2026-07-02T11:00:00Z` | Insertar |
| `515_apache-httpd-cve-2024-42516` | `2026-07-02T11:00:00Z` | Rechazar |

### 8.6 Flujo de insercion esperado en MiFIbra

Para cada payload recibido, MiFIbra deberia:

1. Leer `finding_id` y `snapshot_id`.
2. Verificar si la combinacion ya existe en `alarmas`.
3. Si no existe, insertar en `alarmas`.
4. Insertar el detalle tecnico en `detalle_alerta_insightvm` usando la misma combinacion.
5. Confirmar la transaccion.

Con este flujo, la base de datos almacena snapshots historicos sin romper la relacion entre la tabla principal y la tabla de detalle.

## 9. Validacion solicitada

Solicitamos validar los siguientes puntos del lado de MiFIbra:

1. Estructura de las tablas `alarmas` y `detalle_alerta_insightvm`.
2. Uso de la llave compuesta `(finding_id, snapshot_id)`.
3. Formato de `fechaalarma` como `YYYY-MM-DD HH:mm:ss`.
4. Formato de `snapshot_id` como ISO 8601 UTC.
5. Campos obligatorios y opcionales del payload.
6. Valores iniciales de severidad a procesar: `Critical` y `High`.
7. Endpoint final donde se recibira el payload completo.

Quedamos atentos para realizar los ajustes necesarios y coordinar una primera prueba controlada de envio.
