const snapshotPayload = document.getElementById("snapshotPayload");
const filteredPayload = document.getElementById("filteredPayload");
const alarmasTable = document.getElementById("alarmasTable");
const detalleTable = document.getElementById("detalleTable");
const refreshButton = document.getElementById("refreshButton");
const snapshotSelect = document.getElementById("snapshotSelect");
const metaList = document.getElementById("metaList");
const heroSnapshotId = document.getElementById("heroSnapshotId");
const heroSnapshotFile = document.getElementById("heroSnapshotFile");
const heroAlarmsCount = document.getElementById("heroAlarmsCount");
const heroCriticalHigh = document.getElementById("heroCriticalHigh");
const heroMaxCvss = document.getElementById("heroMaxCvss");
const heroAvgCvss = document.getElementById("heroAvgCvss");
const heroCycleStatus = document.getElementById("heroCycleStatus");
const heroStartedAt = document.getElementById("heroStartedAt");

const tabs = Array.from(document.querySelectorAll(".tab"));
const panels = Array.from(document.querySelectorAll(".tab-panel"));

let currentSnapshotKey = null;
let lastState = null;

tabs.forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

snapshotSelect.addEventListener("change", async () => {
  currentSnapshotKey = snapshotSelect.value || null;
  await refresh();
});

refreshButton.addEventListener("click", refresh);

function activateTab(tabName) {
  tabs.forEach((tab) => tab.classList.toggle("is-active", tab.dataset.tab === tabName));
  panels.forEach((panel) => panel.classList.toggle("is-active", panel.dataset.panel === tabName));
}

function buildStateUrl() {
  const url = new URL("/api/state", window.location.origin);
  if (currentSnapshotKey) {
    url.searchParams.set("snapshot", currentSnapshotKey);
  }
  return url.toString();
}

async function loadState() {
  const response = await fetch(buildStateUrl(), { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function renderSnapshotSelector(availableSnapshots, selectedSnapshot) {
  if (!Array.isArray(availableSnapshots) || availableSnapshots.length === 0) {
    snapshotSelect.innerHTML = '<option value="">Sin snapshots disponibles</option>';
    snapshotSelect.disabled = true;
    return;
  }

  snapshotSelect.disabled = false;
  snapshotSelect.innerHTML = availableSnapshots
    .map((item) => {
      const selected = item.key === selectedSnapshot ? " selected" : "";
      const label = `${item.snapshot_id || item.key} | ${item.alarms_count} alarmas${item.is_latest ? " | latest" : ""}`;
      return `<option value="${escapeHtml(item.key)}"${selected}>${escapeHtml(label)}</option>`;
    })
    .join("");
}

function renderHero(state) {
  const snapshot = state.snapshot || {};
  const alarms = Array.isArray(snapshot.alarms) ? snapshot.alarms : [];
  const criticalCount = alarms.filter((alarm) => String(alarm.severity || "").toLowerCase() === "critical").length;
  const highCount = alarms.filter((alarm) => String(alarm.severity || "").toLowerCase() === "high").length;
  const scores = alarms.map((alarm) => Number(alarm.cvss_score)).filter((value) => Number.isFinite(value));
  const maxCvss = scores.length ? Math.max(...scores) : 0;
  const avgCvss = scores.length ? scores.reduce((sum, value) => sum + value, 0) / scores.length : 0;

  heroSnapshotId.textContent = snapshot.snapshot_id || "-";
  heroSnapshotFile.textContent = state.selected_snapshot || "Sin archivo cargado";
  heroAlarmsCount.textContent = String(alarms.length);
  heroCriticalHigh.textContent = `Critical: ${criticalCount} | High: ${highCount}`;
  heroMaxCvss.textContent = maxCvss.toFixed(1);
  heroAvgCvss.textContent = `Promedio: ${avgCvss.toFixed(1)}`;
  heroCycleStatus.textContent = state.meta?.success === true ? "Exito" : state.meta?.success === false ? "Error" : "-";
  heroStartedAt.textContent = state.meta?.started_at || "-";
}

function renderMeta(meta) {
  const entries = [
    ["Success", meta?.success],
    ["Cycle", meta?.cycle],
    ["Started At", meta?.started_at],
    ["Snapshot ID", meta?.snapshot_id],
    ["Total Assets", meta?.total_assets],
    ["Total Findings", meta?.total_findings],
    ["Filtered Findings", meta?.filtered_findings],
    ["Duration Seconds", meta?.duration_seconds],
  ];

  metaList.innerHTML = entries
    .map(
      ([label, value]) => `
        <div class="meta-item">
          <dt>${escapeHtml(String(label))}</dt>
          <dd>${escapeHtml(formatSimpleValue(value))}</dd>
        </div>
      `,
    )
    .join("");
}

function renderTable(tableElement, rows, tableName) {
  const sibling = tableElement.nextElementSibling;
  if (sibling && sibling.classList.contains("empty")) {
    sibling.remove();
  }

  if (!Array.isArray(rows) || rows.length === 0) {
    tableElement.innerHTML = "";
    tableElement.insertAdjacentHTML("afterend", '<div class="empty">No hay datos disponibles para este snapshot.</div>');
    return;
  }

  const headers = Object.keys(rows[0]);
  const thead = `<thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${rows
    .map((row) => {
      const severityClass = row.severity ? `severity-${String(row.severity).toLowerCase()}` : "";
      return `<tr class="${severityClass}">${headers
        .map((header) => `<td>${formatCell(header, row[header], row, tableName)}</td>`)
        .join("")}</tr>`;
    })
    .join("")}</tbody>`;
  tableElement.innerHTML = thead + tbody;
}

function formatCell(header, value, row, tableName) {
  if (header === "severity") {
    const severity = String(value || "-").trim();
    return `<span class="badge severity-${severity.toLowerCase()}">${escapeHtml(severity)}</span>`;
  }

  if (header === "cvss_score") {
    const score = Number(value);
    if (!Number.isFinite(score)) {
      return '<span class="muted">-</span>';
    }
    const level = score >= 9 ? "critical" : score >= 7 ? "high" : "other";
    return `<span class="badge cvss-${level}">${escapeHtml(score.toFixed(1))}</span>`;
  }

  if (header === "cves") {
    if (!Array.isArray(value) || value.length === 0) {
      return '<span class="muted">-</span>';
    }
    return `<div class="token-list">${value.map((item) => `<span class="token">${escapeHtml(String(item))}</span>`).join("")}</div>`;
  }

  if (header === "finding_id" || header === "snapshot_id" || header === "asset_id" || header === "vulnerability_id") {
    return `<span class="codeish">${escapeHtml(formatSimpleValue(value))}</span>`;
  }

  if (header === "TipoAlarma" && tableName === "alarmas") {
    return `<strong>${escapeHtml(formatSimpleValue(value))}</strong>`;
  }

  if (value === null || value === undefined || value === "") {
    return '<span class="muted">-</span>';
  }

  return escapeHtml(formatSimpleValue(value));
}

function formatSimpleValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderState(state) {
  lastState = state;
  currentSnapshotKey = state.selected_snapshot || currentSnapshotKey;
  renderSnapshotSelector(state.available_snapshots || [], state.selected_snapshot);
  renderHero(state);
  renderMeta(state.meta || {});
  snapshotPayload.textContent = JSON.stringify(state.snapshot || {}, null, 2);
  filteredPayload.textContent = JSON.stringify(state.filtered || {}, null, 2);
  renderTable(detalleTable, state.tables?.detalle_alerta_insightvm || [], "detalle_alerta_insightvm");
  renderTable(alarmasTable, state.tables?.alarmas || [], "alarmas");
}

async function refresh() {
  try {
    snapshotPayload.textContent = "Cargando...";
    filteredPayload.textContent = "Cargando...";
    const state = await loadState();
    renderState(state);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    snapshotPayload.textContent = `Error cargando datos: ${message}`;
    filteredPayload.textContent = "{}";
  }
}

activateTab("alertas");
refresh();
