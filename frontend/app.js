const summaryGrid = document.getElementById("summaryGrid");
const snapshotPayload = document.getElementById("snapshotPayload");
const metaPayload = document.getElementById("metaPayload");
const filteredPayload = document.getElementById("filteredPayload");
const alarmasTable = document.getElementById("alarmasTable");
const detalleTable = document.getElementById("detalleTable");
const refreshButton = document.getElementById("refreshButton");

function renderSummary(summary) {
  const items = [
    ["Snapshot ID", summary.snapshot_id || "-"],
    ["Alarmas en lote", summary.alarms_count ?? 0],
    ["Filas alarmas", summary.alarmas_rows ?? 0],
    ["Filas detalle", summary.detalle_rows ?? 0],
    ["Findings filtrados", summary.findings_count ?? 0],
    ["Ultimo estado", summary.last_success === true ? "Exito" : summary.last_success === false ? "Error" : "-"],
    ["Inicio ciclo", summary.started_at || "-"],
  ];

  summaryGrid.innerHTML = items
    .map(
      ([label, value]) => `
        <article class="summary-card">
          <div class="label">${escapeHtml(String(label))}</div>
          <div class="value">${escapeHtml(String(value))}</div>
        </article>
      `,
    )
    .join("");
}

function renderTable(tableElement, rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    tableElement.outerHTML = `<div class="empty">No hay datos disponibles.</div>`;
    return;
  }

  const headers = Object.keys(rows[0]);
  const thead = `<thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${rows
    .map(
      (row) =>
        `<tr>${headers
          .map((header) => `<td>${formatCell(row[header])}</td>`)
          .join("")}</tr>`,
    )
    .join("")}</tbody>`;
  tableElement.innerHTML = thead + tbody;
}

function formatCell(value) {
  if (Array.isArray(value)) {
    return escapeHtml(value.join(", "));
  }
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "object") {
    return `<code>${escapeHtml(JSON.stringify(value))}</code>`;
  }
  return escapeHtml(String(value));
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadState() {
  snapshotPayload.textContent = "Cargando...";
  metaPayload.textContent = "Cargando...";
  filteredPayload.textContent = "Cargando...";

  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const state = await response.json();
  renderSummary(state.summary || {});
  snapshotPayload.textContent = JSON.stringify(state.snapshot || {}, null, 2);
  metaPayload.textContent = JSON.stringify(state.meta || {}, null, 2);
  filteredPayload.textContent = JSON.stringify(state.filtered || {}, null, 2);
  renderTable(alarmasTable, state.tables?.alarmas || []);
  renderTable(detalleTable, state.tables?.detalle_alerta_insightvm || []);
}

async function refresh() {
  try {
    await loadState();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    snapshotPayload.textContent = `Error cargando datos: ${message}`;
    metaPayload.textContent = "{}";
    filteredPayload.textContent = "{}";
  }
}

refreshButton.addEventListener("click", refresh);
refresh();
