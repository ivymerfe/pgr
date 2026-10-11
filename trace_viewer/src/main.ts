import { createGrid, GridApi } from "ag-grid-community";
import type { GridOptions, ICellRendererParams } from "ag-grid-community";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";

import type { TraceRow, ChunkData } from "./types";
import {
  fetchChunks,
  fetchTracesRange,
  fetchQueries,
  fetchParams,
  queryCache,
  clearApiCaches,
  bytesToDisplay,
  escapeHtml,
  NO_PARAMS,
  queryPending,
} from "./api";

const EVENT_NAMES: Record<string, string> = {
  p: "Parse",
  P: "Plan",
  S: "EStart",
  E: "ERun",
  C: "Commit",
  A: "Abort",
  U: "Utility",
};

const inputEl = document.getElementById("backend-url") as HTMLInputElement;
const btnEl = document.getElementById("connect-btn") as HTMLButtonElement;
const chartLegendEl = document.getElementById("chartLegend") as HTMLDivElement;
const connectStatusEl = document.getElementById(
  "connect-status",
) as HTMLDivElement;
const detailEl = document.getElementById("detail") as HTMLDivElement;
const gridDiv = document.getElementById("myGrid") as HTMLDivElement;
const chartCanvas = document.getElementById("chunkChart") as HTMLDivElement;
let chartRenderer: uPlot | null = null;

function getDefaultBackendUrl(): string {
  return `${window.location.protocol}//${window.location.hostname}:3232`;
}

let currentBackendUrl =
  localStorage.getItem("pgr_backend_url") || getDefaultBackendUrl();
inputEl.value = currentBackendUrl;

let gridApi: GridApi<TraceRow> | null = null;
let chunkData: ChunkData | null = null;

let pendingOffsetsToFetch = new Set<number>();
let fetchTimeout: number | null = null;

function scheduleQueryFetch(offset: number) {
  if (queryCache.has(offset) || queryPending.has(offset)) return;
  pendingOffsetsToFetch.add(offset);
  if (fetchTimeout !== null) return;
  fetchTimeout = window.setTimeout(() => {
    const offsets = Array.from(pendingOffsetsToFetch);
    pendingOffsetsToFetch.clear();
    fetchTimeout = null;
    if (offsets.length > 0) {
      fetchQueries(currentBackendUrl, offsets, () => {
        if (gridApi) gridApi.refreshCells({ columns: ["query"], force: true });
      });
    }
  }, 20);
}

function queryCellRenderer(params: ICellRendererParams<TraceRow>) {
  if (!params.data) return "";
  const offset = params.data.query_offset;
  const client_id = params.data.client_id;

  const rowIndex = params.node.rowIndex ?? -1;
  const nextNode = params.api.getDisplayedRowAtIndex(rowIndex + 1);
  if (
    nextNode?.data?.query_offset === offset &&
    nextNode?.data?.client_id == client_id
  ) {
    return `<span style="color: #555;">↓</span>`;
  }

  const entry = queryCache.get(offset);
  if (!entry) {
    scheduleQueryFetch(offset);
    return "…";
  }
  return `<span style="color: #ce9178;">${escapeHtml(entry.text)}</span>`;
}

const gridOptions: GridOptions<TraceRow> = {
  columnDefs: [
    {
      headerName: "query",
      headerClass: "ag-header-cell-center",
      field: "query_offset",
      colId: "query",
      flex: 3,
      minWidth: 200,
      cellRenderer: queryCellRenderer,
    },
    {
      headerName: "ts",
      headerClass: "ag-header-cell-center",
      field: "ts_secs",
      width: 90,
      flex: 1,
      cellStyle: { textAlign: "center" },
      valueFormatter: (p) => (p.value !== undefined ? p.value.toFixed(3) : ""),
    },
    {
      headerName: "client",
      headerClass: "ag-header-cell-center",
      field: "client_id",
      flex: 1,
      cellStyle: { textAlign: "center" },
      width: 80,
    },
    {
      headerName: "ms",
      headerClass: "ag-header-cell-center",
      field: "duration_ms",
      flex: 1,
      cellStyle: { textAlign: "center" },
      width: 90,
      valueFormatter: (p) => (p.value !== undefined ? p.value.toFixed(3) : ""),
    },
    {
      headerName: "event",
      headerClass: "ag-header-cell-center",
      colId: "event",
      cellStyle: { textAlign: "center" },
      width: 100,
      flex: 1,
      filter: "agTextColumnFilter",
      valueGetter: (p) => {
        if (!p.data) return "";
        const char = String.fromCharCode(p.data.event_type);
        return EVENT_NAMES[char] || char;
      },
    },
  ],
  defaultColDef: { resizable: true, sortable: true, filter: true },
  rowSelection: "single",
  rowHeight: 26,
  headerHeight: 30,
  onRowClicked: (event) => {
    if (event.data) renderDetail(event.data);
  },
  onCellFocused: (event) => {
    if (event.rowIndex == null || !gridApi) return;
    const node = gridApi.getDisplayedRowAtIndex(event.rowIndex);
    if (node?.data) {
      renderDetail(node.data);
      node.setSelected(true, true);
    }
  },
  // query offset повторяется -> строки уже логически сгруппированы, доп сортировка не нужна
  suppressCellFocus: false,
};

gridApi = createGrid(gridDiv, gridOptions);

async function renderDetail(row: TraceRow | null) {
  if (!row) {
    detailEl.className = "detail empty";
    detailEl.innerHTML =
      '<div class="detail-placeholder">Choose row for details</div>';
    return;
  }

  detailEl.className = "detail";
  await fetchQueries(currentBackendUrl, [row.query_offset], () => {});
  const q = queryCache.get(row.query_offset);

  let paramsHtml = "";
  if (row.params_offset !== NO_PARAMS) {
    const entry = await fetchParams(currentBackendUrl, row.params_offset);
    if (entry) {
      const paramRows = entry.params
        .map((p, idx) => {
          const fmt =
            entry.paramFormatCodes[idx] ?? entry.paramFormatCodes[0] ?? 0;
          return `<tr><td>${idx}</td><td>${fmt}</td><td>${escapeHtml(bytesToDisplay(p))}</td></tr>`;
        })
        .join("");

      paramsHtml = `
        <div class="detail-section-title">Parameters</div>
        <table class="detail-table">
          <thead><tr><th>#</th><th>format</th><th>value</th></tr></thead>
          <tbody>${paramRows}</tbody>
        </table>
        <div class="detail-section-title">Result format codes</div>
        <div class="detail-codes">[${entry.resultFormatCodes.join(", ")}]</div>
      `;
    }
  }

  const oidsHtml =
    q && q.oids.length > 0
      ? `<div class="detail-section-title">Parameter type OIDs</div><div class="detail-codes">[${q.oids.join(", ")}]</div>`
      : "";

  detailEl.innerHTML = `
    <div class="detail-section-title">Query</div>
    <div class="detail-query">${escapeHtml(q ? q.text : "(loading...)")}</div>
    ${oidsHtml}
    ${paramsHtml}
  `;
}

function drawChart() {
  if (!chunkData) return;

  const xs = Array.from(chunkData.durations).map(
    (_, i) => i * chunkData!.chunkSeconds,
  );
  const ys = Array.from(chunkData.durations);

  if (chartRenderer) {
    chartRenderer.setData([xs, ys]);
    return;
  }

  const rect = chartCanvas.getBoundingClientRect();

  chartRenderer = new uPlot(
    {
      width: rect.width,
      height: rect.height,
      legend: { show: false },
      series: [
        {
          label: "Time (s)",
        },
        {
          label: "max duration (ms)",
          stroke: "#0e639c",
          fill: "#7fb3d9",
          paths: uPlot.paths.bars!({ size: [0.9, Infinity] }),
          points: { show: false },
        },
      ],
      scales: {
        x: {
          time: false,
          range: (_u, initMin, initMax, _scaleKey) => {
            const MIN_SPAN = chunkData!.chunkSeconds * 10;
            const dataMin = xs[0];
            const dataMax = xs[xs.length - 1];
            if (initMax - initMin < MIN_SPAN) {
              const center = (initMin + initMax) / 2;
              initMin = center - MIN_SPAN / 2;
              initMax = center + MIN_SPAN / 2;
            }
            return [Math.max(dataMin, initMin), Math.min(dataMax, initMax)];
          },
        },
      },
      axes: [
        {
          stroke: "#555",
          grid: { stroke: "#eee" },
          size: 24,
          gap: 4,
          font: "12px ui-monospace, monospace",
        },
        {
          stroke: "#555",
          grid: { stroke: "#eee" },
          font: "12px ui-monospace, monospace",
        },
      ],
      cursor: { drag: { x: true, y: false, uni: 20 } },
      hooks: {
        ready: [
          (u) => {
            u.over.addEventListener("dblclick", () => {
              u.setScale("x", { min: xs[0], max: xs[xs.length - 1] });
            });
            u.over.addEventListener("click", (e) => {
              const idx = u.posToIdx(e.offsetX);
              if (idx != null) selectChunk(idx);
            });
            u.over.addEventListener("mouseleave", () => {
              chartLegendEl.textContent = "hover chart for details";
            });
            u.over.addEventListener(
              "wheel",
              (e) => {
                e.preventDefault();
                const { left, width } = u.over.getBoundingClientRect();
                const mouseX = e.clientX - left;
                const xVal = u.posToVal(mouseX, "x");

                const scale = u.scales.x;
                const range = scale.max! - scale.min!;
                const zoomFactor = e.deltaY < 0 ? 0.85 : 1 / 0.85;
                const newRange = range * zoomFactor;

                const leftPct = mouseX / width;
                const newMin = xVal - newRange * leftPct;
                const newMax = xVal + newRange * (1 - leftPct);

                u.setScale("x", { min: newMin, max: newMax });
              },
              { passive: false },
            );
          },
        ],
        setCursor: [
          (u) => {
            const idx = u.cursor.idx;
            if (idx == null || idx < 0) {
              chartLegendEl.textContent = "hover chart for details";
              return;
            }
            const t = u.data[0][idx];
            const dur = u.data[1][idx];
            if (t == null || dur == null) return;
            chartLegendEl.textContent = `t = ${t.toFixed(2)}s   max duration = ${dur.toFixed(2)}ms`;
          },
        ],
      },
    },
    [xs, ys],
    chartCanvas,
  );
}

async function selectChunk(idx: number) {
  if (!chunkData || !chartRenderer) return;

  const rows = await fetchTracesRange(
    currentBackendUrl,
    Math.max(0, idx - 1),
    idx + 1,
  );
  if (!gridApi) return;

  gridApi.setGridOption("rowData", rows);
  if (rows.length === 0) return;

  const chunkStart = idx * chunkData.chunkSeconds;
  const chunkEnd = chunkStart + chunkData.chunkSeconds;

  let bestNode: any = null;
  gridApi.forEachNodeAfterFilterAndSort((node) => {
    const r = node.data;
    if (!r || r.ts_secs < chunkStart || r.ts_secs >= chunkEnd) return;
    if (!bestNode || r.duration_ms > bestNode.data.duration_ms) bestNode = node;
  });

  if (bestNode) {
    gridApi.ensureNodeVisible(bestNode, "middle");
    bestNode.setSelected(true, true);
    renderDetail(bestNode.data);
  }
}

window.addEventListener("resize", () => {
  if (chartRenderer) {
    const rect = chartCanvas.getBoundingClientRect();
    chartRenderer.setSize({ width: rect.width, height: rect.height });
  }
});

async function loadData(url: string) {
  btnEl.disabled = true;

  pendingOffsetsToFetch.clear();
  if (fetchTimeout !== null) {
    clearTimeout(fetchTimeout);
    fetchTimeout = null;
  }
  clearApiCaches();
  try {
    chunkData = await fetchChunks(url);
    drawChart();
    if (gridApi) gridApi.setGridOption("rowData", []);
    localStorage.setItem("pgr_backend_url", url);
    connectStatusEl.textContent = "ok";
    connectStatusEl.classList.replace("status-error", "status-ok");
  } catch (err: any) {
    console.error(err);
    connectStatusEl.textContent = err.message;
    connectStatusEl.classList.replace("status-ok", "status-error");
    chunkData = null;
    if (gridApi) gridApi.setGridOption("rowData", []);
  } finally {
    btnEl.disabled = false;
    btnEl.textContent = "connect";
  }
}

function connect() {
  const url = inputEl.value.trim();
  if (url) {
    currentBackendUrl = url;
    loadData(currentBackendUrl);
  }
}

btnEl.addEventListener("click", connect);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") connect();
});

loadData(currentBackendUrl);
