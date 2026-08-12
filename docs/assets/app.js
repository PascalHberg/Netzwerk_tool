// Minimal viewer app: parse JSON or CSV with a simple parser, render table, provide filters and export.
// No external libs. Keep keys tolerant to common shapes.

const fileInput = document.getElementById("fileInput");
const printersOnly = document.getElementById("printersOnly");
const searchEl = document.getElementById("search");
const exportCsv = document.getElementById("exportCsv");
const exportJson = document.getElementById("exportJson");
const clearBtn = document.getElementById("clear");
const tableBody = document.querySelector("#devicesTable tbody");
const summary = document.getElementById("summary");

let devices = []; // array of normalized device objects
let filtered = [];

fileInput.addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const text = await f.text();
  if (f.name.endsWith(".json") || text.trim().startsWith("[")) {
    try {
      const parsed = JSON.parse(text);
      normalizeAndLoad(parsed);
    } catch (err) {
      alert("Invalid JSON: " + err.message);
    }
  } else {
    // assume CSV
    const parsed = parseCSV(text);
    normalizeAndLoad(parsed);
  }
});

printersOnly.addEventListener("change", applyFilters);
searchEl.addEventListener("input", debounce(applyFilters, 200));
exportCsv.addEventListener("click", () => downloadCSV(filtered));
exportJson.addEventListener("click", () => downloadJSON(filtered));
clearBtn.addEventListener("click", clearAll);

function normalizeAndLoad(raw){
  // raw could be array of objects, or object with results key
  let arr = raw;
  if (!Array.isArray(raw) && raw && typeof raw === "object") {
    // try to find an array inside common keys
    if (Array.isArray(raw.results)) arr = raw.results;
    else if (Array.isArray(raw.devices)) arr = raw.devices;
    else if (Array.isArray(raw.scans)) arr = raw.scans;
    else arr = [raw];
  }
  devices = arr.map(normalizeDevice);
  applyFilters();
  exportCsv.disabled = false;
  exportJson.disabled = false;
  clearBtn.disabled = false;
}

function normalizeDevice(d){
  // tolerant access to nested fields from common outputs
  const ip = d.ip || d.address || (d.network && d.network.ip) || "";
  const hostname = d.hostname || d.host || (d.mdns && d.mdns.hostname) || "";
  const model = d.model || d.sysDescr || (d.snmp && d.snmp.sysDescr) || (d.ipp && d.ipp["printer-make-and-model"]) || "";
  const serial = d.serial ||
                 (d.snmp && (d.snmp.serial || d.snmp["Serial Number"])) ||
                 (d.ipp && d.ipp.serial) ||
                 "";
  const is_printer = Boolean(d.is_printer || d.isPrinter || (d.tags && d.tags.includes && d.tags.includes("printer")) ||
    (d.services && (d.services.includes("ipp") || d.services.includes("printer")) ) ||
    (model && /print|hp|brother|canon|xerox|konica|kyocera/i.test(model))
  );

  const snmp = d.snmp || d.SNMP || {};
  const ipp = d.ipp || d.IPP || {};
  const http = d.http || d.HTTP || {};

  return { ip, hostname, model, serial, is_printer, snmp, ipp, http, raw: d };
}

function applyFilters(){
  const q = (searchEl.value || "").toLowerCase().trim();
  const onlyPrinters = printersOnly.checked;
  filtered = devices.filter(d => {
    if (onlyPrinters && !d.is_printer) return false;
    if (!q) return true;
    return [d.ip, d.hostname, d.model, d.serial, JSON.stringify(d.snmp), JSON.stringify(d.ipp), JSON.stringify(d.http)]
      .join(" ").toLowerCase().includes(q);
  });
  renderTable(filtered);
}

function renderTable(rows){
  tableBody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(r.ip)}</td>
      <td>${escapeHtml(r.hostname)}</td>
      <td>${escapeHtml(r.model)}</td>
      <td>${escapeHtml(r.serial)}</td>
      <td>${r.is_printer ? "Printer" : "Device"}</td>
      <td>${escapeHtml(shortString(r.snmp))}</td>
      <td>${escapeHtml(shortString(r.ipp))}</td>
      <td>${escapeHtml(shortString(r.http))}</td>
    `;
    tableBody.appendChild(tr);
  }
  summary.textContent = `${rows.length} / ${devices.length} items shown.`;
}

function shortString(obj){
  if (!obj) return "";
  // prefer human fields
  if (obj.title) return obj.title;
  if (obj["printer-name"]) return obj["printer-name"];
  if (obj.sysDescr) return obj.sysDescr;
  // fallback: stringify limited
  try {
    const s = JSON.stringify(obj);
    return s.length > 80 ? s.slice(0, 80) + "…" : s;
  } catch {
    return String(obj);
  }
}

function parseCSV(text){
  // very small CSV parser: assumes first row headers, comma-separated, no fancy quoting
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) return [];
  const headers = lines[0].split(",").map(h => h.trim());
  const rows = lines.slice(1).map(line => {
    const parts = line.split(",").map(p => p.trim());
    const obj = {};
    for (let i=0;i<headers.length;i++) obj[headers[i]] = parts[i]===undefined ? "" : parts[i];
    return obj;
  });
  return rows;
}

function downloadCSV(data){
  if (!data || !data.length) return;
  const keys = ["ip","hostname","model","serial","is_printer"];
  const header = keys.join(",");
  const lines = data.map(d => keys.map(k => `"${String(d[k] ?? "")}"`).join(","));
  const csv = [header].concat(lines).join("\n");
  triggerDownload(csv, "export.csv", "text/csv");
}

function downloadJSON(data){
  const json = JSON.stringify(data.map(d => d.raw || d), null, 2);
  triggerDownload(json, "export.json", "application/json");
}

function triggerDownload(content, filename, type){
  const blob = new Blob([content], {type});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}

function clearAll(){
  devices = []; filtered = [];
  tableBody.innerHTML = "";
  summary.textContent = "";
  fileInput.value = "";
  searchEl.value = "";
  printersOnly.checked = false;
  exportCsv.disabled = true;
  exportJson.disabled = true;
  clearBtn.disabled = true;
}

function escapeHtml(s){
  if (!s && s !== 0) return "";
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function debounce(fn, ms=200){
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(()=>fn(...args), ms); };
}
