// Spyglass frontend. All server data is escaped before insertion.
const SEV_COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#38bdf8" };
const ST_COLORS = { PASS: "#22c55e", FAIL: "#ef4444", WARNING: "#eab308", "NOT ASSESSED": "#8a9bbd" };

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const $ = id => document.getElementById(id);

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: {} };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-Requested-With"] = "Spyglass";
    opts.body = JSON.stringify(body || {});
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) throw new Error(data.error || (data.connection && data.connection.error) || `HTTP ${res.status}`);
  return data;
}

const sevBadge = s => `<span class="badge-sev sev-${esc(s)}">${esc(s)}</span>`;
const stBadge = s => `<span class="badge-st st-${esc(s).replace(" ", "-")}">${esc(s)}</span>`;

function findingsTable(findings) {
  if (!findings.length) return '<div class="empty">No findings.</div>';
  const rows = findings.map(f => `
    <tr>
      <td>${stBadge(f.status)}</td><td>${sevBadge(f.severity)}</td>
      <td>${esc(f.check_id)}</td><td>${esc(f.resource)}</td>
      <td>${esc(f.title)}<div class="muted">${esc(f.evidence)}</div></td>
      <td>${esc(f.remediation)}</td>
    </tr>`).join("");
  return `<table class="dark"><thead><tr><th>Status</th><th>Severity</th><th>Check</th>
    <th>Resource</th><th>Finding / Evidence</th><th>Remediation</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function count(list, key) {
  const m = {};
  list.forEach(x => { m[x[key]] = (m[x[key]] || 0) + 1; });
  return m;
}

function doughnut(canvasId, labels, values, colors) {
  new Chart($(canvasId), {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { color: "#dbe4f5" } } } },
  });
}

function drawDashboardCharts(scan) {
  const failed = scan.findings.filter(f => f.status === "FAIL");
  const sev = count(failed, "severity");
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  new Chart($("chartSeverity"), {
    type: "bar",
    data: { labels: sevOrder, datasets: [{ data: sevOrder.map(s => sev[s] || 0),
      backgroundColor: sevOrder.map(s => SEV_COLORS[s]) }] },
    options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0, color: "#8a9bbd" }, grid: { color: "#22304f" } },
                x: { ticks: { color: "#8a9bbd" }, grid: { display: false } } } },
  });
  const st = count(scan.findings, "status");
  const stOrder = ["PASS", "FAIL", "WARNING", "NOT ASSESSED"];
  doughnut("chartStatus", stOrder, stOrder.map(s => st[s] || 0), stOrder.map(s => ST_COLORS[s]));
  const svc = count(scan.findings, "service");
  const names = Object.keys(svc);
  doughnut("chartService", names, names.map(n => svc[n]), ["#38bdf8", "#a78bfa", "#f472b6", "#34d399", "#fbbf24"]);
}

function renderDashboard(scan) {
  $("d-score").textContent = scan.score === null ? "N/A" : scan.score;
  $("d-rating").textContent = scan.rating;
  $("d-total").textContent = scan.total_checks;
  $("d-pass").textContent = scan.passed;
  $("d-fail").textContent = scan.failed;
  $("d-crit").textContent = scan.critical_findings;
  $("d-high").textContent = scan.high_findings;
  $("d-cov").textContent = scan.coverage_pct + "%";
  $("d-account").textContent = scan.account_id || "-";
  $("d-region").textContent = scan.region || "-";
  $("d-time").textContent = new Date(scan.scanned_at).toLocaleString();
  $("d-mode").textContent = scan.mode.toUpperCase();
  const rc = Object.values(scan.resource_counts).reduce((a, b) => a + (b || 0), 0);
  $("d-resources").textContent = rc;
  $("d-method").textContent = scan.method;
  const top = scan.findings.filter(f => f.status === "FAIL")
    .sort((a, b) => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(a.severity) - ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(b.severity))
    .slice(0, 10);
  $("d-top").innerHTML = findingsTable(top);
  drawDashboardCharts(scan);
}

async function runScan() {
  const btn = $("scanBtn"), out = $("scanOut");
  btn.disabled = true;
  out.innerHTML = '<span class="muted">Scanning... this can take a minute on a real account.</span>';
  try {
    const { scan } = await api("/api/scan", "POST");
    out.innerHTML = `<div class="card-panel"><b>Scan #${esc(scan.id)} complete.</b>
      Score <b>${esc(scan.score)}</b> (${esc(scan.rating)}), ${esc(scan.failed)} failed,
      ${esc(scan.warnings)} warnings, ${esc(scan.not_assessed)} not assessed.
      <a href="/">View dashboard</a> &middot; <a href="/findings">View findings</a></div>`;
  } catch (e) {
    out.innerHTML = `<div class="card-panel" style="border-color:#ef4444">Scan failed: ${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

// ---------------------------------------------------------- inventory --
async function loadInventory() {
  const out = $("inv-out");
  out.innerHTML = '<span class="muted">Discovering resources...</span>';
  try {
    const { inventory } = await api("/api/inventory");
    out.innerHTML = Object.entries(inventory).map(([name, r]) => {
      const head = r.status === "OK"
        ? `<span class="stat" style="font-size:1.4rem">${esc(r.count)}</span>`
        : `<span class="badge-st st-NOT-ASSESSED">NOT ASSESSED (${esc(r.error)})</span>`;
      const cols = r.items.length ? Object.keys(r.items[0]) : [];
      const body = r.items.length
        ? `<div style="overflow-x:auto"><table class="dark"><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>` +
          r.items.map(i => `<tr>${cols.map(c => `<td>${esc(Array.isArray(i[c]) ? i[c].join(", ") : i[c])}</td>`).join("")}</tr>`).join("") +
          "</tbody></table></div>"
        : '<div class="muted">None found.</div>';
      return `<div class="card-panel mb-3"><div class="d-flex justify-content-between"><h6>${esc(name)}</h6>${head}</div>${body}</div>`;
    }).join("");
  } catch (e) {
    out.innerHTML = `<div class="card-panel" style="border-color:#ef4444">${esc(e.message)}</div>`;
  }
}

// ----------------------------------------------------------- findings --
let findingsCache = [];
function applyFilters() {
  const f = { status: $("f-status").value, severity: $("f-sev").value, service: $("f-svc").value };
  const rows = findingsCache.filter(x =>
    (!f.status || x.status === f.status) && (!f.severity || x.severity === f.severity) &&
    (!f.service || x.service === f.service));
  $("f-count").textContent = `${rows.length} of ${findingsCache.length} findings`;
  $("f-out").innerHTML = findingsTable(rows);
}
async function loadFindings() {
  const sel = $("f-scan");
  if (!sel.value) { $("f-out").innerHTML = '<div class="empty">No scans yet.</div>'; return; }
  try {
    const { scan } = await api("/api/scans/" + encodeURIComponent(sel.value));
    findingsCache = scan.findings;
    applyFilters();
  } catch (e) { $("f-out").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

// ------------------------------------------------------------ connect --
async function refreshConnection() {
  try {
    const { state, connection } = await api("/api/status");
    $("c-status").innerHTML = connection.connected
      ? `Connected &middot; account <b>${esc(connection.account_id)}</b> &middot; ${esc(connection.region)} &middot; mode ${esc(state.mode)}`
      : `Not connected: ${esc(connection.error)}`;
  } catch (e) { $("c-status").textContent = e.message; }
}
async function connectAws(ev) {
  ev.preventDefault();
  const body = { access_key_id: $("c-key").value, secret_access_key: $("c-secret").value,
                 region: $("c-region").value, session_token: $("c-token").value };
  try {
    await api("/api/connect", "POST", body);
    $("c-secret").value = ""; $("c-key").value = ""; $("c-token").value = "";
    $("c-msg").innerHTML = '<span style="color:var(--pass)">Connected. Credentials are held in server memory only. Reload to update the mode banner.</span>';
  } catch (e) { $("c-msg").innerHTML = `<span style="color:var(--fail)">${esc(e.message)}</span>`; }
  refreshConnection();
}
async function useMode(mode) {
  try { await api("/api/mode", "POST", { mode }); location.reload(); }
  catch (e) { $("c-msg").textContent = e.message; }
}
async function disconnectAws() {
  await api("/api/disconnect", "POST");
  $("c-msg").textContent = "Credentials wiped from memory.";
  refreshConnection();
}

// --------------------------------------------------------------- init --
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-local-time]").forEach(el => {
    const d = new Date(el.dataset.localTime);
    if (!isNaN(d)) el.textContent = d.toLocaleString();
  });
  const scanDataEl = $("scan-data");
  if (scanDataEl) renderDashboard(JSON.parse(scanDataEl.textContent));
  if ($("scanBtn")) $("scanBtn").addEventListener("click", runScan);
  if ($("inv-out")) loadInventory();
  if ($("f-scan")) {
    ["f-scan"].forEach(id => $(id).addEventListener("change", loadFindings));
    ["f-status", "f-sev", "f-svc"].forEach(id => $(id).addEventListener("change", applyFilters));
    loadFindings();
  }
  if ($("c-form")) {
    $("c-form").addEventListener("submit", connectAws);
    $("c-disc").addEventListener("click", disconnectAws);
    $("c-demo").addEventListener("click", () => useMode("demo"));
    $("c-live").addEventListener("click", () => useMode("live"));
    refreshConnection();
  }
});
