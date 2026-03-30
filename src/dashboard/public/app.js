// ============================================================
// NGO Guardian — Dashboard Application
// ============================================================

let state = {
  targets: [],
  sisDashboard: null,
  vulnFilter: "ALL",
  vulnSearch: "",
  targetSearch: "",
};

// ─── Bootstrap ───────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadData();
  setupKeyboard();
});

async function loadData() {
  const [targets, sisDash] = await Promise.allSettled([
    fetchJSON("/api/targets"),
    fetchJSON("/api/sis-dashboard"),
  ]);

  state.targets = targets.status === "fulfilled" ? targets.value : [];
  state.sisDashboard = sisDash.status === "fulfilled" ? sisDash.value : null;

  renderAll();
}

async function refreshData() {
  const btn = document.querySelector(".btn-ghost");
  btn.disabled = true;
  btn.textContent = "Refreshing...";
  await loadData();
  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd"/></svg> Refresh`;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function renderAll() {
  renderDashboard();
  renderTargets();
  renderVulnerabilities();
  renderSIS();
  renderDisclosures();
  renderReports();
  updateNavBadges();
  updateLastScan();
}

// ─── View Routing ─────────────────────────────────────────────

const VIEW_TITLES = {
  dashboard:       ["Dashboard",        "Security intelligence overview"],
  targets:         ["Scanned Targets",  "NGOs discovered and analyzed"],
  vulnerabilities: ["Vulnerabilities",  "All findings ranked by severity"],
  sis:             ["SIS Scoring",      "Social Impact Score analysis"],
  disclosures:     ["Disclosure Drafts","Empathy-first disclosure emails"],
  reports:         ["Reports",          "Generated output files"],
};

function switchView(view, el) {
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));

  if (el) el.classList.add("active");
  const panel = document.getElementById(`view-${view}`);
  if (panel) panel.classList.add("active");

  const [title, subtitle] = VIEW_TITLES[view] || ["", ""];
  document.getElementById("topbar-title").textContent = title;
  document.getElementById("topbar-subtitle").textContent = subtitle;
}

// ─── Dashboard ────────────────────────────────────────────────

function renderDashboard() {
  const targets = state.targets;
  const sis = state.sisDashboard;

  // Stats
  const totalVulns = targets.reduce((s, t) => s + (t.vulnerabilities?.length || 0), 0);
  const totalCritical = targets.reduce((s, t) =>
    s + (t.vulnerabilities?.filter(v => v.severity === "CRITICAL").length || 0), 0);
  const avgSIS = sis?.summary?.avg_sis ?? "—";
  const draftsCount = sis?.summary?.ngos_with_drafts ?? 0;

  setText("dash-targets", targets.length || (sis?.summary?.total_ngos ?? "—"));
  setText("dash-vulns", totalVulns || "—");
  setText("dash-critical", totalCritical || "—");
  setText("dash-avg-sis", avgSIS !== "—" ? avgSIS.toFixed(1) : "—");
  setText("dash-drafts", draftsCount);

  // Severity chart
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const t of targets) {
    for (const v of (t.vulnerabilities || [])) {
      if (counts[v.severity] !== undefined) counts[v.severity]++;
    }
  }
  const maxCount = Math.max(...Object.values(counts), 1);

  document.getElementById("dash-severity-chart").innerHTML = Object.entries(counts).map(([sev, count]) => `
    <div class="sev-row">
      <div class="sev-label" style="color: var(--sev-${sev.toLowerCase()})">${sev}</div>
      <div class="sev-track">
        <div class="sev-fill ${sev.toLowerCase()}" style="width:${(count/maxCount)*100}%"></div>
      </div>
      <div class="sev-count">${count}</div>
    </div>
  `).join("");

  // SIS bars from Python dashboard
  const sisBars = document.getElementById("dash-sis-bars");
  if (sis?.ngos?.length) {
    const sorted = [...sis.ngos].sort((a, b) => b.headline_sis - a.headline_sis);
    sisBars.innerHTML = sorted.map(n => `
      <div class="sis-bar-row">
        <div class="sis-bar-name" title="${n.name}">${n.name}</div>
        <div class="sis-bar-track">
          <div class="sis-bar-fill" style="width:${n.headline_sis}%"></div>
        </div>
        <div class="sis-bar-val">${n.headline_sis}</div>
      </div>
    `).join("");
  } else {
    sisBars.innerHTML = `<div class="empty-state" style="padding:24px">
      <p style="font-size:12px">Run <code>python -m agents.sis_agent</code> to see SIS scores</p>
    </div>`;
  }

  // Pipeline
  setText("pipe-discovery", targets.length ? `${targets.length} NGOs` : "—");
  setText("pipe-scan", totalVulns ? `${totalVulns} findings` : "—");
  setText("pipe-sis", sis?.summary?.total_ngos ? `${sis.summary.total_ngos} scored` : "—");
  setText("pipe-disclosure", draftsCount ? `${draftsCount} drafted` : "Pending");

  const hasDrafts = draftsCount > 0;
  const dot = document.getElementById("pipe-dot-disclosure");
  const line = document.getElementById("pipe-line-3");
  if (dot) dot.className = `step-dot${hasDrafts ? " done" : ""}`;
  if (line) line.className = `pipeline-line${hasDrafts ? " done" : ""}`;
}

// ─── Targets ─────────────────────────────────────────────────

function renderTargets() {
  const tbody = document.getElementById("targets-tbody");
  const filterGroup = document.getElementById("sector-filter-group");

  if (!state.targets.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No scan data. Run the JS pipeline first.</td></tr>`;
    return;
  }

  // Build sector filters
  const sectors = [...new Set(state.targets.map(t => t.sector).filter(Boolean))];
  filterGroup.innerHTML = sectors.map(s =>
    `<button class="filter-btn" onclick="setSectorFilter('${s}', this)">${s}</button>`
  ).join("");

  filterTargets();
}

let activeSectorFilter = null;

function setSectorFilter(sector, el) {
  activeSectorFilter = activeSectorFilter === sector ? null : sector;
  document.querySelectorAll("#sector-filter-group .filter-btn").forEach(b => b.classList.remove("active"));
  if (activeSectorFilter) el.classList.add("active");
  filterTargets();
}

function filterTargets() {
  const q = document.getElementById("target-search").value.toLowerCase();
  const tbody = document.getElementById("targets-tbody");

  const filtered = state.targets.filter(t => {
    const matchQ = !q || t.name?.toLowerCase().includes(q) || t.domain?.toLowerCase().includes(q);
    const matchSector = !activeSectorFilter || t.sector === activeSectorFilter;
    return matchQ && matchSector;
  });

  const sev = t => {
    const crit = t.vulnerabilities?.filter(v => v.severity === "CRITICAL").length || 0;
    const high = t.vulnerabilities?.filter(v => v.severity === "HIGH").length || 0;
    return `${crit ? `<span class="badge badge-critical">${crit} C</span> ` : ""}${high ? `<span class="badge badge-high">${high} H</span> ` : ""}${(t.vulnerabilities?.length || 0) - crit - high > 0 ? `<span class="badge badge-low">${(t.vulnerabilities?.length || 0) - crit - high}</span>` : ""}`;
  };

  tbody.innerHTML = filtered.map((t, i) => {
    const scoreColor = t.scoring?.vibeRiskScore >= 80 ? "var(--red)" : t.scoring?.vibeRiskScore >= 60 ? "var(--amber)" : "var(--green)";
    return `
      <tr>
        <td><div style="font-weight:600">${t.name || "—"}</div></td>
        <td><code style="font-size:11.5px;color:var(--text-3)">${t.domain || "—"}</code></td>
        <td><span class="badge badge-sector">${t.sector || "—"}</span></td>
        <td><span style="font-size:12px;color:var(--text-2)">${t.techStack?.platform || "—"}</span></td>
        <td>${t.techStack?.isVibeCoded ? '<span class="tag-vibecoded">Yes</span>' : '<span style="color:var(--text-3);font-size:12px">No</span>'}</td>
        <td>${sev(t) || `<span class="badge badge-low">${t.vulnerabilities?.length || 0}</span>`}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-weight:700;color:${scoreColor}">${t.scoring?.vibeRiskScore ?? "—"}</span>
            <div class="risk-score-bar"><div class="risk-score-fill" style="width:${t.scoring?.vibeRiskScore || 0}%;background:${scoreColor}"></div></div>
          </div>
        </td>
        <td><button class="link-btn" onclick="openTargetModal(${i})">Details</button></td>
      </tr>
    `;
  }).join("");
}

// ─── Vulnerabilities ─────────────────────────────────────────

function renderVulnerabilities() {
  filterVulns();
}

function setVulnFilter(sev, el) {
  state.vulnFilter = sev;
  document.querySelectorAll(".filter-group .filter-btn").forEach(b => b.classList.remove("active"));
  if (el) el.classList.add("active");
  filterVulns();
}

function filterVulns() {
  const q = document.getElementById("vuln-search")?.value?.toLowerCase() || "";
  const tbody = document.getElementById("vuln-tbody");

  let vulns = [];
  for (const t of state.targets) {
    for (const v of (t.vulnerabilities || [])) {
      vulns.push({ ...v, orgName: t.name });
    }
  }

  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  vulns.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  if (state.vulnFilter !== "ALL") vulns = vulns.filter(v => v.severity === state.vulnFilter);
  if (q) vulns = vulns.filter(v =>
    v.title?.toLowerCase().includes(q) ||
    v.orgName?.toLowerCase().includes(q) ||
    v.category?.toLowerCase().includes(q) ||
    v.id?.toLowerCase().includes(q)
  );

  if (!vulns.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No vulnerabilities match your filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = vulns.map(v => `
    <tr>
      <td><code style="font-size:11px;color:var(--text-3)">${v.id || "—"}</code></td>
      <td style="font-weight:500">${v.title || "—"}</td>
      <td style="color:var(--text-2)">${v.orgName || "—"}</td>
      <td><span style="font-size:12px;color:var(--text-2)">${v.category || "—"}</span></td>
      <td><code style="font-size:11px;color:var(--text-3)">${v.cwe || "—"}</code></td>
      <td><span class="badge badge-${(v.severity || "LOW").toLowerCase()}">${v.severity || "—"}</span></td>
    </tr>
  `).join("");
}

// ─── SIS Scoring ─────────────────────────────────────────────

function renderSIS() {
  const grid = document.getElementById("sis-grid");
  const empty = document.getElementById("sis-empty");

  if (!state.sisDashboard?.ngos?.length) {
    grid.style.display = "none";
    empty.style.display = "flex";
    return;
  }

  empty.style.display = "none";
  grid.style.display = "grid";

  grid.innerHTML = state.sisDashboard.ngos.map(ngo => {
    const findings = ngo.findings || [];
    return `
      <div class="sis-card">
        <div class="sis-card-header">
          <div>
            <div class="sis-card-name">${ngo.name}</div>
            <div class="sis-card-slug">${ngo.slug}</div>
          </div>
          <div class="sis-score-ring">
            <div class="sis-score-num" style="color:${sisColor(ngo.headline_sis)}">${ngo.headline_sis}</div>
            <div class="sis-score-label">SIS / 100</div>
          </div>
        </div>
        <div class="sis-card-body">
          <div class="sis-breakdown">
            <div class="sis-breakdown-item">
              <div class="breakdown-val">${findings[0]?.sis?.population_score ?? "—"}</div>
              <div class="breakdown-label">Population</div>
            </div>
            <div class="sis-breakdown-item">
              <div class="breakdown-val">${findings[0]?.sis?.data_sensitivity_score ?? "—"}</div>
              <div class="breakdown-label">Data</div>
            </div>
            <div class="sis-breakdown-item">
              <div class="breakdown-val">${findings[0]?.sis?.ease_of_remediation_score ?? "—"}</div>
              <div class="breakdown-label">Ease Fix</div>
            </div>
          </div>

          ${ngo.mission_alignment_narrative ? `
          <div class="sis-narrative">${ngo.mission_alignment_narrative}</div>
          ` : ""}

          ${ngo.urgency_note ? `
          <div class="sis-urgency">
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14" style="flex-shrink:0;margin-top:1px"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
            ${ngo.urgency_note}
          </div>
          ` : ""}

          <div class="sis-findings">
            ${findings.map(f => `
              <div class="sis-finding-row">
                <span class="finding-id">${f.id}</span>
                <span class="finding-title" title="${f.title}">${f.title}</span>
                <span class="badge badge-${(f.severity || "low").toLowerCase()}">${f.severity}</span>
                <span style="font-size:12px;font-weight:700;color:var(--indigo);margin-left:6px">${f.sis?.total_sis ?? ""}</span>
              </div>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function sisColor(score) {
  if (score >= 80) return "var(--red)";
  if (score >= 60) return "var(--amber)";
  return "var(--green)";
}

// ─── Disclosures ─────────────────────────────────────────────

function renderDisclosures() {
  const ngos = state.sisDashboard?.ngos || [];
  const empty = document.getElementById("disclosures-empty");
  const layout = document.getElementById("disclosure-layout");
  const list = document.getElementById("disclosure-list");

  const withDrafts = ngos.filter(n => n.disclosure_draft_path);

  if (!withDrafts.length) {
    empty.style.display = "flex";
    layout.style.display = "none";
    return;
  }

  empty.style.display = "none";
  layout.style.display = "grid";

  list.innerHTML = `<div class="disclosure-list-header">NGO Disclosures (${withDrafts.length})</div>` +
    withDrafts.map((ngo, i) => `
      <div class="disclosure-item" onclick="loadDisclosure('${ngo.slug}', this)">
        <div class="disclosure-item-name">${ngo.name}</div>
        <div class="disclosure-item-meta">
          <span class="badge badge-sector" style="font-size:10px;padding:1px 6px">SIS ${ngo.headline_sis}</span>
          <span>${ngo.findings?.length || 0} finding${(ngo.findings?.length || 0) !== 1 ? "s" : ""}</span>
        </div>
      </div>
    `).join("");

  // Auto-load first
  if (withDrafts.length > 0) {
    const firstItem = list.querySelector(".disclosure-item");
    loadDisclosure(withDrafts[0].slug, firstItem);
  }
}

async function loadDisclosure(slug, el) {
  document.querySelectorAll(".disclosure-item").forEach(i => i.classList.remove("active"));
  if (el) el.classList.add("active");

  const content = document.getElementById("disclosure-content");
  content.innerHTML = `<div class="empty-state"><p style="color:var(--text-3)">Loading...</p></div>`;

  try {
    const res = await fetch(`/api/disclosures/${slug}`);
    if (!res.ok) throw new Error("Not found");
    const md = await res.text();
    content.innerHTML = `<div class="md-content">${renderMarkdown(md)}</div>`;
  } catch {
    content.innerHTML = `<div class="empty-state"><p>Could not load disclosure draft.</p><code>/api/disclosures/${slug}</code></div>`;
  }
}

// ─── Reports ─────────────────────────────────────────────────

function renderReports() {
  const list = document.getElementById("report-list");

  const reports = [
    { name: "Vibe Check Report", type: "output/vibe-check-report.md", endpoint: "/api/report" },
    { name: "Fix Artifact (Patch)", type: "output/fix-artifact.patch", endpoint: "/api/fix-artifact" },
    ...(state.targets || []).map(t => ({
      name: t.name,
      type: `findings/vibe-check-report-${t.domain?.replace(/\./g, "-")}.md`,
      endpoint: `/api/findings/${t.domain?.replace(/\./g, "-")}`,
    })),
  ];

  list.innerHTML = `<div class="report-list-header">Generated Files</div>` +
    reports.map(r => `
      <div class="report-list-item" onclick="loadReport('${r.endpoint}', this)">
        <div class="report-item-name">${r.name}</div>
        <div class="report-item-type">${r.type}</div>
      </div>
    `).join("");
}

async function loadReport(endpoint, el) {
  document.querySelectorAll(".report-list-item").forEach(i => i.classList.remove("active"));
  if (el) el.classList.add("active");

  const display = document.getElementById("report-display");
  display.innerHTML = `<div class="empty-state"><p style="color:var(--text-3)">Loading...</p></div>`;

  try {
    const res = await fetch(endpoint);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    display.innerHTML = `<div class="md-content">${renderMarkdown(text)}</div>`;
  } catch (err) {
    display.innerHTML = `<div class="empty-state"><p>Could not load report.</p></div>`;
  }
}

// ─── Markdown Renderer ────────────────────────────────────────

function renderMarkdown(md) {
  let html = md
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Code blocks
  html = html.replace(/```[\w]*\n([\s\S]*?)```/g, (_, code) =>
    `<pre><code>${code.trim()}</code></pre>`);

  // Inline code
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Headers
  html = html.replace(/^#### (.+)$/gm, "<h4>$1</h4>");
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");

  // Bold / italic
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");

  // Blockquotes
  html = html.replace(/^&gt; (.+)$/gm, "<blockquote>$1</blockquote>");

  // HR
  html = html.replace(/^---$/gm, "<hr>");

  // Unordered lists
  html = html.replace(/((?:^- .+\n?)+)/gm, (match) => {
    const items = match.trim().split("\n").map(l => `<li>${l.replace(/^- /, "")}</li>`).join("");
    return `<ul>${items}</ul>`;
  });

  // Tables
  const lines = html.split("\n");
  let out = [];
  let inTable = false;
  let tableRows = [];

  for (const line of lines) {
    if (/^\|.+\|$/.test(line)) {
      const cells = line.split("|").slice(1, -1).map(c => c.trim());
      if (cells.every(c => /^[-: ]+$/.test(c))) continue; // separator
      tableRows.push(cells);
      inTable = true;
    } else {
      if (inTable) {
        const header = tableRows[0].map(c => `<th>${c}</th>`).join("");
        const body = tableRows.slice(1).map(row =>
          `<tr>${row.map(c => `<td>${c}</td>`).join("")}</tr>`
        ).join("");
        out.push(`<table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table>`);
        tableRows = [];
        inTable = false;
      }
      out.push(line);
    }
  }
  if (inTable && tableRows.length) {
    const header = tableRows[0].map(c => `<th>${c}</th>`).join("");
    const body = tableRows.slice(1).map(row =>
      `<tr>${row.map(c => `<td>${c}</td>`).join("")}</tr>`
    ).join("");
    out.push(`<table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table>`);
  }

  html = out.join("\n");

  // Paragraphs (lines not already in block elements)
  html = html.replace(/^(?!<[a-z|\/])(.+)$/gm, "<p>$1</p>");

  return html;
}

// ─── Target Modal ─────────────────────────────────────────────

function openTargetModal(index) {
  const t = state.targets[index];
  if (!t) return;

  const critCount = t.vulnerabilities?.filter(v => v.severity === "CRITICAL").length || 0;
  const highCount = t.vulnerabilities?.filter(v => v.severity === "HIGH").length || 0;
  const scoreColor = t.scoring?.vibeRiskScore >= 80 ? "var(--red)" : t.scoring?.vibeRiskScore >= 60 ? "var(--amber)" : "var(--green)";

  document.getElementById("modal-body").innerHTML = `
    <div class="modal-org-name">${t.name}</div>
    <div class="modal-org-domain">${t.domain}</div>
    <span class="badge badge-sector">${t.sector}</span>

    <div class="modal-section">
      <div class="modal-section-title">Risk Assessment</div>
      <div class="modal-meta-grid">
        <div class="modal-meta-item">
          <div class="modal-meta-val" style="color:${scoreColor}">${t.scoring?.vibeRiskScore ?? "—"}</div>
          <div class="modal-meta-label">Risk Score</div>
        </div>
        <div class="modal-meta-item">
          <div class="modal-meta-val" style="color:var(--red)">${critCount}</div>
          <div class="modal-meta-label">Critical</div>
        </div>
        <div class="modal-meta-item">
          <div class="modal-meta-val">${t.vulnerabilities?.length || 0}</div>
          <div class="modal-meta-label">Total Findings</div>
        </div>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Mission</div>
      <div class="modal-mission">${t.mission || "Not available"}</div>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Tech Stack</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <span class="badge badge-sector">${t.techStack?.platform || "—"}</span>
        ${t.techStack?.framework ? `<span class="badge badge-low">${t.techStack.framework}</span>` : ""}
        ${t.techStack?.isVibeCoded ? `<span class="tag-vibecoded">Vibe-Coded</span>` : ""}
      </div>
    </div>

    ${t.securityHeaders ? `
    <div class="modal-section">
      <div class="modal-section-title">Security Headers (${t.securityHeaders.score ?? "?"}%)</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${(t.securityHeaders.present || []).map(h => `<span class="chip header-chip-ok">✓ ${h}</span>`).join("")}
        ${(t.securityHeaders.missing || []).map(h => `<span class="chip header-chip-missing">✗ ${h}</span>`).join("")}
      </div>
    </div>
    ` : ""}

    <div class="modal-section">
      <div class="modal-section-title">Vulnerabilities (${t.vulnerabilities?.length || 0})</div>
      <div class="modal-vuln-list">
        ${(t.vulnerabilities || []).map(v => `
          <div class="modal-vuln-row">
            <span class="modal-vuln-id">${v.id}</span>
            <span class="modal-vuln-title">${v.title}</span>
            <span class="badge badge-${(v.severity || "low").toLowerCase()}">${v.severity}</span>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  document.getElementById("modal-backdrop").classList.add("open");
  document.body.style.overflow = "hidden";
}

function closeModal() {
  document.getElementById("modal-backdrop").classList.remove("open");
  document.body.style.overflow = "";
}

// ─── Helpers ─────────────────────────────────────────────────

function updateNavBadges() {
  const totalVulns = state.targets.reduce((s, t) => s + (t.vulnerabilities?.length || 0), 0);
  const sisCount = state.sisDashboard?.ngos?.length || 0;
  const draftsCount = state.sisDashboard?.summary?.ngos_with_drafts || 0;

  document.getElementById("nav-badge-targets").textContent = state.targets.length;
  document.getElementById("nav-badge-vulns").textContent = totalVulns;
  document.getElementById("nav-badge-sis").textContent = sisCount;
  document.getElementById("nav-badge-disclosures").textContent = draftsCount;
}

function updateLastScan() {
  const ts = state.sisDashboard?.generated_at;
  const el = document.getElementById("last-scan-label");
  if (ts && el) {
    const d = new Date(ts);
    el.textContent = `Last analyzed: ${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setupKeyboard() {
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
  });
}
