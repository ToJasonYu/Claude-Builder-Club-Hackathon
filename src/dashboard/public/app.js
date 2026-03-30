// ============================================================================
// NGO-Guardian Dashboard — Interactive Frontend
// ============================================================================

let targets = [];
let currentFilter = "all";

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await loadData();
  setupTabs();
  setupFilters();
  setupModal();
  setupPipelineAnimation();
  setupRunButton();
});

// ─── Data Loading ────────────────────────────────────────────────────────────

async function loadData() {
  try {
    const res = await fetch("/api/targets");
    targets = await res.json();
    renderStats();
    renderTargets();
    renderVulnerabilities();
    renderRiskMatrix();
    renderReportList();
  } catch (err) {
    console.error("Failed to load data:", err);
  }
}

// ─── Stats ───────────────────────────────────────────────────────────────────

function renderStats() {
  const totalVulns = targets.reduce((s, t) => s + t.vulnerabilities.length, 0);
  const totalCritical = targets.reduce((s, t) =>
    s + t.vulnerabilities.filter(v => v.severity === "CRITICAL").length, 0);
  const avgScore = Math.round(targets.reduce((s, t) => s + t.scoring.vibeRiskScore, 0) / targets.length);
  const criticalData = targets.filter(t => t.scoring.criticalDataExposure).length;

  animateNumber("stat-targets", targets.length);
  animateNumber("stat-vulns", totalVulns);
  animateNumber("stat-critical", totalCritical);
  animateNumber("stat-avgscore", avgScore, "/100");
  animateNumber("stat-data-risk", criticalData);
}

function animateNumber(id, target, suffix = "") {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const duration = 1200;
  const step = target / (duration / 16);
  const timer = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(timer);
    }
    el.innerHTML = Math.round(current) + (suffix ? `<span class="stat-unit">${suffix}</span>` : "");
  }, 16);
}

// ─── Targets ─────────────────────────────────────────────────────────────────

function renderTargets() {
  const grid = document.getElementById("targets-grid");
  grid.innerHTML = targets.map((t, i) => {
    const critCount = t.vulnerabilities.filter(v => v.severity === "CRITICAL").length;
    const highCount = t.vulnerabilities.filter(v => v.severity === "HIGH").length;
    const medCount = t.vulnerabilities.filter(v => v.severity === "MEDIUM").length;
    const lowCount = t.vulnerabilities.filter(v => v.severity === "LOW").length;
    const scoreColor = getScoreColor(t.scoring.vibeRiskScore);
    const circumference = 2 * Math.PI * 26;
    const offset = circumference - (t.scoring.vibeRiskScore / 100) * circumference;

    return `
      <div class="target-card animate-in" style="animation-delay: ${i * 100}ms" data-index="${i}">
        <div class="target-card-header">
          <div class="target-info">
            <h3>${t.name}</h3>
            <div class="target-domain">${t.domain}</div>
            <span class="target-sector ${t.sector}">${t.sector}</span>
          </div>
          <div class="target-score">
            <div class="score-ring">
              <svg viewBox="0 0 64 64">
                <circle class="score-ring-bg" cx="32" cy="32" r="26"/>
                <circle class="score-ring-fill" cx="32" cy="32" r="26"
                  stroke="${scoreColor}"
                  stroke-dasharray="${circumference}"
                  stroke-dashoffset="${offset}"/>
              </svg>
              <div class="score-ring-value" style="color: ${scoreColor}">${t.scoring.vibeRiskScore}</div>
            </div>
          </div>
        </div>
        <div class="target-card-body">
          <p class="target-mission">${t.mission}</p>
          <div class="target-stack">
            <span class="stack-tag">${t.techStack.platform}</span>
            <span class="stack-tag">${t.techStack.framework || "Unknown"}</span>
            ${t.techStack.isVibeCoded ? '<span class="stack-tag" style="background: rgba(255, 97, 216, 0.12); color: #ff61d8; border-color: rgba(255, 97, 216, 0.2);">⚡ vibe-coded</span>' : ""}
          </div>
        </div>
        <div class="target-card-footer">
          <div class="vuln-badges">
            ${critCount ? `<span class="vuln-badge critical">${critCount} C</span>` : ""}
            ${highCount ? `<span class="vuln-badge high">${highCount} H</span>` : ""}
            ${medCount ? `<span class="vuln-badge medium">${medCount} M</span>` : ""}
            ${lowCount ? `<span class="vuln-badge low">${lowCount} L</span>` : ""}
          </div>
          <button class="target-view-btn" onclick="openTargetModal(${i})">
            View Details →
          </button>
        </div>
      </div>
    `;
  }).join("");
}

function getScoreColor(score) {
  if (score >= 80) return "#ff3b5c";
  if (score >= 60) return "#ff8c42";
  if (score >= 40) return "#ffd166";
  return "#00c896";
}

// ─── Vulnerabilities ─────────────────────────────────────────────────────────

function renderVulnerabilities(filter = "all") {
  const list = document.getElementById("vuln-list");
  let allVulns = [];
  for (const t of targets) {
    for (const v of t.vulnerabilities) {
      allVulns.push({ ...v, org: t.name, domain: t.domain });
    }
  }

  if (filter !== "all") {
    allVulns = allVulns.filter(v => v.severity === filter);
  }

  // Sort: CRITICAL first
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  allVulns.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  list.innerHTML = allVulns.map((v, i) => `
    <div class="vuln-item animate-in" style="animation-delay: ${i * 50}ms">
      <div class="vuln-severity-bar ${v.severity}"></div>
      <div class="vuln-id">${v.id}</div>
      <div>
        <div class="vuln-title">${v.title}</div>
        <div class="vuln-location" title="${v.location}">${v.org} — ${v.location}</div>
      </div>
      <div class="vuln-category-tag">${v.category}</div>
      <div class="vuln-badge ${v.severity.toLowerCase()}" style="justify-content: center;">${v.severity}</div>
    </div>
  `).join("");
}

// ─── Risk Matrix ─────────────────────────────────────────────────────────────

function renderRiskMatrix() {
  renderSeverityChart();
  renderRiskBars();
  renderStackChart();
  renderDataSensitivity();
}

function renderSeverityChart() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const t of targets) {
    for (const v of t.vulnerabilities) {
      counts[v.severity] = (counts[v.severity] || 0) + 1;
    }
  }
  const max = Math.max(...Object.values(counts), 1);

  document.getElementById("severity-chart").innerHTML = Object.entries(counts).map(([sev, count]) => `
    <div class="severity-row">
      <div class="severity-label" style="color: var(--severity-${sev.toLowerCase()})">${sev}</div>
      <div class="severity-bar-track">
        <div class="severity-bar-fill ${sev.toLowerCase()}" style="width: ${(count / max) * 100}%">
          <span class="severity-bar-count">${count}</span>
        </div>
      </div>
    </div>
  `).join("");
}

function renderRiskBars() {
  const sorted = [...targets].sort((a, b) => b.scoring.vibeRiskScore - a.scoring.vibeRiskScore);

  document.getElementById("risk-bars").innerHTML = sorted.map(t => `
    <div class="risk-bar-row">
      <div class="risk-bar-name">${t.name}</div>
      <div class="risk-bar-track">
        <div class="risk-bar-fill" style="width: ${t.scoring.vibeRiskScore}%; background: linear-gradient(90deg, ${getScoreColor(t.scoring.vibeRiskScore)}88, ${getScoreColor(t.scoring.vibeRiskScore)});">
          ${t.scoring.vibeRiskScore}/100
        </div>
      </div>
    </div>
  `).join("");
}

function renderStackChart() {
  const stacks = {};
  for (const t of targets) {
    const platform = t.techStack.platform || "Unknown";
    stacks[platform] = (stacks[platform] || 0) + 1;
  }

  document.getElementById("stack-chart").innerHTML = Object.entries(stacks).map(([name, count]) => `
    <div class="stack-item">
      <div class="stack-count">${count}</div>
      <div class="stack-name">${name}</div>
    </div>
  `).join("");
}

function renderDataSensitivity() {
  const dataTypes = [
    { icon: "👶", type: "Protected Minor PII", detail: "Child profiles, photos, welfare records", level: "CRITICAL" },
    { icon: "📋", type: "Case File Records", detail: "Refugee status, legal cases, personal histories", level: "CRITICAL" },
    { icon: "🏥", type: "Health & Welfare", detail: "Medical histories, disability status, trauma assessments", level: "CRITICAL" },
    { icon: "📍", type: "Location Data", detail: "Refugee camps, aid distribution points, field worker locations", level: "HIGH" },
    { icon: "💰", type: "Financial Records", detail: "Donor payment info, transaction histories", level: "HIGH" },
    { icon: "🔵", type: "Personal PII", detail: "Names, emails, phone numbers, addresses", level: "MEDIUM" }
  ];

  document.getElementById("data-sensitivity").innerHTML = dataTypes.map(d => `
    <div class="sensitivity-item">
      <div class="sensitivity-icon">${d.icon}</div>
      <div class="sensitivity-info">
        <div class="sensitivity-type">${d.type}</div>
        <div class="sensitivity-detail">${d.detail}</div>
      </div>
      <span class="sensitivity-level ${d.level}">${d.level}</span>
    </div>
  `).join("");
}

// ─── Reports ─────────────────────────────────────────────────────────────────

function renderReportList() {
  const reports = [
    { name: "Full Vibe Check Report", type: "vibe-check-report.md", endpoint: "/api/report" },
    { name: "Fix Artifact (Patches)", type: "fix-artifact.patch", endpoint: "/api/fix-artifact" },
    ...targets.map(t => ({
      name: t.name,
      type: `findings/${t.domain.replace(/\./g, "-")}.md`,
      endpoint: `/api/findings/${t.domain.replace(/\./g, "-")}`
    }))
  ];

  const list = document.getElementById("report-list");
  list.innerHTML = reports.map((r, i) => `
    <div class="report-list-item" data-endpoint="${r.endpoint}" onclick="loadReport(this, '${r.endpoint}')">
      <div class="report-item-name">${r.name}</div>
      <div class="report-item-type">${r.type}</div>
    </div>
  `).join("");
}

async function loadReport(el, endpoint) {
  // Update active state
  document.querySelectorAll(".report-list-item").forEach(i => i.classList.remove("active"));
  el.classList.add("active");

  const display = document.getElementById("report-display");
  display.innerHTML = '<p class="report-placeholder">Loading...</p>';

  try {
    const res = await fetch(endpoint);
    const text = await res.text();
    display.innerHTML = renderMarkdown(text);
  } catch (err) {
    display.innerHTML = '<p class="report-placeholder">Failed to load report.</p>';
  }
}

function renderMarkdown(md) {
  // Simple markdown to HTML renderer
  let html = md;

  // Escape HTML
  html = html.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  // Code blocks (``` ... ```)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre><code class="language-${lang}">${code.trim()}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Headers
  html = html.replace(/^#### (.+)$/gm, "<h4>$1</h4>");
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");

  // Bold and italic
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.+?)\*/g, "<em>$1</em>");

  // Blockquotes
  html = html.replace(/^&gt; (.+)$/gm, "<blockquote>$1</blockquote>");

  // Horizontal rules
  html = html.replace(/^---$/gm, "<hr>");

  // Tables
  html = html.replace(/^\|(.+)\|$/gm, (match) => {
    const cells = match.split("|").filter(c => c.trim());
    if (cells.every(c => /^[\s-:]+$/.test(c))) return "<!-- sep -->";
    return cells.map(c => `<td>${c.trim()}</td>`).join("");
  });

  // Wrap table rows
  const lines = html.split("\n");
  let inTable = false;
  let tableHtml = "";
  const output = [];

  for (const line of lines) {
    if (line.startsWith("<td>")) {
      if (!inTable) { tableHtml = "<table><tbody>"; inTable = true; }
      if (line !== "<!-- sep -->") {
        tableHtml += `<tr>${line}</tr>`;
      }
    } else {
      if (inTable) {
        tableHtml += "</tbody></table>";
        // Convert first row to th
        tableHtml = tableHtml.replace(/<tbody><tr>(.*?)<\/tr>/, (_, cells) => {
          return `<thead><tr>${cells.replace(/<td>/g, "<th>").replace(/<\/td>/g, "</th>")}</tr></thead><tbody>`;
        });
        output.push(tableHtml);
        inTable = false;
        tableHtml = "";
      }
      output.push(line);
    }
  }
  if (inTable) {
    tableHtml += "</tbody></table>";
    tableHtml = tableHtml.replace(/<tbody><tr>(.*?)<\/tr>/, (_, cells) => {
      return `<thead><tr>${cells.replace(/<td>/g, "<th>").replace(/<\/td>/g, "</th>")}</tr></thead><tbody>`;
    });
    output.push(tableHtml);
  }

  html = output.join("\n");

  // Lists
  html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>\n?)+/g, (match) => `<ul>${match}</ul>`);

  // Paragraphs (lines not wrapped in tags)
  html = html.replace(/^(?!<[a-z]|$)(.+)$/gm, "<p>$1</p>");

  // Clean up consecutive blockquotes
  html = html.replace(/<\/blockquote>\n<blockquote>/g, "<br>");

  return html;
}

// ─── Modal ───────────────────────────────────────────────────────────────────

function setupModal() {
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal-overlay").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
}

function openTargetModal(index) {
  const t = targets[index];
  const scoreColor = getScoreColor(t.scoring.vibeRiskScore);

  const critCount = t.vulnerabilities.filter(v => v.severity === "CRITICAL").length;
  const highCount = t.vulnerabilities.filter(v => v.severity === "HIGH").length;

  document.getElementById("modal-content").innerHTML = `
    <div class="modal-target-header">
      <div>
        <div class="modal-target-name">${t.name}</div>
        <div class="modal-target-domain">${t.domain}</div>
        <span class="target-sector ${t.sector}" style="margin-top: 8px; display: inline-block;">${t.sector}</span>
      </div>
      <div class="modal-score-display">
        <div class="modal-score-number" style="color: ${scoreColor}">${t.scoring.vibeRiskScore}</div>
        <div class="modal-score-label">Vibe Risk Score</div>
      </div>
    </div>

    <div class="modal-section">
      <h4>📋 Mission</h4>
      <p style="font-size: 13px; color: var(--text-secondary);">${t.mission}</p>
    </div>

    <div class="modal-section">
      <h4>⚡ Tech Stack</h4>
      <div class="target-stack">
        <span class="stack-tag">${t.techStack.platform}</span>
        <span class="stack-tag">${t.techStack.framework || "Unknown"}</span>
        ${t.techStack.isVibeCoded ? '<span class="stack-tag" style="background: rgba(255, 97, 216, 0.12); color: #ff61d8; border-color: rgba(255, 97, 216, 0.2);">⚡ vibe-coded</span>' : ""}
      </div>
    </div>

    <div class="modal-section">
      <h4>🌐 Discovered Subdomains (${t.subdomains.length})</h4>
      <div class="modal-subdomains">
        ${t.subdomains.map(s => `<span class="subdomain-chip">${s}</span>`).join("")}
      </div>
    </div>

    <div class="modal-section">
      <h4>🔒 Security Headers (${t.securityHeaders.score ?? "N/A"}%)</h4>
      <div class="modal-headers">
        ${t.securityHeaders.missing.map(h => `<span class="header-chip missing">✗ ${h}</span>`).join("")}
        ${t.securityHeaders.present.map(h => `<span class="header-chip present">✓ ${h}</span>`).join("")}
      </div>
    </div>

    <div class="modal-section">
      <h4>🐛 Vulnerabilities (${t.vulnerabilities.length}) — ${critCount} Critical, ${highCount} High</h4>
      <div class="modal-vuln-list">
        ${t.vulnerabilities.map(v => `
          <div class="modal-vuln ${v.severity}">
            <div class="modal-vuln-header">
              <span class="modal-vuln-title">${v.title}</span>
              <span class="modal-vuln-severity ${v.severity}">${v.severity}</span>
            </div>
            <div class="modal-vuln-location">${v.id} · ${v.category} · ${v.cwe} · ${v.location}</div>
          </div>
        `).join("")}
      </div>
    </div>

    ${t.scoring.criticalDataExposure ? `
    <div class="modal-section" style="padding: 16px; background: rgba(255, 59, 92, 0.06); border: 1px solid rgba(255, 59, 92, 0.15); border-radius: var(--radius-md);">
      <h4 style="color: var(--severity-critical);">⚠️ Critical Data Exposure Detected</h4>
      <p style="font-size: 12px; color: var(--text-secondary);">This organization handles sensitive data (PII, minor data, or health records) that appears to be insufficiently protected based on the vulnerabilities found.</p>
    </div>
    ` : ""}
  `;

  document.getElementById("modal-overlay").classList.add("active");
  document.body.style.overflow = "hidden";
}

function closeModal() {
  document.getElementById("modal-overlay").classList.remove("active");
  document.body.style.overflow = "";
}

// ─── Tabs ────────────────────────────────────────────────────────────────────

function setupTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(`panel-${tab.dataset.tab}`).classList.add("active");
    });
  });
}

// ─── Filters ─────────────────────────────────────────────────────────────────

function setupFilters() {
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      renderVulnerabilities(btn.dataset.severity);
    });
  });
}

// ─── Pipeline Animation ─────────────────────────────────────────────────────

function setupPipelineAnimation() {
  // Pipeline stages are already marked as completed
  // We animate them in sequence on load
  const stages = document.querySelectorAll(".pipeline-stage");
  const connectors = document.querySelectorAll(".pipeline-connector");

  stages.forEach(s => s.classList.remove("completed"));
  connectors.forEach(c => c.classList.remove("completed"));

  stages.forEach((stage, i) => {
    setTimeout(() => {
      stage.classList.add("completed");
      if (connectors[i]) {
        setTimeout(() => connectors[i].classList.add("completed"), 200);
      }
    }, i * 400 + 300);
  });
}

// ─── Run Button ──────────────────────────────────────────────────────────────

function setupRunButton() {
  document.getElementById("btn-run-scan").addEventListener("click", async () => {
    const btn = document.getElementById("btn-run-scan");
    btn.disabled = true;
    btn.innerHTML = `<span class="pulse-dot"></span> Scanning...`;

    // Re-animate pipeline
    setupPipelineAnimation();

    // Simulate delay
    await new Promise(r => setTimeout(r, 2500));

    // Reload data
    await loadData();

    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 2L14 8L4 14V2Z" fill="currentColor"/></svg> Run Pipeline`;
  });
}
