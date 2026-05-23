/**
 * static/js/app.js
 * Front-end logic for CodeSentinel ML Flask app.
 */

// ── Scroll-reveal for feature cards ────────────────────────────────────
const observer = new IntersectionObserver((entries) => {
  entries.forEach((e, i) => {
    if (e.isIntersecting) {
      setTimeout(() => e.target.classList.add('visible'), i * 100);
      observer.unobserve(e.target);
    }
  });
}, { threshold: 0.15 });
document.querySelectorAll('.feature-card').forEach(c => observer.observe(c));

// ── Scan tabs ───────────────────────────────────────────────────────────
document.querySelectorAll('.scan-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ── Dashboard tabs ──────────────────────────────────────────────────────
document.querySelectorAll('.dtab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.dtab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.dtab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('dtab-' + tab.dataset.dtab).classList.add('active');
  });
});

// ── File upload drop zone ───────────────────────────────────────────────
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileNameEl = document.getElementById('file-name');

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) {
    fileInput.files = e.dataTransfer.files;
    fileNameEl.textContent = '📦 ' + file.name;
    fileNameEl.style.display = 'block';
  }
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) {
    fileNameEl.textContent = '📦 ' + fileInput.files[0].name;
    fileNameEl.style.display = 'block';
  }
});

// ── Loader animation ────────────────────────────────────────────────────
const LOADER_PHRASES = [
  'Initializing Cyber Threat Intelligence Engine...',
  'Recursively Traversing Directory Hierarchy...',
  'Executing Regex Signature Vulnerability Pass...',
  'Correlating Attack Source-Sink Chains...',
  'Running Logistic Regression TF-IDF Classifier...',
  'Mapping Exposed Attack Surface Vectors...',
  'Generating Security Hotspots Matrix...',
  'Compiling Analysis Report...'
];

let loaderInterval = null;
function startLoader() {
  const loaderEl = document.getElementById('loader');
  const barEl    = document.getElementById('loader-bar');
  const textEl   = document.getElementById('loader-text');
  loaderEl.style.display = 'block';

  let phraseIdx = 0;
  let charIdx   = 0;
  barEl.style.width = '0%';

  function tick() {
    if (phraseIdx >= LOADER_PHRASES.length) return;
    const phrase = LOADER_PHRASES[phraseIdx];
    charIdx++;
    const pct = Math.round(((phraseIdx + charIdx / phrase.length) / LOADER_PHRASES.length) * 100);
    barEl.style.width = pct + '%';
    textEl.innerHTML = '&gt;_ ' + phrase.slice(0, charIdx) + '<span class="loader-cursor"></span>';

    if (charIdx >= phrase.length) {
      phraseIdx++;
      charIdx = 0;
    }
  }

  loaderInterval = setInterval(tick, 28);
}

function stopLoader() {
  if (loaderInterval) clearInterval(loaderInterval);
  document.getElementById('loader-bar').style.width = '100%';
  document.getElementById('loader-text').innerHTML = '&gt;_ Scan complete. Building report...<span class="loader-cursor"></span>';
  setTimeout(() => { document.getElementById('loader').style.display = 'none'; }, 600);
}

// ── Error display ───────────────────────────────────────────────────────
function showError(msg) {
  const el = document.getElementById('scan-error');
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
}
function clearError() {
  document.getElementById('scan-error').style.display = 'none';
}

// ── Scan buttons ────────────────────────────────────────────────────────
document.getElementById('btn-path').addEventListener('click', () => {
  clearError();
  const path = document.getElementById('path-input').value.trim();
  if (!path) { showError('Please enter a directory path.'); return; }
  runScan('/api/scan/path', 'json', { path });
});

document.getElementById('btn-github').addEventListener('click', () => {
  clearError();
  const url = document.getElementById('github-input').value.trim();
  if (!url) { showError('Please enter a GitHub URL.'); return; }
  runScan('/api/scan/github', 'json', { url });
});

document.getElementById('btn-upload').addEventListener('click', () => {
  clearError();
  const file = fileInput.files[0];
  if (!file) { showError('Please select a ZIP file.'); return; }
  const fd = new FormData();
  fd.append('file', file);
  runScan('/api/scan/upload', 'form', fd);
});

// ── Main scan runner ────────────────────────────────────────────────────
function runScan(endpoint, mode, payload) {
  // Disable all buttons
  document.querySelectorAll('.scan-btn').forEach(b => b.disabled = true);
  startLoader();

  const opts = { method: 'POST' };
  if (mode === 'json') {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(payload);
  } else {
    opts.body = payload; // FormData
  }

  fetch(endpoint, opts)
    .then(r => r.json())
    .then(data => {
      stopLoader();
      document.querySelectorAll('.scan-btn').forEach(b => b.disabled = false);
      if (data.error) { showError(data.error); return; }
      renderDashboard(data);
    })
    .catch(err => {
      stopLoader();
      document.querySelectorAll('.scan-btn').forEach(b => b.disabled = false);
      showError('Scan failed: ' + err.message);
    });
}

// ── Back button ─────────────────────────────────────────────────────────
document.getElementById('back-btn').addEventListener('click', () => {
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('hero').style.display = 'flex';
  document.getElementById('features').style.display = 'block';
  document.getElementById('scan').style.display = 'block';
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ── Render Dashboard ────────────────────────────────────────────────────
function renderDashboard(d) {
  // Hide hero/features/scan, show dashboard
  document.getElementById('hero').style.display = 'none';
  document.getElementById('features').style.display = 'none';
  document.getElementById('scan').style.display = 'none';
  const dash = document.getElementById('dashboard');
  dash.style.display = 'block';
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Title
  document.getElementById('dash-title').textContent = d.project_name + ' — Analysis Complete';
  document.getElementById('dash-sub').textContent =
    `${d.stats.total_files} files · ${d.stats.total_lines.toLocaleString()} lines · ${d.findings.length} findings · ${new Date().toLocaleTimeString()}`;

  // ── Metric Grid ────────────────────────────────────────────────────
  const sc = d.severity_counts;
  document.getElementById('metric-grid').innerHTML = `
    <div class="metric-card">
      <div class="metric-label">Security Score</div>
      <div class="metric-value" style="color:${d.security_score >= 70 ? '#34d399' : d.security_score >= 40 ? '#fbbf24' : '#f87171'}">${d.security_score}</div>
      <div class="metric-sub">out of 100</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Files Scanned</div>
      <div class="metric-value">${d.stats.total_files}</div>
      <div class="metric-sub">${(d.stats.size_kb / 1024).toFixed(2)} MB</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Vulnerabilities</div>
      <div class="metric-value" style="color:#f87171">${d.findings.length}</div>
      <div class="metric-sub">H:${sc.high} M:${sc.medium} L:${sc.low}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Entry Points</div>
      <div class="metric-value" style="color:#fbbf24">${d.entry_points.length}</div>
      <div class="metric-sub">exposed vectors</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Attack Chains</div>
      <div class="metric-value" style="color:#f87171">${d.attack_chains.length}</div>
      <div class="metric-sub">source→sink paths</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Code Lines</div>
      <div class="metric-value">${d.stats.total_lines.toLocaleString()}</div>
      <div class="metric-sub">${d.stats.functions} functions</div>
    </div>
  `;

  // ── Vibe Risk Panel ────────────────────────────────────────────────
  const vr = d.vibe_risk;
  const vrCls = vr.score <= 30 ? 'risk-low' : vr.score <= 70 ? 'risk-med' : 'risk-high';
  const bkd = vr.breakdown;
  let bkdHtml = '';
  const bkdColors = ['#f87171', '#fbbf24', '#f87171', '#a78bfa', '#60a5fa'];
  Object.entries(bkd).forEach(([k, v], i) => {
    const color = bkdColors[i] || '#94a3b8';
    bkdHtml += `
      <div class="pbar-wrap">
        <div class="pbar-label">${k}</div>
        <div class="pbar-track"><div class="pbar-fill" style="width:${v}%; background:${color}"></div></div>
        <div class="pbar-val">${v}</div>
      </div>`;
  });

  document.getElementById('vibe-panel').innerHTML = `
    <div class="panel-title"><span>⚡</span> Vibe Coding Risk Index</div>
    <div class="risk-ring-wrap" style="margin-bottom:24px;">
      <div class="risk-ring ${vrCls}">${vr.score}</div>
      <div>
        <div style="font-size:1.1rem; font-weight:700; color:#fff">${vr.category}</div>
        <div style="font-size:0.82rem; color:#64748b; margin-top:4px;">Score out of 100 — higher = more insecure</div>
      </div>
    </div>
    ${bkdHtml}
  `;

  // ── ML File Risks ──────────────────────────────────────────────────
  let mlHtml = '';
  d.file_risks.slice(0, 8).forEach(f => {
    const pillCls = f.ml_prediction === 'High Risk' ? 'pill-high' :
                    f.ml_prediction === 'Medium Risk' ? 'pill-medium' : 'pill-safe';
    mlHtml += `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid rgba(255,255,255,0.04);">
        <div style="font-size:0.8rem; color:#94a3b8; max-width:55%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${f.file}</div>
        <div style="display:flex; align-items:center; gap:10px; flex-shrink:0;">
          <span class="pill ${pillCls}">${f.ml_prediction}</span>
          <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#64748b;">${f.confidence.toFixed(1)}%</span>
        </div>
      </div>`;
  });
  document.getElementById('ml-content').innerHTML = mlHtml || '<p style="color:#64748b">No ML results.</p>';

  // ── Vulnerabilities Tab ────────────────────────────────────────────
  let vulnsHtml = `
    <table class="data-table">
      <thead><tr>
        <th>Severity</th><th>Issue</th><th>File</th><th>Line</th><th>Code</th>
      </tr></thead><tbody>`;
  if (d.findings.length === 0) {
    vulnsHtml += '<tr><td colspan="5" style="color:#34d399; text-align:center; padding:24px;">✓ No vulnerabilities detected</td></tr>';
  }
  d.findings.forEach(f => {
    const pillCls = f.severity === 'High' ? 'pill-high' : f.severity === 'Medium' ? 'pill-medium' : 'pill-low';
    vulnsHtml += `<tr>
      <td><span class="pill ${pillCls}">${f.severity}</span></td>
      <td style="color:#f1f5f9; font-weight:600">${f.issue}</td>
      <td style="color:#64748b; font-size:0.78rem; max-width:200px; overflow:hidden; text-overflow:ellipsis;">${f.file}</td>
      <td style="font-family:'JetBrains Mono',monospace; color:#8b5cf6">${f.line}</td>
      <td><span class="code-snippet">${escHtml(f.matched_code)}</span></td>
    </tr>`;
  });
  vulnsHtml += '</tbody></table>';
  document.getElementById('dtab-vulns').innerHTML = vulnsHtml;

  // ── Entry Points Tab ───────────────────────────────────────────────
  let entHtml = `
    <table class="data-table">
      <thead><tr><th>Type</th><th>Pattern</th><th>File</th><th>Line</th></tr></thead><tbody>`;
  if (d.entry_points.length === 0) {
    entHtml += '<tr><td colspan="4" style="color:#34d399; text-align:center; padding:24px;">No entry points detected</td></tr>';
  }
  d.entry_points.slice(0, 100).forEach(e => {
    const pillCls = e.severity === 'High' ? 'pill-high' : e.severity === 'Medium' ? 'pill-medium' : 'pill-low';
    entHtml += `<tr>
      <td><span class="pill ${pillCls}">${e.type || e.severity}</span></td>
      <td style="font-family:'JetBrains Mono',monospace; font-size:0.78rem; color:#a78bfa">${escHtml(e.pattern || '')}</td>
      <td style="color:#64748b; font-size:0.78rem">${e.file}</td>
      <td style="font-family:'JetBrains Mono',monospace; color:#8b5cf6">${e.line}</td>
    </tr>`;
  });
  entHtml += '</tbody></table>';
  document.getElementById('dtab-entries').innerHTML = entHtml;

  // ── Attack Chains Tab ──────────────────────────────────────────────
  let chainHtml = '';
  if (d.attack_chains.length === 0) {
    chainHtml = '<p style="color:#34d399; text-align:center; padding:32px;">✓ No attack chains detected</p>';
  }
  d.attack_chains.forEach(c => {
    chainHtml += `
      <div class="chain-card">
        <div>
          <span style="color:#00f0ff">${escHtml(c.source || c.entry_pattern || 'Source')}</span>
          <span class="chain-arrow">→</span>
          <span style="color:#ff007f">${escHtml(c.sink || c.vuln_issue || 'Sink')}</span>
        </div>
        <div class="chain-file">📄 ${c.file || 'unknown'} · Line ${c.line || '?'}</div>
      </div>`;
  });
  document.getElementById('dtab-chains').innerHTML = chainHtml;

  // ── Security Maturity Tab ──────────────────────────────────────────
  const m = d.maturity;
  const mColor = m.level === 'Advanced' ? '#34d399' : m.level === 'Intermediate' ? '#fbbf24' : '#f87171';
  let matHtml = `
    <div style="display:flex; align-items:center; gap:24px; margin-bottom:28px;">
      <div class="risk-ring" style="background:rgba(0,0,0,0.3); color:${mColor}; border:2px solid ${mColor}; box-shadow:0 0 20px ${mColor}40;">
        ${m.score}
      </div>
      <div>
        <div style="font-size:1.5rem; font-weight:800; color:${mColor}">${m.level}</div>
        <div style="color:#64748b; font-size:0.85rem; margin-top:4px;">Security Maturity Level · Score ${m.score}/100</div>
      </div>
    </div>
    <div style="display:flex; flex-direction:column; gap:10px;">`;
  m.indicators.forEach(ind => {
    const col = ind.startsWith('✓') ? '#34d399' : '#fbbf24';
    matHtml += `<div style="font-size:0.88rem; color:${col}; padding:10px 16px; background:rgba(0,0,0,0.25); border-radius:10px; border-left:3px solid ${col}">${ind}</div>`;
  });
  matHtml += '</div>';
  document.getElementById('dtab-maturity').innerHTML = matHtml;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
