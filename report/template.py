"""
HTML template for Guardian security scan reports.
All CSS and JS are inlined — the output is a single self-contained file.

Placeholder tokens replaced by generator.py:
  {{SCAN_DATE}}       - human-readable scan date/time
  {{MACOS_VERSION}}   - macOS version string
  {{DEVICE_INFO}}     - iOS device info HTML snippet (or empty string)
  {{SUMMARY_STATS}}   - HTML for the severity count tiles + risk badge
  {{MODULE_STATUS}}   - HTML for the module status pill bar
  {{FINDINGS_JSON}}   - JSON array of Finding dicts injected into JS
"""

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Guardian Security Report</title>
<style>
/* ── Reset & base ────────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg-base:    #0d1117;
  --bg-surface: #161b22;
  --bg-raised:  #21262d;
  --bg-hover:   #30363d;
  --border:     #30363d;
  --border-subtle: #21262d;
  --text-primary:   #e6edf3;
  --text-secondary: #8b949e;
  --text-muted:     #6e7681;

  --critical: #ff4444;
  --high:     #ff8c00;
  --medium:   #ffd700;
  --low:      #4fc3f7;
  --info:     #9e9e9e;
  --success:  #3fb950;
  --warning:  #d29922;
  --error:    #f85149;

  --radius-sm: 4px;
  --radius:    8px;
  --radius-lg: 12px;

  --font-mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}

html { scroll-behavior: smooth; }

body {
  font-family: var(--font-sans);
  background: var(--bg-base);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}

/* ── Typography ──────────────────────────────────────────────────────────── */
h1, h2, h3, h4 { font-weight: 600; letter-spacing: -0.01em; }
a { color: var(--low); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre { font-family: var(--font-mono); font-size: 0.875em; }

/* ── Layout ──────────────────────────────────────────────────────────────── */
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

/* ── Header ──────────────────────────────────────────────────────────────── */
.header {
  background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 0 24px;
}

.header-top {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 24px;
}

.logo {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo svg { flex-shrink: 0; }

.logo-text {
  display: flex;
  flex-direction: column;
}

.logo-name {
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  background: linear-gradient(135deg, #e6edf3 0%, #8b949e 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.logo-tagline {
  font-size: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.header-meta {
  margin-left: auto;
  text-align: right;
  font-size: 0.8125rem;
  color: var(--text-secondary);
  line-height: 1.8;
}

.header-meta strong { color: var(--text-primary); }

/* ── Summary tiles ───────────────────────────────────────────────────────── */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.severity-tile {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
  position: relative;
  overflow: hidden;
}

.severity-tile::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: var(--tile-color, var(--border));
}

.severity-tile:hover {
  transform: translateY(-2px);
  border-color: var(--tile-color, var(--border));
  background: var(--bg-raised);
}

.severity-tile.active {
  border-color: var(--tile-color, var(--border));
  background: var(--bg-raised);
}

.tile-count {
  font-size: 2.25rem;
  font-weight: 700;
  color: var(--tile-color, var(--text-primary));
  line-height: 1;
  margin-bottom: 4px;
}

.tile-label {
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-secondary);
}

/* ── Risk badge ──────────────────────────────────────────────────────────── */
.risk-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--bg-surface);
  font-size: 0.875rem;
}

.risk-label { color: var(--text-secondary); }

.risk-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.risk-critical { background: rgba(255, 68,  68,  0.15); color: var(--critical); border: 1px solid rgba(255,68,68,0.3); }
.risk-high     { background: rgba(255,140,  0,  0.15); color: var(--high);     border: 1px solid rgba(255,140,0,0.3); }
.risk-medium   { background: rgba(255,215,  0,  0.15); color: var(--medium);   border: 1px solid rgba(255,215,0,0.3); }
.risk-low      { background: rgba( 79,195,247, 0.15); color: var(--low);      border: 1px solid rgba(79,195,247,0.3); }
.risk-clean    { background: rgba( 63,185, 80, 0.15); color: var(--success);  border: 1px solid rgba(63,185,80,0.3); }

/* ── Module status bar ───────────────────────────────────────────────────── */
.module-bar-section {
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
}

.module-bar-title {
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  margin-bottom: 10px;
}

.module-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.module-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 500;
  border: 1px solid transparent;
}

.module-pill-success { background: rgba(63,185,80,0.12);  color: var(--success); border-color: rgba(63,185,80,0.25); }
.module-pill-skipped { background: rgba(210,153,34,0.12); color: var(--warning); border-color: rgba(210,153,34,0.25); }
.module-pill-error   { background: rgba(248,81,73,0.12);  color: var(--error);   border-color: rgba(248,81,73,0.25); }

.pill-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}
.module-pill-success .pill-dot { background: var(--success); }
.module-pill-skipped .pill-dot { background: var(--warning); }
.module-pill-error   .pill-dot { background: var(--error); }

/* ── Main content ────────────────────────────────────────────────────────── */
.main { padding: 32px 0 64px; }

/* ── Toolbar (filter + search) ───────────────────────────────────────────── */
.toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}

.filter-group {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.filter-btn {
  padding: 5px 14px;
  border-radius: 20px;
  border: 1px solid var(--border);
  background: var(--bg-surface);
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  font-family: var(--font-sans);
}

.filter-btn:hover { background: var(--bg-raised); color: var(--text-primary); }

.filter-btn.active {
  color: var(--text-primary);
  background: var(--bg-raised);
}

.filter-btn[data-sev="all"].active     { border-color: var(--text-secondary); }
.filter-btn[data-sev="critical"].active { border-color: var(--critical); color: var(--critical); }
.filter-btn[data-sev="high"].active     { border-color: var(--high);     color: var(--high); }
.filter-btn[data-sev="medium"].active   { border-color: var(--medium);   color: var(--medium); }
.filter-btn[data-sev="low"].active      { border-color: var(--low);      color: var(--low); }
.filter-btn[data-sev="info"].active     { border-color: var(--info);     color: var(--info); }

.search-wrap {
  margin-left: auto;
  position: relative;
}

.search-wrap svg {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-muted);
  pointer-events: none;
}

.search-input {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 0.8125rem;
  padding: 7px 12px 7px 34px;
  width: 240px;
  transition: border-color 0.15s ease, width 0.25s ease;
  outline: none;
}

.search-input:focus {
  border-color: #388bfd;
  width: 300px;
}

.search-input::placeholder { color: var(--text-muted); }

/* ── Section headers ─────────────────────────────────────────────────────── */
.section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  user-select: none;
  margin-bottom: 2px;
  transition: background 0.15s ease;
}

.section-header:hover { background: var(--bg-raised); }

.section-header.collapsed { border-radius: var(--radius); margin-bottom: 16px; }

.section-title {
  font-size: 0.875rem;
  font-weight: 600;
}

.section-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 22px;
  height: 22px;
  padding: 0 6px;
  border-radius: 20px;
  font-size: 0.6875rem;
  font-weight: 700;
}

.chevron {
  margin-left: auto;
  transition: transform 0.25s ease;
  color: var(--text-muted);
}

.section-header.collapsed .chevron { transform: rotate(-90deg); }

/* ── Findings table ──────────────────────────────────────────────────────── */
.findings-group { margin-bottom: 12px; }

.findings-table-wrap {
  border: 1px solid var(--border);
  border-top: none;
  border-radius: 0 0 var(--radius) var(--radius);
  overflow: hidden;
  margin-bottom: 16px;
}

.findings-table {
  width: 100%;
  border-collapse: collapse;
}

.findings-table thead th {
  background: var(--bg-raised);
  padding: 10px 16px;
  text-align: left;
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  font-weight: 600;
}

.findings-table tbody tr.finding-row {
  border-bottom: 1px solid var(--border-subtle);
  transition: background 0.1s ease;
  cursor: pointer;
}

.findings-table tbody tr.finding-row:last-child { border-bottom: none; }
.findings-table tbody tr.finding-row:hover { background: var(--bg-raised); }
.findings-table tbody tr.finding-row.expanded { background: var(--bg-raised); }

.findings-table td {
  padding: 12px 16px;
  vertical-align: middle;
  font-size: 0.8125rem;
}

/* ── Severity badge ──────────────────────────────────────────────────────── */
.sev-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 20px;
  font-size: 0.6875rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  white-space: nowrap;
}

.sev-critical { background: rgba(255, 68,  68, 0.15); color: var(--critical); border: 1px solid rgba(255,68,68,0.25); }
.sev-high     { background: rgba(255,140,  0, 0.15); color: var(--high);     border: 1px solid rgba(255,140,0,0.25); }
.sev-medium   { background: rgba(255,215,  0, 0.15); color: var(--medium);   border: 1px solid rgba(255,215,0,0.25); }
.sev-low      { background: rgba( 79,195,247,0.15); color: var(--low);      border: 1px solid rgba(79,195,247,0.25); }
.sev-info     { background: rgba(158,158,158,0.15); color: var(--info);     border: 1px solid rgba(158,158,158,0.25); }

.sev-dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  display: inline-block;
}
.sev-critical .sev-dot { background: var(--critical); }
.sev-high     .sev-dot { background: var(--high); }
.sev-medium   .sev-dot { background: var(--medium); }
.sev-low      .sev-dot { background: var(--low); }
.sev-info     .sev-dot { background: var(--info); }

/* ── Category tag ────────────────────────────────────────────────────────── */
.category-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: var(--radius-sm);
  font-size: 0.6875rem;
  background: var(--bg-hover);
  color: var(--text-secondary);
  border: 1px solid var(--border);
}

/* ── Expand arrow ────────────────────────────────────────────────────────── */
.expand-arrow {
  color: var(--text-muted);
  transition: transform 0.25s ease;
  display: flex;
  align-items: center;
}
.finding-row.expanded .expand-arrow { transform: rotate(90deg); }

/* ── Finding detail row ──────────────────────────────────────────────────── */
tr.detail-row td {
  padding: 0;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
}

.detail-inner {
  overflow: hidden;
  max-height: 0;
  transition: max-height 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}

.detail-inner.open { max-height: 2000px; }

.detail-content {
  padding: 20px 24px;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

@media (max-width: 768px) {
  .detail-content { grid-template-columns: 1fr; }
}

.detail-card {
  background: var(--bg-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
}

.detail-card-title {
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.detail-card p {
  font-size: 0.8125rem;
  color: var(--text-secondary);
  line-height: 1.7;
}

/* Evidence code block */
.evidence-block {
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 14px;
  overflow-x: auto;
  font-size: 0.75rem;
  line-height: 1.7;
  color: #a5d6ff;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow-y: auto;
}

.evidence-block::-webkit-scrollbar { width: 6px; height: 6px; }
.evidence-block::-webkit-scrollbar-track { background: transparent; }
.evidence-block::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* Remediation card */
.detail-card.remediation-card {
  border-color: rgba(63,185,80,0.2);
  background: rgba(63,185,80,0.03);
  grid-column: 1 / -1;
}

.remediation-card .detail-card-title { color: var(--success); }

.remediation-explanation {
  color: var(--text-primary);
  font-size: 0.875rem;
  line-height: 1.7;
  margin-top: 6px;
}

.remediation-steps {
  list-style: none;
  counter-reset: step;
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 8px;
}

.remediation-steps li {
  counter-increment: step;
  display: grid;
  grid-template-columns: 22px 1fr;
  column-gap: 10px;
  font-size: 0.8125rem;
  color: var(--text-secondary);
  line-height: 1.6;
  align-items: start;
}

.remediation-steps li::before {
  content: counter(step);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 22px;
  height: 22px;
  border-radius: 50%;
  background: rgba(63,185,80,0.15);
  border: 1px solid rgba(63,185,80,0.3);
  color: var(--success);
  font-size: 0.6875rem;
  font-weight: 700;
  margin-top: 1px;
}

.remediation-step-body {
  min-width: 0;
}

.remediation-step-text {
  color: var(--text-primary);
}

.remediation-command-block {
  margin-top: 8px;
  background: #0d1117;
  border: 1px solid rgba(88, 166, 255, 0.22);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  overflow-x: auto;
  color: #a5d6ff;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.75rem;
  line-height: 1.6;
}

.remediation-command-block code {
  font-family: var(--font-mono);
  color: inherit;
}

/* Finding ID + source */
.finding-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.finding-id {
  font-family: var(--font-mono);
  font-size: 0.6875rem;
  color: var(--text-muted);
  background: var(--bg-base);
  padding: 2px 7px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
}

.source-tag {
  font-size: 0.6875rem;
  color: var(--text-muted);
  background: var(--bg-base);
  padding: 2px 7px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
}

/* ── iOS section divider ─────────────────────────────────────────────────── */
.ios-divider {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px 0 16px;
  margin-top: 8px;
}

.ios-divider-line {
  flex: 1;
  height: 1px;
  background: var(--border);
}

.ios-divider-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  white-space: nowrap;
}

/* ── Clean bill of health ────────────────────────────────────────────────── */
.clean-screen {
  text-align: center;
  padding: 80px 24px;
  display: none;
}

.clean-screen.visible { display: block; }

.clean-icon {
  margin: 0 auto 20px;
  width: 72px; height: 72px;
  border-radius: 50%;
  background: rgba(63,185,80,0.12);
  border: 2px solid rgba(63,185,80,0.3);
  display: flex;
  align-items: center;
  justify-content: center;
}

.clean-title {
  font-size: 1.375rem;
  font-weight: 700;
  color: var(--success);
  margin-bottom: 8px;
}

.clean-subtitle {
  color: var(--text-secondary);
  font-size: 0.875rem;
  max-width: 400px;
  margin: 0 auto;
}

/* ── No results state ────────────────────────────────────────────────────── */
.no-results {
  text-align: center;
  padding: 40px 24px;
  color: var(--text-muted);
  font-size: 0.875rem;
  display: none;
}

.no-results.visible { display: block; }

/* ── Empty group ─────────────────────────────────────────────────────────── */
.group-hidden { display: none; }

/* ── Footer ──────────────────────────────────────────────────────────────── */
.footer {
  border-top: 1px solid var(--border);
  padding: 20px 0;
  text-align: center;
  font-size: 0.75rem;
  color: var(--text-muted);
}

/* ── Print styles ────────────────────────────────────────────────────────── */
@media print {
  body { background: #fff; color: #000; }
  .header { background: #fff; border-color: #ccc; }
  .severity-tile, .detail-card, .evidence-block {
    background: #f5f5f5; border-color: #ccc;
  }
  .toolbar, .filter-group, .search-wrap { display: none; }
  .detail-inner { max-height: none !important; }
  .detail-inner:not(.open) { max-height: none !important; }
  .chevron { display: none; }
  .findings-table-wrap { border: 1px solid #ccc; }
  .section-header { background: #f0f0f0; cursor: default; }
  a { color: #000; }
  .logo-name { -webkit-text-fill-color: #000; }
}

/* ── Scrollbar (webkit) ──────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--bg-hover); }
</style>
</head>
<body>

<!-- ═══════════════════════════════ HEADER ═══════════════════════════════ -->
<header class="header">
  <div class="container">
    <div class="header-top">
      <div class="logo">
        <!-- Shield SVG icon -->
        <svg width="40" height="46" viewBox="0 0 40 46" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M20 2L4 8.5V21C4 30.94 10.84 40.22 20 43C29.16 40.22 36 30.94 36 21V8.5L20 2Z"
                fill="url(#shield-grad)" stroke="url(#shield-stroke)" stroke-width="1.5"/>
          <path d="M14 22.5L18 26.5L26 18.5" stroke="#3fb950" stroke-width="2.5"
                stroke-linecap="round" stroke-linejoin="round"/>
          <defs>
            <linearGradient id="shield-grad" x1="4" y1="2" x2="36" y2="43" gradientUnits="userSpaceOnUse">
              <stop stop-color="#21262d"/>
              <stop offset="1" stop-color="#0d1117"/>
            </linearGradient>
            <linearGradient id="shield-stroke" x1="4" y1="2" x2="36" y2="43" gradientUnits="userSpaceOnUse">
              <stop stop-color="#58a6ff"/>
              <stop offset="1" stop-color="#388bfd"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="logo-text">
          <span class="logo-name">Guardian</span>
          <span class="logo-tagline">Security Scanner</span>
        </div>
      </div>

      <div class="header-meta">
        <div>Scan date: <strong>{{SCAN_DATE}}</strong></div>
        <div>macOS: <strong>{{MACOS_VERSION}}</strong></div>
        {{DEVICE_INFO}}
      </div>
    </div>

    <!-- Summary stats tiles + risk badge -->
    {{SUMMARY_STATS}}
  </div>
</header>

<!-- ═══════════════════════════════ MODULE BAR ═══════════════════════════ -->
<div class="module-bar-section">
  <div class="container">
    <div class="module-bar-title">Modules scanned</div>
    <div class="module-bar" id="modulebar">
      {{MODULE_STATUS}}
    </div>
  </div>
</div>

<!-- ═══════════════════════════════ MAIN ════════════════════════════════ -->
<main class="main">
  <div class="container">

    <!-- Toolbar -->
    <div class="toolbar" id="toolbar">
      <div class="filter-group" role="group" aria-label="Filter by severity">
        <button class="filter-btn active" data-sev="all">All</button>
        <button class="filter-btn" data-sev="critical">Critical</button>
        <button class="filter-btn" data-sev="high">High</button>
        <button class="filter-btn" data-sev="medium">Medium</button>
        <button class="filter-btn" data-sev="low">Low</button>
        <button class="filter-btn" data-sev="info">Info</button>
      </div>
      <div class="search-wrap">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input type="search" class="search-input" id="searchInput"
               placeholder="Search findings…" aria-label="Search findings">
      </div>
    </div>

    <!-- Clean bill of health (shown when total = 0 or all filtered out) -->
    <div class="clean-screen" id="cleanScreen">
      <div class="clean-icon">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2" aria-hidden="true">
          <path d="M12 2L4 5.5V11C4 15.97 7.42 20.61 12 22C16.58 20.61 20 15.97 20 11V5.5L12 2Z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>
      </div>
      <div class="clean-title">No findings detected</div>
      <div class="clean-subtitle">Guardian scanned your system and found no security issues. Stay vigilant.</div>
    </div>

    <!-- No results after filter -->
    <div class="no-results" id="noResults">
      No findings match your current filter.
    </div>

    <!-- Dynamic findings area -->
    <div id="findingsArea"></div>

  </div>
</main>

<!-- ═══════════════════════════════ FOOTER ══════════════════════════════ -->
<footer class="footer">
  <div class="container">
    Generated by <strong>Guardian</strong> &mdash; {{SCAN_DATE}}
  </div>
</footer>

<script>
(function () {
  'use strict';

  // ── Injected data ──────────────────────────────────────────────────────
  const FINDINGS = {{FINDINGS_JSON}};

  // ── Severity ordering + config ─────────────────────────────────────────
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_COLORS = {
    critical: '#ff4444',
    high:     '#ff8c00',
    medium:   '#ffd700',
    low:      '#4fc3f7',
    info:     '#9e9e9e',
  };

  // ── State ──────────────────────────────────────────────────────────────
  let activeSev = 'all';
  let searchQuery = '';

  // ── Helpers ────────────────────────────────────────────────────────────
  function escHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function sevBadge(sev) {
    const s = (sev || 'info').toLowerCase();
    return `<span class="sev-badge sev-${s}"><span class="sev-dot"></span>${escHtml(s.charAt(0).toUpperCase() + s.slice(1))}</span>`;
  }

  function formatEvidence(ev) {
    if (!ev || typeof ev !== 'object') return escHtml(String(ev || ''));
    try {
      return escHtml(JSON.stringify(ev, null, 2));
    } catch (_) {
      return escHtml(String(ev));
    }
  }

  function renderRemediation(text) {
    if (!text) {
      return `
        <div class="remediation-explanation">No remediation explanation provided.</div>
        <ol class="remediation-steps"><li><div class="remediation-step-body"><div class="remediation-step-text">No remediation steps provided.</div></div></li></ol>
      `;
    }

    const lines = String(text)
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean);

    let explanation = '';
    const steps = [];
    let currentStep = null;

    lines.forEach(line => {
      if (line.startsWith('Explanation:')) {
        explanation = line.replace(/^Explanation:\s*/, '').trim();
        return;
      }
      const stepMatch = line.match(/^(\d+)\.\s+(.*)$/);
      if (stepMatch) {
        currentStep = { text: stepMatch[2].trim(), commands: [] };
        steps.push(currentStep);
        return;
      }
      if (line.startsWith('$ ') && currentStep) {
        currentStep.commands.push(line.slice(2));
        return;
      }
      if (currentStep) {
        currentStep.text += ` ${line}`;
      } else if (!explanation) {
        explanation = line;
      } else {
        explanation += ` ${line}`;
      }
    });

    const explanationHtml = `<div class="remediation-explanation">${escHtml(explanation || 'Review the steps below to remediate this finding.')}</div>`;
    const stepsHtml = steps.length
      ? steps.map(step => {
          const commandsHtml = step.commands.length
            ? `<pre class="remediation-command-block"><code>${escHtml(step.commands.join('\n'))}</code></pre>`
            : '';
          return `
            <li>
              <div class="remediation-step-body">
                <div class="remediation-step-text">${escHtml(step.text)}</div>
                ${commandsHtml}
              </div>
            </li>`;
        }).join('')
      : '<li><div class="remediation-step-body"><div class="remediation-step-text">No remediation steps provided.</div></div></li>';

    return `${explanationHtml}<ol class="remediation-steps">${stepsHtml}</ol>`;
  }

  // ── Render ─────────────────────────────────────────────────────────────
  function getVisibleFindings() {
    return FINDINGS.filter(f => {
      const sev = (f.severity || 'info').toLowerCase();
      if (activeSev !== 'all' && sev !== activeSev) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const haystack = [
          f.title, f.description, f.category, f.source, f.id
        ].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }

  function isIosFinding(f) {
    const src = (f.source || '').toLowerCase();
    const cat = (f.category || '').toLowerCase();
    return src.startsWith('ios') || cat.startsWith('ios') ||
           src.includes('iphone') || src.includes('ipad') || src.includes('mobile');
  }

  function renderFindings() {
    const area = document.getElementById('findingsArea');
    const cleanScreen = document.getElementById('cleanScreen');
    const noResults = document.getElementById('noResults');
    const toolbar = document.getElementById('toolbar');

    if (FINDINGS.length === 0) {
      cleanScreen.classList.add('visible');
      noResults.classList.remove('visible');
      toolbar.style.display = 'none';
      area.innerHTML = '';
      return;
    }

    const visible = getVisibleFindings();

    cleanScreen.classList.remove('visible');

    if (visible.length === 0) {
      noResults.classList.add('visible');
      area.innerHTML = '';
      return;
    }

    noResults.classList.remove('visible');

    // Separate mac vs ios findings
    const macFindings = visible.filter(f => !isIosFinding(f));
    const iosFindings = visible.filter(f => isIosFinding(f));

    let html = '';

    // Group by severity
    function renderGroup(findings, prefix) {
      let out = '';
      SEV_ORDER.forEach(sev => {
        const group = findings.filter(f => (f.severity || 'info').toLowerCase() === sev);
        if (group.length === 0) return;

        const color = SEV_COLORS[sev] || '#9e9e9e';
        const title = sev.charAt(0).toUpperCase() + sev.slice(1);
        const groupId = `${prefix}-${sev}`;

        out += `
          <div class="findings-group" id="group-${groupId}">
            <div class="section-header" role="button" tabindex="0"
                 aria-expanded="true" aria-controls="table-${groupId}"
                 data-group="${groupId}">
              <span class="sev-badge sev-${sev}"><span class="sev-dot"></span>${escHtml(title)}</span>
              <span class="section-count"
                    style="background:${color}22;color:${color};border:1px solid ${color}44">
                ${group.length}
              </span>
              <svg class="chevron" width="14" height="14" viewBox="0 0 24 24"
                   fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </div>
            <div id="table-${groupId}" class="findings-table-wrap">
              <table class="findings-table" aria-label="${escHtml(title)} findings">
                <thead>
                  <tr>
                    <th style="width:110px">Severity</th>
                    <th style="width:150px">Category</th>
                    <th>Title</th>
                    <th style="width:140px">Source</th>
                    <th style="width:36px"></th>
                  </tr>
                </thead>
                <tbody>
                  ${group.map((f, idx) => renderFindingRows(f, `${groupId}-${idx}`)).join('')}
                </tbody>
              </table>
            </div>
          </div>`;
      });
      return out;
    }

    html += renderGroup(macFindings, 'mac');

    // iOS divider + group (only if there are iOS findings)
    if (iosFindings.length > 0) {
      html += `
        <div class="ios-divider">
          <div class="ios-divider-line"></div>
          <div class="ios-divider-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2" aria-hidden="true">
              <rect x="7" y="2" width="10" height="20" rx="2" ry="2"/>
              <line x1="12" y1="18" x2="12" y2="18"/>
            </svg>
            iPhone / iPad Findings
          </div>
          <div class="ios-divider-line"></div>
        </div>`;
      html += renderGroup(iosFindings, 'ios');
    }

    area.innerHTML = html;

    // Attach event listeners
    attachGroupToggles();
    attachRowExpanders();
  }

  function renderFindingRows(f, uid) {
    const sev = (f.severity || 'info').toLowerCase();
    return `
      <tr class="finding-row" data-uid="${escHtml(uid)}"
          role="button" tabindex="0" aria-expanded="false">
        <td>${sevBadge(f.severity)}</td>
        <td><span class="category-tag">${escHtml(f.category || '—')}</span></td>
        <td style="font-weight:500">${escHtml(f.title || '—')}</td>
        <td style="font-size:0.75rem;color:var(--text-secondary)">${escHtml(f.source || '—')}</td>
        <td>
          <span class="expand-arrow" aria-hidden="true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2.5">
              <polyline points="9 18 15 12 9 6"/>
            </svg>
          </span>
        </td>
      </tr>
      <tr class="detail-row" data-for="${escHtml(uid)}">
        <td colspan="5">
          <div class="detail-inner" id="detail-${escHtml(uid)}">
            <div class="detail-content">
              <div class="finding-meta" style="grid-column:1/-1">
                <span class="finding-id">${escHtml(f.id || '—')}</span>
                <span class="source-tag">Source: ${escHtml(f.source || '—')}</span>
              </div>

              <div class="detail-card">
                <div class="detail-card-title">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  Description
                </div>
                <p>${escHtml(f.description || 'No description available.')}</p>
              </div>

              <div class="detail-card">
                <div class="detail-card-title">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
                  </svg>
                  Evidence
                </div>
                <pre class="evidence-block">${formatEvidence(f.evidence)}</pre>
              </div>

              <div class="detail-card remediation-card">
                <div class="detail-card-title">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2" aria-hidden="true">
                    <polyline points="9 11 12 14 22 4"/>
                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                  </svg>
                  How to Fix
                </div>
                ${renderRemediation(f.remediation)}
              </div>
            </div>
          </div>
        </td>
      </tr>`;
  }

  // ── Interactivity ──────────────────────────────────────────────────────
  function attachGroupToggles() {
    document.querySelectorAll('.section-header[data-group]').forEach(header => {
      header.addEventListener('click', toggleGroup);
      header.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleGroup.call(header, e); }
      });
    });
  }

  function toggleGroup(e) {
    const header = e.currentTarget || this;
    const groupId = header.dataset.group;
    const tableWrap = document.getElementById(`table-${groupId}`);
    const isCollapsed = header.classList.contains('collapsed');
    header.classList.toggle('collapsed', !isCollapsed);
    header.setAttribute('aria-expanded', isCollapsed ? 'true' : 'false');
    tableWrap.style.display = isCollapsed ? '' : 'none';
  }

  function attachRowExpanders() {
    document.querySelectorAll('.finding-row').forEach(row => {
      row.addEventListener('click', () => toggleDetail(row));
      row.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleDetail(row); }
      });
    });
  }

  function toggleDetail(row) {
    const uid = row.dataset.uid;
    const detail = document.getElementById(`detail-${uid}`);
    const isOpen = detail.classList.contains('open');

    // Close all others in this table for cleaner UX (optional accordion style)
    // (We allow multiple open — just toggle the clicked one)

    detail.classList.toggle('open', !isOpen);
    row.classList.toggle('expanded', !isOpen);
    row.setAttribute('aria-expanded', (!isOpen).toString());
  }

  // ── Filters ────────────────────────────────────────────────────────────
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSev = btn.dataset.sev;
      renderFindings();
    });
  });

  document.getElementById('searchInput').addEventListener('input', function () {
    searchQuery = this.value.trim();
    renderFindings();
  });

  // ── Tile clicks wire to filter ─────────────────────────────────────────
  document.querySelectorAll('.severity-tile[data-sev]').forEach(tile => {
    tile.addEventListener('click', () => {
      const sev = tile.dataset.sev;
      document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.sev === sev);
      });
      activeSev = sev;
      renderFindings();
    });
  });

  // ── Initial render ─────────────────────────────────────────────────────
  renderFindings();

})();
</script>
</body>
</html>"""
