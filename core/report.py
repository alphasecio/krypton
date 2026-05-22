"""
HTML report renderer.
Single self-contained file — favicon, CSS, JS all embedded.
Two sections: Findings (actionable) and Asset Inventory (CBOM layer).
"""

import base64
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core import config, store

logger = logging.getLogger(__name__)

# ── Favicon (embedded so report is fully self-contained) ──────────────────────
_FAVICON_B64 = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+CiAgPHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzBmMTcyYSIvPgogIDxsaW5lIHgxPSI5IiB5MT0iNCIgeDI9IjkiIHkyPSIyOCIgc3Ryb2tlPSIjMzhiZGY4IiBzdHJva2Utd2lkdGg9IjMuNSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIi8+CiAgPGxpbmUgeDE9IjkiIHkxPSIxNiIgeDI9IjI0IiB5Mj0iNCIgc3Ryb2tlPSIjMzhiZGY4IiBzdHJva2Utd2lkdGg9IjMuNSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIi8+CiAgPGxpbmUgeDE9IjkiIHkxPSIxNiIgeDI9IjI0IiB5Mj0iMjgiIHN0cm9rZT0iIzM4YmRmOCIgc3Ryb2tlLXdpZHRoPSIzLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K"

# ── Badge helpers ─────────────────────────────────────────────────────────────
_PRIORITY_COLOR = {
    "CRITICAL":      "#dc2626",
    "HIGH":          "#ea580c",
    "MEDIUM":        "#d97706",
    "LOW":           "#2563eb",
    "INFORMATIONAL": "#6b7280",
}
_PQC_COLOR = {
    "NOT_READY":            "#dc2626",
    "CLASSICAL":            "#d97706",
    "PQC_CAPABLE": "#2563eb",
    "PQC_READY":            "#16a34a",
    "SAFE":                 "#16a34a",
}
# Phase labels removed — PQC Status column covers this
_MODULE_LABEL = {
    config.MODULE_TLS:   "TLS Policies",
    config.MODULE_CERTS: "Certificates",
    config.MODULE_KMS:   "KMS/HSM Keys",
    config.MODULE_SSH:   "SSH Keys",
}

def _e(s) -> str:
    if s is None: return ""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _priority_badge(p: str) -> str:
    c = _PRIORITY_COLOR.get(p, "#6b7280")
    return f'<span class="badge" style="background:{c}22;color:{c};border:1px solid {c}44">{p}</span>'

_PQC_LABEL = {
    "NOT_READY":            "Not Ready",
    "CLASSICAL":            "Classical",
    "PQC_CAPABLE": "PQC Capable",
    "PQC_READY":            "PQC Ready",
    "SAFE":                 "Quantum-Safe",
}
def _pqc_badge(s: str) -> str:
    c2 = _PQC_COLOR.get(s, "#6b7280")
    l = _PQC_LABEL.get(s, s.replace("_", " ").title())
    return f'<span class="badge" style="background:{c2}22;color:{c2};border:1px solid {c2}44">{l}</span>'



def _local_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def _display_resource(rname: str) -> str:
    """Strip GCP boilerplate for readable display. Full path stays in title."""
    import re
    s = rname
    for prefix in (
        "https://www.googleapis.com/compute/v1/",
        "https://cloudkms.googleapis.com/v1/",
    ):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    # Strip projects/PROJECT/ — project is its own column
    s = re.sub(r"^projects/[^/]+/", "", s)
    # Strip regions/REGION/ or zones/ZONE/ or locations/LOC/
    s = re.sub(r"^(regions|zones|locations)/[^/]+/", "", s)
    return s or rname

def _fmt_protocol(p: Optional[str]) -> str:
    """Format protocol strings for display: TLS_1_0 -> TLS 1.0 etc."""
    if not p: return "—"
    return (p.replace("TLS_1_3","TLS 1.3")
             .replace("TLS_1_2","TLS 1.2")
             .replace("TLS_1_1","TLS 1.1")
             .replace("TLS_1_0","TLS 1.0")
             .replace("SSH-2","SSH-2"))  # already readable


# ── Findings section ──────────────────────────────────────────────────────────

def _build_findings_section(findings: List[Dict]) -> str:
    if not findings:
        return """
  <div class="section">
    <div class="section-header" id="sec-findings" onclick="toggle('sec-findings')">
      <h2>&#x26A0;&#xFE0F; Findings</h2>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="count-badge">0 findings</span>
        <span class="chevron">&#x25BE;</span>
      </div>
    </div>
    <div class="section-body" id="sec-findings-body">
      <p style="padding:24px;color:var(--muted);text-align:center">
        No findings. All scanned resources meet the required posture.
      </p>
    </div>
  </div>"""

    rows = []
    for f in findings:
        rurl  = f.get("resource_url","")
        rname = _e(f.get("resource_name",""))
        disp  = _display_resource(rname)
        link  = (f'<a href="{_e(rurl)}" target="_blank" title="{rname}">{_e(disp)}</a>'
                 if rurl else f'<span title="{rname}">{_e(disp)}</span>')
        copy  = f'<button class="copy-btn" onclick="copyText(\'{rname}\')" title="Copy full path">&#x2398;</button>'

        algo     = _e(f.get("algorithm") or "—")
        protocol = _e(f.get("protocol") or "—")

        rows.append(f"""
        <tr>
          <td><code class="code-sm">{_e(f.get('finding_type',''))}</code></td>
          <td>{_priority_badge(f.get('priority',''))}</td>
          <td>{_e(f.get('project',''))}<span class="sub">{_e(f.get('region',''))}</span></td>
          <td class="col-resource">{link}{copy}</td>
          <td>{algo}</td>
          <td>{_fmt_protocol(f.get('protocol'))}</td>
          <td>{_pqc_badge(f.get('pqc_status',''))}</td>
          <td class="col-detail">{_e(f.get('detail',''))}</td>
          <td class="col-rem">{_e(f.get('remediation',''))}</td>
        </tr>""")

    count = len(findings)
    return f"""
  <div class="section">
    <div class="section-header" id="sec-findings" onclick="toggle('sec-findings')">
      <h2>&#x26A0;&#xFE0F; Findings</h2>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="count-badge">{count} finding{'s' if count != 1 else ''}</span>
        <span class="chevron">&#x25BE;</span>
      </div>
    </div>
    <div class="section-body" id="sec-findings-body">
      <div class="table-wrap">
        <table class="fixed-table">
          <colgroup>
            <col style="width:160px"><col style="width:90px"><col style="width:110px">
            <col style="width:190px"><col style="width:110px"><col style="width:80px">
            <col style="width:110px"><col style="width:220px"><col style="width:200px">
          </colgroup>
          <thead><tr>
            <th>Finding</th><th>Severity</th><th>Project</th>
            <th>Resource</th><th>Algorithm</th><th>Protocol</th>
            <th>PQC Status</th><th>Detail</th><th>Remediation</th>
          </tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </div>
  </div>"""


# ── Inventory section ─────────────────────────────────────────────────────────

def _build_inventory_section(assets: List[Dict]) -> str:
    by_module: Dict[str, List[Dict]] = {m: [] for m in config.ALL_MODULES}
    for a in assets:
        m = a.get("check_module","")
        if m in by_module:
            by_module[m].append(a)

    module_tables = []
    for module in config.ALL_MODULES:
        module_assets = by_module[module]
        if not module_assets:
            continue
        label = _MODULE_LABEL.get(module, module)
        rows  = []
        for a in module_assets:
            rurl  = a.get("resource_url","")
            rname = _e(a.get("resource_name",""))
            disp  = _display_resource(rname)
            link  = (f'<a href="{_e(rurl)}" target="_blank" title="{rname}">{_e(disp)}</a>'
                     if rurl else f'<span title="{rname}">{_e(disp)}</span>')
            copy  = f'<button class="copy-btn" onclick="copyText(\'{rname}\')" title="Copy">&#x2398;</button>'
            rows.append(f"""
            <tr>
              <td>{_e(a.get('resource_type',''))}</td>
              <td>{_e(a.get('classification') or '—')}</td>
              <td>{_e(a.get('project',''))}<span class="sub">{_e(a.get('region',''))}</span></td>
              <td class="col-resource">{link}{copy}</td>
              <td>{_e(a.get('algorithm') or '—')}</td>
              <td>{_fmt_protocol(a.get('protocol'))}</td>
              <td>{_pqc_badge(a.get('pqc_status',''))}</td>
            </tr>""")

        module_tables.append(f"""
        <div class="inv-module">
          <div class="inv-module-header" onclick="toggleInv('{module}')">
            <span>{label}</span>
            <span class="count-badge">{len(module_assets)} assets</span>
          </div>
          <div id="inv-{module}" class="inv-module-body">
            <div class="table-wrap">
              <table class="fixed-table">
                <colgroup>
                  <col style="width:130px"><col style="width:180px"><col style="width:110px">
                  <col style="width:180px"><col style="width:130px"><col style="width:75px">
                  <col style="width:110px">
                </colgroup>
                <thead><tr>
                  <th>Type</th><th>Classification</th><th>Project</th><th>Resource</th>
                  <th>Algorithm</th><th>Protocol</th><th>PQC Status</th>
                </tr></thead>
                <tbody>{''.join(rows)}</tbody>
              </table>
            </div>
          </div>
        </div>""")

    total = len(assets)
    return f"""
  <div class="section">
    <div class="section-header" id="sec-inventory" onclick="toggle('sec-inventory')">
      <h2>&#x1F4CB; Crypto Assets</h2>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="count-badge">{total} asset{'s' if total != 1 else ''}</span>
        <span class="chevron">&#x25BE;</span>
      </div>
    </div>
    <div class="section-body" id="sec-inventory-body">
      {''.join(module_tables)}
    </div>
  </div>"""


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
/* ── Design tokens ── */
:root {
  --bg:       #0f172a;
  --surface:  #1e293b;
  --surface2: #273548;
  --border:   #334155;
  --text:     #e2e8f0;
  --muted:    #94a3b8;
  --accent:   #38bdf8;
  --accent2:  #0ea5e9;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg:       #f8fafc;
    --surface:  #ffffff;
    --surface2: #f1f5f9;
    --border:   #e2e8f0;
    --text:     #0f172a;
    --muted:    #64748b;
    --accent:   #0284c7;
    --accent2:  #0369a1;
  }
}
@media print {
  :root {
    --bg:       #ffffff;
    --surface:  #ffffff;
    --surface2: #f8fafc;
    --border:   #e2e8f0;
    --text:     #0f172a;
    --muted:    #475569;
    --accent:   #0284c7;
    --accent2:  #0369a1;
  }
  .copy-btn { display: none; }
  .chevron  { display: none; }
  .section-body.hidden { display: block !important; }
  .inv-module-body { display: block !important; }
  header { border-bottom: 2px solid var(--border); }
}

/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Header ── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 18px 32px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.header-brand { display: flex; align-items: center; gap: 14px; }
.header-brand img { width: 36px; height: 36px; }
.brand-name {
  font-size: 1.5rem;
  font-weight: 800;
  color: var(--accent);
  letter-spacing: 2px;
  text-transform: uppercase;
}
.brand-sub {
  font-size: .8rem;
  color: var(--muted);
  margin-top: 1px;
  letter-spacing: .3px;
}
.header-meta { color: var(--muted); font-size: .82rem; text-align: right; line-height: 1.8; }

/* ── Layout ── */
main { max-width: 1500px; margin: 0 auto; padding: 24px 24px; }

/* ── Three summary cards ── */
.three-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 20px;
}
.summary-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
}
.card-title {
  font-size: .78rem;
  font-weight: 700;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .6px;
  margin-bottom: 6px;
}
.card-total {
  font-size: 2.4rem;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 14px;
  line-height: 1;
}
.card-rows { display: flex; flex-direction: column; gap: 7px; }
.card-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: .83rem;
  color: var(--muted);
  padding-bottom: 7px;
  border-bottom: 1px solid var(--border);
}
.card-row:last-child { border-bottom: none; padding-bottom: 0; }
.card-val { font-weight: 700; font-size: .95rem; color: var(--text); }
.sev-critical { color: #dc2626; }
.sev-high     { color: #ea580c; }
.sev-medium   { color: #d97706; }
.sev-low      { color: #2563eb; }
.sev-info     { color: #6b7280; }
.pqc-ready    { color: #16a34a; }
.pqc-safe     { color: #16a34a; }
.pqc-classical{ color: #d97706; }
.pqc-notready { color: #dc2626; }
.pqc-pending  { color: #2563eb; }

/* ── Sections ── */
.section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
}
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 20px;
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid var(--border);
}
.section-header:hover { background: var(--surface2); }
.section-header h2 { font-size: 1rem; font-weight: 700; }
.section-sub { font-size: .8rem; font-weight: 400; color: var(--muted); margin-left: 6px; }
.section-body { overflow: hidden; }
.section-body.hidden { display: none; }
.chevron { color: var(--muted); transition: transform .2s; display: inline-block; }
.collapsed .chevron { transform: rotate(-90deg); }
.count-badge {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2px 10px;
  font-size: .78rem;
  color: var(--muted);
}

/* ── Tables ── */
.table-wrap { overflow-x: auto; }
.fixed-table {
  width: 100%;
  border-collapse: collapse;
  font-size: .82rem;
  table-layout: fixed;
}
thead th {
  background: var(--surface2);
  padding: 9px 12px;
  text-align: left;
  font-weight: 700;
  color: var(--muted);
  text-transform: uppercase;
  font-size: .69rem;
  letter-spacing: .7px;
  white-space: nowrap;
  border-bottom: 1px solid var(--border);
}
tbody tr { border-bottom: 1px solid var(--border); transition: background .1s; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--surface2); }
td {
  padding: 9px 12px;
  vertical-align: top;
  overflow: hidden;
  text-overflow: ellipsis;
}
.col-resource { font-family: monospace; font-size: .77rem; word-break: break-all; overflow: visible; }
.col-detail   { white-space: normal; }
.col-rem      { white-space: normal; color: var(--muted); }
.sub          { color: var(--muted); font-size: .75rem; display: block; }
.code-sm      { font-size: .75rem; font-family: monospace; }

/* ── Badges ── */
.badge {
  display: inline-block;
  border-radius: 4px;
  padding: 2px 7px;
  font-size: .71rem;
  font-weight: 700;
  letter-spacing: .3px;
  white-space: nowrap;
}

/* ── Copy button ── */
.copy-btn {
  background: none;
  border: none;
  color: var(--muted);
  cursor: pointer;
  font-size: .72rem;
  padding: 0 3px;
  vertical-align: middle;
}
.copy-btn:hover { color: var(--accent); }

/* ── Inventory module sub-sections ── */
.inv-module { border-bottom: 1px solid var(--border); }
.inv-module:last-child { border-bottom: none; }
.inv-module-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 16px;
  cursor: pointer;
  background: var(--surface2);
  font-size: .88rem;
  font-weight: 600;
}
.inv-module-header:hover { background: var(--border); }
.inv-module-body { border-top: 1px solid var(--border); }

/* ── Footer ── */
footer {
  text-align: center;
  color: var(--muted);
  font-size: .78rem;
  padding: 20px;
  border-top: 1px solid var(--border);
  margin-top: 8px;
}

/* ── Responsive ── */
@media (max-width: 900px) {
  .three-cards { grid-template-columns: 1fr; }
  .col-rem { display: none; }
}
"""

_JS = """
function toggle(id){
  const h=document.getElementById(id);
  const b=document.getElementById(id+'-body');
  h.classList.toggle('collapsed');
  b.classList.toggle('hidden');
}
function toggleInv(mod){
  const b=document.getElementById('inv-'+mod);
  b.classList.toggle('hidden');
}
function copyText(t){
  navigator.clipboard.writeText(t).catch(()=>{
    const e=document.createElement('textarea');
    e.value=t;document.body.appendChild(e);
    e.select();document.execCommand('copy');
    document.body.removeChild(e);
  });
}
"""


# ── Main render ───────────────────────────────────────────────────────────────

def render_html(db_path: Path, scan_id: str, output_path: Path) -> None:
    scan    = store.get_scan(db_path, scan_id)
    summary = store.get_summary(db_path, scan_id)
    if not scan or not summary:
        raise ValueError(f"No scan data found for scan_id={scan_id}")

    all_findings = store.get_findings(db_path, scan_id, include_informational=True)
    all_assets   = store.get_assets(db_path, scan_id)

    # Asset counts by module for Card 1
    asset_counts = Counter(a.get("check_module","") for a in all_assets)
    for m in config.ALL_MODULES:
        asset_counts.setdefault(m, 0)

    # PQC posture across all assets for Card 3 (richer than findings-only view)
    pqc_counts = Counter(a.get("pqc_status","") for a in all_assets)
    summary["safe_count"]               = pqc_counts.get(config.PQC_SAFE, 0)
    summary["pqc_capable_count"] = pqc_counts.get(config.PQC_CAPABLE, 0)
    summary["classical_count"]          = pqc_counts.get(config.PQC_CLASSICAL, 0)
    summary["not_ready_count"]          = pqc_counts.get(config.PQC_NOT_READY, 0)
    summary["pqc_ready_count"]          = pqc_counts.get(config.PQC_READY, 0)

    scope_str = (
        f"Organization {scan['scope_id']}"
        if scan["scan_scope"] == "org"
        else f"Project {scan['scope_id']}"
    )
    generated_at = _local_now()

    findings_section  = _build_findings_section(all_findings)
    inventory_section = _build_inventory_section(all_assets)

    favicon_uri = f"data:image/svg+xml;base64,{_FAVICON_B64}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>KRYPTON — PQC Readiness Report</title>
<link rel="icon" type="image/svg+xml" href="{favicon_uri}"/>
<style>{_CSS}</style>
</head>
<body>

<header>
  <div class="header-brand">
    <img src="{favicon_uri}" alt="Krypton"/>
    <div>
      <div class="brand-name">Krypton</div>
      <div class="brand-sub">PQC Readiness Report</div>
    </div>
  </div>
  <div class="header-meta">
    <div>Scope: {_e(scope_str)}</div>
    <div>Date: {generated_at}</div>
  </div>
</header>

<main>

<div class="three-cards">

  <div class="summary-card">
    <div class="card-title">&#x1F4CB; Crypto Assets</div>
    <div class="card-total">{summary['total_assets']}</div>
    <div class="card-rows">
      <div class="card-row"><span>TLS Endpoints</span><span class="card-val">{asset_counts[config.MODULE_TLS]}</span></div>
      <div class="card-row"><span>Certificates</span><span class="card-val">{asset_counts[config.MODULE_CERTS]}</span></div>
      <div class="card-row"><span>KMS/HSM Keys</span><span class="card-val">{asset_counts[config.MODULE_KMS]}</span></div>
      <div class="card-row"><span>SSH Keys</span><span class="card-val">{asset_counts[config.MODULE_SSH]}</span></div>
    </div>
  </div>

  <div class="summary-card">
    <div class="card-title">&#x1F6E1; PQC Status</div>
    <div class="card-total">{summary['total_assets']}</div>
    <div class="card-rows">
      <div class="card-row"><span>PQC Ready</span><span class="card-val pqc-ready">{summary['pqc_ready_count']}</span></div>
      <div class="card-row"><span>Quantum-Safe</span><span class="card-val pqc-safe">{summary['safe_count']}</span></div>
      <div class="card-row"><span>Classical (HNDL Risk)</span><span class="card-val pqc-classical">{summary['classical_count']}</span></div>
      <div class="card-row"><span>Not Ready</span><span class="card-val pqc-notready">{summary['not_ready_count']}</span></div>
      <div class="card-row"><span>PQC Capable</span><span class="card-val pqc-pending">{summary.get('pqc_capable_count', 0)}</span></div>
    </div>
  </div>

  <div class="summary-card">
    <div class="card-title">&#x26A0;&#xFE0F; PQC Findings</div>
    <div class="card-total">{summary['total_findings']}</div>
    <div class="card-rows">
      <div class="card-row"><span>Critical</span><span class="card-val sev-critical">{summary['critical_count']}</span></div>
      <div class="card-row"><span>High</span><span class="card-val sev-high">{summary['high_count']}</span></div>
      <div class="card-row"><span>Medium</span><span class="card-val sev-medium">{summary['medium_count']}</span></div>
      <div class="card-row"><span>Low</span><span class="card-val sev-low">{summary['low_count']}</span></div>
      <div class="card-row"><span>Informational</span><span class="card-val sev-info">{summary['informational_count']}</span></div>
    </div>
  </div>

</div>

{findings_section}

{inventory_section}

</main>

<footer>
  KRYPTON &middot; Google Cloud PQC Readiness Scanner &middot; Scan {scan_id}
</footer>

<script>{_JS}</script>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    logger.info(f"HTML report written to {output_path}")
