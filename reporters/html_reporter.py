"""
ArgosScan - HTML Reporter
"""

from pathlib import Path
from typing import Dict

from jinja2 import Template

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ArgosScan — {{ target }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
    <style>
        :root {
            --bg:        #0d0d0d;
            --surface:   #141414;
            --surface2:  #1a1a1a;
            --border:    #2a2a2a;
            --border2:   #333;
            --text:      #e8e8e8;
            --muted:     #666;
            --muted2:    #888;
            --accent:    #c8f560;   /* argos green — the one bright thing */
            --red:       #f05050;
            --orange:    #f07830;
            --yellow:    #e8c84a;
            --green:     #50c878;
            --mono:      'IBM Plex Mono', 'Courier New', monospace;
            --sans:      'IBM Plex Sans', system-ui, sans-serif;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            font-size: 13px;
            line-height: 1.6;
            padding: 40px 24px 80px;
        }

        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }

        .page { max-width: 960px; margin: 0 auto; }

        /* ─── HEADER ─────────────────────────────────── */
        .site-header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 28px;
            margin-bottom: 40px;
        }

        .wordmark {
            font-family: var(--mono);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: .18em;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 20px;
        }

        .target-line {
            font-family: var(--mono);
            font-size: 28px;
            font-weight: 600;
            color: var(--text);
            line-height: 1.2;
            margin-bottom: 14px;
            word-break: break-all;
        }

        .meta-row {
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
        }
        .meta-row span { display: flex; flex-direction: column; gap: 2px; }
        .meta-row .label { color: var(--muted); }
        .meta-row .val   { color: var(--muted2); }

        /* ─── RISK BAR ───────────────────────────────── */
        .risk-strip {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            border: 1px solid var(--border);
            margin-bottom: 40px;
        }
        .risk-cell {
            padding: 20px 24px;
            border-right: 1px solid var(--border);
        }
        .risk-cell:last-child { border-right: none; }
        .risk-cell .rc-label {
            font-family: var(--mono);
            font-size: 10px;
            letter-spacing: .12em;
            text-transform: uppercase;
            color: var(--muted);
            margin-bottom: 8px;
        }
        .risk-cell .rc-num {
            font-family: var(--mono);
            font-size: 36px;
            font-weight: 600;
            line-height: 1;
        }
        .rc-num.crit   { color: var(--red); }
        .rc-num.high   { color: var(--orange); }
        .rc-num.medium { color: var(--yellow); }
        .rc-num.score  { color: var(--accent); }

        /* ─── SECTION HEADING ────────────────────────── */
        .section-head {
            font-family: var(--mono);
            font-size: 10px;
            letter-spacing: .16em;
            text-transform: uppercase;
            color: var(--muted);
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
            margin: 40px 0 20px;
        }

        /* ─── PORTS TABLE ────────────────────────────── */
        table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--mono);
            font-size: 12px;
        }
        thead tr {
            border-bottom: 1px solid var(--border);
        }
        thead th {
            text-align: left;
            font-size: 10px;
            letter-spacing: .12em;
            text-transform: uppercase;
            color: var(--muted);
            padding: 0 16px 10px 0;
            font-weight: 400;
        }
        tbody tr {
            border-bottom: 1px solid var(--border);
        }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover td { color: var(--text); }
        tbody td {
            padding: 11px 16px 11px 0;
            color: var(--muted2);
            transition: color .1s;
        }
        td.port-col { color: var(--accent); font-weight: 600; }
        td.name-col { color: var(--text); }
        td.ver-col  { color: var(--muted); }

        /* ─── VULN LIST ──────────────────────────────── */
        .vuln-list { display: flex; flex-direction: column; gap: 2px; }

        .vuln-row {
            display: grid;
            grid-template-columns: 80px 160px 1fr 60px;
            align-items: start;
            gap: 16px;
            padding: 18px 0;
            border-bottom: 1px solid var(--border);
        }
        .vuln-row:last-child { border-bottom: none; }

        .sev-tag {
            font-family: var(--mono);
            font-size: 9px;
            font-weight: 600;
            letter-spacing: .14em;
            text-transform: uppercase;
            padding: 3px 8px;
            border: 1px solid;
            display: inline-block;
            line-height: 1.4;
        }
        .sev-tag.CRITICAL { color: var(--red);    border-color: var(--red);    background: rgba(240,80,80,.08); }
        .sev-tag.HIGH     { color: var(--orange);  border-color: var(--orange);  background: rgba(240,120,48,.08); }
        .sev-tag.MEDIUM   { color: var(--yellow);  border-color: var(--yellow);  background: rgba(232,200,74,.08); }
        .sev-tag.LOW      { color: var(--green);   border-color: var(--green);   background: rgba(80,200,120,.08); }
        .sev-tag.UNKNOWN  { color: var(--muted);   border-color: var(--border2); }

        .vuln-id-block { display: flex; flex-direction: column; gap: 4px; }
        .cve-id {
            font-family: var(--mono);
            font-size: 12px;
            font-weight: 600;
            color: var(--text);
        }
        .port-tag {
            font-family: var(--mono);
            font-size: 10px;
            color: var(--muted);
        }

        .vuln-body {}
        .vuln-product {
            font-family: var(--mono);
            font-size: 12px;
            color: var(--muted2);
            margin-bottom: 6px;
        }
        .vuln-desc {
            font-size: 12px;
            color: var(--muted);
            line-height: 1.65;
        }
        .vuln-links {
            margin-top: 8px;
            font-family: var(--mono);
            font-size: 11px;
        }

        .cvss-num {
            font-family: var(--mono);
            font-size: 22px;
            font-weight: 600;
            text-align: right;
        }
        .cvss-num.crit   { color: var(--red); }
        .cvss-num.high   { color: var(--orange); }
        .cvss-num.medium { color: var(--yellow); }
        .cvss-num.low    { color: var(--green); }

        /* ─── SSL ────────────────────────────────────── */
        .ssl-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
            margin-bottom: 16px;
        }
        .ssl-cell {
            background: var(--surface);
            padding: 18px 20px;
        }
        .ssl-cell.full { grid-column: 1 / -1; }
        .ssl-cell-label {
            font-family: var(--mono);
            font-size: 10px;
            letter-spacing: .12em;
            text-transform: uppercase;
            color: var(--muted);
            margin-bottom: 6px;
        }
        .ssl-cell-val {
            font-family: var(--mono);
            font-size: 13px;
            color: var(--muted2);
            line-height: 1.7;
        }

        .ssl-issues { display: flex; flex-direction: column; gap: 0; }
        .ssl-issue-row {
            display: flex;
            align-items: baseline;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            font-size: 12px;
        }
        .ssl-issue-row:last-child { border-bottom: none; }
        .ssl-sev {
            font-family: var(--mono);
            font-size: 9px;
            letter-spacing: .1em;
            flex-shrink: 0;
            padding: 2px 6px;
            border: 1px solid;
        }
        .ssl-sev.CRITICAL { color: var(--red);    border-color: var(--red); }
        .ssl-sev.HIGH     { color: var(--orange);  border-color: var(--orange); }
        .ssl-sev.MEDIUM   { color: var(--yellow);  border-color: var(--yellow); }
        .ssl-sev.LOW, .ssl-sev.INFO { color: var(--green); border-color: var(--green); }
        .ssl-issue-txt { color: var(--muted2); }

        /* ─── EMPTY STATE ────────────────────────────── */
        .empty-state {
            padding: 48px 0;
            border: 1px solid var(--border);
        }
        .empty-state .es-line {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            text-align: center;
        }
        .empty-state .es-line.ok { color: var(--green); margin-bottom: 8px; }

        /* ─── FOOTER ─────────────────────────────────── */
        .site-footer {
            margin-top: 64px;
            border-top: 1px solid var(--border);
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            flex-wrap: wrap;
            gap: 8px;
        }
    </style>
</head>
<body>
<div class="page">

    <!-- Header -->
    <header class="site-header">
        <div class="wordmark">ArgosScan &nbsp;/&nbsp; Vulnerability Report</div>
        <div class="target-line">{{ target }}</div>
        <div class="meta-row">
            <span><span class="label">scanned</span><span class="val">{{ timestamp[:19].replace('T', ' ') }} UTC</span></span>
            <span><span class="label">ports</span><span class="val">{{ scan_params.ports }}</span></span>
            <span><span class="label">speed</span><span class="val">{{ scan_params.speed }}</span></span>
            <span><span class="label">open ports</span><span class="val">{{ open_ports | length }}</span></span>
            <span><span class="label">findings</span><span class="val">{{ summary.total }}</span></span>
        </div>
    </header>

    <!-- Risk strip -->
    <div class="risk-strip">
        <div class="risk-cell">
            <div class="rc-label">Critical</div>
            <div class="rc-num crit">{{ summary.critical }}</div>
        </div>
        <div class="risk-cell">
            <div class="rc-label">High</div>
            <div class="rc-num high">{{ summary.high }}</div>
        </div>
        <div class="risk-cell">
            <div class="rc-label">Medium</div>
            <div class="rc-num medium">{{ summary.medium }}</div>
        </div>
        <div class="risk-cell">
            <div class="rc-label">Risk score</div>
            <div class="rc-num score">{{ summary.risk_score }}</div>
        </div>
    </div>

    <!-- Open ports -->
    {% if open_ports %}
    <div class="section-head">Open ports &mdash; {{ open_ports | length }} found</div>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Proto</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
            </tr>
        </thead>
        <tbody>
        {% for p in open_ports %}
            <tr>
                <td class="port-col">{{ p.port }}</td>
                <td>{{ p.protocol }}</td>
                <td class="name-col">{{ p.name }}</td>
                <td>{{ p.product or '—' }}</td>
                <td class="ver-col">{{ p.version or '—' }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <!-- Vulnerabilities -->
    <div class="section-head">Vulnerabilities &mdash; {{ vulnerabilities | length }} matched</div>

    {% if vulnerabilities %}
    <div class="vuln-list">
        {% for v in vulnerabilities %}
        {% set cvss_class = 'crit' if v.severity == 'CRITICAL' else ('high' if v.severity == 'HIGH' else ('medium' if v.severity == 'MEDIUM' else 'low')) %}
        <div class="vuln-row">

            <div>
                <span class="sev-tag {{ v.severity }}">{{ v.severity }}</span>
            </div>

            <div class="vuln-id-block">
                <span class="cve-id">{{ v.cve_id }}</span>
                <span class="port-tag">port {{ v.port }}</span>
                {% if v.published %}<span class="port-tag">{{ v.published[:10] }}</span>{% endif %}
            </div>

            <div class="vuln-body">
                <div class="vuln-product">{{ v.affected_product }}{% if v.affected_version %} {{ v.affected_version }}{% endif %}</div>
                <div class="vuln-desc">{{ v.description }}</div>
                <div class="vuln-links">
                    <a href="{{ v.url }}" target="_blank">nvd.nist.gov &rarr;</a>
                    &nbsp;&nbsp;
                    <span style="color:var(--muted)">{{ v.remediation }}</span>
                </div>
            </div>

            <div class="cvss-num {{ cvss_class }}">{{ v.cvss_score }}</div>

        </div>
        {% endfor %}
    </div>
    {% else %}
    <div class="empty-state">
        <div class="es-line ok">-- no vulnerabilities matched --</div>
        <div class="es-line">Scan completed. No known CVEs found for detected service versions.</div>
    </div>
    {% endif %}

    <!-- SSL / TLS -->
    {% if ssl_analysis %}
    <div class="section-head">SSL / TLS &mdash; port {{ ssl_analysis.port }}</div>
    <div class="ssl-grid">
        <div class="ssl-cell">
            <div class="ssl-cell-label">Protocol</div>
            <div class="ssl-cell-val">{{ ssl_analysis.tls_version or 'unknown' }}</div>
        </div>
        <div class="ssl-cell">
            <div class="ssl-cell-label">Cipher suite</div>
            <div class="ssl-cell-val">
                {% if ssl_analysis.cipher %}
                    {{ ssl_analysis.cipher.name }}<br>
                    <span style="color:var(--muted)">{{ ssl_analysis.cipher.bits }} bit</span>
                {% else %}—{% endif %}
            </div>
        </div>
        {% if ssl_analysis.certificate %}
        <div class="ssl-cell">
            <div class="ssl-cell-label">Subject</div>
            <div class="ssl-cell-val">
                {% for k, v in ssl_analysis.certificate.subject.items() %}{{ k }}: {{ v }}<br>{% endfor %}
            </div>
        </div>
        <div class="ssl-cell">
            <div class="ssl-cell-label">Validity</div>
            <div class="ssl-cell-val">
                {{ ssl_analysis.certificate.not_before }}<br>
                {{ ssl_analysis.certificate.not_after }}
            </div>
        </div>
        {% endif %}
        {% if ssl_analysis.issues %}
        <div class="ssl-cell full">
            <div class="ssl-cell-label">Issues &mdash; {{ ssl_analysis.issues | length }}</div>
            <div class="ssl-issues">
                {% for issue in ssl_analysis.issues %}
                <div class="ssl-issue-row">
                    <span class="ssl-sev {{ issue.severity }}">{{ issue.severity }}</span>
                    <span class="ssl-issue-txt">{{ issue.issue }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>
    {% endif %}

    <!-- Footer -->
    <footer class="site-footer">
        <span>ArgosScan v0.1.0</span>
        <a href="https://github.com/lBENDUl/ArgosScan">github.com/lBENDUl/ArgosScan</a>
    </footer>

</div>
</body>
</html>"""


class HTMLReporter:
    """Render a polished HTML vulnerability report."""

    def __init__(self, results: Dict):
        self._results = results

    def generate(self, output_file: str) -> None:
        """
        Write the HTML report to *output_file*.

        Args:
            output_file: Destination path (e.g. 'report.html').
        """
        html = Template(_TEMPLATE).render(
            target=self._results["target"],
            timestamp=self._results["timestamp"],
            scan_params=self._results["scan_params"],
            open_ports=self._results.get("open_ports", []),
            vulnerabilities=self._results.get("vulnerabilities", []),
            ssl_analysis=self._results.get("ssl_analysis"),
            summary=self._results["summary"],
        )
        Path(output_file).write_text(html, encoding="utf-8")
