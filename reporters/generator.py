from collections import defaultdict
from core.models import Finding

class ReportGenerator:
    @staticmethod
    def generate_html_report(findings: list[Finding], output_path: str):
        components = defaultdict(list)
        for f in findings:
            comp_key = f"{f.service_name or 'unknown'}:{f.target_port}"
            components[comp_key].append(f)

        summary_counts = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
        status_counts = {"Open": 0, "Validated": 0, "Remediating": 0, "Retesting": 0, "Fixed": 0}
        
        def rank_decision(dec):
            return {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}.get(dec, 4)

        sorted_comps = []
        for comp_key, vulns in components.items():
            decisions = [v.ssvc_decision.value for v in vulns]
            worst_decision = min(decisions, key=rank_decision)
            worst_finding = min(vulns, key=lambda v: (rank_decision(v.ssvc_decision.value), -(v.epss_score or 0.0)))
            
            summary_counts[worst_decision] += 1
            status_counts[worst_finding.status.value] += 1
            
            service = vulns[0].service_name or "unknown"
            port = vulns[0].target_port
            version = vulns[0].service_version or "Unknown Version"
            protocol = vulns[0].protocol or "tcp"
            
            unique_cves = list(set([v.cve_id for v in vulns if v.cve_id]))
            unique_cves.sort()
            
            kev_count = sum(1 for v in vulns if v.is_in_cisa_kev)
            max_epss = max([v.epss_score for v in vulns if v.epss_score is not None] + [0.0])
            max_cvss = max([v.cvss_base for v in vulns if v.cvss_base is not None] + [0.0])
            
            breakdown = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
            for d in decisions:
                if d in breakdown:
                    breakdown[d] += 1
                    
            sorted_comps.append({
                "key": comp_key,
                "service": service,
                "port": port,
                "protocol": protocol,
                "version": version,
                "worst_decision": worst_decision,
                "status": worst_finding.status.value,
                "justification": worst_finding.justification,
                "vulns": vulns,
                "unique_cves": unique_cves,
                "kev_count": kev_count,
                "max_epss": max_epss,
                "max_cvss": max_cvss,
                "breakdown": breakdown
            })
            
        sorted_comps.sort(key=lambda x: (rank_decision(x['worst_decision']), -x['max_epss']))

        spotlights_html = '<div class="spotlight-grid">'
        top_comps = sorted_comps[:3] if sorted_comps else []
        for c in top_comps:
            dec = c['worst_decision']
            css_var = dec.replace('*', '-star').lower()
            spotlights_html += f'''
    <div class="spotlight-card" style="border-left-color: var(--{css_var});">
        <div class="spotlight-header">
            <span class="spotlight-title">[{c['service'].upper()}] Upgrade {c['version']} (Port {c['port']}/{c['protocol']})</span>
            <span class="badge badge-{css_var}">{dec.upper()}</span>
        </div>
        <div class="business-impact" style="background:var(--{css_var}-bg); border-color:var(--{css_var}); color:var(--{css_var});">
            <strong>Decision Logic:</strong> SLA tier assigned based on SSVC assessment matrix.
        </div>
        <div style="font-size: 13px; color: #475569; margin-top: auto;">
            Upgrading this component resolves <strong>{len(c['vulns'])} vulnerabilities</strong> simultaneously.
            <div style="margin-top: 10px; font-size: 12px; color: #64748b; padding-top: 10px; border-top: 1px solid #f1f5f9;">
                Weaponization: <strong>{c['max_epss'] * 100:.2f}%</strong> | 
                KEV Hits: <strong>{c['kev_count']}</strong><br>
                Peak CVSS: <strong>{c['max_cvss']:.1f}/10</strong>
            </div>
        </div>
    </div>'''
        spotlights_html += '</div>'

        table_rows_html = ""
        for c in sorted_comps:
            decision = c['worst_decision']
            badge_class = f"badge-{decision.replace('*', '-star').lower()}"
            sla_days = "2d" if decision == "Act" else "14d" if decision == "Attend" else "30d" if decision == "Track*" else "90d"
            
            breakdown_html = ""
            if c['breakdown']['Act'] > 0: breakdown_html += f'<span style="color:var(--act); font-weight:700;">• {c["breakdown"]["Act"]} Act</span> '
            if c['breakdown']['Attend'] > 0: breakdown_html += f'<span style="color:var(--attend); font-weight:700;">• {c["breakdown"]["Attend"]} Attend</span> '
            if c['breakdown']['Track*'] > 0: breakdown_html += f'<span style="color:var(--track-star); font-weight:700;">• {c["breakdown"]["Track*"]} Track (30d)</span> '
            if c['breakdown']['Track'] > 0: breakdown_html += f'<span style="color:var(--track); font-weight:700;">• {c["breakdown"]["Track"]} Track (90d)</span> '

            cve_log = ", ".join(c['unique_cves']) if c['unique_cves'] else "No CVEs assigned"
            justification_html = c['justification'].replace('\n', '<br>') if c['justification'] else "No logic provided"

            table_rows_html += f'''
        <tr data-decision="{decision}" data-service="{c['service']}">
            <td>
                <span class="badge {badge_class}">{decision.upper()}</span><br>
                <div style="font-size:10px; margin-top:6px; color:#64748b;">SLA: {sla_days}</div>
            </td>
            <td><strong>{c['service']}</strong><br><span style="font-size:11px; color:#64748b;">{c['version']}</span></td>
            <td>{c['port']}/{c['protocol']}</td>
            <td>
                <div style="font-weight:600; margin-bottom:4px; font-size:13px;">{len(c['vulns'])} Vulnerabilities Consolidated</div>
                <div style="font-size:11px; margin-bottom:8px; display:flex; gap:8px; flex-wrap:wrap;">{breakdown_html}</div>
                <details>
                    <summary><div class="cve-expand-btn">View Risk Logic & CVEs</div></summary>
                    <div class="cve-log-content">
                        <div style="margin-bottom:8px; padding-bottom:8px; border-bottom:1px solid #e2e8f0;">
                            <strong>Why {decision.upper()}?</strong><br>
                            {justification_html}
                        </div>
                        <strong>CVEs:</strong> {cve_log}
                    </div>
                </details>
            </td>
            <td><strong>{c['status'].upper()}</strong></td>
            <td>{c['max_epss'] * 100:.2f}%</td>
        </tr>'''

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vuln2Risk Executive Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{ --act: #ef4444; --act-bg: #fef2f2; --attend: #f59e0b; --attend-bg: #fffbeb; --track-star: #3b82f6; --track-star-bg: #eff6ff; --track: #64748b; --track-bg: #f8fafc; --bg-main: #f8fafc; --card-bg: #ffffff; --border: #e2e8f0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-main); color: #334155; margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #0f172a; color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: flex-start; }}
        .header-content h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
        .header-content p {{ margin: 0; color: #94a3b8; font-size: 15px; }}
        .header-actions {{ display: flex; gap: 10px; }}
        .btn-action {{ background-color: #334155; color: #ffffff; border: none; padding: 8px 16px; font-size: 13px; font-weight: 600; border-radius: 6px; cursor: pointer; }}
        .btn-csv {{ background-color: #059669; }}
        .dashboard-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: var(--card-bg); padding: 24px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1); }}
        .chart-container {{ position: relative; height: 180px; width: 100%; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .stat-box {{ padding: 16px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }}
        .stat-num {{ font-size: 28px; font-weight: 800; line-height: 1; }}
        .stat-label {{ font-size: 12px; font-weight: 600; margin-top: 8px; text-transform: uppercase; }}
        
        /* SPOTLIGHT CSS */
        .spotlight-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
        .spotlight-card {{ display: flex; flex-direction: column; background: #fff; padding: 16px; border-radius: 8px; border: 1px solid var(--border); border-left-width: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .spotlight-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 12px; }}
        .spotlight-title {{ font-size: 14px; font-weight: 700; color: #0f172a; line-height: 1.4; }}
        .business-impact {{ padding: 10px; border-radius: 6px; font-size: 12px; border: 1px solid; margin-bottom: 12px; opacity: 0.9; }}
        
        .filter-controls {{ display: flex; gap: 12px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }}
        .filter-input, .filter-select {{ padding: 8px 12px; font-size: 13px; border: 1px solid var(--border); border-radius: 6px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; vertical-align: top; }}
        th {{ background-color: #f1f5f9; font-weight: 600; color: #475569; }}
        tr:hover {{ background-color: #f8fafc; }}
        .badge {{ padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; display: inline-block; text-align: center; }}
        .badge-act {{ background: var(--act); color: white; }}
        .badge-attend {{ background: var(--attend); color: white; }}
        .badge-track-star {{ background: var(--track-star); color: white; }}
        .badge-track {{ background: var(--track); color: white; }}
        details summary {{ outline: none; list-style: none; }}
        details summary::-webkit-details-marker {{ display: none; }}
        .cve-expand-btn {{ display: inline-block; margin-top: 8px; padding: 5px 10px; background-color: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 11px; font-weight: 600; color: #334155; cursor: pointer; }}
        .cve-log-content {{ font-size: 12px; color: #475569; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; max-height: 200px; overflow-y: auto; line-height: 1.5; margin-top: 6px; }}
        @media print {{ body {{ background-color: #fff; padding: 0; }} .header-actions, .filter-controls {{ display: none; }} .dashboard-grid, .spotlight-grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>Vuln2Risk Executive Dashboard</h1>
                <p>Automated Vulnerability Management Lifecycle powered by SSVC & Threat Intelligence.</p>
            </div>
            <div class="header-actions">
                <button class="btn-action btn-csv" onclick="downloadCSV()">Export CSV</button>
                <button class="btn-action" onclick="window.print()">Print / PDF</button>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card">
                <h3 style="margin-top:0;">Risk Distribution</h3>
                <div class="chart-container"><canvas id="ssvcChart"></canvas></div>
            </div>

            <div class="card">
                <h3 style="margin-top:0;">SLA Timelines</h3>
                <div class="stat-grid">
                    <div class="stat-box" style="background:var(--act-bg); border-color:#fecaca; color:#991b1b;">
                        <div class="stat-num">{summary_counts['Act']}</div><div class="stat-label">ACT (48h)</div>
                    </div>
                    <div class="stat-box" style="background:var(--attend-bg); border-color:#fde68a; color:#92400e;">
                        <div class="stat-num">{summary_counts['Attend']}</div><div class="stat-label">ATTEND (14d)</div>
                    </div>
                    <div class="stat-box" style="background:var(--track-star-bg); border-color:#bfdbfe; color:#1e40af;">
                        <div class="stat-num">{summary_counts['Track*']}</div><div class="stat-label">TRACK* (30d)</div>
                    </div>
                    <div class="stat-box" style="background:var(--track-bg); color:#334155;">
                        <div class="stat-num">{summary_counts['Track']}</div><div class="stat-label">TRACK (90d)</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3 style="margin-top:0;">Lifecycle Status</h3>
                <div class="stat-grid">
                    <div class="stat-box">
                        <div class="stat-num">{status_counts['Open']}</div><div class="stat-label">Open</div>
                    </div>
                    <div class="stat-box" style="background:#eff6ff; border-color:#bfdbfe; color:#1e40af;">
                        <div class="stat-num">{status_counts['Remediating']}</div><div class="stat-label">Remediating</div>
                    </div>
                    <div class="stat-box" style="background:#fffbeb; border-color:#fde68a; color:#92400e;">
                        <div class="stat-num">{status_counts['Retesting']}</div><div class="stat-label">Retesting</div>
                    </div>
                    <div class="stat-box" style="background:#f0fdf4; border-color:#bbf7d0; color:#166534;">
                        <div class="stat-num">{status_counts['Fixed']}</div><div class="stat-label">Fixed</div>
                    </div>
                </div>
            </div>
        </div>

        {('<div class="card"><h3 style="margin-top:0; margin-bottom:16px;">Top Component Upgrades Demanding Action</h3>' + spotlights_html + '</div>') if top_comps else ''}

        <div class="card">
            <h3 style="margin-top:0; margin-bottom: 20px;">Actionable Component Upgrade Backlog</h3>
            
            <div class="filter-controls">
                <input type="text" id="searchBox" class="filter-input" placeholder="Search service, port, or CVE..." onkeyup="filterTable()">
                <select id="decisionFilter" class="filter-select" onchange="filterTable()">
                    <option value="ALL">All Decisions</option>
                    <option value="Act">Act Only</option><option value="Attend">Attend Only</option>
                    <option value="Track*">Track (30d) Only</option><option value="Track">Track (90d) Only</option>
                </select>
            </div>

            <table id="backlogTable">
                <thead>
                    <tr>
                        <th>Decision</th>
                        <th>Target Component</th>
                        <th>Port</th>
                        <th style="width: 40%;">Vulnerability Rollup Profile</th>
                        <th>Lifecycle Status</th>
                        <th>Peak EPSS</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('ssvcChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['ACT', 'ATTEND', 'TRACK*', 'TRACK'],
                datasets: [{{ data: [{summary_counts['Act']}, {summary_counts['Attend']}, {summary_counts['Track*']}, {summary_counts['Track']}], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#64748b'], borderWidth: 0 }}]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ position: 'right' }} }}, cutout: '70%' }}
        }});

        function filterTable() {{
            var searchVal = document.getElementById("searchBox").value.toLowerCase().trim();
            var decisionVal = document.getElementById("decisionFilter").value;
            var rows = document.querySelectorAll("#backlogTable tbody tr");

            rows.forEach(function(row) {{
                var text = row.innerText.toLowerCase();
                var rowDecision = row.getAttribute("data-decision") || "";
                row.style.display = ((!searchVal || text.indexOf(searchVal) !== -1) && (decisionVal === "ALL" || rowDecision === decisionVal)) ? "" : "none";
            }});
        }}

        function downloadCSV() {{
            var rows = document.querySelectorAll("#backlogTable tr");
            var csv = [];
            for (var i = 0; i < rows.length; i++) {{
                if (rows[i].style.display === "none") continue;
                var row = [];
                var cols = rows[i].querySelectorAll("th, td");
                for (var j = 0; j < cols.length; j++) {{
                    // Strip the button text but leave interior formatting intact
                    var cleanText = cols[j].innerText.replace('View Risk Logic & CVEs', '').trim();
                    // Escape double quotes to not break standard CSV boundaries
                    cleanText = cleanText.replace(/"/g, '""');
                    // Encase multiline cell fully inside quotes
                    row.push('"' + cleanText + '"');
                }}
                csv.push(row.join(","));
            }}
            // Force the \uFEFF Byte Order Mark so Excel opens it automatically formatted as UTF-8
            var csvBlob = new Blob(["\\uFEFF" + csv.join("\\r\\n")], {{ type: "text/csv;charset=utf-8;" }});
            var downloadUrl = window.URL.createObjectURL(csvBlob);
            var link = document.createElement("a");
            link.href = downloadUrl; link.download = "vuln2risk_backlog.csv";
            document.body.appendChild(link); link.click(); document.body.removeChild(link);
        }}
    </script>
</body>
</html>'''

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            