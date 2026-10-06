import json
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
        
        def rank_decision(dec):
            return {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}.get(dec, 4)

        sorted_comps = []
        for comp_key, vulns in components.items():
            decisions = [v.ssvc_decision.value for v in vulns]
            worst_decision = min(decisions, key=rank_decision)
            
            summary_counts[worst_decision] += 1
            
            service = vulns[0].service_name or "unknown"
            port = vulns[0].target_port
            version = vulns[0].service_version or "Unknown Version"
            protocol = vulns[0].protocol or "tcp"
            
            unique_cves = list(set([v.cve_id for v in vulns if v.cve_id]))
            unique_cves.sort()
            
            kev_count = sum(1 for v in vulns if v.is_in_cisa_kev)
            
            # SAFE MAX COMPARISON: Filter out None values before calculating max
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
                "vulns": vulns,
                "unique_cves": unique_cves,
                "kev_count": kev_count,
                "max_epss": max_epss,
                "max_cvss": max_cvss,
                "breakdown": breakdown
            })
            
        sorted_comps.sort(key=lambda x: (rank_decision(x['worst_decision']), -x['max_epss']))

        spotlights_html = ""
        act_comps = [c for c in sorted_comps if c['worst_decision'] == 'Act']
        for c in act_comps:
            spotlights_html += f'''
    <div class="spotlight-card">
        <div class="spotlight-header">
            <span class="spotlight-title">[{c['service'].upper()}] Upgrade {c['version']} (Port {c['port']}/{c['protocol']})</span>
            <span class="badge badge-act">ACT</span>
        </div>
        <div class="business-impact">
            <strong>Business Impact:</strong> Critical vulnerabilities detected. Immediate patching required to prevent potential exploitation.
        </div>
        <div style="font-size: 13px; color: #475569;">
            Upgrading this component resolves <strong>{len(c['vulns'])} vulnerabilities</strong> simultaneously.
            <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                Peak Weaponization Likelihood: <strong>{c['max_epss'] * 100:.2f}%</strong> | 
                CISA KEV Hits: <strong>{c['kev_count']}</strong> | 
                Peak CVSS: <strong>{c['max_cvss']:.1f}/10</strong>
            </div>
        </div>
    </div>'''

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
            kev_display = f"Yes ({c['kev_count']})" if c['kev_count'] > 0 else "None"

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
                <div style="font-size:11px; margin-bottom:8px; display:flex; gap:8px; flex-wrap:wrap;">
                    {breakdown_html}
                </div>
                <details>
                    <summary><div class="cve-expand-btn">View CVE Log</div></summary>
                    <div class="cve-log-content">{cve_log}</div>
                </details>
            </td>
            <td>{kev_display}</td>
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
        :root {{
            --act: #ef4444; --act-bg: #fef2f2;
            --attend: #f59e0b; --attend-bg: #fffbeb;
            --track-star: #3b82f6; --track-star-bg: #eff6ff;
            --track: #64748b; --track-bg: #f8fafc;
            --bg-main: #f8fafc; --card-bg: #ffffff; --border: #e2e8f0;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-main); color: #334155; margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        .header {{ background: #0f172a; color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: flex-start; }}
        .header-content h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
        .header-content p {{ margin: 0; color: #94a3b8; font-size: 15px; }}
        .header-actions {{ display: flex; gap: 10px; }}
        .btn-action {{ background-color: #334155; color: #ffffff; border: none; padding: 8px 16px; font-size: 13px; font-weight: 600; border-radius: 6px; cursor: pointer; transition: background 0.2s; }}
        .btn-action:hover {{ background-color: #475569; }}
        .btn-csv {{ background-color: #059669; }}
        .btn-csv:hover {{ background-color: #047857; }}

        .dashboard-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-bottom: 30px; }}
        .card {{ background: var(--card-bg); padding: 24px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .chart-container {{ position: relative; height: 250px; width: 100%; }}
        
        .stat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .stat-box {{ padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-act {{ background: var(--act-bg); border: 1px solid #fecaca; color: #991b1b; }}
        .stat-attend {{ background: var(--attend-bg); border: 1px solid #fde68a; color: #92400e; }}
        .stat-track-star {{ background: var(--track-star-bg); border: 1px solid #bfdbfe; color: #1e40af; }}
        .stat-track {{ background: var(--track-bg); border: 1px solid #e2e8f0; color: #334155; }}
        .stat-num {{ font-size: 32px; font-weight: 800; line-height: 1; }}
        .stat-label {{ font-size: 13px; font-weight: 600; margin-top: 8px; text-transform: uppercase; }}

        .spotlight-card {{ border: 1px solid var(--border); border-left: 5px solid var(--act); border-radius: 8px; padding: 20px; margin-bottom: 16px; background: #fff; }}
        .spotlight-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .spotlight-title {{ font-weight: 700; font-size: 15px; color: #0f172a; }}
        .business-impact {{ background: #fff1f2; border: 1px solid #ffe4e6; padding: 10px 12px; border-radius: 6px; font-size: 13px; color: #9f1239; margin-bottom: 10px; }}

        .filter-controls {{ display: flex; gap: 12px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }}
        .filter-input, .filter-select {{ padding: 8px 12px; font-size: 13px; border: 1px solid var(--border); border-radius: 6px; }}
        .filter-input {{ width: 260px; }}

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
        .cve-expand-btn {{ display: inline-block; margin-top: 8px; padding: 5px 10px; background-color: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 11px; font-weight: 600; color: #334155; cursor: pointer; transition: all 0.2s ease; }}
        .cve-expand-btn:hover {{ background-color: #e2e8f0; border-color: #94a3b8; }}
        .cve-log-content {{ font-size: 11px; color: #475569; padding: 10px 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; max-height: 140px; overflow-y: auto; word-break: break-word; line-height: 1.5; margin-top: 6px; }}

        @media print {{
            body {{ background-color: #fff; padding: 0; }}
            .header-actions, .filter-controls {{ display: none; }}
            .card {{ box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>Vuln2Risk Executive Dashboard</h1>
                <p>Automated Vulnerability Prioritization powered by SSVC, CISA KEV, and EPSS Threat Intelligence.</p>
            </div>
            <div class="header-actions">
                <button class="btn-action btn-csv" onclick="downloadCSV()">Export CSV</button>
                <button class="btn-action" onclick="window.print()">Print / PDF</button>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card" style="margin-bottom:0;">
                <h3 style="margin-top:0;">Risk Distribution</h3>
                <div class="chart-container">
                    <canvas id="ssvcChart"></canvas>
                </div>
            </div>

            <div class="card" style="margin-bottom:0;">
                <h3 style="margin-top:0;">Remediation SLA Summary</h3>
                <div class="stat-grid">
                    <div class="stat-box stat-act">
                        <div class="stat-num">{summary_counts['Act']}</div>
                        <div class="stat-label">ACT (48 Hours)</div>
                    </div>
                    <div class="stat-box stat-attend">
                        <div class="stat-num">{summary_counts['Attend']}</div>
                        <div class="stat-label">ATTEND (14 Days)</div>
                    </div>
                    <div class="stat-box stat-track-star">
                        <div class="stat-num">{summary_counts['Track*']}</div>
                        <div class="stat-label">TRACK* (30 Days)</div>
                    </div>
                    <div class="stat-box stat-track">
                        <div class="stat-num">{summary_counts['Track']}</div>
                        <div class="stat-label">TRACK (90 Days)</div>
                    </div>
                </div>
            </div>
        </div>

        {('<div class="card"><h3 style="margin-top:0;">Top Component Upgrades Demanding Immediate Action</h3>' + spotlights_html + '</div>') if spotlights_html else ''}

        <div class="card">
            <h3 style="margin-top:0; margin-bottom: 20px;">Actionable Component Upgrade Backlog</h3>
            
            <div class="filter-controls">
                <input type="text" id="searchBox" class="filter-input" placeholder="Search service, port, or CVE..." onkeyup="filterTable()">
                <select id="decisionFilter" class="filter-select" onchange="filterTable()">
                    <option value="ALL">All Decisions</option>
                    <option value="Act">Act Only</option>
                    <option value="Attend">Attend Only</option>
                    <option value="Track*">Track (30d) Only</option>
                    <option value="Track">Track (90d) Only</option>
                </select>
            </div>

            <table id="backlogTable">
                <thead>
                    <tr>
                        <th>Decision</th>
                        <th>Target Component</th>
                        <th>Port</th>
                        <th style="width: 45%;">Vulnerability Rollup Profile</th>
                        <th>CISA KEV</th>
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
                labels: ['ACT (48h)', 'ATTEND (14d)', 'TRACK* (30d)', 'TRACK (90d)'],
                datasets: [{{
                    data: [{summary_counts['Act']}, {summary_counts['Attend']}, {summary_counts['Track*']}, {summary_counts['Track']}],
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#64748b'],
                    borderWidth: 0,
                    hoverOffset: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom' }} }},
                cutout: '70%'
            }}
        }});

        function filterTable() {{
            var searchVal = document.getElementById("searchBox").value.toLowerCase().trim();
            var decisionVal = document.getElementById("decisionFilter").value;
            var rows = document.querySelectorAll("#backlogTable tbody tr");

            rows.forEach(function(row) {{
                var text = row.innerText.toLowerCase();
                var rowDecision = row.getAttribute("data-decision") || "";
                var matchesSearch = (!searchVal || text.indexOf(searchVal) !== -1);
                var matchesDecision = (decisionVal === "ALL" || rowDecision === decisionVal);

                row.style.display = (matchesSearch && matchesDecision) ? "" : "none";
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
                    var rawText = cols[j].innerText;
                    rawText = rawText.replace('View CVE Log', '');
                    var cleanText = rawText.split("\\r\\n").join(" ").split("\\n").join(" ").split("\\r").join(" ");
                    cleanText = cleanText.replace(/"/g, '""').trim();
                    row.push('"' + cleanText + '"');
                }}
                csv.push(row.join(","));
            }}
            
            var csvBlob = new Blob([csv.join("\\r\\n")], {{ type: "text/csv;charset=utf-8;" }});
            var downloadUrl = window.URL.createObjectURL(csvBlob);
            var link = document.createElement("a");
            link.href = downloadUrl;
            link.download = "vuln2risk_remediation_backlog.csv";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(downloadUrl);
        }}
    </script>
</body>
</html>'''

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
