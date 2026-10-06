import os
from typing import List, Dict
from jinja2 import Template
from core.models import Finding, SSVCDecision


class ReportGenerator:
    HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vuln2Risk Security Assessment & Remediation Report</title>
    <style>
        :root {
            --act: #dc2626;
            --act-bg: #fef2f2;
            --attend: #d97706;
            --attend-bg: #fffbeb;
            --track-star: #0284c7;
            --track-star-bg: #f0f9ff;
            --track: #475569;
            --track-bg: #f8fafc;
            --border: #e2e8f0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 32px 16px;
            background-color: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        .container {
            max-width: 1150px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -2px rgba(0,0,0,0.05);
            border: 1px solid var(--border);
        }
        header {
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        h1 { margin: 0 0 6px 0; color: #0f172a; font-size: 26px; }
        .subtitle { color: #64748b; font-size: 14px; margin-bottom: 12px; }
        
        .meta-strip {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            background: #f8fafc;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 13px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
        }
        .meta-strip strong { color: #0f172a; }

        .header-actions { display: flex; gap: 10px; }
        .btn-action {
            background-color: #0f172a;
            color: #ffffff;
            border: none;
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-action:hover { background-color: #334155; }
        .btn-csv { background-color: #059669; }
        .btn-csv:hover { background-color: #047857; }

        .exec-box {
            background-color: #eff6ff;
            border-left: 5px solid #2563eb;
            border-radius: 6px;
            padding: 18px 20px;
            margin-bottom: 28px;
        }
        .exec-box h2 { font-size: 16px; margin: 0 0 6px 0; color: #1e40af; }
        .exec-box p { margin: 0; font-size: 14px; color: #1e3a8a; }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 36px;
        }
        .stat-card {
            padding: 18px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: #fff;
            text-align: center;
        }
        .stat-num { font-size: 34px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
        .stat-label { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-desc { font-size: 11px; color: #64748b; margin-top: 4px; }

        .primer-box {
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 36px;
            background: #ffffff;
        }
        .primer-box h3 { margin: 0 0 12px 0; font-size: 15px; color: #0f172a; }
        .primer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            font-size: 13px;
        }
        .primer-item strong { display: block; color: #0f172a; margin-bottom: 3px; }

        .spotlight-card {
            border: 1px solid var(--border);
            border-left: 5px solid var(--act);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            background: #fff;
        }
        .spotlight-card.attend { border-left-color: var(--attend); }
        .spotlight-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .spotlight-title { font-weight: 700; font-size: 15px; color: #0f172a; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .badge-act { background-color: var(--act-bg); color: var(--act); border: 1px solid #fca5a5; }
        .badge-attend { background-color: var(--attend-bg); color: var(--attend); border: 1px solid #fde68a; }
        .badge-track-star { background-color: var(--track-star-bg); color: var(--track-star); border: 1px solid #bae6fd; }
        .badge-track { background-color: var(--track-bg); color: var(--track); border: 1px solid #cbd5e1; }

        .business-impact {
            background: #fff1f2;
            border: 1px solid #ffe4e6;
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 13px;
            color: #9f1239;
            margin-bottom: 10px;
        }
        .business-impact strong { color: #881337; }

        .filter-controls {
            display: flex;
            gap: 12px;
            margin-top: 24px;
            margin-bottom: 12px;
            align-items: center;
            flex-wrap: wrap;
        }
        .filter-input {
            padding: 8px 12px;
            font-size: 13px;
            border: 1px solid var(--border);
            border-radius: 6px;
            width: 260px;
        }
        .filter-select {
            padding: 8px 12px;
            font-size: 13px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: #fff;
        }

        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
        th, td { border: 1px solid var(--border); padding: 10px 12px; text-align: left; vertical-align: top; }
        th { background-color: #f8fafc; color: #475569; font-weight: 600; }
        tr:hover { background-color: #fbfcfd; }

        /* Enhanced Details/Summary CSS */
        details summary { outline: none; list-style: none; }
        details summary::-webkit-details-marker { display: none; }
        
        .cve-expand-btn {
            display: inline-block;
            margin-top: 8px;
            padding: 5px 10px;
            background-color: #f1f5f9;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 600;
            color: #334155;
            cursor: pointer;
            user-select: none;
            transition: all 0.2s ease;
        }
        .cve-expand-btn:hover {
            background-color: #e2e8f0;
            border-color: #94a3b8;
        }
        .cve-expand-btn::before {
            content: '▶';
            display: inline-block;
            margin-right: 5px;
            font-size: 9px;
            transition: transform 0.2s;
        }
        details[open] .cve-expand-btn {
            background-color: #e0f2fe;
            border-color: #7dd3fc;
            color: #0369a1;
            margin-bottom: 6px;
        }
        details[open] .cve-expand-btn::before {
            transform: rotate(90deg);
        }
        .cve-log-content {
            font-size: 11px;
            color: #475569;
            padding: 10px 12px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            max-height: 140px;
            overflow-y: auto;
            word-break: break-word;
            line-height: 1.5;
            box-shadow: inset 0 2px 4px 0 rgb(0 0 0 / 0.02);
        }

        @media print {
            body { padding: 0; background-color: #ffffff; }
            .container { border: none; box-shadow: none; padding: 0; max-width: 100%; }
            .header-actions, .filter-controls { display: none; }
            .spotlight-card, table { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>Vuln2Risk Component Remediation Plan</h1>
            <div class="subtitle">Actionable Upgrades: Aggregated {{ total_findings }} Scanner Alerts into {{ aggregated_items|length }} Actionable Component Upgrades</div>
        </div>
        <div class="header-actions">
            <button class="btn-action btn-csv" onclick="downloadCSV()">Export CSV</button>
            <button class="btn-action" onclick="window.print()">Print Report</button>
        </div>
    </header>

    <div class="meta-strip">
        <div>Target Host: <strong>{{ target_host }}</strong></div>
        <div>Exposure: <strong>{{ "Internet-Facing" if is_internet_facing else "Internal Protected Network" }}</strong></div>
        <div>Asset Criticality: <strong>{{ criticality }}</strong></div>
        <div>Total Detected Alerts: <strong>{{ total_findings }}</strong></div>
        <div>Emergency Component Fixes: <strong style="color: var(--act);">{{ summary.Act }}</strong></div>
    </div>

    <div class="exec-box">
        <h2>Executive Summary</h2>
        <p>
            The scanner detected <strong>{{ total_findings }} raw vulnerability alerts</strong>. Instead of wasting developer hours tracking separate CVE issues, Vuln2Risk rolled these into <strong>{{ aggregated_items|length }} actionable package upgrades</strong>.
            Upgrading the <strong>{{ summary.Act }} components marked ACT</strong> within the next 48 hours resolves the vast majority of real-world exploitation risks on this host.
        </p>
    </div>

    <div class="primer-box">
        <h3>Layman's Guide: Understanding Risk Metrics</h3>
        <div class="primer-grid">
            <div class="primer-item">
                <strong>Exploit Likelihood (EPSS Score)</strong>
                A machine learning calculation of the probability (0-100%) that a vulnerability is currently being weaponized in real-world attacks. Over 50% indicates active wild exploitation.
            </div>
            <div class="primer-item">
                <strong>CISA KEV Catalog</strong>
                The official U.S. Cybersecurity Agency list of vulnerabilities confirmed to be leveraged by ransomware operators to breach corporate networks.
            </div>
            <div class="primer-item">
                <strong>SSVC Triage SLA</strong>
                Operational prioritizations: <strong>ACT</strong> (remediate within 48 hours) versus <strong>ATTEND</strong> (prioritize in next 14-day sprint).
            </div>
        </div>
    </div>

    <div class="stat-grid">
        <div class="stat-card" style="border-top: 4px solid var(--act);">
            <div class="stat-num" style="color: var(--act);">{{ summary.Act }}</div>
            <div class="stat-label" style="color: var(--act);">ACT Components (48h)</div>
            <div class="stat-desc">Contains weaponized / KEV flaws</div>
        </div>
        <div class="stat-card" style="border-top: 4px solid var(--attend);">
            <div class="stat-num" style="color: var(--attend);">{{ summary.Attend }}</div>
            <div class="stat-label" style="color: var(--attend);">ATTEND Components (14d)</div>
            <div class="stat-desc">Contains elevated exposed flaws</div>
        </div>
        <div class="stat-card" style="border-top: 4px solid var(--track-star);">
            <div class="stat-num" style="color: var(--track-star);">{{ summary['Track*'] }}</div>
            <div class="stat-label" style="color: var(--track-star);">TRACK (30d SLA)</div>
            <div class="stat-desc">Standard sprint items</div>
        </div>
        <div class="stat-card" style="border-top: 4px solid var(--track);">
            <div class="stat-num" style="color: var(--track);">{{ summary.Track }}</div>
            <div class="stat-label" style="color: var(--track);">TRACK (90d Cycle)</div>
            <div class="stat-desc">Routine scheduled maintenance</div>
        </div>
    </div>

    <h2>Top Component Upgrades Demanding Immediate Action</h2>
    {% for item in spotlight_items %}
    <div class="spotlight-card {{ 'attend' if item.highest_decision == 'Attend' else '' }}">
        <div class="spotlight-header">
            <span class="spotlight-title">[{{ item.service_name.upper() }}] Upgrade {{ item.service_version }} (Port {{ item.target_port }}/{{ item.protocol }})</span>
            <span class="badge badge-{{ item.highest_decision_css }}">{{ item.highest_decision_display }}</span>
        </div>
        <div class="business-impact">
            <strong>Business Impact:</strong> {{ item.layman_impact }}
        </div>
        <div style="font-size: 13px; color: #475569;">
            Upgrading this package resolves <strong>{{ item.cve_count }} vulnerabilities</strong> simultaneously, including: <em>{{ item.cve_list_display }}</em>.
            <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                Peak Weaponization Likelihood: <strong>{{ "%.2f"|format(item.max_epss * 100) }}%</strong> | 
                CISA KEV Hits: <strong>{{ item.kev_count }}</strong> | 
                Peak CVSS: <strong>{{ item.max_cvss }}/10</strong>
            </div>
        </div>
    </div>
    {% endfor %}

    <h2 style="margin-top: 40px; margin-bottom: 4px;">Actionable Component Remediation Backlog</h2>
    <div class="filter-controls">
        <input type="text" id="searchBox" class="filter-input" placeholder="Search service, port, or CVE..." onkeyup="filterTable()">
        <select id="decisionFilter" class="filter-select" onchange="filterTable()">
            <option value="ALL">All Decisions</option>
            <option value="Act">Act Only</option>
            <option value="Attend">Attend Only</option>
            <option value="Track*">Track (30d) Only</option>
            <option value="Track">Track (90d) Only</option>
        </select>
        <select id="serviceFilter" class="filter-select" onchange="filterTable()">
            <option value="ALL">All Services</option>
            <option value="http">HTTP / Web</option>
            <option value="ssh">SSH</option>
            <option value="domain">DNS / BIND</option>
            <option value="ftp">FTP</option>
            <option value="postgresql">PostgreSQL</option>
            <option value="mysql">MySQL</option>
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
            {% for item in aggregated_items %}
            <tr data-decision="{{ item.highest_decision }}" data-service="{{ item.service_name.lower() }}">
                <td>
                    <span class="badge badge-{{ item.highest_decision_css }}">{{ item.highest_decision_display }}</span><br>
                    <div style="font-size:10px; margin-top:6px; color:#64748b;">SLA: {{ item.remediation_sla_days }}d</div>
                </td>
                <td><strong>{{ item.service_name }}</strong><br><span style="font-size:11px; color:#64748b;">{{ item.service_version }}</span></td>
                <td>{{ item.target_port }}/{{ item.protocol }}</td>
                <td>
                    <div style="font-weight:600; margin-bottom:4px; font-size:13px;">{{ item.cve_count }} Vulnerabilities Consolidated</div>
                    
                    <div style="font-size:11px; margin-bottom:8px; display:flex; gap:8px; flex-wrap:wrap;">
                        {% if item.decision_counts['Act'] > 0 %}<span style="color:var(--act); font-weight:700;">• {{item.decision_counts['Act']}} Act</span>{% endif %}
                        {% if item.decision_counts['Attend'] > 0 %}<span style="color:var(--attend); font-weight:700;">• {{item.decision_counts['Attend']}} Attend</span>{% endif %}
                        {% if item.decision_counts['Track*'] > 0 %}<span style="color:var(--track-star); font-weight:700;">• {{item.decision_counts['Track*']}} Track (30d)</span>{% endif %}
                        {% if item.decision_counts['Track'] > 0 %}<span style="color:var(--track); font-weight:700;">• {{item.decision_counts['Track']}} Track (90d)</span>{% endif %}
                    </div>

                    {% if item.cve_count > 0 %}
                    <details>
                        <summary><div class="cve-expand-btn">View CVE Log</div></summary>
                        <div class="cve-log-content">
                            {{ item.cve_list_full }}
                        </div>
                    </details>
                    {% endif %}
                </td>
                <td>{{ "Yes (" ~ item.kev_count ~ ")" if item.kev_count > 0 else "None" }}</td>
                <td>{{ "%.2f"|format(item.max_epss * 100) }}%</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<script>
function filterTable() {
    var searchInput = document.getElementById("searchBox");
    var decisionSelect = document.getElementById("decisionFilter");
    var serviceSelect = document.getElementById("serviceFilter");

    var searchVal = searchInput ? searchInput.value.toLowerCase().trim() : "";
    var decisionVal = decisionSelect ? decisionSelect.value : "ALL";
    var serviceVal = serviceSelect ? serviceSelect.value : "ALL";

    var rows = document.querySelectorAll("#backlogTable tbody tr");

    rows.forEach(function(row) {
        var text = row.innerText.toLowerCase();
        var rowDecision = row.getAttribute("data-decision") || "";
        var rowService = row.getAttribute("data-service") || "";

        var matchesSearch = (!searchVal || text.indexOf(searchVal) !== -1);
        var matchesDecision = (decisionVal === "ALL" || rowDecision === decisionVal);
        var matchesService = (serviceVal === "ALL" || rowService.toLowerCase().indexOf(serviceVal.toLowerCase()) !== -1);

        if (matchesSearch && matchesDecision && matchesService) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

function downloadCSV() {
    var rows = document.querySelectorAll("#backlogTable tr");
    var csv = [];
    
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].style.display === "none") continue;
        var row = [];
        var cols = rows[i].querySelectorAll("th, td");
        for (var j = 0; j < cols.length; j++) {
            var rawText = cols[j].innerText;
            // Remove 'View CVE Log' from CSV output
            rawText = rawText.replace('► Expand full CVE log', '').replace('View CVE Log', '');
            var cleanText = rawText.split("\r\n").join(" ").split("\n").join(" ").split("\r").join(" ");
            cleanText = cleanText.replace(/"/g, '""').trim();
            row.push('"' + cleanText + '"');
        }
        csv.push(row.join(","));
    }
    
    var crlf = String.fromCharCode(13) + String.fromCharCode(10);
    var csvBlob = new Blob([csv.join(crlf)], { type: "text/csv;charset=utf-8;" });
    var downloadUrl = window.URL.createObjectURL(csvBlob);
    var link = document.createElement("a");
    link.href = downloadUrl;
    link.download = "vuln2risk_remediation_backlog.csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
}
</script>
</body>
</html>
"""

    @staticmethod
    def _get_layman_impact(service_name: str) -> str:
        s = (service_name or "").lower()
        if "ftp" in s:
            return "Attackers can bypass authentication to execute arbitrary commands or steal files."
        elif "http" in s or "web" in s:
            return "Attackers can send crafted web requests to force the server to reveal data or execute unauthorized code."
        elif "ssh" in s:
            return "Attackers can exploit weaknesses in key exchange to intercept administrative connections or enumerate accounts."
        elif "domain" in s or "dns" in s or "bind" in s:
            return "Flaws allow attackers to crash the domain resolver or poison routing, knocking services offline."
        elif "postgres" in s or "sql" in s:
            return "Attackers can abuse database query interfaces to bypass access controls or alter confidential records."
        else:
            return "Allows an unauthenticated remote attacker to disrupt system availability or escalate privileges."

    @classmethod
    def generate_html_report(cls, findings: List[Finding], output_path: str = "vuln2risk_report.html") -> str:
        if not findings:
            return ""

        service_rollups = {}

        for f in findings:
            decision_val = f.ssvc_decision.value
            key = f"{f.target_host}:{f.target_port}-{f.service_name}"
            
            if key not in service_rollups:
                service_rollups[key] = {
                    "target_host": f.target_host,
                    "target_port": f.target_port,
                    "protocol": f.protocol,
                    "service_name": f.service_name or "Unknown Service",
                    "service_version": f.service_version or "Unknown Version",
                    "cves": set(),
                    "max_cvss": 0.0,
                    "max_epss": 0.0,
                    "kev_count": 0,
                    "highest_decision": decision_val,
                    "layman_impact": cls._get_layman_impact(f.service_name),
                    "remediation_sla_days": f.remediation_sla_days,
                    "decision_counts": {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
                }
            
            sr = service_rollups[key]
            sr["decision_counts"][decision_val] += 1
            
            if f.cve_id:
                sr["cves"].add(f.cve_id)
            if f.cvss_base and f.cvss_base > sr["max_cvss"]:
                sr["max_cvss"] = f.cvss_base
            if f.epss_score and f.epss_score > sr["max_epss"]:
                sr["max_epss"] = f.epss_score
            if f.is_in_cisa_kev:
                sr["kev_count"] += 1
            
            priority_map = {"Act": 4, "Attend": 3, "Track*": 2, "Track": 1}
            if priority_map.get(decision_val, 0) > priority_map.get(sr["highest_decision"], 0):
                sr["highest_decision"] = decision_val
                sr["remediation_sla_days"] = f.remediation_sla_days

        aggregated_items = []
        rollup_summary = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
        
        for item in service_rollups.values():
            item["cve_count"] = len(item["cves"])
            cve_list = sorted(list(item["cves"]))
            item["cve_list_display"] = ", ".join(cve_list[:3]) + (f" (+{len(cve_list)-3} more)" if len(cve_list) > 3 else "")
            item["cve_list_full"] = ", ".join(cve_list)
            
            # Formatted Naming
            if item["highest_decision"] == "Track*":
                item["highest_decision_display"] = "Track (30d)"
                item["highest_decision_css"] = "track-star"
            elif item["highest_decision"] == "Track":
                item["highest_decision_display"] = "Track (90d)"
                item["highest_decision_css"] = "track"
            else:
                item["highest_decision_display"] = item["highest_decision"]
                item["highest_decision_css"] = item["highest_decision"].lower()
                
            rollup_summary[item["highest_decision"]] += 1
            aggregated_items.append(item)

        def get_risk_score(item):
            decision_weight = 0 if item["highest_decision"] == "Act" else 1
            epss = -(item.get("max_epss") or 0.0)
            cvss = -(item.get("max_cvss") or 0.0)
            kev = -item["kev_count"]
            return (decision_weight, kev, epss, cvss)

        aggregated_items.sort(key=get_risk_score)
        spotlight_items = [item for item in aggregated_items if item["highest_decision"] in ["Act", "Attend"]][:5]

        template = Template(cls.HTML_TEMPLATE)
        rendered = template.render(
            target_host=findings[0].target_host if findings else "Unknown",
            is_internet_facing=findings[0].is_internet_facing if findings else False,
            criticality=findings[0].asset_criticality.value if findings else "Medium",
            total_findings=len(findings),
            summary=rollup_summary,
            spotlight_items=spotlight_items,
            aggregated_items=aggregated_items
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        return output_path