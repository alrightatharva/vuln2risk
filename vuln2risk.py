import argparse
import json
import os
import socket
from datetime import datetime
from dataclasses import asdict
from enum import Enum

from parsers.nmap import NmapParser
from parsers.nuclei import NucleiParser
from parsers.openvas import OpenVASParser
from core.enricher import EnrichmentEngine
from ssvc.decision import SSVCEngine
from reporters.generator import ReportGenerator
from core.models import AssetCriticality

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)

def main():
    default_report = f"{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    parser = argparse.ArgumentParser(description="Vuln2Risk: Risk-based Vulnerability Prioritization Pipeline")
    parser.add_argument("--nmap", help="Path to Nmap XML output file", type=str)
    parser.add_argument("--nuclei", help="Path to Nuclei JSONL output file", type=str)
    parser.add_argument("--openvas", help="Path to OpenVAS XML output file", type=str)
    parser.add_argument("--report-id", default=default_report, help="Custom ID for the generated files (defaults to Hostname_Timestamp)", type=str)
    parser.add_argument("--criticality", choices=['Low', 'Medium', 'High', 'Critical'], default='Medium', help="Asset Criticality")
    parser.add_argument("--internet-facing", action='store_true', help="Flag if the asset is exposed to the internet")
    args = parser.parse_args()

    if not any([args.nmap, args.nuclei, args.openvas]):
        console.print("[bold red][-] Error:[/bold red] You must provide at least one scan file (--nmap, --nuclei, or --openvas)")
        return

    console.print(Panel.fit("[bold blue]Vuln2Risk[/bold blue] | Risk-Based Vulnerability Prioritization Pipeline", border_style="blue"))

    all_findings = []
    
    # Dynamic Loading Spinners
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        
        # 1. Ingestion
        task_ingest = progress.add_task("[cyan]Ingesting scanner data...", start=False)
        if args.nmap:
            all_findings.extend(NmapParser.parse(args.nmap))
        if args.nuclei:
            all_findings.extend(NucleiParser.parse(args.nuclei))
        if args.openvas:
            all_findings.extend(OpenVASParser.parse(args.openvas))
        progress.update(task_ingest, description=f"[green]✔ Ingested {len(all_findings)} raw findings")

        # 2. Deduplication
        task_dedup = progress.add_task("[cyan]Deduplicating cross-scanner findings...", start=False)
        unique_findings = {}
        for f in all_findings:
            key = f"{f.target_host}_{f.target_port}_{f.cve_id or f.title}"
            if key not in unique_findings:
                unique_findings[key] = f
        findings = list(unique_findings.values())
        progress.update(task_dedup, description=f"[green]✔ Deduplicated down to {len(findings)} unique findings")

        # 3. Enrichment
        task_enrich = progress.add_task("[cyan]Enriching with CISA KEV & EPSS Threat Intel...", start=False)
        criticality_enum = AssetCriticality[args.criticality]
        findings = EnrichmentEngine.enrich(findings, is_internet_facing=args.internet_facing, asset_criticality=criticality_enum)
        progress.update(task_enrich, description="[green]✔ Threat Intelligence enrichment complete")

        # 4. SSVC Decision Engine
        task_ssvc = progress.add_task("[cyan]Calculating SSVC Remediation SLAs...", start=False)
        summary = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
        for f in findings:
            f.ssvc_decision = SSVCEngine.evaluate(f)
            summary[f.ssvc_decision.value] += 1
        progress.update(task_ssvc, description="[green]✔ SSVC Prioritization complete")

    # Beautiful Output Table
    console.print("")
    table = Table(title="Actionable Findings Summary", show_header=True, header_style="bold white")
    table.add_column("SSVC Decision", style="bold")
    table.add_column("SLA", justify="center")
    table.add_column("Component Count", justify="right", style="cyan bold")

    table.add_row("[red]ACT (Immediate Action)[/red]", "48 Hours", str(summary['Act']))
    table.add_row("[yellow]ATTEND (Prioritize)[/yellow]", "14 Days", str(summary['Attend']))
    table.add_row("[blue]TRACK (Next Sprint)[/blue]", "30 Days", str(summary['Track*']))
    table.add_row("[bright_black]TRACK (Standard Cycle)[/bright_black]", "90 Days", str(summary['Track']))

    console.print(table)

    # 5. Output Management
    os.makedirs("reports", exist_ok=True)
    
    json_path = os.path.join("reports", f"findings_{args.report_id}.json")
    html_path = os.path.join("reports", f"vuln2risk_report_{args.report_id}.html")

    with open(json_path, "w", encoding="utf-8") as out:
        json.dump([asdict(f) for f in findings], out, indent=2, cls=EnumEncoder)

    ReportGenerator.generate_html_report(findings, output_path=html_path)

    console.print(f"\n[bold green]✔ JSON Ledger saved to:[/bold green] {json_path}")
    console.print(f"[bold green]✔ Assessment report generated at:[/bold green] {html_path}\n")

if __name__ == "__main__":
    main()
