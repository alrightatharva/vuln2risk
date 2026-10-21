import argparse
import json
import os
import sys
import socket
import csv
from datetime import datetime
from dataclasses import asdict
from enum import Enum

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding='utf-8')
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from parsers.nmap import NmapParser
from parsers.nuclei import NucleiParser
from parsers.openvas import OpenVASParser
from core.enricher import EnrichmentEngine
from ssvc.decision import SSVCEngine
from reporters.generator import ReportGenerator
from core.models import AssetCriticality
from core.inventory import AssetInventory
from enrichment.nvd import NVDEngine
from enrichment.exploit import ExploitEngine

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

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
    parser.add_argument("--inventory", help="Path to Asset Inventory JSON file (supporting Host & CPE matching)", type=str)
    parser.add_argument("--proactive-nvd", action='store_true', help="Poll NVD API 2.0 to catch zero-days / unpatched CVEs on CPEs")
    parser.add_argument("--sync-exploitdb", action='store_true', help="Download latest Exploit-DB vulnerability mapping CSV into local cache")
    parser.add_argument("--report-id", default=default_report, help="Custom ID for the generated files", type=str)
    parser.add_argument("--criticality", choices=['Low', 'Medium', 'High', 'Critical'], default='Medium', help="Global Asset Criticality fallback")
    parser.add_argument("--internet-facing", action='store_true', help="Global flag if assets are internet exposed")
    parser.add_argument("--csv", action='store_true', help="Export findings to CSV")
    parser.add_argument("--pdf", action='store_true', help="Export HTML report to PDF")
    args = parser.parse_args()

    if not any([args.nmap, args.nuclei, args.openvas]):
        console.print("[bold red][-] Error:[/bold red] You must provide at least one scan file.")
        return

    console.print(Panel.fit("[bold blue]Vuln2Risk[/bold blue] | Vulnerability Prioritization Pipeline", border_style="blue", box=box.ROUNDED))

    all_findings = []
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        if args.sync_exploitdb:
            task_edb = progress.add_task("[cyan]Syncing Exploit-DB catalog...", start=False)
            success = ExploitEngine.sync_exploitdb()
            if success:
                progress.update(task_edb, description="[green]✔ Exploit-DB catalog synced successfully")
            else:
                progress.update(task_edb, description="[yellow]⚠ Exploit-DB sync failed (offline or network error, using fallback)")

        task_ingest = progress.add_task("[cyan]Ingesting scanner data...", start=False)
        if args.nmap: all_findings.extend(NmapParser.parse(args.nmap))
        if args.nuclei: all_findings.extend(NucleiParser.parse(args.nuclei))
        if args.openvas: all_findings.extend(OpenVASParser.parse(args.openvas))
        progress.update(task_ingest, description=f"[green]✔ Ingested {len(all_findings)} raw findings")

        task_dedup = progress.add_task("[cyan]Deduplicating cross-scanner findings...", start=False)
        unique_findings = {}
        for f in all_findings:
            key = f"{f.target_host}_{f.target_port}_{f.cve_id or f.title}"
            if key not in unique_findings:
                unique_findings[key] = f
            else:
                existing = unique_findings[key]
                if not existing.cpe and f.cpe:
                    existing.cpe = f.cpe
                if f.cpes:
                    existing.cpes = list(dict.fromkeys(existing.cpes + f.cpes))
        findings = list(unique_findings.values())
        progress.update(task_dedup, description=f"[green]✔ Deduplicated down to {len(findings)} unique findings")

        if args.proactive_nvd:
            task_nvd = progress.add_task("[cyan]Proactively polling NVD API 2.0 for CPE zero-days...", start=False)
            proactive_findings = NVDEngine.discover_unpatched_cves(findings)
            if proactive_findings:
                findings.extend(proactive_findings)
            progress.update(task_nvd, description=f"[green]✔ Proactive NVD polling complete (+{len(proactive_findings)} CVEs)")

        task_enrich = progress.add_task("[cyan]Enriching with Threat Intel & EOL Lifecycle...", start=False)
        criticality_enum = AssetCriticality[args.criticality]
        findings = EnrichmentEngine.enrich(findings, is_internet_facing=args.internet_facing, asset_criticality=criticality_enum)
        progress.update(task_enrich, description="[green]✔ Threat Intelligence, EOL & Exploit enrichment complete")

        task_ssvc = progress.add_task("[cyan]Mapping Assets (Host & CPE) & Calculating SLAs...", start=False)
        inventory = AssetInventory.load_from_file(args.inventory)

        for f in findings:
            meta = inventory.match(f, default_criticality=criticality_enum, default_internet_facing=args.internet_facing)
            f.asset_criticality = meta.criticality
            f.is_internet_facing = meta.internet_facing
            f.ssvc_decision = SSVCEngine.evaluate(f)
            
        progress.update(task_ssvc, description="[green]✔ SSVC Prioritization complete")

    # Compute component rollups using the exact same logic as the report
    consolidated_components = ReportGenerator.consolidate_components(findings)
    comp_summary = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for c in consolidated_components:
        comp_summary[c['worst_decision']] += 1

    raw_summary = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for f in findings:
        raw_summary[f.ssvc_decision.value] += 1

    console.print("")
    
    act_findings = [f for f in findings if f.ssvc_decision.value == "Act"]
    if act_findings:
        top_threat = sorted(act_findings, key=lambda x: x.epss_score or 0.0, reverse=True)[0]
        
        factors = f"{'[bold green]✔[/bold green]' if top_threat.is_in_cisa_kev else '[dim]✖[/dim]'} CISA KEV Listed\n"
        if top_threat.has_public_exploit and not top_threat.is_in_cisa_kev:
            exploit_text = top_threat.exploit_references[0] if top_threat.exploit_references else "Weaponized Exploit"
            factors += f"[bold red]✔[/bold red] Exploit: {exploit_text}\n"
        if top_threat.is_eol:
            factors += f"[bold red]⚠[/bold red] End-of-Life: {top_threat.eol_cycle or 'Unsupported'}\n"
        factors += f"[bold green]✔[/bold green] EPSS Score: [bold]{(top_threat.epss_score or 0.0) * 100:.1f}%[/bold]\n"
        factors += f"{'[bold green]✔[/bold green]' if top_threat.is_internet_facing else '[dim]✖[/dim]'} Internet Facing\n"
        factors += f"[bold green]✔[/bold green] Asset: {top_threat.asset_criticality.value}"

        verdict = f"\n[bold white]SSVC Decision:[/bold white]\n[bold red]► {top_threat.ssvc_decision.value.upper()}[/bold red]\n\n"
        verdict += f"[bold white]Remediation SLA:[/bold white]\n[bold red]► {top_threat.remediation_sla_days} Days[/bold red]"

        grid = Table.grid(padding=(0, 2))
        grid.add_row(
            Panel.fit(factors, title="[yellow]Risk Factors[/yellow]", border_style="yellow", box=box.ROUNDED),
            Panel.fit(verdict, title="[red]Verdict[/red]", border_style="red", box=box.ROUNDED)
        )

        spotlight = Panel.fit(
            grid,
            title=f"[bold red]🚨 Priority Spotlight: {top_threat.cve_id or top_threat.title}[/bold red]",
            border_style="red",
            box=box.HEAVY
        )
        console.print(spotlight)

    console.print("")
    table = Table(title="Actionable Prioritization Summary", show_header=True, header_style="bold white", box=box.ROUNDED)
    table.add_column("Decision Tier", style="bold")
    table.add_column("SLA", justify="center")
    table.add_column("Components (Rollup)", justify="right", style="cyan bold")
    table.add_column("Raw CVEs", justify="right", style="dim")

    table.add_row("[red]ACT (Immediate Action)[/red]", "48 Hours", str(comp_summary['Act']), str(raw_summary['Act']))
    table.add_row("[yellow]ATTEND (Prioritize)[/yellow]", "14 Days", str(comp_summary['Attend']), str(raw_summary['Attend']))
    table.add_row("[blue]TRACK* (Next Sprint)[/blue]", "30 Days", str(comp_summary['Track*']), str(raw_summary['Track*']))
    table.add_row("[bright_black]TRACK (Standard Cycle)[/bright_black]", "90 Days", str(comp_summary['Track']), str(raw_summary['Track']))
    table.add_section()
    table.add_row("[bold white]Total Consolidated[/bold white]", "-", f"[bold cyan]{len(consolidated_components)}[/bold cyan]", f"[dim]{len(findings)}[/dim]")
    console.print(table)

    os.makedirs("reports", exist_ok=True)
    json_path = os.path.join("reports", f"findings_{args.report_id}.json")
    html_path = os.path.join("reports", f"vuln2risk_report_{args.report_id}.html")

    with open(json_path, "w", encoding="utf-8") as out:
        json.dump([asdict(f) for f in findings], out, indent=2, cls=EnumEncoder)

    ReportGenerator.generate_html_report(findings, output_path=html_path)

    console.print(f"\n[bold green]✔ JSON Ledger saved to:[/bold green] {json_path}")
    console.print(f"[bold green]✔ HTML report saved to:[/bold green] {html_path}")

    if args.csv:
        csv_path = os.path.join("reports", f"findings_{args.report_id}.csv")
        
        clean_findings = []
        for f in findings:
            row = asdict(f)
            row['asset_criticality'] = row['asset_criticality'].value if isinstance(row['asset_criticality'], Enum) else row['asset_criticality']
            row['ssvc_decision'] = row['ssvc_decision'].value if row['ssvc_decision'] else None
            row['status'] = row['status'].value if isinstance(row['status'], Enum) else row['status']
            
            # Preserve original newlines and format but handle None values safely
            for field in ['justification', 'raw_evidence', 'description', 'cpe', 'eol_cycle', 'eol_date']:
                row[field] = str(row[field]) if row.get(field) is not None else ""
            
            # Format list fields cleanly for CSV export
            if isinstance(row.get('cpes'), list):
                row['cpes'] = ", ".join(row['cpes'])
            if isinstance(row.get('exploit_references'), list):
                row['exploit_references'] = "; ".join(row['exploit_references'])

            clean_findings.append(row)

        # Ensure utf-8-sig (BOM) is used so Excel recognizes the UTF-8 encoding on Windows
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as csvfile:
            if clean_findings:
                # QUOTE_ALL ensures Excel treats the multiline newlines as a single cell block
                writer = csv.DictWriter(csvfile, fieldnames=clean_findings[0].keys(), quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows(clean_findings)
        console.print(f"[bold green]✔ CSV Ledger saved to:[/bold green] {csv_path}")

    if args.pdf:
        pdf_path = os.path.join("reports", f"vuln2risk_report_{args.report_id}.pdf")
        try:
            import pdfkit
            pdfkit.from_file(html_path, pdf_path)
            console.print(f"[bold green]✔ PDF report saved to:[/bold green] {pdf_path}")
        except ImportError:
            console.print("[yellow]⚠ PDF generation skipped: 'pdfkit' module is not installed. Run 'pip install pdfkit' to enable.[/yellow]")
        except Exception as e:
            console.print(f"[red]⚠ PDF generation failed: {e}[/red]")
            
    console.print("")

if __name__ == "__main__":
    main()
