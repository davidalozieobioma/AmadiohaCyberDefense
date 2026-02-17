"""Master CLI for Amadioha Cyber Defense toolkit."""

import argparse
import sys
from . import network_scanner, log_analyzer, threat_intel
from rich.console import Console

console = Console()


def cmd_scan(args):
    """Run network scanner."""
    profiles = {
        "fast": {"workers": 200, "timeout": 0.3},
        "balanced": {"workers": 50, "timeout": 0.2},
        "safe": {"workers": 20, "timeout": 0.5},
    }

    profile = profiles.get(args.profile, profiles["balanced"])
    workers = args.workers if args.workers is not None else profile["workers"]
    timeout = args.timeout if args.timeout is not None else profile["timeout"]

    open_ports = network_scanner.scan_range_concurrent(
        args.target, args.start, args.end, timeout, workers
    )
    if args.out:
        try:
            with open(args.out, "w") as fh:
                for p in open_ports:
                    fh.write(f"{p}\n")
            console.print(f"[green]Wrote {len(open_ports)} open ports to {args.out}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to write output: {e}[/red]")


def cmd_analyze(args):
    """Run log analyzer."""
    results = log_analyzer.analyze_log(args.log_file)
    if results:
        log_analyzer.display_results(results)
        if args.out:
            try:
                with open(args.out, "w") as fh:
                    for ip, count in sorted(results.items(), key=lambda x: x[1], reverse=True):
                        fh.write(f"{ip},{count}\n")
                console.print(f"[green]Wrote analysis to {args.out}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to write output: {e}[/red]")


def cmd_intel(args):
    """Run threat intelligence lookup."""
    intel_data = threat_intel.lookup_ip(args.ip)
    threat_intel.display_ip_intel(args.ip, intel_data)


def cmd_report(args):
    """Generate integrated security report."""
    console.print("[bold cyan]Amadioha Security Report Generation[/bold cyan]\n")

    # Step 1: Network Scan
    console.print("[bold yellow]1. Running network scan...[/bold yellow]")
    profiles = {
        "fast": {"workers": 200, "timeout": 0.3},
        "balanced": {"workers": 50, "timeout": 0.2},
        "safe": {"workers": 20, "timeout": 0.5},
    }
    profile = profiles.get(args.profile, profiles["balanced"])
    workers = args.scan_workers if args.scan_workers is not None else profile["workers"]
    timeout = args.scan_timeout if args.scan_timeout is not None else profile["timeout"]

    open_ports = network_scanner.scan_range_concurrent(
        args.target, args.scan_start, args.scan_end, timeout, workers
    )
    console.print(f"[green]✓ Found {len(open_ports)} open ports[/green]\n")

    # Step 2: Log Analysis
    console.print("[bold yellow]2. Analyzing auth logs...[/bold yellow]")
    log_results = log_analyzer.analyze_log(args.log_file)
    if log_results:
        console.print(f"[green]✓ Found {len(log_results)} unique attacking IPs[/green]\n")
    else:
        console.print("[yellow]No suspicious activity detected[/yellow]\n")
        log_results = {}

    # Step 3: Threat Intelligence Enrichment
    console.print("[bold yellow]3. Enriching with threat intelligence...[/bold yellow]")
    threat_summary = []
    if log_results:
        from rich.table import Table
        table = Table(title="Integrated Security Report — Brute Force Attacks with Intelligence")
        table.add_column("IP Address", style="cyan")
        table.add_column("Attempts", style="magenta")
        table.add_column("Risk Level", style="red")
        table.add_column("Reputation", style="yellow")

        for ip, count in sorted(log_results.items(), key=lambda x: x[1], reverse=True):
            intel_data = threat_intel.lookup_ip(ip)
            risk_level = "🔴 CRITICAL" if intel_data["reputation_score"] > 80 else \
                         "🟠 HIGH" if intel_data["reputation_score"] > 60 else \
                         "🟡 MEDIUM" if intel_data["reputation_score"] > 40 else \
                         "🟢 LOW"

            table.add_row(
                ip,
                str(count),
                risk_level,
                f"{intel_data['reputation_score']}/100"
            )
            threat_summary.append({
                "ip": ip,
                "attempts": count,
                "score": intel_data["reputation_score"],
                "threat_type": intel_data["threat_type"]
            })

        console.print(table)
        console.print("[green]✓ Threat intelligence enriched\n[/green]")

    # Step 4: Save Report
    if args.out:
        try:
            with open(args.out, "w") as fh:
                fh.write("=== AMADIOHA SECURITY REPORT ===\n\n")
                fh.write(f"Target: {args.target}\n")
                fh.write(f"Log File: {args.log_file}\n")
                fh.write(f"Report Generated: {__import__('datetime').datetime.now().isoformat()}\n\n")

                fh.write("NETWORK SCAN RESULTS\n")
                fh.write(f"Open Ports Found: {len(open_ports)}\n")
                if open_ports:
                    fh.write(f"Ports: {', '.join(map(str, open_ports))}\n\n")

                fh.write("BRUTE FORCE ATTACKS\n")
                for threat in threat_summary:
                    fh.write(f"  IP: {threat['ip']}\n")
                    fh.write(f"    Attempts: {threat['attempts']}\n")
                    fh.write(f"    Threat Type: {threat['threat_type']}\n")
                    fh.write(f"    Reputation Score: {threat['score']}/100\n\n")

            console.print(f"[green]✓ Report saved to {args.out}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save report: {e}[/red]")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Amadioha Cyber Defense — Integrated Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  amadioha scan --target 192.168.1.1 --profile fast
  amadioha analyze --log-file /var/log/auth.log
  amadioha intel --ip 185.220.101.1
  amadioha report --target 192.168.1.1 --log-file sample_auth.log --out report.txt

For help on a specific command:
  amadioha scan --help
  amadioha analyze --help
  amadioha intel --help
  amadioha report --help
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scanner subcommand
    scan_parser = subparsers.add_parser("scan", help="Network port scanner")
    scan_parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname")
    scan_parser.add_argument("--start", type=int, default=1, help="Start port")
    scan_parser.add_argument("--end", type=int, default=1024, help="End port")
    scan_parser.add_argument(
        "--profile",
        choices=[
            "fast",
            "balanced",
            "safe"],
        default="balanced",
        help="Scan profile")
    scan_parser.add_argument("--workers", type=int, default=None, help="Override workers count")
    scan_parser.add_argument("--timeout", type=float, default=None, help="Override timeout")
    scan_parser.add_argument("--out", help="Output file for open ports")
    scan_parser.set_defaults(func=cmd_scan)

    # Log analyzer subcommand
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze auth logs for brute-force attacks")
    analyze_parser.add_argument("--log-file", required=True, help="Path to auth.log file")
    analyze_parser.add_argument("--out", help="Output file for results (CSV format)")
    analyze_parser.set_defaults(func=cmd_analyze)

    # Threat intelligence subcommand
    intel_parser = subparsers.add_parser("intel", help="Look up IP threat intelligence")
    intel_parser.add_argument("--ip", required=True, help="IP address to lookup")
    intel_parser.set_defaults(func=cmd_intel)

    # Report subcommand (integrated workflow)
    report_parser = subparsers.add_parser("report", help="Generate integrated security report")
    report_parser.add_argument("--target", default="127.0.0.1", help="Target IP for scan")
    report_parser.add_argument("--log-file", required=True, help="Path to auth.log file")
    report_parser.add_argument("--scan-start", type=int, default=1, help="Start port for scan")
    report_parser.add_argument("--scan-end", type=int, default=1024, help="End port for scan")
    report_parser.add_argument(
        "--profile",
        choices=[
            "fast",
            "balanced",
            "safe"],
        default="balanced",
        help="Scan profile")
    report_parser.add_argument(
        "--scan-workers",
        type=int,
        default=None,
        help="Override scan workers")
    report_parser.add_argument(
        "--scan-timeout",
        type=float,
        default=None,
        help="Override scan timeout")
    report_parser.add_argument("--out", help="Output file for report")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
