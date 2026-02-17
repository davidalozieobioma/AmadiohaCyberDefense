"""Threat Intelligence module for IP reputation and abuse reporting."""

import argparse
from typing import Dict
from rich.console import Console
from rich.panel import Panel

console = Console()

# Mock threat database of known malicious IPs (easily expandable to real APIs)
KNOWN_THREATS = {
    "185.220.101.1": {
        "reputation_score": 92,
        "threat_type": "Tor Exit Node",
        "abuse_reports": 127,
        "last_reported": "2026-02-16",
        "known_for_attacks": True,
        "confidence": 0.98,
    },
    "203.0.113.45": {
        "reputation_score": 85,
        "threat_type": "Brute Force Attacker",
        "abuse_reports": 89,
        "last_reported": "2026-02-15",
        "known_for_attacks": True,
        "confidence": 0.95,
    },
    "198.51.100.22": {
        "reputation_score": 75,
        "threat_type": "Suspicious Activity",
        "abuse_reports": 34,
        "last_reported": "2026-02-14",
        "known_for_attacks": True,
        "confidence": 0.88,
    },
    "192.168.1.50": {
        "reputation_score": 2,
        "threat_type": "Clean",
        "abuse_reports": 0,
        "last_reported": None,
        "known_for_attacks": False,
        "confidence": 0.99,
    },
}


def lookup_ip(ip: str) -> Dict:
    """Look up an IP in the threat database.

    Returns reputation data or a clean profile if not found.
    """
    if ip in KNOWN_THREATS:
        return KNOWN_THREATS[ip]
    else:
        return {
            "reputation_score": 0,
            "threat_type": "Unknown",
            "abuse_reports": 0,
            "last_reported": None,
            "known_for_attacks": False,
            "confidence": 0.5,
        }


def display_ip_intel(ip: str, data: Dict) -> None:
    """Display threat intelligence for an IP in a formatted panel."""

    risk_level = "🔴 CRITICAL" if data["reputation_score"] > 80 else \
                 "🟠 HIGH" if data["reputation_score"] > 60 else \
                 "🟡 MEDIUM" if data["reputation_score"] > 40 else \
                 "🟢 LOW"

    content = f"""
[bold cyan]IP Address:[/bold cyan] {ip}
[bold cyan]Risk Level:[/bold cyan] {risk_level}
[bold cyan]Reputation Score:[/bold cyan] {data['reputation_score']}/100
[bold cyan]Threat Type:[/bold cyan] {data['threat_type']}
[bold cyan]Abuse Reports:[/bold cyan] {data['abuse_reports']}
[bold cyan]Known for Attacks:[/bold cyan] {'✓ Yes' if data['known_for_attacks'] else '✗ No'}
[bold cyan]Confidence:[/bold cyan] {data['confidence'] * 100:.0f}%
[bold cyan]Last Reported:[/bold cyan] {data['last_reported'] or 'Never'}
"""

    panel = Panel(
        content.strip(),
        title="[bold white]Threat Intel Report[/bold white]",
        expand=False)
    console.print(panel)


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence IP Lookup")
    parser.add_argument("--ip", required=True, help="IP address to lookup")
    args = parser.parse_args()

    intel_data = lookup_ip(args.ip)
    display_ip_intel(args.ip, intel_data)


if __name__ == "__main__":
    main()
