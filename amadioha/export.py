"""Export functionality for scan results and analyses."""

import json
import csv
from datetime import datetime
from io import StringIO
from typing import List, Dict, Optional


def export_scan_to_json(scan: Dict) -> str:
    """Export a network scan result to JSON format."""
    export_data = {
        "type": "network_scan",
        "timestamp": scan.get("timestamp", datetime.now().isoformat()),
        "target": scan.get("target"),
        "port_range": {
            "start": scan.get("start_port"),
            "end": scan.get("end_port")
        },
        "profile": scan.get("profile"),
        "results": {
            "open_ports": scan.get("open_ports", []),
            "total_ports_scanned": (scan.get("end_port", 0) - scan.get("start_port", 0) + 1),
            "total_open": len(scan.get("open_ports", []))
        }
    }
    return json.dumps(export_data, indent=2)


def export_scan_to_csv(scan: Dict) -> str:
    """Export a network scan result to CSV format."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(["Timestamp", "Target", "Port", "Service", "Status"])

    for port in scan.get("open_ports", []):
        writer.writerow([
            scan.get("timestamp", datetime.now().isoformat()),
            scan.get("target"),
            port,
            "Service",  # Can be enhanced with port_services mapping
            "Open"
        ])

    return output.getvalue()


def export_analysis_to_json(analysis: Dict) -> str:
    """Export a log analysis result to JSON format."""
    export_data = {
        "type": "log_analysis",
        "timestamp": analysis.get("timestamp", datetime.now().isoformat()),
        "log_file": analysis.get("log_file"),
        "results": {
            "total_attacking_ips": analysis.get("total_ips", 0),
            "threats": analysis.get("threats", [])
        }
    }
    return json.dumps(export_data, indent=2)


def export_analysis_to_csv(analysis: Dict) -> str:
    """Export a log analysis result to CSV format."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(["IP Address", "Attempts", "Reputation Score",
                    "Threat Type", "Known for Attacks"])

    for threat in analysis.get("threats", []):
        writer.writerow([
            threat.get("ip"),
            threat.get("attempts"),
            threat.get("reputation_score"),
            threat.get("threat_type"),
            threat.get("known_for_attacks", False)
        ])

    return output.getvalue()


def export_threat_intel_to_json(ip: str, intel_data: Dict) -> str:
    """Export threat intelligence data to JSON format."""
    export_data = {
        "type": "threat_intelligence",
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip,
        "intelligence": intel_data
    }
    return json.dumps(export_data, indent=2)


def export_threat_intel_to_csv(ip: str, intel_data: Dict) -> str:
    """Export threat intelligence data to CSV format."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(["Attribute", "Value"])
    for key, value in intel_data.items():
        writer.writerow([key, value])

    return output.getvalue()


def export_multiple_scans_to_json(scans: List[Dict]) -> str:
    """Export multiple scan results to JSON format."""
    export_data = {
        "type": "network_scans_batch",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(scans),
        "scans": scans
    }
    return json.dumps(export_data, indent=2)


def export_multiple_analyses_to_json(analyses: List[Dict]) -> str:
    """Export multiple analysis results to JSON format."""
    export_data = {
        "type": "log_analyses_batch",
        "timestamp": datetime.now().isoformat(),
        "total_analyses": len(analyses),
        "analyses": analyses
    }
    return json.dumps(export_data, indent=2)


def generate_html_report(scan: Optional[Dict] = None, analysis: Optional[Dict] = None) -> str:
    """Generate an HTML report for scan and/or analysis results."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Amadioha Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .report { background: white; padding: 20px; border-radius: 8px; }
            h1 { color: #0d6efd; border-bottom: 2px solid #0d6efd; padding-bottom: 10px; }
            h2 { color: #0dcaf0; margin-top: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #0d6efd; color: white; }
            tr:nth-child(even) { background: #f9f9f9; }
            .stats { display: flex; gap: 20px; margin: 20px 0; }
            .stat-box { background: #0d6efd; color: white; padding: 15px; border-radius: 8px; flex: 1; }
            .stat-number { font-size: 24px; font-weight: bold; }
            .timestamp { color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="report">
            <h1>🛡️ Amadioha Cyber Defense Report</h1>
            <p class="timestamp">Generated: """ + datetime.now().isoformat() + """</p>
    """

    if scan:
        html += f"""
            <h2>Network Scan Results</h2>
            <div class="stats">
                <div class="stat-box">
                    <div>Open Ports</div>
                    <div class="stat-number">{len(scan.get('open_ports', []))}</div>
                </div>
                <div class="stat-box">
                    <div>Target</div>
                    <div class="stat-number">{scan.get('target')}</div>
                </div>
            </div>
            <table>
                <tr><th>Port</th><th>Status</th></tr>
        """
        for port in scan.get("open_ports", []):
            html += f"<tr><td>{port}</td><td>Open</td></tr>"
        html += "</table>"

    if analysis:
        html += f"""
            <h2>Log Analysis Results</h2>
            <div class="stats">
                <div class="stat-box">
                    <div>Attacking IPs</div>
                    <div class="stat-number">{analysis.get('total_ips', 0)}</div>
                </div>
            </div>
            <table>
                <tr><th>IP Address</th><th>Attempts</th><th>Threat Type</th></tr>
        """
        for threat in analysis.get("threats", []):
            html += f"""
                <tr>
                    <td>{threat.get('ip')}</td>
                    <td>{threat.get('attempts')}</td>
                    <td>{threat.get('threat_type')}</td>
                </tr>
            """
        html += "</table>"

    html += """
        </div>
    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    # Test export functionality
    test_scan = {
        "timestamp": datetime.now().isoformat(),
        "target": "192.168.1.1",
        "start_port": 1,
        "end_port": 1024,
        "profile": "balanced",
        "open_ports": [22, 80, 443]
    }

    print("JSON Export:")
    print(export_scan_to_json(test_scan))
