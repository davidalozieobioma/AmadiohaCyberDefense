"""PDF report generation module."""

from datetime import datetime
from typing import Dict, List


def generate_html_report(
        scan_data: Dict,
        analysis_data: Dict = None,
        website_scans: List[Dict] = None) -> str:
    """Generate a comprehensive HTML report that can be printed to PDF."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Amadioha Security Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            header {{
                border-bottom: 3px solid #007bff;
                margin-bottom: 30px;
                padding-bottom: 20px;
            }}
            h1 {{
                color: #007bff;
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            h2 {{
                color: #0056b3;
                font-size: 1.8em;
                margin-top: 30px;
                margin-bottom: 15px;
                border-left: 4px solid #007bff;
                padding-left: 15px;
            }}
            h3 {{
                color: #333;
                font-size: 1.2em;
                margin-top: 15px;
                margin-bottom: 10px;
            }}
            .timestamp {{
                color: #666;
                font-size: 0.95em;
                margin-top: 10px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th {{
                background-color: #007bff;
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: 600;
            }}
            td {{
                padding: 10px 12px;
                border-bottom: 1px solid #ddd;
            }}
            tr:hover {{
                background-color: #f9f9f9;
            }}
            .summary-box {{
                background-color: #e7f3ff;
                border-left: 4px solid #0056b3;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
            }}
            .threat-critical {{
                background-color: #f8d7da;
                color: #721c24;
            }}
            .threat-high {{
                background-color: #fff3cd;
                color: #856404;
            }}
            .threat-medium {{
                background-color: #d1ecf1;
                color: #0c5460;
            }}
            .metric {{
                display: inline-block;
                background: #f0f0f0;
                padding: 15px 25px;
                margin: 10px 10px 10px 0;
                border-radius: 4px;
                min-width: 200px;
            }}
            .metric-label {{
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                margin-bottom: 5px;
            }}
            .metric-value {{
                color: #007bff;
                font-size: 1.8em;
                font-weight: bold;
            }}
            .port-list {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 10px;
                margin: 15px 0;
            }}
            .port-item {{
                background: #f0f0f0;
                padding: 10px;
                border-radius: 4px;
                text-align: center;
                border: 1px solid #ddd;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                text-align: center;
                color: #999;
                font-size: 0.9em;
            }}
            .page-break {{
                page-break-after: always;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Amadioha Security Report</h1>
                <p class="timestamp">Generated: {timestamp}</p>
            </header>
    """

    # Network Scan Summary
    if scan_data:
        html += f"""
        <h2>Network Scan Summary</h2>
        <div class="summary-box">
            <h3>Target: {scan_data.get('target', 'N/A')}</h3>
            <p>Profile: <strong>{scan_data.get('profile', 'N/A')}</strong></p>
            <p>Scan Range: <strong>{scan_data.get('port_range', {}).get('start', '?')}-{scan_data.get('port_range', {}).get('end', '?')}</strong></p>
        </div>

        <h3>Open Ports Detected</h3>
        <div class="port-list">
        """

        open_ports = scan_data.get('results', {}).get('open_ports', [])
        if open_ports:
            for port in open_ports:
                html += f'<div class="port-item">Port {port}</div>'
        else:
            html += '<p>No open ports detected</p>'

        html += """
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
        """

        results = scan_data.get('results', {})
        html += f'<div class="metric"><div class="metric-label">Ports Scanned</div><div class="metric-value">{
            results.get(
                "total_ports_scanned",
                0)}</div></div>'
        html += f'<div class="metric"><div class="metric-label">Open Ports</div><div class="metric-value">{
            results.get(
                "total_open",
                0)}</div></div>'
        html += f'<div class="metric"><div class="metric-label">Closed Ports</div><div class="metric-value">{
            results.get(
                "total_ports_scanned",
                0) -
            results.get(
                "total_open",
                0)}</div></div>'

        html += """</div>"""

    # Analysis Summary
    if analysis_data:
        html += f"""
        <div class="page-break"></div>
        <h2>Log Analysis Summary</h2>
        <div class="summary-box">
            <h3>Log File: {analysis_data.get('log_file', 'N/A')}</h3>
            <p>Total IPs Analyzed: <strong>{analysis_data.get('total_ips', 0)}</strong></p>
        </div>

        <h3>Threats Detected</h3>
        <table>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Count</th>
                <th>Details</th>
            </tr>
        """

        threats = analysis_data.get('threats', [])
        if threats:
            for threat in threats:
                severity = threat.get('severity', 'medium').lower()
                threat_class = f"threat-{severity}"
                html += f"""
                <tr class="{threat_class}">
                    <td>{threat.get('type', 'Unknown')}</td>
                    <td>{severity.upper()}</td>
                    <td>{threat.get('count', 1)}</td>
                    <td>{threat.get('description', 'N/A')}</td>
                </tr>
                """
        else:
            html += '<tr><td colspan="4">No threats detected</td></tr>'

        html += """</table>"""

    # Website Security Summary
    if website_scans:
        html += f"""
        <div class="page-break"></div>
        <h2>Website Security Analysis</h2>
        <p>Analyzed {len(website_scans)} website(s) for security and legitimacy.</p>

        <table>
            <tr>
                <th>URL</th>
                <th>Score</th>
                <th>Status</th>
                <th>SSL</th>
                <th>Threats</th>
            </tr>
        """

        for scan in website_scans:
            score = scan.get('legitimacy_score', 0)
            if score >= 80:
                status = '✓ Safe'
            elif score >= 40:
                status = '⚠ Suspicious'
            else:
                status = '✗ Dangerous'

            ssl_status = '✓ Valid' if scan.get('ssl_valid') else '✗ Invalid'
            threat_count = len(scan.get('phishing_patterns', []))

            html += f"""
            <tr>
                <td>{scan.get('url', 'N/A')}</td>
                <td>{score}/100</td>
                <td>{status}</td>
                <td>{ssl_status}</td>
                <td>{threat_count}</td>
            </tr>
            """

        html += """</table>"""

    # Footer
    html += """
        <div class="footer">
            <p>Amadioha Cyber Defense - Confidential Security Report</p>
            <p>This report contains sensitive security information and should be handled accordingly.</p>
        </div>
        </div>
    </body>
    </html>
    """

    return html


def generate_pdf_from_html(html_content: str, filename: str = None) -> bytes:
    """
    Convert HTML to PDF.
    Note: Requires weasyprint or similar library
    For now, returns HTML as a string that can be printed to PDF by browser.
    """
    try:
        from weasyprint import HTML
        import io

        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
    except ImportError:
        # Fallback: return HTML as bytes for browser printing
        return html_content.encode('utf-8')


def export_report_to_pdf(scan_data: Dict = None, analysis_data: Dict = None,
                         website_scans: List[Dict] = None) -> Dict:
    """Export comprehensive report as PDF."""
    try:
        # Generate HTML
        html = generate_html_report(scan_data, analysis_data, website_scans)

        # Try to convert to PDF
        pdf_content = generate_pdf_from_html(html)

        filename = f"SecurityReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        return {
            "success": True,
            "filename": filename,
            "content_type": "application/pdf",
            "data": pdf_content
        }
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test report generation
    test_scan = {
        "target": "192.168.1.1",
        "profile": "balanced",
        "port_range": {"start": 1, "end": 1024},
        "results": {
            "total_ports_scanned": 1024,
            "total_open": 3,
            "open_ports": [22, 80, 443]
        }
    }

    html = generate_html_report(test_scan)
    print("HTML Report generated successfully")
    print(f"Length: {len(html)} characters")
