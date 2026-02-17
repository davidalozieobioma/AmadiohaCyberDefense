"""Analytics module for dashboard statistics and threat analysis."""

from datetime import datetime, timedelta
from typing import Dict, List
from amadioha import database


def get_scan_statistics() -> Dict:
    """Get network scan statistics."""
    try:
        scans = database.get_scan_history(limit=1000)

        if not scans:
            return {
                "total_scans": 0,
                "total_open_ports": 0,
                "average_open_ports": 0,
                "most_common_ports": [],
                "scans_by_profile": {}
            }

        total_open = 0
        port_counts = {}
        profile_counts = {}

        for scan in scans:
            open_ports = scan.get('open_ports', [])
            total_open += len(open_ports)

            for port in open_ports:
                port_counts[port] = port_counts.get(port, 0) + 1

            profile = scan.get('profile', 'unknown')
            profile_counts[profile] = profile_counts.get(profile, 0) + 1

        # Most common ports
        most_common = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_scans": len(scans),
            "total_open_ports": total_open,
            "average_open_ports": total_open / len(scans) if scans else 0,
            "most_common_ports": [{"port": p[0], "count": p[1]} for p in most_common],
            "scans_by_profile": profile_counts
        }
    except Exception as e:
        print(f"Error getting scan statistics: {e}")
        return {}


def get_threat_statistics() -> Dict:
    """Get threat analysis statistics."""
    try:
        analyses = database.get_analysis_history(limit=1000)

        if not analyses:
            return {
                "total_analyses": 0,
                "total_threats_detected": 0,
                "high_severity_threats": 0,
                "threat_types": {},
                "average_threats_per_log": 0
            }

        total_threats = 0
        high_severity = 0
        threat_types = {}

        for analysis in analyses:
            threats = analysis.get('threats', [])
            total_threats += len(threats)

            for threat in threats:
                threat_type = threat.get('type', 'Unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

                if threat.get('severity') == 'high':
                    high_severity += 1

        return {
            "total_analyses": len(analyses),
            "total_threats_detected": total_threats,
            "high_severity_threats": high_severity,
            "threat_types": threat_types,
            "average_threats_per_log": total_threats / len(analyses) if analyses else 0
        }
    except Exception as e:
        print(f"Error getting threat statistics: {e}")
        return {}


def get_website_security_stats() -> Dict:
    """Get website security scan statistics."""
    try:
        website_scans = database.get_website_scan_history(limit=1000)

        if not website_scans:
            return {
                "total_scans": 0,
                "safe_websites": 0,
                "suspicious_websites": 0,
                "dangerous_websites": 0,
                "average_legitimacy_score": 0,
                "ssl_usage": 0
            }

        safe = 0
        suspicious = 0
        dangerous = 0
        total_score = 0
        ssl_count = 0

        for scan in website_scans:
            score = scan.get('legitimacy_score', 0)
            total_score += score

            if score >= 80:
                safe += 1
            elif score >= 40:
                suspicious += 1
            else:
                dangerous += 1

            if scan.get('ssl_valid'):
                ssl_count += 1

        return {
            "total_scans": len(website_scans),
            "safe_websites": safe,
            "suspicious_websites": suspicious,
            "dangerous_websites": dangerous,
            "average_legitimacy_score": total_score / len(website_scans) if website_scans else 0,
            "ssl_usage_percentage": (ssl_count / len(website_scans) * 100) if website_scans else 0
        }
    except Exception as e:
        print(f"Error getting website stats: {e}")
        return {}


def get_dashboard_summary() -> Dict:
    """Get comprehensive dashboard summary."""
    return {
        "scan_stats": get_scan_statistics(),
        "threat_stats": get_threat_statistics(),
        "website_stats": get_website_security_stats(),
        "timestamp": datetime.now().isoformat()
    }


def get_threat_timeline(days: int = 30) -> List[Dict]:
    """Get threat detection timeline for the past N days."""
    try:
        analyses = database.get_analysis_history(limit=10000)

        # Group by date
        timeline = {}
        cutoff_date = datetime.now() - timedelta(days=days)

        for analysis in analyses:
            timestamp_str = analysis.get('timestamp', '')
            if not timestamp_str:
                continue

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp < cutoff_date:
                    continue

                date_key = timestamp.strftime('%Y-%m-%d')
                threats = analysis.get('threats', [])
                threat_count = len(threats)

                if date_key not in timeline:
                    timeline[date_key] = 0
                timeline[date_key] += threat_count
            except BaseException:
                continue

        # Convert to sorted list
        result = [
            {"date": date, "threats": count}
            for date, count in sorted(timeline.items())
        ]

        return result
    except Exception as e:
        print(f"Error getting threat timeline: {e}")
        return []


def get_top_ports_at_risk() -> List[Dict]:
    """Get ports with the most vulnerability issues."""
    try:
        scans = database.get_scan_history(limit=1000)
        port_vuln_count = {}

        for scan in scans:
            open_ports = scan.get('open_ports', [])
            for port in open_ports:
                vulns = database.get_vulnerabilities_by_port(port)
                if vulns:
                    port_vuln_count[port] = port_vuln_count.get(port, 0) + len(vulns)

        # Sort by vulnerability count
        sorted_ports = sorted(port_vuln_count.items(), key=lambda x: x[1], reverse=True)

        return [
            {"port": port, "vulnerability_count": count}
            for port, count in sorted_ports[:20]
        ]
    except Exception as e:
        print(f"Error getting top vulnerable ports: {e}")
        return []


if __name__ == "__main__":
    summary = get_dashboard_summary()
    print(f"Dashboard Summary: {summary}")
