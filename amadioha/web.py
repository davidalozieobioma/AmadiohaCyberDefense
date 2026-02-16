"""Web dashboard for Amadioha Cyber Defense toolkit."""

from flask import Flask, render_template, request, jsonify
import json
from datetime import datetime
from . import network_scanner, log_analyzer, threat_intel

app = Flask(__name__, template_folder='templates', static_folder='static')

# Store results in memory (in production, use a database)
results = {
    "scans": [],
    "analyses": [],
    "reports": []
}


@app.route('/')
def dashboard():
    """Main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for network scanning."""
    try:
        data = request.json
        target = data.get('target', '127.0.0.1')
        start = int(data.get('start', 1))
        end = int(data.get('end', 1024))
        profile = data.get('profile', 'balanced')
        
        profiles = {
            "fast": {"workers": 200, "timeout": 0.3},
            "balanced": {"workers": 50, "timeout": 0.2},
            "safe": {"workers": 20, "timeout": 0.5},
        }
        
        profile_config = profiles.get(profile, profiles["balanced"])
        workers = profile_config["workers"]
        timeout = profile_config["timeout"]
        
        open_ports = network_scanner.scan_range_concurrent(
            target, start, end, timeout, workers
        )
        
        scan_result = {
            "id": len(results["scans"]) + 1,
            "target": target,
            "start": start,
            "end": end,
            "profile": profile,
            "open_ports": sorted(open_ports),
            "timestamp": datetime.now().isoformat(),
            "status": "completed"
        }
        
        results["scans"].append(scan_result)
        return jsonify(scan_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for log analysis."""
    try:
        data = request.json
        log_file = data.get('log_file', 'sample_auth.log')
        
        log_results = log_analyzer.analyze_log(log_file)
        
        if not log_results:
            return jsonify({"error": "No results found or file not found"}), 400
        
        # Enrich with threat intelligence
        enriched = []
        for ip, count in sorted(log_results.items(), key=lambda x: x[1], reverse=True):
            intel = threat_intel.lookup_ip(ip)
            enriched.append({
                "ip": ip,
                "attempts": count,
                "reputation_score": intel["reputation_score"],
                "threat_type": intel["threat_type"],
                "known_for_attacks": intel["known_for_attacks"]
            })
        
        analysis_result = {
            "id": len(results["analyses"]) + 1,
            "log_file": log_file,
            "total_ips": len(log_results),
            "threats": enriched,
            "timestamp": datetime.now().isoformat(),
            "status": "completed"
        }
        
        results["analyses"].append(analysis_result)
        return jsonify(analysis_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/intel', methods=['POST'])
def api_intel():
    """API endpoint for threat intelligence lookup."""
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({"error": "IP required"}), 400
        
        intel_data = threat_intel.lookup_ip(ip)
        
        risk_level = "🔴 CRITICAL" if intel_data["reputation_score"] > 80 else \
                     "🟠 HIGH" if intel_data["reputation_score"] > 60 else \
                     "🟡 MEDIUM" if intel_data["reputation_score"] > 40 else \
                     "🟢 LOW"
        
        return jsonify({
            "ip": ip,
            "risk_level": risk_level,
            "reputation_score": intel_data["reputation_score"],
            "threat_type": intel_data["threat_type"],
            "abuse_reports": intel_data["abuse_reports"],
            "known_for_attacks": intel_data["known_for_attacks"],
            "confidence": intel_data["confidence"],
            "last_reported": intel_data["last_reported"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/results', methods=['GET'])
def api_results():
    """Get all stored results."""
    return jsonify(results)


@app.route('/api/results/scan', methods=['GET'])
def api_scan_results():
    """Get scan results."""
    return jsonify(results["scans"])


@app.route('/api/results/analysis', methods=['GET'])
def api_analysis_results():
    """Get analysis results."""
    return jsonify(results["analyses"])


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "Amadioha Web Dashboard"})


def run_server(host='127.0.0.1', port=5000, debug=False):
    """Run the Flask development server."""
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server(debug=True)
