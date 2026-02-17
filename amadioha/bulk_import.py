"""Bulk import module for processing multiple log files."""

import csv
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime
from amadioha import database, log_analyzer


def parse_csv_log_file(file_path: str) -> List[Dict]:
    """Parse a CSV log file."""
    entries = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            if reader.fieldnames:
                for row in reader:
                    entries.append(row)
    except Exception as e:
        print(f"Error parsing CSV file: {e}")
    
    return entries


def parse_text_log_file(file_path: str) -> List[str]:
    """Parse a text log file line by line."""
    lines = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log file: {e}")
    
    return lines


def extract_ips_from_log(file_path: str) -> Dict:
    """Extract and analyze IPs from a log file."""
    import re
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_counts = {}
    
    lines = parse_text_log_file(file_path)
    
    for line in lines:
        ips = re.findall(ip_pattern, line)
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    return {
        "total_unique_ips": len(ip_counts),
        "ips": ip_counts
    }


def analyze_bulk_logs(file_paths: List[str]) -> Dict:
    """Analyze multiple log files."""
    results = []
    total_ips = set()
    total_threats = 0
    
    for file_path in file_paths:
        try:
            # Analyze individual file
            analysis = log_analyzer.analyze_auth_log(file_path)
            
            # Save to database
            threat_list = analysis.get('threats', [])
            save_id = database.save_analysis(
                log_file=file_path,
                total_ips=analysis.get('unique_ips', 0),
                threats=threat_list
            )
            
            # Track unique IPs
            for threat in threat_list:
                if 'ip' in threat:
                    total_ips.add(threat['ip'])
            
            total_threats += len(threat_list)
            
            results.append({
                "file": file_path,
                "analysis_id": save_id,
                "threats": len(threat_list),
                "unique_ips": analysis.get('unique_ips', 0),
                "status": "success"
            })
        except Exception as e:
            results.append({
                "file": file_path,
                "error": str(e),
                "status": "failed"
            })
    
    return {
        "files_processed": len(file_paths),
        "successful": sum(1 for r in results if r.get('status') == 'success'),
        "failed": sum(1 for r in results if r.get('status') == 'failed'),
        "total_unique_ips": len(total_ips),
        "total_threats": total_threats,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }


def bulk_import_logs(directory_path: str, pattern: str = "*.log") -> Dict:
    """Import all matching log files from a directory."""
    try:
        directory = Path(directory_path)
        
        if not directory.exists():
            return {
                "success": False,
                "error": f"Directory not found: {directory_path}"
            }
        
        # Find matching files
        log_files = list(directory.glob(pattern))
        
        if not log_files:
            return {
                "success": True,
                "files_found": 0,
                "message": f"No files matching pattern {pattern}"
            }
        
        # Analyze all files
        file_paths = [str(f) for f in log_files]
        results = analyze_bulk_logs(file_paths)
        
        return {
            "success": True,
            **results
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def import_csv_logs(csv_file_path: str, ip_column: str = 'source_ip',
                    threat_column: str = 'threat_type') -> Dict:
    """Import threat data from CSV file."""
    try:
        entries = parse_csv_log_file(csv_file_path)
        
        if not entries:
            return {
                "success": False,
                "error": "CSV file is empty or could not be parsed"
            }
        
        ips_analyzed = set()
        threats_processed = 0
        
        for entry in entries:
            ip = entry.get(ip_column)
            threat_type = entry.get(threat_column)
            
            if ip and threat_type:
                ips_analyzed.add(ip)
                threats_processed += 1
        
        # Save analysis
        analysis_id = database.save_analysis(
            log_file=csv_file_path,
            total_ips=len(ips_analyzed),
            threats=[{
                'type': entry.get(threat_column, 'unknown'),
                'ip': entry.get(ip_column),
                'details': str(entry)
            } for entry in entries if entry.get(ip_column)]
        )
        
        return {
            "success": True,
            "file": csv_file_path,
            "analysis_id": analysis_id,
            "ips_analyzed": len(ips_analyzed),
            "threats_processed": threats_processed
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def get_supported_formats() -> Dict:
    """Get information about supported import formats."""
    return {
        "formats": [
            {
                "name": "Text Log Files",
                "extension": ".log",
                "description": "Standard Linux/Unix log files (auth.log, syslog, etc)",
                "parser": "parse_text_log_file"
            },
            {
                "name": "CSV Files",
                "extension": ".csv",
                "description": "Comma-separated threat data",
                "parser": "parse_csv_log_file",
                "columns": ["source_ip", "threat_type", "timestamp"]
            },
            {
                "name": "JSON Lines",
                "extension": ".jsonl",
                "description": "One JSON object per line",
                "parser": "parse_json_lines"
            }
        ]
    }


if __name__ == "__main__":
    # Example usage
    print("Bulk Import Module")
    print(f"Supported formats: {get_supported_formats()}")
