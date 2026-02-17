"""Database module for persisting Amadioha scan results and analyses."""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

DB_PATH = Path(__file__).parent.parent / "amadioha.db"

def init_db():
    """Initialize the database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            start_port INTEGER NOT NULL,
            end_port INTEGER NOT NULL,
            open_ports TEXT NOT NULL,
            profile TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            workers INTEGER,
            timeout REAL
        )
    """)
    
    # Analyses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_file TEXT NOT NULL,
            total_ips INTEGER,
            threats TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # IP Intelligence table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            reputation_score INTEGER,
            threat_type TEXT,
            abuse_reports INTEGER,
            known_for_attacks BOOLEAN,
            confidence REAL,
            last_reported TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Email alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_email TEXT NOT NULL,
            ip_address TEXT,
            threat_type TEXT,
            severity TEXT,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'sent'
        )
    """)
    
    # Website scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS website_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            legitimacy_score INTEGER,
            status TEXT,
            threat_type TEXT,
            phishing_patterns TEXT,
            ssl_valid BOOLEAN,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Vulnerabilities/CVE table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER NOT NULL,
            service_name TEXT,
            cve_id TEXT,
            cvss_score REAL,
            severity TEXT,
            description TEXT,
            remediation TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Webhook alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_url TEXT NOT NULL,
            webhook_type TEXT,
            threat_type TEXT,
            severity TEXT,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'sent',
            response_code INTEGER
        )
    """)
    
    # Scan schedules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT,
            schedule_time TEXT,
            frequency TEXT,
            profile TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_run DATETIME
        )
    """)
    
    # Users table for authentication
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    """)

    # Ensure MFA columns exist
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if "mfa_secret" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    if "mfa_enabled" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0")
    if "mfa_updated" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_updated DATETIME")
    
    conn.commit()
    conn.close()


def save_scan(target: str, start_port: int, end_port: int, open_ports: List[int], 
              profile: str, workers: int, timeout: float) -> int:
    """Save a network scan result to the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    open_ports_json = json.dumps(open_ports)
    cursor.execute("""
        INSERT INTO scans (target, start_port, end_port, open_ports, profile, workers, timeout)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (target, start_port, end_port, open_ports_json, profile, workers, timeout))
    
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def save_analysis(log_file: str, total_ips: int, threats: List[Dict]) -> int:
    """Save a log analysis result to the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    threats_json = json.dumps(threats)
    cursor.execute("""
        INSERT INTO analyses (log_file, total_ips, threats)
        VALUES (?, ?, ?)
    """, (log_file, total_ips, threats_json))
    
    conn.commit()
    analysis_id = cursor.lastrowid
    conn.close()
    return analysis_id


def save_ip_intel(ip: str, reputation_score: int, threat_type: str, abuse_reports: int,
                  known_for_attacks: bool, confidence: float, last_reported: Optional[str]) -> int:
    """Save IP intelligence data to the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO ip_intel (ip_address, reputation_score, threat_type, abuse_reports,
                             known_for_attacks, confidence, last_reported)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip, reputation_score, threat_type, abuse_reports, known_for_attacks, confidence, last_reported))
    
    conn.commit()
    intel_id = cursor.lastrowid
    conn.close()
    return intel_id


def get_scan_history(limit: int = 50) -> List[Dict]:
    """Retrieve scan history from the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, target, start_port, end_port, open_ports, profile, timestamp, workers, timeout
        FROM scans
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "target": row["target"],
            "start_port": row["start_port"],
            "end_port": row["end_port"],
            "open_ports": json.loads(row["open_ports"]),
            "profile": row["profile"],
            "timestamp": row["timestamp"],
            "workers": row["workers"],
            "timeout": row["timeout"]
        })
    
    return results


def get_analysis_history(limit: int = 50) -> List[Dict]:
    """Retrieve analysis history from the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, log_file, total_ips, threats, timestamp
        FROM analyses
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "log_file": row["log_file"],
            "total_ips": row["total_ips"],
            "threats": json.loads(row["threats"]),
            "timestamp": row["timestamp"]
        })
    
    return results


def save_email_alert(recipient_email: str, ip_address: str, threat_type: str, severity: str) -> int:
    """Log an email alert in the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO email_alerts (recipient_email, ip_address, threat_type, severity)
        VALUES (?, ?, ?, ?)
    """, (recipient_email, ip_address, threat_type, severity))
    
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id


def get_email_alert_history(limit: int = 50) -> List[Dict]:
    """Retrieve email alert history."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, recipient_email, ip_address, threat_type, severity, sent_at, status
        FROM email_alerts
        ORDER BY sent_at DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def save_website_scan(url: str, domain: str, legitimacy_score: int, status: str,
                     threat_type: str, phishing_patterns: List[str], ssl_valid: bool) -> int:
    """Save a website scan result to the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    patterns_json = json.dumps(phishing_patterns)
    cursor.execute("""
        INSERT INTO website_scans (url, domain, legitimacy_score, status, threat_type,
                                  phishing_patterns, ssl_valid)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (url, domain, legitimacy_score, status, threat_type, patterns_json, ssl_valid))
    
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_website_scan_history(limit: int = 50) -> List[Dict]:
    """Retrieve website scan history."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, url, domain, legitimacy_score, status, threat_type, phishing_patterns,
               ssl_valid, timestamp
        FROM website_scans
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "legitimacy_score": row["legitimacy_score"],
            "status": row["status"],
            "threat_type": row["threat_type"],
            "phishing_patterns": json.loads(row["phishing_patterns"]),
            "ssl_valid": row["ssl_valid"],
            "timestamp": row["timestamp"]
        })
    
    return results


def save_vulnerability(port: int, service_name: str, cve_id: str, cvss_score: float,
                      severity: str, description: str, remediation: str) -> int:
    """Save a vulnerability/CVE record."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO vulnerabilities (port, service_name, cve_id, cvss_score, severity,
                                     description, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (port, service_name, cve_id, cvss_score, severity, description, remediation))
    
    conn.commit()
    vuln_id = cursor.lastrowid
    conn.close()
    return vuln_id


def get_vulnerabilities_by_port(port: int) -> List[Dict]:
    """Get vulnerabilities associated with a specific port."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, port, service_name, cve_id, cvss_score, severity, description,
               remediation, timestamp
        FROM vulnerabilities
        WHERE port = ?
        ORDER BY cvss_score DESC
    """, (port,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def save_webhook_alert(webhook_url: str, webhook_type: str, threat_type: str,
                      severity: str, response_code: int) -> int:
    """Log a webhook alert."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO webhook_alerts (webhook_url, webhook_type, threat_type, severity,
                                   response_code)
        VALUES (?, ?, ?, ?, ?)
    """, (webhook_url, webhook_type, threat_type, severity, response_code))
    
    conn.commit()
    webhook_id = cursor.lastrowid
    conn.close()
    return webhook_id


def get_webhook_alert_history(limit: int = 50) -> List[Dict]:
    """Retrieve webhook alert history."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, webhook_url, webhook_type, threat_type, severity, sent_at, status,
               response_code
        FROM webhook_alerts
        ORDER BY sent_at DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def save_scan_schedule(target: str, scan_type: str, schedule_time: str, frequency: str,
                      profile: str) -> int:
    """Save a scheduled scan."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scan_schedules (target, scan_type, schedule_time, frequency, profile)
        VALUES (?, ?, ?, ?, ?)
    """, (target, scan_type, schedule_time, frequency, profile))
    
    conn.commit()
    schedule_id = cursor.lastrowid
    conn.close()
    return schedule_id


def get_scan_schedules() -> List[Dict]:
    """Get all scheduled scans."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, target, scan_type, schedule_time, frequency, profile, enabled,
               created_at, last_run
        FROM scan_schedules
        WHERE enabled = 1
        ORDER BY schedule_time
    """)
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def create_user(username: str, password_hash: str, email: str, role: str = 'user') -> int:
    """Create a new user account."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, email, role))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # User already exists


def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
         SELECT id, username, password_hash, email, role, created_at, last_login,
             mfa_secret, mfa_enabled, mfa_updated
        FROM users
        WHERE username = ?
    """, (username,))
    
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
         SELECT id, username, password_hash, email, role, created_at, last_login,
             mfa_secret, mfa_enabled, mfa_updated
        FROM users
        WHERE id = ?
    """, (user_id,))

    row = cursor.fetchone()
    conn.close()

    return dict(row) if row else None


def update_user_last_login(user_id: int):
    """Update user last login timestamp."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (user_id,))
    
    conn.commit()
    conn.close()


def update_user_mfa(user_id: int, mfa_secret: str, mfa_enabled: bool):
    """Update MFA settings for a user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET mfa_secret = ?, mfa_enabled = ?, mfa_updated = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (mfa_secret, int(bool(mfa_enabled)), user_id))

    conn.commit()
    conn.close()


def count_users() -> int:
    """Return total number of users."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_all_users() -> List[Dict]:
    """Get all users from the database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
         SELECT id, username, email, role, created_at, last_login, mfa_secret, 
                mfa_enabled, mfa_updated
        FROM users
        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def delete_user(user_id: int) -> bool:
    """Delete a user by ID."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False


def update_user_role(user_id: int, role: str) -> bool:
    """Update a user's role."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE users
            SET role = ?
            WHERE id = ?
        """, (role, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False


def get_audit_logs(limit: int = 50) -> List[Dict]:
    """Get audit logs. Currently returns a placeholder."""
    # In future, implement actual audit logging table
    init_db()
    return [
        {
            "timestamp": datetime.now().isoformat(),
            "user": "admin",
            "action": "Dashboard accessed",
            "details": "Admin dashboard view"
        }
    ] * min(limit, 5)  # Placeholder


def get_settings() -> Dict:
    """Get system settings. Currently returns defaults."""
    # In future, implement settings table
    return {
        "max_concurrent_scans": 5,
        "session_timeout": 120,
        "logging": "enabled",
        "mfa_required": False
    }


def update_setting(key: str, value) -> bool:
    """Update a system setting. Currently a placeholder."""
    # In future, implement settings persistence
    return True


if __name__ == "__main__":
    init_db()
    print(f"✓ Database initialized at {DB_PATH}")
