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

    # Activity logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Threat logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT,
            ip_address TEXT,
            severity TEXT,
            port INTEGER,
            scan_id INTEGER,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # IP whitelist/blacklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_access_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            list_type TEXT NOT NULL,
            reason TEXT,
            added_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY(added_by) REFERENCES users(id)
        )
    """)

    # API keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            name TEXT,
            permissions TEXT,
            last_used DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Custom roles table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custom_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            permissions TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # User role assignments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(role_id) REFERENCES custom_roles(id)
        )
    """)

    # Usage tracking table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usage_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scans_count INTEGER DEFAULT 0,
            analyses_count INTEGER DEFAULT 0,
            api_calls INTEGER DEFAULT 0,
            bandwidth_mb REAL DEFAULT 0,
            month_year TEXT,
            reset_date DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # System logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT,
            message TEXT,
            component TEXT,
            traceback TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Department/teams table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Team members table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            department_id INTEGER NOT NULL,
            role TEXT,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(department_id) REFERENCES departments(id)
        )
    """)

    # Backup records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backup_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_file TEXT,
            size_mb REAL,
            backup_type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            status TEXT DEFAULT 'completed'
        )
    """)

    # Security alerts configuration table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            user_id INTEGER,
            channel TEXT,
            contact_info TEXT,
            enabled BOOLEAN DEFAULT 1,
            severity_threshold TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Usage limits table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usage_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            max_concurrent_scans INTEGER DEFAULT 5,
            max_monthly_scans INTEGER DEFAULT 100,
            max_api_calls_per_hour INTEGER DEFAULT 100,
            bandwidth_limit_mb INTEGER DEFAULT 5000,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    
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


# ============================================================================
# ACTIVITY LOGGING
# ============================================================================

def log_activity(user_id: int, action: str, details: str = "", ip_address: str = "") -> int:
    """Log user activity."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO activity_logs (user_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    """, (user_id, action, details, ip_address))

    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    return log_id


def get_activity_logs(limit: int = 100) -> List[Dict]:
    """Get activity logs."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, user_id, action, details, ip_address, timestamp
        FROM activity_logs
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# THREAT LOGS
# ============================================================================

def log_threat(threat_type: str, ip_address: str, severity: str, port: int = None, 
               scan_id: int = None, details: str = "") -> int:
    """Log a threat detection."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO threat_logs (threat_type, ip_address, severity, port, scan_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (threat_type, ip_address, severity, port, scan_id, details))

    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    return log_id


def get_threat_logs(limit: int = 100, severity: str = None) -> List[Dict]:
    """Get threat logs, optionally filtered by severity."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if severity:
        cursor.execute("""
            SELECT id, threat_type, ip_address, severity, port, scan_id, details, timestamp
            FROM threat_logs
            WHERE severity = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (severity, limit))
    else:
        cursor.execute("""
            SELECT id, threat_type, ip_address, severity, port, scan_id, details, timestamp
            FROM threat_logs
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# IP ACCESS CONTROL (WHITELIST/BLACKLIST)
# ============================================================================

def add_ip_to_list(ip_address: str, list_type: str, reason: str = "", added_by: int = None) -> int:
    """Add IP to whitelist or blacklist."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO ip_access_control (ip_address, list_type, reason, added_by)
        VALUES (?, ?, ?, ?)
    """, (ip_address, list_type, reason, added_by))

    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return record_id


def remove_ip_from_list(ip_address: str) -> bool:
    """Remove IP from access control lists."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM ip_access_control WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()
    return True


def get_ip_access_list(list_type: str = None) -> List[Dict]:
    """Get IPs in whitelist/blacklist."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if list_type:
        cursor.execute("""
            SELECT id, ip_address, list_type, reason, added_by, created_at
            FROM ip_access_control
            WHERE list_type = ?
            ORDER BY created_at DESC
        """, (list_type,))
    else:
        cursor.execute("""
            SELECT id, ip_address, list_type, reason, added_by, created_at
            FROM ip_access_control
            ORDER BY created_at DESC
        """)

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

def create_api_key(user_id: int, name: str, permissions: str) -> str:
    """Create API key for user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    api_key = secrets.token_urlsafe(32)
    cursor.execute("""
        INSERT INTO api_keys (user_id, api_key, name, permissions)
        VALUES (?, ?, ?, ?)
    """, (user_id, api_key, name, permissions))

    conn.commit()
    conn.close()
    return api_key


def get_user_api_keys(user_id: int) -> List[Dict]:
    """Get API keys for a user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, api_key, name, permissions, last_used, created_at, expires_at
        FROM api_keys
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def revoke_api_key(api_key_id: int) -> bool:
    """Revoke an API key."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM api_keys WHERE id = ?", (api_key_id,))
    conn.commit()
    conn.close()
    return True


# ============================================================================
# SYSTEM LOGS
# ============================================================================

def log_system_event(level: str, message: str, component: str = "", traceback: str = "") -> int:
    """Log system event."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO system_logs (level, message, component, traceback)
        VALUES (?, ?, ?, ?)
    """, (level, message, component, traceback))

    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    return log_id


def get_system_logs(limit: int = 100, level: str = None) -> List[Dict]:
    """Get system logs."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if level:
        cursor.execute("""
            SELECT id, level, message, component, traceback, timestamp
            FROM system_logs
            WHERE level = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (level, limit))
    else:
        cursor.execute("""
            SELECT id, level, message, component, traceback, timestamp
            FROM system_logs
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# USAGE TRACKING & LIMITS
# ============================================================================

def get_user_usage(user_id: int, month_year: str = None) -> Optional[Dict]:
    """Get user usage statistics."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if month_year:
        cursor.execute("""
            SELECT * FROM usage_tracking
            WHERE user_id = ? AND month_year = ?
        """, (user_id, month_year))
    else:
        cursor.execute("""
            SELECT * FROM usage_tracking
            WHERE user_id = ?
            ORDER BY month_year DESC
            LIMIT 1
        """, (user_id,))

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_usage(user_id: int, scans: int = 0, analyses: int = 0, api_calls: int = 0, 
                bandwidth_mb: float = 0) -> bool:
    """Update user usage statistics."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE usage_tracking
        SET scans_count = scans_count + ?,
            analyses_count = analyses_count + ?,
            api_calls = api_calls + ?,
            bandwidth_mb = bandwidth_mb + ?
        WHERE user_id = ?
    """, (scans, analyses, api_calls, bandwidth_mb, user_id))

    conn.commit()
    conn.close()
    return True


def get_user_limits(user_id: int) -> Optional[Dict]:
    """Get usage limits for a user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM usage_limits WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def set_user_limits(user_id: int, max_concurrent: int = 5, max_monthly: int = 100,
                   max_api_calls: int = 100, bandwidth_limit: int = 5000) -> bool:
    """Set usage limits for a user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO usage_limits
        (user_id, max_concurrent_scans, max_monthly_scans, max_api_calls_per_hour, bandwidth_limit_mb)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, max_concurrent, max_monthly, max_api_calls, bandwidth_limit))

    conn.commit()
    conn.close()
    return True


# ============================================================================
# DEPARTMENTS & TEAMS
# ============================================================================

def create_department(name: str, description: str = "") -> int:
    """Create a new department."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO departments (name, description)
            VALUES (?, ?)
        """, (name, description))
        conn.commit()
        dept_id = cursor.lastrowid
        conn.close()
        return dept_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1


def get_all_departments() -> List[Dict]:
    """Get all departments."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM departments ORDER BY name")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_user_to_department(user_id: int, department_id: int, role: str = "") -> bool:
    """Add user to department."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO team_members (user_id, department_id, role)
        VALUES (?, ?, ?)
    """, (user_id, department_id, role))

    conn.commit()
    conn.close()
    return True


def get_department_members(department_id: int) -> List[Dict]:
    """Get members of a department."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT tm.id, tm.user_id, tm.role, tm.joined_at, u.username, u.email
        FROM team_members tm
        JOIN users u ON tm.user_id = u.id
        WHERE tm.department_id = ?
        ORDER BY tm.joined_at DESC
    """, (department_id,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# BACKUP MANAGEMENT
# ============================================================================

def create_backup_record(backup_file: str, size_mb: float, backup_type: str = "full") -> int:
    """Create backup record."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO backup_records (backup_file, size_mb, backup_type)
        VALUES (?, ?, ?)
    """, (backup_file, size_mb, backup_type))

    conn.commit()
    backup_id = cursor.lastrowid
    conn.close()
    return backup_id


def get_backup_records(limit: int = 50) -> List[Dict]:
    """Get backup records."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM backup_records
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================================
# SECURITY ALERTS
# ============================================================================

def create_security_alert(alert_type: str, user_id: int, channel: str, 
                         contact_info: str, severity_threshold: str = "HIGH") -> int:
    """Create security alert configuration."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_alerts (alert_type, user_id, channel, contact_info, severity_threshold)
        VALUES (?, ?, ?, ?, ?)
    """, (alert_type, user_id, channel, contact_info, severity_threshold))

    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id


def get_user_alerts(user_id: int) -> List[Dict]:
    """Get security alerts for user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM security_alerts
        WHERE user_id = ? AND enabled = 1
        ORDER BY created_at DESC
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


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
