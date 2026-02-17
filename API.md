# Amadioha Cyber Defense - API Documentation

## Overview

The Amadioha Cyber Defense API provides a comprehensive suite of endpoints for network security operations, threat intelligence, vulnerability assessment, and system administration.

**Base URL:** `http://localhost:5000` (development) or `http://your-domain:8080` (production)

**Authentication:** All endpoints except `/login`, `/register`, and `/health` require session-based authentication. Admin endpoints require admin role.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Network Scanning](#network-scanning)
3. [Log Analysis](#log-analysis)
4. [Threat Intelligence](#threat-intelligence)
5. [Vulnerability Management](#vulnerability-management)
6. [Results & History](#results--history)
7. [Export & Reporting](#export--reporting)
8. [Alerts & Notifications](#alerts--notifications)
9. [Webhooks](#webhooks)
10. [Scheduled Scans](#scheduled-scans)
11. [Billing & Credits](#billing--credits)
12. [Analytics](#analytics)
13. [Admin Operations](#admin-operations)

---


### Register User
**POST** `/api/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Response:** `200 OK`
```json
{
  "message": "User created successfully",
  "user_id": 123
}
```

---
### Login
**POST** `/api/auth/login`

Authenticate and create session.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

```json
{
  "message": "Login successful",
  "user": {
    "id": 123,
    "username": "string",
    "email": "string",
    "role": "user"
  }
}
```

---

### Logout
**POST** `/api/auth/logout`

End current session.

**Response:** `200 OK`
{
  "message": "Logged out successfully"
}
```

---
### Get Current User
**GET** `/api/auth/me`

Get information about the currently authenticated user.

**Response:** `200 OK`
```json
{
  "id": 123,
  "username": "string",
  "email": "string",
  "role": "user",
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

### MFA Setup
**POST** `/api/auth/mfa/setup`

Initialize multi-factor authentication for current user.

**Response:** `200 OK`
```json
{
  "qr_code": "data:image/png;base64,...",
  "secret": "BASE32SECRET"
}
```

---

### Enable MFA
**POST** `/api/auth/mfa/enable`

Enable MFA after verification.

**Request Body:**
```json
{
  "token": "123456"
}
```

---

## Network Scanning

### Perform Network Scan
**POST** `/api/scan`

Execute a network port scan on target host.

**Request Body:**
```json
{
  "target": "192.168.1.1",
  "start_port": 1,
  "end_port": 1000,
  "profile": "quick",
  "workers": 10,
  "timeout": 0.5
}
```

**Parameters:**
- `target` (required): IP address or hostname
- `start_port` (default: 1): Starting port number
- `end_port` (default: 65535): Ending port number
- `profile`: Scan profile - "quick", "thorough", "custom"
- `workers` (default: 10): Number of concurrent workers
- `timeout` (default: 0.5): Socket timeout in seconds

**Response:** `200 OK`
```json
{
  "scan_id": 456,
  "target": "192.168.1.1",
  "open_ports": [22, 80, 443],
  "total_scanned": 1000,
  "duration": 12.34
}
```

---

## Log Analysis

### Analyze Log File
**POST** `/api/analyze`

Analyze authentication logs for suspicious activity.

**Request Body:**
```json
{
  "log_file": "/path/to/auth.log",
  "threshold": 5
}
```

**Parameters:**
- `log_file` (required): Path to log file
- `threshold` (default: 5): Minimum failed attempts to flag as threat

**Response:** `200 OK`
```json
{
  "analysis_id": 789,
  "total_ips": 15,
  "threats": [
    {
      "ip": "203.0.113.45",
      "count": 10,
      "severity": "high"
    }
  ]
}
```

---

## Threat Intelligence

### Check IP Reputation
**POST** `/api/intel`

Query threat intelligence for IP address reputation.

**Request Body:**
```json
{
  "ip": "185.220.101.1"
}
```

**Response:** `200 OK`
```json
{
  "ip": "185.220.101.1",
  "reputation_score": 85,
  "threat_type": "tor_exit_node",
  "abuse_reports": 23,
  "known_for_attacks": true,
  "confidence": 0.95
}
```

---

### Scan URL/Website
**POST** `/api/scan-url`

Analyze URL for phishing and malicious content.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:** `200 OK`
```json
{
  "url": "https://example.com",
  "legitimacy_score": 92,
  "status": "safe",
  "ssl_valid": true,
  "phishing_patterns": []
}
```

---

### Batch URL Scan
**POST** `/api/scan-urls`

Scan multiple URLs simultaneously.

**Request Body:**
```json
{
  "urls": [
    "https://example.com",
    "https://test.com"
  ]
}
```

---

## Vulnerability Management

### Get Vulnerabilities by Port
**GET** `/api/vulnerabilities/:port`

Retrieve known vulnerabilities for a specific port.

**Parameters:**
- `port`: Port number (path parameter)

**Response:** `200 OK`
```json
{
  "port": 22,
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-12345",
      "cvss_score": 7.5,
      "severity": "high",
      "description": "SSH vulnerability description",
      "remediation": "Update to version X.Y.Z"
    }
  ]
}
```

---

### Assess Vulnerabilities
**POST** `/api/vulnerability/assess`

Perform vulnerability assessment on scan results.

**Request Body:**
```json
{
  "scan_id": 456
}
```

---

### Get Top Vulnerabilities
**GET** `/api/vulnerability/top`

Get most critical vulnerabilities across all scans.

**Query Parameters:**
- `limit` (default: 10): Number of results

---

### Get Remediation Steps
**POST** `/api/vulnerability/remediation`

Get remediation steps for specific vulnerability.

**Request Body:**
```json
{
  "cve_id": "CVE-2021-12345"
}
```

---

## Results & History

### Get Latest Results
**GET** `/api/results`

Retrieve most recent scan and analysis results.

---

### Get Latest Scan Results
**GET** `/api/results/scan`

Get the most recent network scan results.

---

### Get Latest Analysis Results
**GET** `/api/results/analyze`

Get the most recent log analysis results.

---

### Get Scan History
**GET** `/api/history/scans`

Retrieve historical scan records.

**Query Parameters:**
- `limit` (default: 50): Number of records

**Response:** `200 OK`
```json
{
  "scans": [
    {
      "id": 456,
      "target": "192.168.1.1",
      "open_ports": [22, 80, 443],
      "timestamp": "2026-02-17T10:30:00Z"
    }
  ]
}
```

---

### Get Analysis History
**GET** `/api/history/analyses`

Retrieve historical log analysis records.

---

### Get Website Scan History
**GET** `/api/history/website-scans`

Retrieve historical website scan records.

---

## Export & Reporting

### Export Scan Report
**GET** `/api/export/scan/:scan_id`

Export scan results as text report.

**Parameters:**
- `scan_id`: Scan ID (path parameter)

**Response:** `200 OK` (text/plain)

---

### Export Analysis Report
**GET** `/api/export/analysis/:analysis_id`

Export analysis results as text report.

---

### Generate PDF Report
**POST** `/api/export/pdf`

Generate comprehensive PDF report.

**Request Body:**
```json
{
  "scan_id": 456,
  "analysis_id": 789,
  "include_charts": true,
  "include_recommendations": true
}
```

**Response:** `200 OK` (application/pdf)

---

## Alerts & Notifications

### Configure Email Alerts
**POST** `/api/email/configure`

Configure email notification settings.

**Request Body:**
```json
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "username": "user@example.com",
  "password": "app_password",
  "from_address": "alerts@example.com"
}
```

---

### Send Email Alert
**POST** `/api/email/alert`

Send email alert for specific threat.

**Request Body:**
```json
{
  "recipient": "admin@example.com",
  "ip_address": "203.0.113.45",
  "threat_type": "brute_force",
  "severity": "high"
}
```

---

### Get Email Alert History
**GET** `/api/email/alerts`

Retrieve sent email alert history.

---

## Webhooks

### Configure Webhook
**POST** `/api/webhook/configure`

Set up webhook for real-time notifications.

**Request Body:**
```json
{
  "url": "https://hooks.example.com/alerts",
  "webhook_type": "slack",
  "events": ["threat_detected", "scan_complete"]
}
```

---

### Get Webhook History
**GET** `/api/webhook/alerts`

Retrieve webhook delivery history.

---

### Test Webhook
**POST** `/api/webhook/send-test`

Send test payload to configured webhook.

**Request Body:**
```json
{
  "webhook_id": 123
}
```

---

## Scheduled Scans

### Create Scan Schedule
**POST** `/api/schedule/create`

Schedule recurring scans.

**Request Body:**
```json
{
  "target": "192.168.1.1",
  "scan_type": "port_scan",
  "schedule_time": "02:00",
  "frequency": "daily",
  "enabled": true
}
```

**Frequency options:** "hourly", "daily", "weekly", "monthly"

---

### List Scheduled Scans
**GET** `/api/schedule/list`

Get all scheduled scan jobs.

---

### Get Schedule Status
**GET** `/api/schedule/status`

Check status of scheduled scans.

---

### Execute Schedule
**POST** `/api/schedule/execute`

Manually trigger a scheduled scan.

**Request Body:**
```json
{
  "schedule_id": 123
}
```

---

## Analytics

### Get Analytics Summary
**GET** `/api/analytics/summary`

Get dashboard analytics summary.

**Response:** `200 OK`
```json
{
  "total_scans": 150,
  "total_threats": 23,
  "critical_alerts": 5,
  "avg_scan_duration": 15.4
}
```

---

### Get Threat Timeline
**GET** `/api/analytics/threat-timeline`

Get threat detection timeline data.

**Query Parameters:**
- `days` (default: 7): Number of days

---

### Get Top Ports
**GET** `/api/analytics/top-ports`

Get most commonly open ports across scans.

---

### Get Network Topology
**GET** `/api/topology/network`

Get network topology visualization data.

---

## Admin Operations

**Note:** All admin endpoints require admin role.

### Get System Statistics
**GET** `/api/admin/stats`

Get comprehensive system statistics.

**Response:** `200 OK`
```json
{
  "total_users": 42,
  "total_scans": 1337,
  "total_threats": 89,
  "active_sessions": 5,
  "database_size_mb": 128.5
}
```

---

### Get Earnings Summary
**GET** `/api/admin/earnings`

Get revenue, credits sold, and recent payments.

**Response:** `200 OK`
```json
{
  "summary": {
    "total_revenue_cents": 5000,
    "total_credits_sold": 100,
    "total_transactions": 4
  },
  "payments": [
    {
      "id": 12,
      "user_id": 3,
      "username": "alice",
      "amount_cents": 500,
      "currency": "usd",
      "credits": 10,
      "status": "paid",
      "created_at": "2026-02-17T10:30:00Z"
    }
  ],
  "currency": "usd"
}
```

---

### List All Users
**GET** `/api/admin/users`

Get list of all registered users.

---

### Create User (Admin)
**POST** `/api/admin/create-user`

Create new user with specified role.

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "role": "user"
}
```

**Roles:** "user", "admin", "analyst", "viewer"

---

### Delete User
**DELETE** `/api/admin/users/:user_id`

Remove user from system.

---

### Update User Role
**PUT** `/api/admin/users/:user_id/role`

Change user's role.

**Request Body:**
```json
{
  "role": "admin"
}
```

---

### Get Audit Log
**GET** `/api/admin/audit-log`

Retrieve system audit logs.

**Query Parameters:**
- `limit` (default: 100): Number of records

---

### Get Activity Logs
**GET** `/api/admin/activity`

Get user activity logs.

---

### Get System Settings
**GET** `/api/admin/settings`

Retrieve system configuration.

---

### Update System Settings
**PUT** `/api/admin/settings`

Update system configuration.

**Request Body:**
```json
{
  "setting_name": "value"
}
```

---

### Get Threat Logs
**GET** `/api/admin/threats`

Retrieve all threat detection logs.

**Query Parameters:**
- `severity`: Filter by severity ("low", "medium", "high", "critical")
- `limit`: Number of records

---

### Manage IP Access Lists
**GET** `/api/admin/ip-access`

Get IP whitelist/blacklist.

**POST** `/api/admin/ip-access`

Add IP to access list.

**Request Body:**
```json
{
  "ip_address": "192.168.1.100",
  "list_type": "whitelist",
  "reason": "Trusted internal IP"
}
```

**DELETE** `/api/admin/ip-access/:ip_address`

Remove IP from access list.

---

### Manage API Keys
**GET** `/api/admin/api-keys/:user_id`

Get API keys for user.

**POST** `/api/admin/api-keys`

Create new API key.

**DELETE** `/api/admin/api-keys/:key_id`

Revoke API key.

---

### Get User Usage
**GET** `/api/admin/usage/:user_id`

Get usage statistics for user.

---

### Set Usage Limits
**PUT** `/api/admin/usage-limits/:user_id`

Set rate limits for user.

**Request Body:**
```json
{
  "max_concurrent": 5,
  "max_monthly": 1000
}
```

---

### Get System Logs
**GET** `/api/admin/logs`

Retrieve system error and debug logs.

---

### Manage Departments
**GET** `/api/admin/departments`

List all departments.

**POST** `/api/admin/departments`

Create new department.

**GET** `/api/admin/departments/:dept_id/members`

Get department members.

**POST** `/api/admin/departments/:dept_id/members`

Add user to department.

---

### Manage Security Alerts
**GET** `/api/admin/alerts/:user_id`

Get alerts for user.

**POST** `/api/admin/alerts`

Create security alert.

---

### Database Backups
**GET** `/api/admin/backups`

List database backups.

**POST** `/api/admin/backups`

Create database backup.

---

## Data Import

### Import Logs
**POST** `/api/import/logs`

Import external log files.

**Request Body:**
```json
{
  "file_path": "/path/to/logs",
  "format": "syslog"
}
```

---

### Import CSV
**POST** `/api/import/csv`

Import data from CSV.

---

### Get Import Formats
**GET** `/api/import/formats`

List supported import formats.

---

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
  "error": "Invalid request parameters"
}
```

### 401 Unauthorized
```json
{
  "error": "Unauthorized"
}
```

### 403 Forbidden
```json
{
  "error": "Forbidden"
}
```

### 404 Not Found
```json
{
  "error": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "message": "Detailed error message"
}
```

---

## Rate Limiting

API requests are subject to rate limiting based on user role:

- **Free tier:** 100 requests/hour
- **Standard:** 1,000 requests/hour
- **Admin:** Unlimited

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1676635200
```

---

## Webhooks Payload Format

Webhook notifications are sent as POST requests with the following format:

```json
{
  "event": "threat_detected",
  "timestamp": "2026-02-17T10:30:00Z",
  "data": {
    "ip": "203.0.113.45",
    "severity": "high",
    "threat_type": "brute_force",
    "details": {}
  }
}
```

---

## Support

For API support, contact: support@amadioha.security

Documentation Version: 1.0.0  
Last Updated: February 17, 2026
