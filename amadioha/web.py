"""Web dashboard for Amadioha Cyber Defense toolkit."""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from datetime import datetime
from . import network_scanner, log_analyzer, threat_intel
from . import database, port_services, export, email_alerts, website_scanner
from . import auth, webhooks, analytics, pdf_export, vulnerability_db, scheduler, bulk_import
from pathlib import Path
import io
import os
import secrets
try:
    import stripe
except ImportError:
    stripe = None

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get("AMADIOHA_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_PATH='/'
)

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_CURRENCY = os.environ.get("STRIPE_CURRENCY", "usd")
APP_BASE_URL = os.environ.get("AMADIOHA_APP_URL", "").rstrip("/")

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Initialize database
database.init_db()

# Store results in memory (in production, use a database)
results = {
    "scans": [],
    "analyses": [],
    "reports": []
}

# Initialize scheduler
try:
    scan_scheduler = scheduler.start_background_scheduler()
except BaseException:
    pass  # Scheduler not critical


def get_current_user():
    """Get the current authenticated user from session."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = database.get_user_by_id(user_id)
    if not user:
        session.clear()
    return user


def is_admin(user: dict) -> bool:
    """Return True if user has admin role."""
    return bool(user) and user.get('role') == 'admin'


def get_base_url() -> str:
    """Resolve base URL for redirects and external integrations."""
    if APP_BASE_URL:
        return APP_BASE_URL
    return request.host_url.rstrip("/")


@app.before_request
def enforce_authentication():
    """Require authentication for dashboard and all API routes."""
    public_paths = {
        '/login', '/register',
        '/api/auth/login', '/api/auth/register',
        '/health',
        '/api/billing/webhook'
    }

    if request.method == 'OPTIONS':
        return None

    if request.path.startswith('/static/'):
        return None

    if request.path in public_paths:
        return None

    if not session.get('user_id'):
        if request.path.startswith('/api/'):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for('login_page'))

    return None


@app.route('/')
def dashboard():
    """Main dashboard page."""
    return render_template('dashboard.html', current_user=get_current_user())


@app.route('/login')
def login_page():
    """Login and registration page."""
    allow_self_signup = database.count_users() == 0
    return render_template('login.html', allow_self_signup=allow_self_signup)


@app.route('/login', methods=['POST'])
def login_submit():
    """Handle form-based login."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    mfa_code = request.form.get('mfa_code', '').strip()
    success, msg, user_info, mfa_required = auth.login_user(username, password, mfa_code)
    if success:
        session['user_id'] = user_info.get('id')
        return redirect(url_for('dashboard'))

    allow_self_signup = database.count_users() == 0
    return render_template(
        'login.html',
        login_error=msg,
        mfa_required=mfa_required,
        allow_self_signup=allow_self_signup)


@app.route('/register', methods=['POST'])
def register_submit():
    """Handle form-based registration."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')

    if database.count_users() > 0:
        allow_self_signup = database.count_users() == 0
        return render_template(
            'login.html',
            register_error="Account creation is admin-only.",
            allow_self_signup=allow_self_signup)

    success, msg, user_id = auth.register_user(username, password, email, role='admin')
    if success:
        session['user_id'] = user_id
        return redirect(url_for('dashboard'))

    allow_self_signup = database.count_users() == 0
    return render_template('login.html', register_error=msg, allow_self_signup=allow_self_signup)


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for network scanning."""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({"error": "Unauthorized"}), 401
        if not is_admin(current_user):
            if not database.deduct_user_credits(current_user.get('id'), 1):
                balance = database.get_user_credits(current_user.get('id'))
                return jsonify({
                    "error": "Insufficient credits",
                    "balance": balance
                }), 402

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

        # Save to database
        scan_id = database.save_scan(target, start, end, open_ports, profile, workers, timeout)

        # Enrich with port service names
        enriched_ports = port_services.enrich_scan_results(sorted(open_ports))

        scan_result = {
            "id": scan_id,
            "target": target,
            "start": start,
            "end": end,
            "profile": profile,
            "open_ports": sorted(open_ports),
            "enriched_ports": enriched_ports,
            "credits_used": 0 if is_admin(current_user) else 1,
            "credits_remaining": database.get_user_credits(current_user.get('id'))
            if not is_admin(current_user) else None,
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
        sorted_results = sorted(
            log_results.items(), key=lambda x: x[1], reverse=True
        )
        for ip, count in sorted_results:
            intel = threat_intel.lookup_ip(ip)
            enriched.append({
                "ip": ip,
                "attempts": count,
                "reputation_score": intel["reputation_score"],
                "threat_type": intel["threat_type"],
                "known_for_attacks": intel["known_for_attacks"],
                "abuse_reports": intel["abuse_reports"],
                "confidence": intel["confidence"]
            })
            # Save IP intel to database
            database.save_ip_intel(ip, intel["reputation_score"], intel["threat_type"],
                                   intel["abuse_reports"], intel["known_for_attacks"],
                                   intel["confidence"], intel["last_reported"])

        # Save analysis to database
        analysis_id = database.save_analysis(log_file, len(log_results), enriched)

        analysis_result = {
            "id": analysis_id,
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

        score = intel_data["reputation_score"]
        if score > 80:
            risk_level = "🔴 CRITICAL"
        elif score > 60:
            risk_level = "🟠 HIGH"
        elif score > 40:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"

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


@app.route('/api/results/analyze', methods=['GET'])
def api_analyze_results():
    """Get analysis results."""
    return jsonify(results["analyses"])


@app.route('/api/history/scans', methods=['GET'])
def api_scan_history():
    """Get scan history from database."""
    limit = request.args.get('limit', 50, type=int)
    history = database.get_scan_history(limit)
    return jsonify(history)


@app.route('/api/history/analyses', methods=['GET'])
def api_analysis_history():
    """Get analysis history from database."""
    limit = request.args.get('limit', 50, type=int)
    history = database.get_analysis_history(limit)
    return jsonify(history)


@app.route('/api/export/scan/<int:scan_id>', methods=['GET'])
def api_export_scan(scan_id):
    """Export a scan result."""
    format_type = request.args.get('format', 'json')  # json, csv, or html
    history = database.get_scan_history()
    scan = next((s for s in history if s['id'] == scan_id), None)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if format_type == 'csv':
        csv_data = export.export_scan_to_csv(scan)
        return csv_data, 200, {'Content-Disposition': f'attachment; filename=scan_{scan_id}.csv'}
    elif format_type == 'html':
        html_data = export.generate_html_report(scan=scan)
        return html_data, 200, {'Content-Type': 'text/html'}
    else:  # json
        json_data = export.export_scan_to_json(scan)
        headers = {
            'Content-Disposition':
                f'attachment; filename=scan_{scan_id}.json',
            'Content-Type': 'application/json'
        }
        return json_data, 200, headers


@app.route('/api/export/analysis/<int:analysis_id>', methods=['GET'])
def api_export_analysis(analysis_id):
    """Export an analysis result."""
    format_type = request.args.get('format', 'json')  # json, csv, or html
    history = database.get_analysis_history()
    analysis = next((a for a in history if a['id'] == analysis_id), None)

    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404

    if format_type == 'csv':
        csv_data = export.export_analysis_to_csv(analysis)
        return csv_data, 200, {
            'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.csv'}
    elif format_type == 'html':
        html_data = export.generate_html_report(analysis=analysis)
        return html_data, 200, {'Content-Type': 'text/html'}
    else:  # json
        json_data = export.export_analysis_to_json(analysis)
        headers = {
            'Content-Disposition':
                f'attachment; filename=analysis_{analysis_id}.json',
            'Content-Type': 'application/json'
        }
        return json_data, 200, headers


@app.route('/api/email/configure', methods=['POST'])
def api_email_configure():
    """Configure email settings."""
    try:
        data = request.json
        success = email_alerts.configure_email(
            data.get('smtp_server', 'smtp.gmail.com'),
            data.get('smtp_port', 587),
            data.get('sender_email', ''),
            data.get('sender_password', ''),
            data.get('enabled', False)
        )
        if success:
            return jsonify({"status": "configured"})
        else:
            return jsonify({"error": "Failed to save configuration"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/email/alert', methods=['POST'])
def api_email_alert():
    """Send an email alert."""
    try:
        data = request.json
        recipient = data.get('recipient')
        ip = data.get('ip')
        threat_type = data.get('threat_type')

        if not all([recipient, ip, threat_type]):
            return jsonify({"error": "recipient, ip, and threat_type required"}), 400

        intel = threat_intel.lookup_ip(ip)
        success = email_alerts.send_critical_threat_alert(recipient, ip, intel)

        if success:
            return jsonify({"status": "alert_sent"})
        else:
            return jsonify({"error": "Failed to send alert"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/email/alerts', methods=['GET'])
def api_email_alerts():
    """Get email alert history."""
    limit = request.args.get('limit', 50, type=int)
    history = database.get_email_alert_history(limit)
    return jsonify(history)


@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    """API endpoint for website scanning."""
    try:
        data = request.json
        url = data.get('url')

        if not url:
            return jsonify({"error": "URL required"}), 400

        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result = website_scanner.scan_url(url)
        result['threat_summary'] = website_scanner.get_threat_summary(result)
        result['legitimacy_badge'] = website_scanner.get_legitimacy_badge(
            result['legitimacy_score'])

        # Save to database
        scan_id = database.save_website_scan(
            url=url,
            domain=result.get('domain', ''),
            legitimacy_score=result.get('legitimacy_score', 0),
            status=result.get('status', 'Unknown'),
            threat_type=result.get('threat_type', ''),
            phishing_patterns=result.get('phishing_patterns', []),
            ssl_valid=result.get('ssl_valid', False)
        )
        result['scan_id'] = scan_id

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/scan-urls', methods=['POST'])
def api_scan_urls():
    """API endpoint for batch website scanning."""
    try:
        data = request.json
        urls = data.get('urls', [])

        if not urls:
            return jsonify({"error": "URLs required"}), 400

        results = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            result = website_scanner.scan_url(url)
            result['threat_summary'] = website_scanner.get_threat_summary(result)
            result['legitimacy_badge'] = website_scanner.get_legitimacy_badge(
                result['legitimacy_score'])

            # Save to database
            scan_id = database.save_website_scan(
                url=url,
                domain=result.get('domain', ''),
                legitimacy_score=result.get('legitimacy_score', 0),
                status=result.get('status', 'Unknown'),
                threat_type=result.get('threat_type', ''),
                phishing_patterns=result.get('phishing_patterns', []),
                ssl_valid=result.get('ssl_valid', False)
            )
            result['scan_id'] = scan_id

            results.append(result)

        return jsonify({
            "total_scanned": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/history/website-scans', methods=['GET'])
def api_website_scan_history():
    """Get website scan history."""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = database.get_website_scan_history(limit)
        return jsonify({
            "total": len(history),
            "scans": history
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/vulnerabilities/<int:port>', methods=['GET'])
def api_get_vulnerabilities(port):
    """Get vulnerabilities for a specific port."""
    try:
        vulns = database.get_vulnerabilities_by_port(port)
        return jsonify({
            "port": port,
            "total_vulnerabilities": len(vulns),
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/webhook/configure', methods=['POST'])
def api_webhook_configure():
    """Configure webhook alerts."""
    try:
        data = request.json
        webhook_config = {
            "webhook_url": data.get('webhook_url'),
            "webhook_type": data.get('webhook_type', 'slack'),  # slack, discord, custom
            "enabled": data.get('enabled', True)
        }

        # Save to webhook_config.json
        import json
        config_path = Path(__file__).parent.parent / "webhook_config.json"
        with open(config_path, 'w') as f:
            json.dump(webhook_config, f, indent=2)

        return jsonify({"status": "configured"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/webhook/alerts', methods=['GET'])
def api_webhook_alerts():
    """Get webhook alert history."""
    try:
        limit = request.args.get('limit', 50, type=int)
        alerts = database.get_webhook_alert_history(limit)
        return jsonify({
            "total": len(alerts),
            "alerts": alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/schedule/create', methods=['POST'])
def api_create_schedule():
    """Create a scheduled scan."""
    try:
        data = request.json
        schedule_id = database.save_scan_schedule(
            target=data.get('target'),
            scan_type=data.get('scan_type', 'network'),
            schedule_time=data.get('schedule_time'),
            frequency=data.get('frequency', 'daily'),  # daily, weekly, monthly
            profile=data.get('profile', 'balanced')
        )
        return jsonify({"schedule_id": schedule_id, "status": "created"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/schedule/list', methods=['GET'])
def api_list_schedules():
    """Get all active scheduled scans."""
    try:
        schedules = database.get_scan_schedules()
        return jsonify({
            "total": len(schedules),
            "schedules": schedules
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== AUTHENTICATION ENDPOINTS =====

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """User registration endpoint."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if database.count_users() > 0:
            return jsonify({"status": "error", "message": "Account creation is admin-only"}), 403

        success, msg, user_id = auth.register_user(username, password, email, role='admin')

        if success:
            session['user_id'] = user_id
            return jsonify({"status": "success", "user_id": user_id, "message": msg})
        else:
            return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """User login endpoint."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        mfa_code = data.get('mfa_code')
        success, msg, user_info, mfa_required = auth.login_user(username, password, mfa_code)

        if success:
            session['user_id'] = user_info.get('id')
            return jsonify({"status": "success", "user": user_info})
        if mfa_required:
            return jsonify({"status": "mfa_required", "message": msg}), 401
        else:
            return jsonify({"status": "error", "message": msg}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """API logout endpoint."""
    session.clear()
    return jsonify({"status": "success"})


@app.route('/api/admin/create-user', methods=['POST'])
def api_admin_create_user():
    """Create a new user (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'user')

        success, msg, user_id = auth.register_user(username, password, email, role=role)
        if success:
            return jsonify({"status": "success", "user_id": user_id})
        return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/auth/mfa/setup', methods=['POST'])
def api_mfa_setup():
    """Generate and store MFA secret for the current user."""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({"error": "Unauthorized"}), 401

        secret = auth.generate_mfa_secret()
        database.update_user_mfa(current_user['id'], secret, False)

        issuer = "AmadiohaCyberDefense"
        label = f"{issuer}:{current_user['username']}"
        otpauth = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"

        return jsonify({
            "secret": secret,
            "otpauth_url": otpauth
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/auth/mfa/enable', methods=['POST'])
def api_mfa_enable():
    """Enable MFA after verifying code."""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.json
        code = data.get('code')
        secret = current_user.get('mfa_secret') or ''

        if not auth.verify_totp(secret, code):
            return jsonify({"error": "Invalid MFA code"}), 400

        database.update_user_mfa(current_user['id'], secret, True)
        return jsonify({"status": "enabled"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/auth/me', methods=['GET'])
def api_auth_me():
    """Return current authenticated user."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "id": user.get('id'),
        "username": user.get('username'),
        "email": user.get('email'),
        "role": user.get('role')
    })


# ===== BILLING & CREDITS =====

@app.route('/api/billing/credits/plans', methods=['GET'])
def api_credit_plans():
    """Return active credit plans."""
    plans = database.get_credit_plans(active_only=True)
    return jsonify({"plans": plans})


@app.route('/api/billing/credits/balance', methods=['GET'])
def api_credit_balance():
    """Return current user's credit balance."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    balance = database.get_user_credits(user.get('id'))
    return jsonify({"balance": balance})


@app.route('/api/billing/credits/checkout', methods=['POST'])
def api_credit_checkout():
    """Create a Stripe Checkout session for credit purchase."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if not stripe or not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe not configured"}), 500

    data = request.json or {}
    try:
        plan_id = int(data.get('plan_id', 0))
    except ValueError:
        plan_id = 0

    plan = database.get_credit_plan(plan_id)
    if not plan or not plan.get('active'):
        return jsonify({"error": "Plan not found"}), 404

    payment_id = database.create_payment_record(
        user_id=user.get('id'),
        amount_cents=plan.get('price_cents'),
        currency=plan.get('currency') or STRIPE_CURRENCY,
        credits=plan.get('credits'),
        provider='stripe',
        status='pending'
    )

    base_url = get_base_url()
    success_url = f"{base_url}/?purchase=success"
    cancel_url = f"{base_url}/?purchase=cancel"

    session_obj = stripe.checkout.Session.create(
        mode="payment",
        payment_method_types=["card"],
        line_items=[
            {
                "price_data": {
                    "currency": plan.get('currency') or STRIPE_CURRENCY,
                    "product_data": {
                        "name": plan.get('name'),
                        "description": f"{plan.get('credits')} scan credits"
                    },
                    "unit_amount": plan.get('price_cents')
                },
                "quantity": 1
            }
        ],
        metadata={
            "user_id": str(user.get('id')),
            "credits": str(plan.get('credits')),
            "payment_id": str(payment_id)
        },
        success_url=success_url,
        cancel_url=cancel_url
    )

    database.update_payment_record(payment_id, "pending", provider_ref=session_obj.id)
    return jsonify({"checkout_url": session_obj.url})


@app.route('/api/billing/webhook', methods=['POST'])
def api_billing_webhook():
    """Stripe webhook handler for completed payments."""
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook not configured"}), 400

    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({"error": "Invalid webhook"}), 400

    if event.get('type') == 'checkout.session.completed':
        session_obj = event.get('data', {}).get('object', {})
        metadata = session_obj.get('metadata', {})
        try:
            payment_id = int(metadata.get('payment_id', 0))
            user_id = int(metadata.get('user_id', 0))
            credits = int(metadata.get('credits', 0))
        except ValueError:
            payment_id = 0
            user_id = 0
            credits = 0

        payment = database.get_payment_by_id(payment_id)
        if payment and payment.get('status') != 'paid':
            database.update_payment_record(payment_id, 'paid', session_obj.get('id'))
            if user_id and credits:
                database.add_user_credits(user_id, credits)

    return jsonify({"status": "ok"})


# ===== ANALYTICS ENDPOINTS =====

@app.route('/api/analytics/summary', methods=['GET'])
def api_analytics_summary():
    """Get comprehensive analytics summary."""
    try:
        summary = analytics.get_dashboard_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/analytics/threat-timeline', methods=['GET'])
def api_threat_timeline():
    """Get threat detection timeline."""
    try:
        days = request.args.get('days', 30, type=int)
        timeline = analytics.get_threat_timeline(days)
        return jsonify({
            "days": days,
            "timeline": timeline
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/analytics/top-ports', methods=['GET'])
def api_top_ports():
    """Get top ports at risk."""
    try:
        ports = analytics.get_top_ports_at_risk()
        return jsonify({
            "total": len(ports),
            "ports": ports
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/topology/network', methods=['GET'])
def api_network_topology():
    """Build a simple topology graph from the latest scan."""
    try:
        scans = database.get_scan_history(limit=1)
        if not scans:
            return jsonify({"nodes": [], "edges": []})

        scan = scans[0]
        target = scan.get('target', 'Unknown')
        open_ports = scan.get('open_ports', [])

        nodes = [{
            "id": f"target:{target}",
            "label": target,
            "group": "target"
        }]
        edges = []

        for port in open_ports:
            service = port_services.get_service_name(port)
            node_id = f"port:{port}"
            nodes.append({
                "id": node_id,
                "label": f"{port} ({service})",
                "group": "port"
            })
            edges.append({
                "from": f"target:{target}",
                "to": node_id
            })

        return jsonify({
            "target": target,
            "nodes": nodes,
            "edges": edges
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== PDF EXPORT ENDPOINTS =====

@app.route('/api/export/pdf', methods=['POST'])
def api_export_pdf():
    """Export comprehensive report as PDF."""
    try:
        data = request.json
        scan_id = data.get('scan_id')
        analysis_id = data.get('analysis_id')

        # Get data from database
        scan_data = None
        analysis_data = None

        if scan_id:
            scans = database.get_scan_history(limit=1)
            scan_data = scans[0] if scans else None

        if analysis_id:
            analyses = database.get_analysis_history(limit=1)
            analysis_data = analyses[0] if analyses else None

        website_scans = database.get_website_scan_history(limit=10)

        # Generate PDF
        report = pdf_export.export_report_to_pdf(scan_data, analysis_data, website_scans)

        if report.get('success'):
            pdf_bytes = report.get('data', b'')
            filename = report.get('filename', 'SecurityReport.pdf')

            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype=report.get('content_type', 'application/pdf'),
                as_attachment=True,
                download_name=filename
            )
        else:
            return jsonify(report), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== VULNERABILITY ASSESSMENT ENDPOINTS =====

@app.route('/api/vulnerability/assess', methods=['POST'])
def api_assess_vulnerabilities():
    """Assess vulnerabilities for a list of ports."""
    try:
        data = request.json
        ports = data.get('ports', [])

        assessment = vulnerability_db.assess_scan_vulnerabilities(ports)

        return jsonify(assessment)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/vulnerability/top', methods=['GET'])
def api_top_vulnerabilities():
    """Get top vulnerable ports."""
    try:
        ports = vulnerability_db.get_top_vulnerable_ports()
        return jsonify({
            "total": len(ports),
            "ports": ports
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/vulnerability/remediation', methods=['POST'])
def api_remediation_report():
    """Get remediation recommendations."""
    try:
        data = request.json
        ports = data.get('ports', [])

        report = vulnerability_db.generate_remediation_report(ports)

        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== WEBHOOK ENDPOINTS =====

@app.route('/api/webhook/send-test', methods=['POST'])
def api_send_test_webhook():
    """Send a test webhook alert."""
    try:
        data = request.json

        test_threat = {
            "threat_type": data.get('threat_type', 'Test Alert'),
            "severity": data.get('severity', 'medium'),
            "details": data.get('details', 'This is a test webhook alert')
        }

        result = webhooks.send_webhook_alert(test_threat)

        return jsonify({
            "status": "sent" if result.get('sent') > 0 else "failed",
            "result": result
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== BULK IMPORT ENDPOINTS =====

@app.route('/api/import/logs', methods=['POST'])
def api_import_logs():
    """Import logs from a directory."""
    try:
        data = request.json
        directory = data.get('directory')
        pattern = data.get('pattern', '*.log')

        result = bulk_import.bulk_import_logs(directory, pattern)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/import/csv', methods=['POST'])
def api_import_csv():
    """Import threat data from CSV."""
    try:
        data = request.json
        csv_file = data.get('file_path')
        ip_column = data.get('ip_column', 'source_ip')
        threat_column = data.get('threat_column', 'threat_type')

        result = bulk_import.import_csv_logs(csv_file, ip_column, threat_column)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/import/formats', methods=['GET'])
def api_import_formats():
    """Get supported import formats."""
    try:
        formats = bulk_import.get_supported_formats()
        return jsonify(formats)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===== SCHEDULER ENDPOINTS =====

@app.route('/api/schedule/status', methods=['GET'])
def api_schedule_status():
    """Get scheduler status."""
    try:
        status = scheduler.get_schedule_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/schedule/execute', methods=['POST'])
def api_execute_schedules():
    """Execute all pending schedules."""
    try:
        sched = scheduler.ScanScheduler()
        result = sched.execute_schedules()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ============================================================================
# ADMIN PORTAL ROUTES
# ============================================================================


@app.route('/admin')
def admin_dashboard():
    """Admin control panel."""
    current_user = get_current_user()
    if not is_admin(current_user):
        return redirect(url_for('dashboard'))
    return render_template('admin.html', current_user=current_user)


@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    """Get system statistics for admin dashboard."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        # Get user statistics
        all_users = database.get_all_users()
        admin_count = sum(1 for u in all_users if u.get('role') == 'admin')
        user_count = len(all_users)

        # Get scan statistics
        scan_count = len(results.get("scans", []))
        analysis_count = len(results.get("analyses", []))

        return jsonify({
            "status": "success",
            "total_users": user_count,
            "admin_users": admin_count,
            "regular_users": user_count - admin_count,
            "total_scans": scan_count,
            "total_analyses": analysis_count,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/earnings', methods=['GET'])
def api_admin_earnings():
    """Get earnings summary and recent payments (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        summary = database.get_earnings_summary()
        payments = database.get_recent_payments(limit=20)
        return jsonify({
            "status": "success",
            "summary": summary,
            "payments": payments,
            "currency": STRIPE_CURRENCY
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/users', methods=['GET'])
def api_admin_get_users():
    """Get all users (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        users = database.get_all_users()
        # Remove sensitive data
        safe_users = [
            {
                "id": u.get('id'),
                "username": u.get('username'),
                "email": u.get('email'),
                "role": u.get('role'),
                "created_at": u.get('created_at'),
                "mfa_enabled": bool(u.get('mfa_secret'))
            }
            for u in users
        ]
        return jsonify({"status": "success", "users": safe_users})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
def api_admin_delete_user(user_id):
    """Delete a user (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        # Prevent deleting self
        if str(current_user.get('id')) == str(user_id):
            return jsonify({"error": "Cannot delete yourself"}), 400

        # Prevent deleting if only one admin left
        all_users = database.get_all_users()
        admin_users = [u for u in all_users if u.get('role') == 'admin']
        target_user = database.get_user_by_id(user_id)

        if len(admin_users) == 1 and target_user.get('role') == 'admin':
            return jsonify({"error": "Cannot delete the last admin user"}), 400

        database.delete_user(user_id)
        return jsonify({"status": "success", "message": "User deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/users/<user_id>/role', methods=['PUT'])
def api_admin_update_user_role(user_id):
    """Update user role (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        new_role = data.get('role', 'user')

        if new_role not in ['user', 'admin']:
            return jsonify({"error": "Invalid role"}), 400

        # Prevent removing all admins
        all_users = database.get_all_users()
        admin_users = [u for u in all_users if u.get('role') == 'admin']
        target_user = database.get_user_by_id(user_id)

        if new_role == 'user' and len(admin_users) == 1 and target_user.get('role') == 'admin':
            return jsonify({"error": "Cannot remove the last admin role"}), 400

        database.update_user_role(user_id, new_role)
        return jsonify({"status": "success", "message": f"User role updated to {new_role}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/audit-log', methods=['GET'])
def api_admin_audit_log():
    """Get audit log (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        limit = int(request.args.get('limit', 50))
        logs = database.get_audit_logs(limit=limit)

        return jsonify({
            "status": "success",
            "logs": logs,
            "count": len(logs)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/settings', methods=['GET'])
def api_admin_get_settings():
    """Get system settings (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        settings = database.get_settings()
        return jsonify({"status": "success", "settings": settings})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/settings', methods=['PUT'])
def api_admin_update_settings():
    """Update system settings (admin only)."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        for key, value in data.items():
            database.update_setting(key, value)

        return jsonify({"status": "success", "message": "Settings updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# THREAT INTELLIGENCE & MONITORING
# ============================================================================

@app.route('/api/admin/threats', methods=['GET'])
def api_admin_get_threats():
    """Get threat logs and statistics."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        limit = int(request.args.get('limit', 50))
        threats = database.get_threat_logs(limit=limit)

        # Calculate threat statistics
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for threat in threats:
            severity_counts[threat.get('severity', 'LOW')] += 1

        return jsonify({
            "status": "success",
            "threats": threats,
            "statistics": severity_counts,
            "total": len(threats)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/activity', methods=['GET'])
def api_admin_get_activity():
    """Get recent activity logs."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        limit = int(request.args.get('limit', 100))
        activities = database.get_activity_logs(limit=limit)

        return jsonify({
            "status": "success",
            "activities": activities,
            "count": len(activities)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# IP ACCESS CONTROL
# ============================================================================

@app.route('/api/admin/ip-access', methods=['GET'])
def api_admin_get_ip_access():
    """Get IP whitelist/blacklist."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        list_type = request.args.get('type', None)
        ips = database.get_ip_access_list(list_type=list_type)

        return jsonify({
            "status": "success",
            "ips": ips,
            "count": len(ips)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/ip-access', methods=['POST'])
def api_admin_add_ip():
    """Add IP to whitelist or blacklist."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        ip_address = data.get('ip_address')
        list_type = data.get('list_type')  # 'whitelist' or 'blacklist'
        reason = data.get('reason', '')

        if not ip_address or not list_type:
            return jsonify({"error": "Missing required fields"}), 400

        record_id = database.add_ip_to_list(ip_address, list_type, reason, current_user.get('id'))
        return jsonify({
            "status": "success",
            "message": f"IP added to {list_type}",
            "record_id": record_id
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/ip-access/<ip_address>', methods=['DELETE'])
def api_admin_remove_ip(ip_address):
    """Remove IP from access lists."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        database.remove_ip_from_list(ip_address)
        return jsonify({"status": "success", "message": "IP removed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

@app.route('/api/admin/api-keys/<user_id>', methods=['GET'])
def api_admin_get_api_keys(user_id):
    """Get API keys for a user."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        keys = database.get_user_api_keys(int(user_id))
        # Mask keys for security
        masked_keys = [
            {**k, 'api_key': k['api_key'][:10] + '***' + k['api_key'][-5:]}
            for k in keys
        ]

        return jsonify({
            "status": "success",
            "api_keys": masked_keys,
            "count": len(masked_keys)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/api-keys', methods=['POST'])
def api_admin_create_api_key():
    """Create API key for a user."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        user_id = data.get('user_id')
        name = data.get('name', 'API Key')
        permissions = data.get('permissions', 'read')

        api_key = database.create_api_key(int(user_id), name, permissions)
        return jsonify({
            "status": "success",
            "api_key": api_key,
            "message": "API key created"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/api-keys/<key_id>', methods=['DELETE'])
def api_admin_revoke_api_key(key_id):
    """Revoke an API key."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        database.revoke_api_key(int(key_id))
        return jsonify({"status": "success", "message": "API key revoked"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# USAGE TRACKING & LIMITS
# ============================================================================

@app.route('/api/admin/usage/<user_id>', methods=['GET'])
def api_admin_get_usage(user_id):
    """Get user usage statistics."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        usage = database.get_user_usage(int(user_id))
        limits = database.get_user_limits(int(user_id))

        return jsonify({
            "status": "success",
            "usage": usage,
            "limits": limits
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/usage-limits/<user_id>', methods=['PUT'])
def api_admin_set_usage_limits(user_id):
    """Set usage limits for a user."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        database.set_user_limits(
            int(user_id),
            max_concurrent=data.get('max_concurrent_scans', 5),
            max_monthly=data.get('max_monthly_scans', 100),
            max_api_calls=data.get('max_api_calls_per_hour', 100),
            bandwidth_limit=data.get('bandwidth_limit_mb', 5000)
        )

        return jsonify({
            "status": "success",
            "message": "Usage limits updated"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# SYSTEM LOGS
# ============================================================================

@app.route('/api/admin/logs', methods=['GET'])
def api_admin_get_logs():
    """Get system logs."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        limit = int(request.args.get('limit', 100))
        level = request.args.get('level', None)
        logs = database.get_system_logs(limit=limit, level=level)

        return jsonify({
            "status": "success",
            "logs": logs,
            "count": len(logs)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# DEPARTMENTS & TEAMS
# ============================================================================

@app.route('/api/admin/departments', methods=['GET'])
def api_admin_get_departments():
    """Get all departments."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        departments = database.get_all_departments()
        return jsonify({
            "status": "success",
            "departments": departments
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/departments', methods=['POST'])
def api_admin_create_department():
    """Create a new department."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        name = data.get('name')
        description = data.get('description', '')

        dept_id = database.create_department(name, description)
        if dept_id == -1:
            return jsonify({"error": "Department already exists"}), 400

        return jsonify({
            "status": "success",
            "department_id": dept_id,
            "message": "Department created"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/departments/<dept_id>/members', methods=['GET'])
def api_admin_get_dept_members(dept_id):
    """Get department members."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        members = database.get_department_members(int(dept_id))
        return jsonify({
            "status": "success",
            "members": members
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/departments/<dept_id>/members', methods=['POST'])
def api_admin_add_dept_member(dept_id):
    """Add user to department."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        user_id = data.get('user_id')
        role = data.get('role', '')

        database.add_user_to_department(int(user_id), int(dept_id), role)
        return jsonify({
            "status": "success",
            "message": "User added to department"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# SECURITY ALERTS
# ============================================================================

@app.route('/api/admin/alerts/<user_id>', methods=['GET'])
def api_admin_get_alerts(user_id):
    """Get security alerts for user."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        alerts = database.get_user_alerts(int(user_id))
        return jsonify({
            "status": "success",
            "alerts": alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/alerts', methods=['POST'])
def api_admin_create_alert():
    """Create security alert."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        data = request.json
        alert_id = database.create_security_alert(
            alert_type=data.get('alert_type'),
            user_id=int(data.get('user_id')),
            channel=data.get('channel'),
            contact_info=data.get('contact_info'),
            severity_threshold=data.get('severity_threshold', 'HIGH')
        )

        return jsonify({
            "status": "success",
            "alert_id": alert_id,
            "message": "Alert configured"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================================
# BACKUP MANAGEMENT
# ============================================================================

@app.route('/api/admin/backups', methods=['GET'])
def api_admin_get_backups():
    """Get backup records."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        limit = int(request.args.get('limit', 50))
        backups = database.get_backup_records(limit=limit)

        return jsonify({
            "status": "success",
            "backups": backups
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/admin/backups', methods=['POST'])
def api_admin_create_backup():
    """Create database backup."""
    try:
        current_user = get_current_user()
        if not is_admin(current_user):
            return jsonify({"error": "Forbidden"}), 403

        # Implementation would backup the actual database
        backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        backup_id = database.create_backup_record(backup_file, 0.5, 'manual')

        return jsonify({
            "status": "success",
            "backup_id": backup_id,
            "backup_file": backup_file,
            "message": "Backup created"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "Amadioha Web Dashboard"})


def run_server(host='127.0.0.1', port=5000, debug=False):
    """Run the Flask development server."""
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_server(debug=True)
