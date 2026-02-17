"""Webhook alerts module for sending threat notifications to external services."""

import json
import requests
from typing import Dict
from datetime import datetime
from amadioha import database


def load_webhook_config() -> Dict:
    """Load webhook configuration."""
    try:
        from pathlib import Path
        config_path = Path(__file__).parent.parent / "webhook_config.json"
        with open(config_path, 'r') as f:
            return json.load(f)
    except BaseException:
        return {}


def send_slack_alert(webhook_url: str, threat_data: Dict) -> tuple[bool, int]:
    """Send alert to Slack."""
    try:
        # Format Slack message
        color = "danger" if threat_data.get('severity') == 'critical' else "warning"

        slack_message = {
            "attachments": [
                {
                    "color": color,
                    "title": "🚨 Security Threat Alert",
                    "fields": [
                        {
                            "title": "Threat Type",
                            "value": threat_data.get('threat_type', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Severity",
                            "value": threat_data.get('severity', 'Medium').upper(),
                            "short": True
                        },
                        {
                            "title": "Details",
                            "value": threat_data.get('details', 'No details'),
                            "short": False
                        }
                    ],
                    "timestamp": int(datetime.now().timestamp())
                }
            ]
        }

        response = requests.post(webhook_url, json=slack_message, timeout=10)

        # Log to database
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='slack',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=response.status_code
        )

        return response.status_code == 200, response.status_code
    except Exception as e:
        print(f"Slack webhook error: {e}")
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='slack',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=500
        )
        return False, 500


def send_discord_alert(webhook_url: str, threat_data: Dict) -> tuple[bool, int]:
    """Send alert to Discord."""
    try:
        # Format Discord embed message
        color = 0xDC143C if threat_data.get('severity') == 'critical' else 0xFFD700

        discord_message = {
            "embeds": [
                {
                    "title": "🚨 Security Threat Alert",
                    "description": threat_data.get('details', 'New threat detected'),
                    "color": color,
                    "fields": [
                        {
                            "name": "Threat Type",
                            "value": threat_data.get('threat_type', 'Unknown'),
                            "inline": True
                        },
                        {
                            "name": "Severity",
                            "value": threat_data.get('severity', 'Medium').upper(),
                            "inline": True
                        },
                        {
                            "name": "Timestamp",
                            "value": datetime.now().isoformat(),
                            "inline": False
                        }
                    ]
                }
            ]
        }

        response = requests.post(webhook_url, json=discord_message, timeout=10)

        # Log to database
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='discord',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=response.status_code
        )

        return response.status_code in [200, 204], response.status_code
    except Exception as e:
        print(f"Discord webhook error: {e}")
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='discord',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=500
        )
        return False, 500


def send_custom_webhook(webhook_url: str, threat_data: Dict) -> tuple[bool, int]:
    """Send alert to custom webhook endpoint."""
    try:
        payload = {
            "event": "threat_alert",
            "threat_type": threat_data.get('threat_type'),
            "severity": threat_data.get('severity'),
            "details": threat_data.get('details'),
            "timestamp": datetime.now().isoformat()
        }

        response = requests.post(webhook_url, json=payload, timeout=10)

        # Log to database
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='custom',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=response.status_code
        )

        return response.status_code == 200, response.status_code
    except Exception as e:
        print(f"Custom webhook error: {e}")
        database.save_webhook_alert(
            webhook_url=webhook_url,
            webhook_type='custom',
            threat_type=threat_data.get('threat_type', ''),
            severity=threat_data.get('severity', ''),
            response_code=500
        )
        return False, 500


def send_webhook_alert(threat_data: Dict) -> Dict:
    """Send threat alert via configured webhooks."""
    config = load_webhook_config()

    if not config.get('enabled'):
        return {"sent": 0, "failed": 0}

    webhook_url = config.get('webhook_url')
    webhook_type = config.get('webhook_type', 'custom')

    if not webhook_url:
        return {"sent": 0, "failed": 0}

    # Send to appropriate service
    if webhook_type == 'slack':
        success, code = send_slack_alert(webhook_url, threat_data)
    elif webhook_type == 'discord':
        success, code = send_discord_alert(webhook_url, threat_data)
    else:
        success, code = send_custom_webhook(webhook_url, threat_data)

    return {
        "sent": 1 if success else 0,
        "failed": 0 if success else 1,
        "response_code": code
    }


if __name__ == "__main__":
    # Test webhook alert
    test_threat = {
        "threat_type": "Port Scan",
        "severity": "high",
        "details": "Suspicious port scanning activity detected on 192.168.1.100"
    }

    result = send_webhook_alert(test_threat)
    print(f"Webhook alert result: {result}")
