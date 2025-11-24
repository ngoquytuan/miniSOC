#!/usr/bin/env python3
"""
Example: Alerting System Demo
Demonstrates different types of alerts and channels

NOTE: This demo simulates alerts. To send real alerts:
- Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in configs/.env
- Or set them as environment variables
"""

import sys
import os
from pathlib import Path
import asyncio
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

# For demo, we'll simulate the alert manager
# from alerting.alert_manager import AlertManager


class DemoAlertManager:
    """Simulated alert manager for demo"""

    def __init__(self):
        self.alerts_sent = []
        self.telegram_enabled = os.getenv('TELEGRAM_BOT_TOKEN') is not None
        self.email_enabled = os.getenv('SMTP_USER') is not None

    async def send_alert(self, alert_type, severity, title, message, details=None, channels=None):
        """Simulate sending an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'title': title,
            'message': message,
            'details': details or {},
            'channels': channels or []
        }

        self.alerts_sent.append(alert)

        # Display alert
        emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🟠',
            'critical': '🔴'
        }.get(severity, '⚪')

        print(f"\n{emoji} ALERT: {title}")
        print(f"   Severity: {severity.upper()}")
        print(f"   Type: {alert_type}")
        print(f"   Message: {message}")

        if details:
            print(f"   Details:")
            for key, value in details.items():
                print(f"      - {key}: {value}")

        print(f"   Channels: {', '.join(channels)}")

        # Simulate sending
        if self.telegram_enabled and 'telegram' in channels:
            print(f"   ✅ Sent to Telegram")
        elif 'telegram' in channels:
            print(f"   ⚠️  Telegram not configured (skipped)")

        if self.email_enabled and 'email' in channels:
            print(f"   ✅ Sent to Email")
        elif 'email' in channels:
            print(f"   ⚠️  Email not configured (skipped)")

        if 'log' in channels:
            print(f"   ✅ Logged to file")

        print()


async def demo_anomaly_alert(alert_mgr):
    """Demo: Anomaly detection alert"""
    await alert_mgr.send_alert(
        alert_type='anomaly',
        severity='high',
        title='Anomalous Traffic Detected',
        message='Unusual network pattern detected from internal host',
        details={
            'source_ip': '192.168.1.130',
            'destination_ip': '45.142.212.61',
            'destination_port': '8080',
            'anomaly_score': '0.15',
            'threshold': '0.30',
            'total_bytes': '1,234,567',
            'duration': '300.12s',
            'reason': 'Large data transfer to unknown external IP'
        },
        channels=['telegram', 'email', 'log']
    )


async def demo_new_device_alert(alert_mgr):
    """Demo: New device detection alert"""
    await alert_mgr.send_alert(
        alert_type='new_device',
        severity='medium',
        title='New Device Joined Network',
        message='An unknown device has connected to your network',
        details={
            'ip': '192.168.1.199',
            'mac': 'FF:EE:DD:CC:BB:AA',
            'vendor': 'Unknown',
            'device_type': 'unknown',
            'first_seen': datetime.now().isoformat(),
            'action': 'Review device and add to whitelist or block'
        },
        channels=['telegram', 'log']
    )


async def demo_port_scan_alert(alert_mgr):
    """Demo: Port scan detection alert"""
    await alert_mgr.send_alert(
        alert_type='port_scan',
        severity='high',
        title='Port Scan Detected',
        message='Multiple ports scanned from external source',
        details={
            'scanner_ip': '103.224.182.245',
            'target_ip': '192.168.1.70',
            'ports_scanned': '150',
            'time_window': '5 minutes',
            'scan_type': 'TCP SYN Scan',
            'action': 'Source IP temporarily blocked'
        },
        channels=['telegram', 'email', 'log']
    )


async def demo_suspicious_domain_alert(alert_mgr):
    """Demo: Suspicious domain alert"""
    await alert_mgr.send_alert(
        alert_type='suspicious_domain',
        severity='critical',
        title='Malicious Domain Contacted',
        message='Device attempted to contact known malicious domain',
        details={
            'source_ip': '192.168.1.105',
            'domain': 'malicious-c2-server-xyz123.com',
            'resolved_ip': '45.142.212.61',
            'threat_category': 'C2 Server',
            'threat_intel_source': 'abuse.ch',
            'action': 'Connection blocked. Scan device for malware.'
        },
        channels=['telegram', 'email', 'log']
    )


async def demo_failed_login_alert(alert_mgr):
    """Demo: Failed login attempts alert"""
    await alert_mgr.send_alert(
        alert_type='brute_force',
        severity='medium',
        title='Multiple Failed Login Attempts',
        message='SSH brute force attack detected',
        details={
            'target_ip': '192.168.1.70',
            'target_service': 'SSH (port 22)',
            'source_ip': '185.220.101.42',
            'failed_attempts': '25',
            'time_window': '10 minutes',
            'action': 'Source IP blocked by firewall'
        },
        channels=['telegram', 'log']
    )


async def demo_low_priority_alert(alert_mgr):
    """Demo: Low priority informational alert"""
    await alert_mgr.send_alert(
        alert_type='info',
        severity='low',
        title='Weekly Security Summary',
        message='Your network security status for the past week',
        details={
            'total_devices': '12',
            'new_devices': '1',
            'anomalies_detected': '3',
            'threats_blocked': '5',
            'total_traffic': '45.6 GB',
            'uptime': '99.8%'
        },
        channels=['email', 'log']
    )


def main():
    print("="*60)
    print("   Alerting System Demo")
    print("="*60)
    print()

    # Check configuration
    telegram_configured = os.getenv('TELEGRAM_BOT_TOKEN') is not None
    email_configured = os.getenv('SMTP_USER') is not None

    print("📋 Alert Configuration:")
    print(f"   Telegram: {'✅ Configured' if telegram_configured else '⚠️  Not configured'}")
    print(f"   Email: {'✅ Configured' if email_configured else '⚠️  Not configured'}")
    print()

    if not telegram_configured and not email_configured:
        print("ℹ️  Note: This demo simulates alerts.")
        print("   To send real alerts, configure Telegram or Email in configs/.env")
        print()

    alert_mgr = DemoAlertManager()

    # === Demo different alert types ===
    print("="*60)
    print("Demonstrating Different Alert Types")
    print("="*60)

    print("\n1️⃣  Anomaly Detection Alert")
    print("-"*60)
    asyncio.run(demo_anomaly_alert(alert_mgr))

    print("\n2️⃣  New Device Alert")
    print("-"*60)
    asyncio.run(demo_new_device_alert(alert_mgr))

    print("\n3️⃣  Port Scan Alert")
    print("-"*60)
    asyncio.run(demo_port_scan_alert(alert_mgr))

    print("\n4️⃣  Suspicious Domain Alert")
    print("-"*60)
    asyncio.run(demo_suspicious_domain_alert(alert_mgr))

    print("\n5️⃣  Brute Force Attack Alert")
    print("-"*60)
    asyncio.run(demo_failed_login_alert(alert_mgr))

    print("\n6️⃣  Low Priority Info Alert")
    print("-"*60)
    asyncio.run(demo_low_priority_alert(alert_mgr))

    # === Summary ===
    print("\n" + "="*60)
    print("Alert Summary")
    print("="*60)

    print(f"\n📊 Total alerts sent: {len(alert_mgr.alerts_sent)}")

    # Count by severity
    severity_counts = {}
    for alert in alert_mgr.alerts_sent:
        sev = alert['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n📈 Alerts by Severity:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[severity]
            print(f"   {emoji} {severity.capitalize()}: {count}")

    # Count by type
    type_counts = {}
    for alert in alert_mgr.alerts_sent:
        atype = alert['type']
        type_counts[atype] = type_counts.get(atype, 0) + 1

    print(f"\n📋 Alerts by Type:")
    for atype, count in sorted(type_counts.items()):
        print(f"   - {atype}: {count}")

    print()

    # === Best Practices ===
    print("="*60)
    print("Alert Best Practices")
    print("="*60)
    print()
    print("✅ DO:")
    print("   - Use severity levels appropriately")
    print("   - Include actionable information in alerts")
    print("   - Route critical alerts to multiple channels")
    print("   - Add context (IP, time, details)")
    print("   - Test alerts regularly")
    print()
    print("❌ DON'T:")
    print("   - Send too many low-priority alerts (alert fatigue)")
    print("   - Use critical for non-urgent issues")
    print("   - Skip important details")
    print("   - Ignore alert configuration")
    print()

    # === Configuration Instructions ===
    print("="*60)
    print("How to Configure Real Alerts")
    print("="*60)
    print()
    print("📱 Telegram Setup:")
    print("   1. Chat with @BotFather on Telegram")
    print("   2. Send /newbot and follow instructions")
    print("   3. Save the bot token")
    print("   4. Start a chat with your bot")
    print("   5. Get chat ID: curl https://api.telegram.org/bot<TOKEN>/getUpdates")
    print("   6. Add to configs/.env:")
    print("      TELEGRAM_BOT_TOKEN=your_token")
    print("      TELEGRAM_CHAT_ID=your_chat_id")
    print()
    print("📧 Email Setup:")
    print("   1. Use Gmail app password (not regular password)")
    print("   2. Add to configs/.env:")
    print("      SMTP_SERVER=smtp.gmail.com")
    print("      SMTP_PORT=587")
    print("      SMTP_USER=your_email@gmail.com")
    print("      SMTP_PASSWORD=your_app_password")
    print("      ALERT_EMAIL=your_email@gmail.com")
    print()
    print("🧪 Test Real Alerts:")
    print("   python src/alerting/alert_manager.py --type telegram")
    print("   python src/alerting/alert_manager.py --type email")
    print()

    print("="*60)
    print("Demo completed!")
    print("="*60)
    print()


if __name__ == "__main__":
    main()
