#!/usr/bin/env python3
"""
Alert Manager
Gửi alerts qua Telegram, Email, và log
"""

import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import json

# Telegram
try:
    from telegram import Bot
    from telegram.error import TelegramError
    HAS_TELEGRAM = True
except ImportError:
    HAS_TELEGRAM = False
    logging.warning("python-telegram-bot not installed")

# Email
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertManager:
    """Quản lý và gửi alerts"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Args:
            config_path: Path to config file (hoặc dùng env vars)
        """
        self.config = self._load_config(config_path)
        self.alert_log_path = Path('logs/alerts.log')
        self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Telegram bot
        if HAS_TELEGRAM and self.config.get('telegram', {}).get('enabled'):
            self.telegram_bot = Bot(token=self.config['telegram']['bot_token'])
        else:
            self.telegram_bot = None

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load config từ file hoặc environment"""
        config = {
            'telegram': {
                'enabled': os.getenv('TELEGRAM_ENABLED', 'true').lower() == 'true',
                'bot_token': os.getenv('TELEGRAM_BOT_TOKEN', ''),
                'chat_id': os.getenv('TELEGRAM_CHAT_ID', '')
            },
            'email': {
                'enabled': os.getenv('EMAIL_ENABLED', 'false').lower() == 'true',
                'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
                'smtp_port': int(os.getenv('SMTP_PORT', '587')),
                'smtp_user': os.getenv('SMTP_USER', ''),
                'smtp_password': os.getenv('SMTP_PASSWORD', ''),
                'from_addr': os.getenv('SMTP_USER', ''),
                'to_addr': os.getenv('ALERT_EMAIL', '')
            }
        }

        # Load từ file nếu có
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                # Merge configs
                for key in file_config:
                    if key in config:
                        config[key].update(file_config[key])

        return config

    async def send_alert(self,
                        alert_type: str,
                        severity: str,
                        title: str,
                        message: str,
                        details: Optional[Dict] = None,
                        channels: Optional[List[str]] = None):
        """
        Gửi alert qua các channels

        Args:
            alert_type: 'anomaly', 'new_device', 'port_scan', etc.
            severity: 'low', 'medium', 'high', 'critical'
            title: Alert title
            message: Alert message
            details: Additional details dict
            channels: List of channels ['telegram', 'email', 'log']
        """
        if channels is None:
            # Default channels theo severity
            if severity in ['high', 'critical']:
                channels = ['telegram', 'email', 'log']
            elif severity == 'medium':
                channels = ['telegram', 'log']
            else:
                channels = ['log']

        # Format alert
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'title': title,
            'message': message,
            'details': details or {}
        }

        # Log alert
        if 'log' in channels:
            self._log_alert(alert_data)

        # Send to Telegram
        if 'telegram' in channels and self.telegram_bot:
            await self._send_telegram(alert_data)

        # Send email
        if 'email' in channels and self.config['email']['enabled']:
            self._send_email(alert_data)

        logger.info(f"Alert sent: {title} (severity: {severity}, channels: {channels})")

    def _log_alert(self, alert_data: Dict):
        """Log alert to file"""
        with open(self.alert_log_path, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')

    async def _send_telegram(self, alert_data: Dict):
        """Send alert via Telegram"""
        if not self.telegram_bot:
            return

        try:
            # Format message
            emoji = {
                'low': '🟢',
                'medium': '🟡',
                'high': '🟠',
                'critical': '🔴'
            }.get(alert_data['severity'], '⚪')

            msg = f"{emoji} *{alert_data['severity'].upper()}* - {alert_data['title']}\n\n"
            msg += f"{alert_data['message']}\n\n"

            if alert_data['details']:
                msg += "*Details:*\n"
                for key, value in alert_data['details'].items():
                    msg += f"• {key}: `{value}`\n"

            msg += f"\n_Time: {alert_data['timestamp']}_"

            # Send message
            await self.telegram_bot.send_message(
                chat_id=self.config['telegram']['chat_id'],
                text=msg,
                parse_mode='Markdown'
            )

            logger.info("✅ Telegram alert sent")

        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")

    def _send_email(self, alert_data: Dict):
        """Send alert via email"""
        try:
            config = self.config['email']

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[Mini-SOC] {alert_data['severity'].upper()}: {alert_data['title']}"
            msg['From'] = config['from_addr']
            msg['To'] = config['to_addr']

            # HTML body
            html = f"""
            <html>
              <head></head>
              <body>
                <h2 style="color: {'red' if alert_data['severity'] in ['high', 'critical'] else 'orange'}">
                  {alert_data['title']}
                </h2>
                <p><strong>Severity:</strong> {alert_data['severity'].upper()}</p>
                <p><strong>Type:</strong> {alert_data['type']}</p>
                <p><strong>Time:</strong> {alert_data['timestamp']}</p>
                <hr>
                <p>{alert_data['message']}</p>
            """

            if alert_data['details']:
                html += "<h3>Details:</h3><ul>"
                for key, value in alert_data['details'].items():
                    html += f"<li><strong>{key}:</strong> {value}</li>"
                html += "</ul>"

            html += """
              </body>
            </html>
            """

            msg.attach(MIMEText(html, 'html'))

            # Send email
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                server.starttls()
                server.login(config['smtp_user'], config['smtp_password'])
                server.send_message(msg)

            logger.info("✅ Email alert sent")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")


# Convenience functions

def send_anomaly_alert(ip_src: str, ip_dst: str, score: float,
                      alert_manager: AlertManager):
    """Send anomaly detection alert"""
    asyncio.run(alert_manager.send_alert(
        alert_type='anomaly',
        severity='high' if score < 0.2 else 'medium',
        title='Anomalous Traffic Detected',
        message=f'Unusual traffic pattern detected from {ip_src} to {ip_dst}',
        details={
            'source_ip': ip_src,
            'destination_ip': ip_dst,
            'anomaly_score': f'{score:.4f}',
            'threshold': '0.3'
        }
    ))


def send_new_device_alert(device: Dict, alert_manager: AlertManager):
    """Send new device alert"""
    asyncio.run(alert_manager.send_alert(
        alert_type='new_device',
        severity='medium',
        title='New Device Detected',
        message=f'A new device has joined the network: {device.get("ip")}',
        details={
            'ip': device.get('ip'),
            'mac': device.get('mac', 'N/A'),
            'vendor': device.get('vendor', 'Unknown'),
            'device_type': device.get('device_type', 'unknown'),
            'hostname': device.get('hostname', 'N/A')
        }
    ))


def send_port_scan_alert(scanner_ip: str, target_ip: str, port_count: int,
                        alert_manager: AlertManager):
    """Send port scan alert"""
    asyncio.run(alert_manager.send_alert(
        alert_type='port_scan',
        severity='high',
        title='Port Scan Detected',
        message=f'Possible port scan from {scanner_ip} to {target_ip}',
        details={
            'scanner_ip': scanner_ip,
            'target_ip': target_ip,
            'ports_scanned': str(port_count),
            'action': 'Monitor or block source IP'
        }
    ))


def main():
    """Test alert manager"""
    import argparse

    parser = argparse.ArgumentParser(description='Test alert system')
    parser.add_argument('--type', type=str, default='test',
                       help='Alert type to test')
    args = parser.parse_args()

    # Load config from env
    alert_mgr = AlertManager()

    # Test alert
    if args.type == 'telegram':
        asyncio.run(alert_mgr.send_alert(
            alert_type='test',
            severity='low',
            title='Test Alert - Telegram',
            message='This is a test alert from Mini-SOC',
            details={'test': 'value'},
            channels=['telegram']
        ))
    elif args.type == 'email':
        asyncio.run(alert_mgr.send_alert(
            alert_type='test',
            severity='low',
            title='Test Alert - Email',
            message='This is a test alert from Mini-SOC',
            details={'test': 'value'},
            channels=['email']
        ))
    else:
        # Test anomaly alert
        send_anomaly_alert(
            '192.168.1.100',
            '8.8.8.8',
            0.15,
            alert_mgr
        )


if __name__ == "__main__":
    main()
