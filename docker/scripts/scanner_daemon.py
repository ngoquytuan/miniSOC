#!/usr/bin/env python3
"""
Scanner Daemon
Chạy network scanner định kỳ
"""

import os
import sys
import time
import logging
from datetime import datetime

# Add paths
sys.path.insert(0, '/app')

from scanner.network_scanner import NetworkScanner, DeviceInventory
from alerting.alert_manager import AlertManager, send_new_device_alert

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    subnet = os.getenv('SUBNET', '192.168.1.0/24')
    scan_interval = int(os.getenv('SCAN_INTERVAL', '600'))  # 10 minutes

    logger.info("="*60)
    logger.info("Mini-SOC Network Scanner Daemon")
    logger.info("="*60)
    logger.info(f"Subnet: {subnet}")
    logger.info(f"Scan interval: {scan_interval}s")

    scanner = NetworkScanner(subnet=subnet)
    inventory = DeviceInventory(db_path='/app/data/device_inventory.json')
    alert_mgr = AlertManager()

    logger.info("🚀 Scanner daemon started")

    try:
        while True:
            logger.info(f"\n{'='*60}")
            logger.info(f"Scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"{'='*60}")

            # Scan network
            devices = scanner.scan_network(fast=True)

            # Update inventory
            result = inventory.update_devices(devices)

            logger.info(f"📊 Scan results:")
            logger.info(f"   Total devices: {result['total_devices']}")
            logger.info(f"   New devices: {len(result['new_devices'])}")
            logger.info(f"   Updated: {len(result['updated_devices'])}")

            # Alert for new devices
            if result['new_devices']:
                for device in result['new_devices']:
                    logger.warning(f"🆕 New device detected: {device['ip']} ({device.get('vendor', 'Unknown')})")
                    send_new_device_alert(device, alert_mgr)

            # Sleep
            logger.info(f"\n💤 Sleeping for {scan_interval} seconds...")
            time.sleep(scan_interval)

    except KeyboardInterrupt:
        logger.info("\n⏹ Scanner daemon stopped")
    except Exception as e:
        logger.error(f"Error in scanner daemon: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
