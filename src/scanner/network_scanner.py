#!/usr/bin/env python3
"""
Network Scanner
Quét mạng LAN để phát hiện thiết bị, build inventory
"""

import nmap
import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import logging

try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    logging.warning("mac_vendor_lookup not available")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkScanner:
    """Scan mạng LAN để phát hiện thiết bị"""

    def __init__(self, subnet: str = "192.168.1.0/24"):
        """
        Args:
            subnet: Subnet cần scan (CIDR notation)
        """
        self.subnet = subnet
        self.nm = nmap.PortScanner()

        if HAS_MAC_LOOKUP:
            self.mac_lookup = MacLookup()
            self.mac_lookup.update_vendors()  # Update vendor database

    def scan_network(self, fast: bool = True) -> List[Dict]:
        """
        Scan toàn bộ subnet

        Args:
            fast: Nếu True, chỉ ping scan. False = scan ports

        Returns:
            List of discovered devices
        """
        logger.info(f"🔍 Scanning {self.subnet}...")

        devices = []

        try:
            if fast:
                # Ping scan only (-sn)
                self.nm.scan(hosts=self.subnet, arguments='-sn -T4')
            else:
                # Full scan với common ports
                self.nm.scan(
                    hosts=self.subnet,
                    arguments='-sS -T4 -p 22,80,443,445,3389,8080,8443'
                )

            # Parse results
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device = self._parse_host(host)
                    devices.append(device)

            logger.info(f"✅ Found {len(devices)} devices")

        except Exception as e:
            logger.error(f"Error scanning network: {e}")

        return devices

    def scan_single_host(self, ip: str) -> Optional[Dict]:
        """
        Scan một host cụ thể

        Args:
            ip: IP address

        Returns:
            Device info dict hoặc None
        """
        try:
            self.nm.scan(hosts=ip, arguments='-sS -T4 -p-')  # Scan all ports

            if ip in self.nm.all_hosts():
                return self._parse_host(ip)
            else:
                return None

        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
            return None

    def _parse_host(self, host: str) -> Dict:
        """Parse thông tin từ nmap result"""
        device = {
            'ip': host,
            'hostname': None,
            'mac': None,
            'vendor': None,
            'status': 'up',
            'open_ports': [],
            'os_guess': None,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }

        # Hostname
        if 'hostnames' in self.nm[host]:
            hostnames = self.nm[host]['hostnames']
            if hostnames:
                device['hostname'] = hostnames[0].get('name', None)

        # MAC address (chỉ có khi scan từ local network)
        if 'addresses' in self.nm[host]:
            if 'mac' in self.nm[host]['addresses']:
                mac = self.nm[host]['addresses']['mac']
                device['mac'] = mac

                # Vendor lookup
                if HAS_MAC_LOOKUP:
                    try:
                        vendor = self.mac_lookup.lookup(mac)
                        device['vendor'] = vendor
                    except:
                        device['vendor'] = self._guess_vendor_from_mac(mac)

        # Open ports
        if 'tcp' in self.nm[host]:
            for port, info in self.nm[host]['tcp'].items():
                if info['state'] == 'open':
                    device['open_ports'].append({
                        'port': port,
                        'service': info.get('name', 'unknown'),
                        'product': info.get('product', ''),
                        'version': info.get('version', '')
                    })

        # OS detection
        if 'osmatch' in self.nm[host]:
            if self.nm[host]['osmatch']:
                device['os_guess'] = self.nm[host]['osmatch'][0].get('name')

        # Device type guessingdevice['device_type'] = self._guess_device_type(device)

        return device

    def _guess_vendor_from_mac(self, mac: str) -> Optional[str]:
        """Guess vendor từ MAC OUI (3 bytes đầu)"""
        # OUI database đơn giản
        oui_db = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1B:63': 'Apple',
            '00:23:32': 'Apple',
            'AC:DE:48': 'Apple',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:E0:4C': 'Realtek',
            '00:D0:B7': 'Intel',
        }

        mac_prefix = mac.upper()[:8]
        return oui_db.get(mac_prefix, 'Unknown')

    def _guess_device_type(self, device: Dict) -> str:
        """
        Guess loại thiết bị dựa trên ports, vendor, etc.

        Returns:
            'computer', 'router', 'iot', 'camera', 'phone', 'unknown'
        """
        vendor = (device.get('vendor') or '').lower()
        open_ports = [p['port'] for p in device.get('open_ports', [])]

        # Cameras
        if 554 in open_ports or 8000 in open_ports:  # RTSP
            return 'camera'

        # Routers/Network devices
        if any(port in open_ports for port in [23, 80, 443]) and \
           any(v in vendor for v in ['mikrotik', 'cisco', 'tp-link', 'ubiquiti']):
            return 'router'

        # IoT devices
        if any(v in vendor for v in ['hikvision', 'dahua', 'xiaomi', 'tuya', 'smartthings']):
            return 'iot'

        # Mobile devices
        if any(v in vendor for v in ['apple', 'samsung', 'huawei', 'xiaomi']) and \
           not any(port in open_ports for port in [22, 80, 443]):
            return 'phone'

        # Computers (SSH, RDP, SMB)
        if any(port in open_ports for port in [22, 3389, 445]):
            return 'computer'

        # Raspberry Pi
        if 'raspberry' in vendor:
            return 'computer'

        return 'unknown'


class DeviceInventory:
    """Quản lý device inventory"""

    def __init__(self, db_path: str = "data/device_inventory.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.devices = self._load_db()

    def _load_db(self) -> Dict:
        """Load device database"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except:
                logger.warning("Failed to load device DB, starting fresh")
                return {}
        return {}

    def _save_db(self):
        """Save device database"""
        with open(self.db_path, 'w') as f:
            json.dump(self.devices, f, indent=2)

    def update_devices(self, scanned_devices: List[Dict]) -> Dict:
        """
        Update inventory với scanned devices

        Returns:
            Dict với new_devices, updated_devices
        """
        new_devices = []
        updated_devices = []

        for device in scanned_devices:
            device_id = device['ip']  # Hoặc MAC nếu có

            if device_id not in self.devices:
                # New device
                new_devices.append(device)
                self.devices[device_id] = device
                logger.info(f"🆕 New device: {device_id} ({device.get('vendor', 'Unknown')})")
            else:
                # Update existing
                old_device = self.devices[device_id]

                # Update last_seen
                device['first_seen'] = old_device.get('first_seen', device['first_seen'])
                device['last_seen'] = datetime.now().isoformat()

                # Merge data
                self.devices[device_id] = {**old_device, **device}
                updated_devices.append(device_id)

        self._save_db()

        return {
            'new_devices': new_devices,
            'updated_devices': updated_devices,
            'total_devices': len(self.devices)
        }

    def get_all_devices(self) -> List[Dict]:
        """Get all devices trong inventory"""
        return list(self.devices.values())

    def get_device(self, identifier: str) -> Optional[Dict]:
        """
        Get device by IP hoặc MAC

        Args:
            identifier: IP hoặc MAC address

        Returns:
            Device dict hoặc None
        """
        # Try IP first
        if identifier in self.devices:
            return self.devices[identifier]

        # Try MAC
        for device in self.devices.values():
            if device.get('mac') == identifier:
                return device

        return None

    def get_unknown_devices(self) -> List[Dict]:
        """Get devices không có trong whitelist"""
        # TODO: Implement whitelist check
        return []


def main():
    """Test scanner"""
    import argparse

    parser = argparse.ArgumentParser(description='Scan mạng LAN')
    parser.add_argument(
        '--subnet',
        type=str,
        default='192.168.1.0/24',
        help='Subnet to scan'
    )
    parser.add_argument(
        '--fast',
        action='store_true',
        help='Fast scan (ping only)'
    )
    parser.add_argument(
        '--ip',
        type=str,
        help='Scan single IP'
    )

    args = parser.parse_args()

    scanner = NetworkScanner(subnet=args.subnet)
    inventory = DeviceInventory()

    if args.ip:
        # Scan single host
        device = scanner.scan_single_host(args.ip)
        if device:
            print(json.dumps(device, indent=2))
    else:
        # Scan network
        devices = scanner.scan_network(fast=args.fast)

        # Update inventory
        result = inventory.update_devices(devices)

        print(f"\n📊 Scan Results:")
        print(f"   Total devices: {result['total_devices']}")
        print(f"   New devices: {len(result['new_devices'])}")
        print(f"   Updated devices: {len(result['updated_devices'])}")

        if result['new_devices']:
            print(f"\n🆕 New Devices:")
            for dev in result['new_devices']:
                print(f"   - {dev['ip']} ({dev.get('vendor', 'Unknown')}) - {dev.get('device_type', 'unknown')}")

        # Show all devices
        print(f"\n📱 All Devices:")
        for dev in inventory.get_all_devices():
            print(f"   {dev['ip']:15} | {dev.get('mac', 'N/A'):17} | "
                  f"{dev.get('vendor', 'Unknown'):20} | {dev.get('device_type', 'unknown')}")


if __name__ == "__main__":
    main()
