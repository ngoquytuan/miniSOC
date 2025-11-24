#!/usr/bin/env python3
"""
Example: Device Scanner Demo
Demonstrates network scanning and device inventory management

NOTE: This demo uses simulated data. Real scanning requires:
- Root/sudo privileges
- Being on the same network as target devices
"""

import sys
import os
from pathlib import Path
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

# We'll simulate scanning instead of real nmap
# from scanner.network_scanner import NetworkScanner, DeviceInventory


def simulate_network_scan():
    """Simulate a network scan with fake devices"""
    return [
        {
            'ip': '192.168.1.1',
            'hostname': 'router.local',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Mikrotik',
            'status': 'up',
            'open_ports': [
                {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.0'},
                {'port': 80, 'service': 'http', 'product': 'lighttpd', 'version': ''},
                {'port': 443, 'service': 'https', 'product': 'lighttpd', 'version': ''}
            ],
            'os_guess': 'Linux',
            'device_type': 'router',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.70',
            'hostname': 'dietpi-security',
            'mac': 'AA:BB:CC:DD:EE:FF',
            'vendor': 'Raspberry Pi Foundation',
            'status': 'up',
            'open_ports': [
                {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '8.4'},
                {'port': 3000, 'service': 'http', 'product': 'Grafana', 'version': ''},
                {'port': 9090, 'service': 'http', 'product': 'Prometheus', 'version': ''}
            ],
            'os_guess': 'Linux',
            'device_type': 'computer',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.100',
            'hostname': None,
            'mac': '11:22:33:44:55:66',
            'vendor': 'Apple',
            'status': 'up',
            'open_ports': [],
            'os_guess': 'iOS',
            'device_type': 'phone',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.105',
            'hostname': 'desktop-pc',
            'mac': '22:33:44:55:66:77',
            'vendor': 'Intel',
            'status': 'up',
            'open_ports': [
                {'port': 445, 'service': 'smb', 'product': '', 'version': ''},
                {'port': 3389, 'service': 'rdp', 'product': 'Microsoft Terminal Services', 'version': ''}
            ],
            'os_guess': 'Windows 10',
            'device_type': 'computer',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.150',
            'hostname': 'camera-front',
            'mac': '33:44:55:66:77:88',
            'vendor': 'Hikvision',
            'status': 'up',
            'open_ports': [
                {'port': 80, 'service': 'http', 'product': '', 'version': ''},
                {'port': 554, 'service': 'rtsp', 'product': '', 'version': ''},
                {'port': 8000, 'service': 'http', 'product': 'Hikvision IP Camera', 'version': ''}
            ],
            'os_guess': 'Embedded Linux',
            'device_type': 'camera',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        },
        # New unknown device (suspicious)
        {
            'ip': '192.168.1.199',
            'hostname': None,
            'mac': 'FF:EE:DD:CC:BB:AA',
            'vendor': 'Unknown',
            'status': 'up',
            'open_ports': [
                {'port': 23, 'service': 'telnet', 'product': '', 'version': ''},
                {'port': 8080, 'service': 'http', 'product': '', 'version': ''}
            ],
            'os_guess': None,
            'device_type': 'unknown',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
    ]


class SimpleDeviceInventory:
    """Simplified device inventory for demo"""

    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.devices = self._load_db()

    def _load_db(self):
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                return json.load(f)
        return {}

    def _save_db(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.devices, f, indent=2)

    def update_devices(self, scanned_devices):
        new_devices = []
        updated_devices = []

        for device in scanned_devices:
            device_id = device['ip']

            if device_id not in self.devices:
                new_devices.append(device)
                self.devices[device_id] = device
            else:
                old_device = self.devices[device_id]
                device['first_seen'] = old_device.get('first_seen', device['first_seen'])
                self.devices[device_id] = {**old_device, **device}
                updated_devices.append(device_id)

        self._save_db()

        return {
            'new_devices': new_devices,
            'updated_devices': updated_devices,
            'total_devices': len(self.devices)
        }

    def get_all_devices(self):
        return list(self.devices.values())


def main():
    print("="*60)
    print("   Network Device Scanner Demo")
    print("="*60)
    print()

    print("⚠️  NOTE: This is a simulated demo using fake data")
    print("   Real scanning requires: sudo privileges + network access")
    print()

    # === Step 1: Simulate network scan ===
    print("Step 1: Scanning network...")
    print("-"*60)

    devices = simulate_network_scan()

    print(f"✅ Found {len(devices)} devices")
    print()

    # === Step 2: Display discovered devices ===
    print("Step 2: Discovered Devices")
    print("-"*60)
    print()

    for i, device in enumerate(devices, 1):
        print(f"Device #{i}: {device['ip']}")
        print(f"   MAC: {device['mac']}")
        print(f"   Vendor: {device['vendor']}")
        print(f"   Type: {device['device_type']}")
        print(f"   Hostname: {device.get('hostname', 'N/A')}")
        print(f"   OS: {device.get('os_guess', 'Unknown')}")
        print(f"   Open Ports: {len(device['open_ports'])}")
        if device['open_ports']:
            for port in device['open_ports'][:3]:  # Show first 3
                print(f"      - {port['port']}/{port['service']}")
        print()

    # === Step 3: Device categorization ===
    print("Step 3: Device Categorization")
    print("-"*60)

    categories = {}
    for device in devices:
        dtype = device['device_type']
        categories[dtype] = categories.get(dtype, 0) + 1

    print(f"\n📊 Device Types:")
    for dtype, count in sorted(categories.items()):
        print(f"   {dtype.capitalize()}: {count}")
    print()

    # === Step 4: Security analysis ===
    print("Step 4: Security Analysis")
    print("-"*60)
    print()

    # Check for insecure services
    insecure_services = ['telnet', 'ftp', 'http']
    risky_devices = []

    for device in devices:
        risky_ports = []
        for port in device['open_ports']:
            if port['service'] in insecure_services:
                risky_ports.append(port)

        if risky_ports:
            risky_devices.append((device, risky_ports))

    if risky_devices:
        print("⚠️  Devices with insecure services:")
        for device, ports in risky_devices:
            print(f"\n   {device['ip']} ({device['device_type']})")
            for port in ports:
                print(f"      - Port {port['port']}/{port['service']} (insecure)")
    else:
        print("✅ No devices with obviously insecure services")

    print()

    # Check for unknown devices
    unknown_devices = [d for d in devices if d['device_type'] == 'unknown']
    if unknown_devices:
        print("🚨 Unknown/Unidentified Devices:")
        for device in unknown_devices:
            print(f"\n   IP: {device['ip']}")
            print(f"   MAC: {device['mac']}")
            print(f"   Vendor: {device['vendor']}")
            print(f"   Open Ports: {[p['port'] for p in device['open_ports']]}")
            print(f"   ⚠️  Action: Investigate this device!")
    else:
        print("✅ All devices identified")

    print()

    # === Step 5: Update inventory ===
    print("Step 5: Updating Device Inventory")
    print("-"*60)

    db_path = Path(__file__).parent / 'demo_inventory.json'
    inventory = SimpleDeviceInventory(db_path)

    result = inventory.update_devices(devices)

    print(f"\n📝 Inventory Update:")
    print(f"   Total devices: {result['total_devices']}")
    print(f"   New devices: {len(result['new_devices'])}")
    print(f"   Updated devices: {len(result['updated_devices'])}")

    if result['new_devices']:
        print(f"\n🆕 New Devices Detected:")
        for device in result['new_devices']:
            print(f"   - {device['ip']} ({device['vendor']}) - {device['device_type']}")

    print(f"\n💾 Inventory saved to: {db_path}")
    print()

    # === Step 6: Generate report ===
    print("Step 6: Generating Network Security Report")
    print("-"*60)

    report = {
        'timestamp': datetime.now().isoformat(),
        'total_devices': len(devices),
        'device_types': categories,
        'security_issues': {
            'insecure_services': len(risky_devices),
            'unknown_devices': len(unknown_devices)
        },
        'recommendations': []
    }

    if risky_devices:
        report['recommendations'].append(
            f"Disable or secure {len(risky_devices)} devices with insecure services"
        )

    if unknown_devices:
        report['recommendations'].append(
            f"Investigate {len(unknown_devices)} unknown devices"
        )

    if not risky_devices and not unknown_devices:
        report['recommendations'].append("Network appears secure")

    print(f"\n📄 Security Report:")
    print(json.dumps(report, indent=2))

    report_path = Path(__file__).parent / 'security_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n💾 Report saved to: {report_path}")
    print()

    # === Summary ===
    print("="*60)
    print("Demo completed!")
    print("="*60)
    print()
    print("📚 What we learned:")
    print("   1. Network scanning discovers devices")
    print("   2. Device profiling identifies types (router, camera, phone...)")
    print("   3. Security analysis finds risky configurations")
    print("   4. Inventory tracking detects new/unknown devices")
    print("   5. Automated reporting for monitoring")
    print()
    print("💡 Real usage:")
    print("   sudo python src/scanner/network_scanner.py --subnet 192.168.1.0/24")
    print()
    print("🔗 Next: See example 04_alerting for notification system")
    print()


if __name__ == "__main__":
    main()
