#!/usr/bin/env python3
"""
Example: Full Mini-SOC Pipeline Demo
Demonstrates the complete workflow from log parsing to alerting

This end-to-end demo shows:
1. Parse Zeek logs
2. Extract features
3. Train ML model
4. Detect anomalies
5. Scan for devices
6. Send alerts
"""

import sys
import os
from pathlib import Path
import pandas as pd
import asyncio
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from analyzer.zeek_parser import ZeekLogParser
from analyzer.feature_extractor import FeatureExtractor
from analyzer.anomaly_detector import AnomalyDetector, AnomalyAnalyzer


class SimplifiedPipeline:
    """Simplified Mini-SOC pipeline for demo"""

    def __init__(self, sample_data_dir):
        self.sample_data_dir = Path(sample_data_dir)
        self.zeek_parser = ZeekLogParser(log_dir=str(self.sample_data_dir))
        self.feature_extractor = FeatureExtractor()
        self.detector = None
        self.alerts = []

    def step1_load_data(self):
        """Step 1: Load and parse Zeek logs"""
        print("\n" + "="*60)
        print("STEP 1: Loading Zeek Logs")
        print("="*60)

        conn_log = self.sample_data_dir / 'conn.log'
        dns_log = self.sample_data_dir / 'dns.log'

        self.df_conn = self.zeek_parser.read_conn_log(
            log_path=str(conn_log),
            hours=24
        )

        self.df_dns = pd.read_csv(
            dns_log,
            sep='\t',
            comment='#',
            names=self.zeek_parser._get_dns_columns(),
            na_values=['-', '(empty)'],
            low_memory=False
        )
        self.df_dns['ts'] = pd.to_datetime(self.df_dns['ts'], unit='s')

        print(f"✅ Loaded {len(self.df_conn)} connections")
        print(f"✅ Loaded {len(self.df_dns)} DNS queries")

        # Quick stats
        print(f"\n📊 Quick Statistics:")
        print(f"   Unique source IPs: {self.df_conn['id.orig_h'].nunique()}")
        print(f"   Unique dest IPs: {self.df_conn['id.resp_h'].nunique()}")
        print(f"   Protocols: {', '.join(self.df_conn['proto'].value_counts().index.tolist())}")
        print(f"   Total traffic: {(self.df_conn['orig_bytes'].sum() + self.df_conn['resp_bytes'].sum()) / 1024 / 1024:.2f} MB")

        return True

    def step2_extract_features(self):
        """Step 2: Extract ML features"""
        print("\n" + "="*60)
        print("STEP 2: Extracting Features for ML")
        print("="*60)

        self.X = self.feature_extractor.extract_features(
            self.df_conn,
            self.df_dns
        )

        print(f"✅ Extracted {self.X.shape[1]} features from {self.X.shape[0]} connections")
        print(f"\n📋 Feature preview:")
        print(f"   {', '.join(self.X.columns[:10].tolist())}...")

        return True

    def step3_train_model(self):
        """Step 3: Train ML model"""
        print("\n" + "="*60)
        print("STEP 3: Training ML Model (Isolation Forest)")
        print("="*60)

        self.detector = AnomalyDetector(
            contamination=0.15,
            n_estimators=100
        )

        print("⏳ Training model...")
        metrics = self.detector.train(self.X)

        print(f"\n✅ Model trained successfully!")
        print(f"   Anomalies detected: {metrics['n_anomalies']} ({metrics['anomaly_rate']:.1f}%)")
        print(f"   Avg score: {metrics['avg_score']:.4f}")

        return metrics

    def step4_detect_anomalies(self):
        """Step 4: Detect anomalies"""
        print("\n" + "="*60)
        print("STEP 4: Detecting Anomalies")
        print("="*60)

        analyzer = AnomalyAnalyzer(self.detector)
        self.anomalies = analyzer.analyze_anomalies(self.X, top_n=3)

        if self.anomalies.empty:
            print("✅ No critical anomalies detected")
            return []

        print(f"\n🚨 Found {len(self.anomalies)} anomalies!\n")

        detected_anomalies = []

        for idx, row in self.anomalies.iterrows():
            conn_idx = self.anomalies.index[idx]
            conn = self.df_conn.iloc[conn_idx]

            anomaly = {
                'type': 'anomaly',
                'severity': 'high' if row['normalized_score'] < 0.2 else 'medium',
                'source_ip': conn['id.orig_h'],
                'dest_ip': conn['id.resp_h'],
                'dest_port': conn['id.resp_p'],
                'score': row['normalized_score'],
                'bytes': row.get('total_bytes', 0),
                'duration': row.get('duration', 0)
            }

            print(f"Anomaly #{idx + 1}:")
            print(f"   {anomaly['source_ip']} → {anomaly['dest_ip']}:{anomaly['dest_port']}")
            print(f"   Score: {anomaly['score']:.4f} | Bytes: {anomaly['bytes']:,.0f} | Duration: {anomaly['duration']:.1f}s")
            print()

            detected_anomalies.append(anomaly)

        return detected_anomalies

    def step5_device_analysis(self):
        """Step 5: Analyze devices in network"""
        print("\n" + "="*60)
        print("STEP 5: Device Analysis")
        print("="*60)

        # Get unique devices from connections
        devices_src = self.df_conn['id.orig_h'].unique()
        devices_dst = self.df_conn[
            self.df_conn['id.resp_h'].str.startswith('192.168.')
        ]['id.resp_h'].unique()

        all_devices = set(list(devices_src) + list(devices_dst))

        print(f"\n📱 Discovered {len(all_devices)} unique devices:")
        for ip in sorted(all_devices):
            # Count connections
            conn_count = len(self.df_conn[
                (self.df_conn['id.orig_h'] == ip) |
                (self.df_conn['id.resp_h'] == ip)
            ])
            print(f"   {ip:15} - {conn_count:3d} connections")

        # Check for suspicious IPs
        print(f"\n🔍 Security Analysis:")

        # External IPs contacted
        external_ips = self.df_conn[
            ~self.df_conn['id.resp_h'].str.startswith('192.168.')
        ]['id.resp_h'].value_counts()

        print(f"   External IPs contacted: {len(external_ips)}")
        print(f"   Top 3 external destinations:")
        for ip, count in external_ips.head(3).items():
            print(f"      {ip}: {count} connections")

        return list(all_devices)

    def step6_generate_alerts(self, anomalies):
        """Step 6: Generate alerts for detected issues"""
        print("\n" + "="*60)
        print("STEP 6: Generating Alerts")
        print("="*60)

        if not anomalies:
            print("\n✅ No alerts needed - system healthy")
            return []

        print(f"\n📢 Generating {len(anomalies)} alerts...\n")

        alerts = []
        for i, anomaly in enumerate(anomalies, 1):
            alert = {
                'timestamp': datetime.now().isoformat(),
                'id': f'ALERT-{i:03d}',
                'type': 'anomaly',
                'severity': anomaly['severity'],
                'title': 'Anomalous Network Traffic',
                'message': f"Unusual traffic from {anomaly['source_ip']} to {anomaly['dest_ip']}",
                'details': {
                    'source': anomaly['source_ip'],
                    'destination': f"{anomaly['dest_ip']}:{anomaly['dest_port']}",
                    'score': f"{anomaly['score']:.4f}",
                    'bytes': f"{anomaly['bytes']:,.0f}",
                    'duration': f"{anomaly['duration']:.1f}s"
                },
                'recommended_action': 'Investigate source host for malware'
            }

            severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
            emoji = severity_emoji.get(alert['severity'], '⚪')

            print(f"{emoji} {alert['id']}: {alert['title']}")
            print(f"   Severity: {alert['severity'].upper()}")
            print(f"   {alert['message']}")
            print(f"   Details: {alert['details']}")
            print(f"   Action: {alert['recommended_action']}")
            print()

            alerts.append(alert)

        return alerts

    def step7_summary_report(self, metrics, anomalies, devices, alerts):
        """Step 7: Generate summary report"""
        print("\n" + "="*60)
        print("STEP 7: Security Summary Report")
        print("="*60)

        report = {
            'timestamp': datetime.now().isoformat(),
            'time_period': '24 hours',
            'overview': {
                'total_connections': len(self.df_conn),
                'total_dns_queries': len(self.df_dns),
                'devices_discovered': len(devices),
                'anomalies_detected': metrics['n_anomalies'],
                'alerts_generated': len(alerts)
            },
            'traffic_stats': {
                'total_bytes': int(self.df_conn['orig_bytes'].sum() + self.df_conn['resp_bytes'].sum()),
                'protocols': self.df_conn['proto'].value_counts().to_dict(),
                'top_talkers': self.df_conn['id.orig_h'].value_counts().head(3).to_dict()
            },
            'security_status': 'HIGH ALERT' if len(alerts) > 0 else 'SECURE',
            'recommendations': []
        }

        if anomalies:
            report['recommendations'].append(
                f"Investigate {len(anomalies)} anomalous connections"
            )
        if len(devices) > 20:
            report['recommendations'].append(
                "Consider network segmentation - many devices detected"
            )

        print(f"\n📊 MINI-SOC SECURITY REPORT")
        print(f"{'='*60}")
        print(f"Period: {report['time_period']}")
        print(f"Generated: {report['timestamp']}")
        print()
        print(f"📈 Overview:")
        for key, value in report['overview'].items():
            print(f"   {key.replace('_', ' ').title()}: {value}")
        print()
        print(f"🚦 Security Status: {report['security_status']}")
        if report['recommendations']:
            print(f"\n⚠️  Recommendations:")
            for rec in report['recommendations']:
                print(f"   • {rec}")

        print()
        return report


def main():
    print("="*60)
    print("   Mini-SOC: End-to-End Demo")
    print("   Full Pipeline Demonstration")
    print("="*60)
    print()
    print("This demo simulates a complete Mini-SOC workflow:")
    print("  1. Parse Zeek network logs")
    print("  2. Extract features for ML")
    print("  3. Train anomaly detection model")
    print("  4. Detect anomalous traffic")
    print("  5. Analyze network devices")
    print("  6. Generate security alerts")
    print("  7. Create summary report")
    print()
    input("Press Enter to start demo...")

    # Initialize pipeline
    sample_dir = Path(__file__).parent.parent / 'sample_data'
    pipeline = SimplifiedPipeline(sample_dir)

    try:
        # Run pipeline steps
        pipeline.step1_load_data()
        input("\nPress Enter to continue...")

        pipeline.step2_extract_features()
        input("\nPress Enter to continue...")

        metrics = pipeline.step3_train_model()
        input("\nPress Enter to continue...")

        anomalies = pipeline.step4_detect_anomalies()
        input("\nPress Enter to continue...")

        devices = pipeline.step5_device_analysis()
        input("\nPress Enter to continue...")

        alerts = pipeline.step6_generate_alerts(anomalies)
        input("\nPress Enter to continue...")

        report = pipeline.step7_summary_report(metrics, anomalies, devices, alerts)

        # Final summary
        print("\n" + "="*60)
        print("🎉 Demo Completed Successfully!")
        print("="*60)
        print()
        print("✅ All pipeline steps executed")
        print(f"📊 Processed {len(pipeline.df_conn)} connections")
        print(f"🚨 Generated {len(alerts)} alerts")
        print()
        print("💡 What's next?")
        print("   • Deploy to production: docker-compose up -d")
        print("   • Configure Mikrotik for traffic mirroring")
        print("   • Set up Telegram/Email alerts")
        print("   • Train model with real 7-day data")
        print("   • Access Grafana dashboard: http://192.168.1.70:3000")
        print()
        print("📚 Documentation:")
        print("   • QUICKSTART.md - Quick deployment guide")
        print("   • docs/DEPLOYMENT_GUIDE.md - Full documentation")
        print("   • examples/ - Individual component demos")
        print()

    except KeyboardInterrupt:
        print("\n\n⏸  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
