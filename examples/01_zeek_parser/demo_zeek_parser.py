#!/usr/bin/env python3
"""
Example: Zeek Log Parser Demo
Demonstrates how to parse Zeek logs using ZeekLogParser
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from analyzer.zeek_parser import ZeekLogParser


def main():
    print("="*60)
    print("     Zeek Log Parser Demo")
    print("="*60)
    print()

    # Path to sample data
    sample_dir = Path(__file__).parent.parent / 'sample_data'

    print(f"📂 Using sample data from: {sample_dir}")
    print()

    # Create parser
    parser = ZeekLogParser(log_dir=str(sample_dir))

    # === Demo 1: Parse connection log ===
    print("="*60)
    print("Demo 1: Parsing Connection Log (conn.log)")
    print("="*60)

    conn_log_path = sample_dir / 'conn.log'
    df_conn = parser.read_conn_log(log_path=str(conn_log_path), hours=24)

    if not df_conn.empty:
        print(f"\n✅ Loaded {len(df_conn)} connections")
        print(f"\nColumns available:")
        print(df_conn.columns.tolist())

        print(f"\n📊 First 5 connections:")
        print(df_conn[['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'orig_bytes', 'resp_bytes']].head())

        # Statistics
        print(f"\n📈 Connection Statistics:")
        print(f"   Total bytes transferred: {(df_conn['orig_bytes'].sum() + df_conn['resp_bytes'].sum()):,} bytes")
        print(f"   Protocols:")
        print(df_conn['proto'].value_counts().to_string())

        # Top talkers
        print(f"\n👥 Top 5 Source IPs:")
        print(df_conn['id.orig_h'].value_counts().head())

        print(f"\n🎯 Top 5 Destination IPs:")
        print(df_conn['id.resp_h'].value_counts().head())

        # Identify potential anomalies (large data transfers)
        print(f"\n🚨 Connections with large data transfer (>100KB):")
        large_transfers = df_conn[
            (df_conn['orig_bytes'] + df_conn['resp_bytes']) > 100000
        ]
        if not large_transfers.empty:
            print(large_transfers[['id.orig_h', 'id.resp_h', 'orig_bytes', 'resp_bytes', 'duration']])
        else:
            print("   None found")

    # === Demo 2: Parse DNS log ===
    print("\n" + "="*60)
    print("Demo 2: Parsing DNS Log (dns.log)")
    print("="*60)

    dns_log_path = sample_dir / 'dns.log'

    # Custom parsing for DNS log
    import pandas as pd
    try:
        df_dns = pd.read_csv(
            dns_log_path,
            sep='\t',
            comment='#',
            names=parser._get_dns_columns(),
            na_values=['-', '(empty)'],
            low_memory=False
        )

        if not df_dns.empty:
            print(f"\n✅ Loaded {len(df_dns)} DNS queries")

            print(f"\n🌐 Top 5 Queried Domains:")
            print(df_dns['query'].value_counts().head())

            print(f"\n📊 DNS Response Codes:")
            print(df_dns['rcode_name'].value_counts().to_string())

            # Identify suspicious domains
            print(f"\n⚠️  Potentially Suspicious Domains:")
            suspicious_keywords = ['malicious', 'c2', 'suspicious', 'phishing', 'dga']
            suspicious_domains = df_dns[
                df_dns['query'].str.contains('|'.join(suspicious_keywords), case=False, na=False)
            ]
            if not suspicious_domains.empty:
                print(suspicious_domains[['ts', 'id.orig_h', 'query', 'answers']])
            else:
                print("   None found in this sample")

    except Exception as e:
        print(f"❌ Error parsing DNS log: {e}")

    # === Demo 3: Correlation ===
    print("\n" + "="*60)
    print("Demo 3: Correlating Connection and DNS Data")
    print("="*60)

    if not df_conn.empty and not df_dns.empty:
        print(f"\nFinding connections with DNS resolution...")

        # Get unique source IPs from both logs
        conn_ips = set(df_conn['id.orig_h'].unique())
        dns_ips = set(df_dns['id.orig_h'].unique())

        common_ips = conn_ips.intersection(dns_ips)
        print(f"\n📍 IPs with both connections and DNS queries: {len(common_ips)}")
        print(f"   {list(common_ips)[:5]}")

        # Find IPs with connections but no DNS (suspicious?)
        no_dns = conn_ips - dns_ips
        if no_dns:
            print(f"\n⚠️  IPs with connections but NO DNS queries: {len(no_dns)}")
            print(f"   (Could indicate direct IP connections)")
            print(f"   {list(no_dns)[:5]}")

    print("\n" + "="*60)
    print("Demo completed!")
    print("="*60)
    print()
    print("💡 Next steps:")
    print("   - Try with your own Zeek logs from /opt/zeek/logs/current/")
    print("   - See example 02_ml_detector for anomaly detection")
    print()


if __name__ == "__main__":
    main()
