#!/usr/bin/env python3
"""
Example: ML Anomaly Detection Demo
Demonstrates training and using Isolation Forest for anomaly detection
"""

import sys
import os
from pathlib import Path
import pandas as pd

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from analyzer.zeek_parser import ZeekLogParser
from analyzer.feature_extractor import FeatureExtractor
from analyzer.anomaly_detector import AnomalyDetector, AnomalyAnalyzer


def main():
    print("="*60)
    print("   ML Anomaly Detection Demo")
    print("="*60)
    print()

    # Path to sample data
    sample_dir = Path(__file__).parent.parent / 'sample_data'

    print("📂 Using sample data from:", sample_dir)
    print()

    # === Step 1: Load and parse Zeek logs ===
    print("Step 1: Loading Zeek logs...")
    print("-"*60)

    parser = ZeekLogParser(log_dir=str(sample_dir))
    conn_log_path = sample_dir / 'conn.log'
    dns_log_path = sample_dir / 'dns.log'

    df_conn = parser.read_conn_log(log_path=str(conn_log_path), hours=24)

    # Parse DNS manually
    df_dns = pd.read_csv(
        dns_log_path,
        sep='\t',
        comment='#',
        names=parser._get_dns_columns(),
        na_values=['-', '(empty)'],
        low_memory=False
    )
    df_dns['ts'] = pd.to_datetime(df_dns['ts'], unit='s')

    print(f"✅ Loaded {len(df_conn)} connections")
    print(f"✅ Loaded {len(df_dns)} DNS queries")
    print()

    # === Step 2: Extract features ===
    print("Step 2: Extracting features for ML...")
    print("-"*60)

    extractor = FeatureExtractor()
    X = extractor.extract_features(df_conn, df_dns)

    print(f"✅ Extracted {X.shape[1]} features from {X.shape[0]} connections")
    print(f"\n📊 Feature names:")
    for i, col in enumerate(X.columns, 1):
        print(f"   {i:2d}. {col}")
    print()

    # Show sample features
    print("📋 Sample feature values (first 3 connections):")
    print(X.head(3).T)
    print()

    # === Step 3: Train Isolation Forest ===
    print("Step 3: Training Isolation Forest model...")
    print("-"*60)

    detector = AnomalyDetector(
        contamination=0.15,  # Expect ~15% anomalies in this demo
        n_estimators=100
    )

    metrics = detector.train(X)

    print(f"\n📈 Training Results:")
    print(f"   Samples: {metrics['n_samples']}")
    print(f"   Features: {metrics['n_features']}")
    print(f"   Anomalies detected: {metrics['n_anomalies']} ({metrics['anomaly_rate']:.2f}%)")
    print(f"   Avg anomaly score: {metrics['avg_score']:.4f} ± {metrics['std_score']:.4f}")
    print()

    # === Step 4: Analyze anomalies ===
    print("Step 4: Analyzing detected anomalies...")
    print("-"*60)

    analyzer = AnomalyAnalyzer(detector)
    anomalies = analyzer.analyze_anomalies(X, top_n=5)

    if not anomalies.empty:
        print(f"\n🚨 Top {len(anomalies)} Anomalies:\n")

        for idx, row in anomalies.iterrows():
            conn_idx = anomalies.index[idx]
            conn_row = df_conn.iloc[conn_idx]

            print(f"{'='*60}")
            print(f"Anomaly #{idx + 1}")
            print(f"{'='*60}")
            print(f"   Connection: {conn_row['id.orig_h']} → {conn_row['id.resp_h']}:{conn_row['id.resp_p']}")
            print(f"   Protocol: {conn_row['proto']}")
            print(f"   Anomaly Score: {row['anomaly_score']:.4f}")
            print(f"   Normalized Score: {row['normalized_score']:.4f}")
            print(f"   Duration: {row.get('duration', 0):.2f}s")
            print(f"   Total Bytes: {row.get('total_bytes', 0):,.0f}")
            print(f"   Orig Bytes: {row.get('orig_bytes', 0):,.0f}")
            print(f"   Resp Bytes: {row.get('resp_bytes', 0):,.0f}")
            print()

            # Explain why it's anomalous
            explanation = analyzer.explain_anomaly(
                X.iloc[conn_idx],
                X
            )

            if explanation:
                print(f"   🔍 Why this is anomalous (top deviations):")
                for i, (feature, stats) in enumerate(list(explanation.items())[:3], 1):
                    print(f"      {i}. {feature}:")
                    print(f"         Value: {stats['value']:.2f}")
                    print(f"         Mean: {stats['mean']:.2f}")
                    print(f"         Z-score: {stats['z_score']:.2f}")
                    print(f"         Percentile: {stats['percentile']:.1f}%")
            print()

    # === Step 5: Visualize anomaly scores ===
    print("Step 5: Anomaly Score Distribution")
    print("-"*60)

    scores = detector.get_anomaly_scores(X)

    print(f"\n📊 Anomaly Score Statistics:")
    print(f"   Min: {scores['anomaly_score'].min():.4f}")
    print(f"   Max: {scores['anomaly_score'].max():.4f}")
    print(f"   Mean: {scores['anomaly_score'].mean():.4f}")
    print(f"   Median: {scores['anomaly_score'].median():.4f}")
    print()

    # Simple ASCII histogram
    print("📈 Score Distribution (Normalized):")
    bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    hist = pd.cut(scores['normalized_score'], bins=bins).value_counts().sort_index()

    for interval, count in hist.items():
        bar = '█' * int(count / len(scores) * 50)
        print(f"   {interval}: {bar} ({count})")
    print()

    # === Step 6: Test real-time detection ===
    print("Step 6: Simulating real-time detection on new data...")
    print("-"*60)

    # Use last 3 connections as "new" data
    X_new = X.tail(3)
    predictions = detector.predict(X_new, return_scores=True)

    print(f"\n🔍 Checking {len(X_new)} new connections:")
    for i, (idx, score) in enumerate(zip(X_new.index, predictions)):
        conn = df_conn.iloc[idx]
        status = "🚨 ANOMALY" if score < 0.3 else "✅ Normal"
        print(f"   {i+1}. {conn['id.orig_h']} → {conn['id.resp_h']} | Score: {score:.4f} | {status}")
    print()

    # === Summary ===
    print("="*60)
    print("Demo completed!")
    print("="*60)
    print()
    print("📚 What we learned:")
    print("   1. Parse Zeek logs into DataFrames")
    print("   2. Extract features for ML")
    print("   3. Train Isolation Forest model")
    print("   4. Detect and analyze anomalies")
    print("   5. Explain why connections are anomalous")
    print()
    print("💡 Next steps:")
    print("   - Try with your own Zeek logs")
    print("   - Adjust contamination parameter (currently 0.15)")
    print("   - Train with more days of data for better accuracy")
    print("   - See example 03_device_scanner for network scanning")
    print()

    # === Optional: Save model ===
    model_path = Path(__file__).parent / 'demo_model.pkl'
    detector.save(str(model_path))
    print(f"💾 Model saved to: {model_path}")
    print()


if __name__ == "__main__":
    main()
