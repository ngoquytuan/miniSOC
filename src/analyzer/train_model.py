#!/usr/bin/env python3
"""
Training Script
Huấn luyện Isolation Forest model từ Zeek logs
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
import logging

from zeek_parser import ZeekLogParser
from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description='Train Isolation Forest model từ Zeek logs'
    )
    parser.add_argument(
        '--zeek-logs',
        type=str,
        default='/opt/zeek/logs',
        help='Path to Zeek logs directory'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='models/isolation_forest.pkl',
        help='Output path cho trained model'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Số ngày training data cần sử dụng'
    )
    parser.add_argument(
        '--contamination',
        type=float,
        default=0.05,
        help='Expected contamination rate (0.01-0.1)'
    )
    parser.add_argument(
        '--n-estimators',
        type=int,
        default=100,
        help='Số trees trong Isolation Forest'
    )
    parser.add_argument(
        '--use-current',
        action='store_true',
        help='Sử dụng current logs thay vì archived'
    )

    args = parser.parse_args()

    logger.info("="*60)
    logger.info("Mini-SOC: Isolation Forest Training")
    logger.info("="*60)

    # 1. Load Zeek logs
    logger.info(f"\n📂 Loading Zeek logs from {args.zeek_logs}")
    zeek_parser = ZeekLogParser(log_dir=args.zeek_logs)

    if args.use_current:
        logger.info("Using current logs (last 24 hours)")
        df_conn = zeek_parser.read_conn_log(hours=24)
        df_dns = zeek_parser.read_dns_log(hours=24)
    else:
        logger.info(f"Loading archived logs from last {args.days} days")
        df_conn = zeek_parser.read_archived_logs(log_type='conn', days=args.days)
        df_dns = zeek_parser.read_archived_logs(log_type='dns', days=args.days)

    if df_conn.empty:
        logger.error("❌ No connection data found!")
        logger.error("Kiểm tra:")
        logger.error(f"  1. Zeek có đang chạy? (zeekctl status)")
        logger.error(f"  2. Logs có tồn tại? (ls {args.zeek_logs})")
        sys.exit(1)

    logger.info(f"✅ Loaded {len(df_conn):,} connections")
    if not df_dns.empty:
        logger.info(f"✅ Loaded {len(df_dns):,} DNS queries")

    # 2. Extract features
    logger.info("\n🔧 Extracting features...")
    feature_extractor = FeatureExtractor()

    X = feature_extractor.extract_features(df_conn, df_dns)
    logger.info(f"✅ Extracted {X.shape[1]} features from {X.shape[0]} samples")

    # Log feature stats
    logger.info(f"\n📊 Feature statistics:")
    logger.info(f"   Total bytes (mean): {X['total_bytes'].mean():.2f}")
    logger.info(f"   Duration (mean): {X['duration'].mean():.2f}s")
    logger.info(f"   TCP connections: {X['proto_tcp'].sum()} ({X['proto_tcp'].mean()*100:.1f}%)")

    # 3. Train model
    logger.info(f"\n🤖 Training Isolation Forest...")
    logger.info(f"   Contamination: {args.contamination}")
    logger.info(f"   N-estimators: {args.n_estimators}")

    detector = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators
    )

    metrics = detector.train(X)

    # 4. Analyze results
    logger.info(f"\n📈 Training Results:")
    logger.info(f"   Samples: {metrics['n_samples']:,}")
    logger.info(f"   Features: {metrics['n_features']}")
    logger.info(f"   Anomalies detected: {metrics['n_anomalies']:,} ({metrics['anomaly_rate']:.2f}%)")
    logger.info(f"   Avg anomaly score: {metrics['avg_score']:.4f} ± {metrics['std_score']:.4f}")

    # 5. Analyze top anomalies
    analyzer = AnomalyAnalyzer(detector)
    anomalies = analyzer.analyze_anomalies(X, top_n=10)

    if not anomalies.empty:
        logger.info(f"\n🚨 Top 10 Anomalies:")
        for idx, row in anomalies.iterrows():
            logger.info(f"   #{idx}: score={row['anomaly_score']:.4f}, "
                       f"bytes={row.get('total_bytes', 0):.0f}, "
                       f"duration={row.get('duration', 0):.2f}s")

    # 6. Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    detector.save(str(output_path))
    logger.info(f"\n💾 Model saved to {output_path}")

    # 7. Save training metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'zeek_logs_path': args.zeek_logs,
        'training_days': args.days,
        'metrics': metrics,
        'feature_columns': detector.feature_columns,
        'contamination': args.contamination,
        'n_estimators': args.n_estimators
    }

    metadata_path = output_path.parent / 'training_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"📝 Metadata saved to {metadata_path}")

    # 8. Summary
    logger.info("\n" + "="*60)
    logger.info("✅ Training completed successfully!")
    logger.info("="*60)
    logger.info(f"\nNext steps:")
    logger.info(f"  1. Test model: python src/analyzer/detect_anomalies.py")
    logger.info(f"  2. Review top anomalies trong logs")
    logger.info(f"  3. Adjust threshold nếu cần thiết")
    logger.info(f"  4. Deploy model vào production")

    return 0


if __name__ == "__main__":
    sys.exit(main())
