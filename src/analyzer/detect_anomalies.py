#!/usr/bin/env python3
"""
Anomaly Detection Script
Chạy real-time hoặc batch anomaly detection
"""

import argparse
import sys
import time
from pathlib import Path
from datetime import datetime
import logging
import pandas as pd

from zeek_parser import ZeekLogParser
from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer

# Import alerting (sẽ tạo sau)
sys.path.append(str(Path(__file__).parent.parent / 'alerting'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AnomalyMonitor:
    """Monitor traffic và detect anomalies"""

    def __init__(self,
                 model_path: str,
                 zeek_logs: str = '/opt/zeek/logs',
                 threshold: float = 0.3):
        """
        Args:
            model_path: Path to trained model
            zeek_logs: Path to Zeek logs
            threshold: Anomaly score threshold (0-1, lower = more anomalous)
        """
        self.zeek_parser = ZeekLogParser(log_dir=zeek_logs)
        self.feature_extractor = FeatureExtractor()
        self.threshold = threshold

        # Load model
        logger.info(f"Loading model from {model_path}")
        self.detector = AnomalyDetector()
        self.detector.load(model_path)

        self.analyzer = AnomalyAnalyzer(self.detector)

    def check_recent_traffic(self, minutes: int = 5) -> pd.DataFrame:
        """
        Check traffic trong N phút gần nhất

        Args:
            minutes: Số phút cần check

        Returns:
            DataFrame với detected anomalies
        """
        hours = minutes / 60.0

        # Load recent logs
        df_conn = self.zeek_parser.read_conn_log(hours=hours)
        df_dns = self.zeek_parser.read_dns_log(hours=hours)

        if df_conn.empty:
            logger.warning(f"No traffic found in last {minutes} minutes")
            return pd.DataFrame()

        logger.info(f"Analyzing {len(df_conn)} connections from last {minutes} minutes")

        # Extract features
        X = self.feature_extractor.extract_features(df_conn, df_dns)

        # Detect anomalies
        scores = self.detector.get_anomaly_scores(X)

        # Filter by threshold
        anomalies_mask = scores['normalized_score'] < self.threshold

        if anomalies_mask.sum() == 0:
            logger.info("✅ No anomalies detected")
            return pd.DataFrame()

        # Combine results với original data
        anomalies = pd.concat([
            df_conn[anomalies_mask].reset_index(drop=True),
            scores[anomalies_mask].reset_index(drop=True)
        ], axis=1)

        logger.warning(f"🚨 Detected {len(anomalies)} anomalies!")

        return anomalies

    def monitor_continuous(self, interval: int = 300):
        """
        Continuous monitoring mode

        Args:
            interval: Check interval in seconds (default: 5 minutes)
        """
        logger.info(f"🔍 Starting continuous monitoring (interval: {interval}s)")
        logger.info(f"   Threshold: {self.threshold}")
        logger.info(f"   Press Ctrl+C to stop")

        try:
            while True:
                logger.info(f"\n{'='*60}")
                logger.info(f"Check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                logger.info(f"{'='*60}")

                # Check traffic
                anomalies = self.check_recent_traffic(minutes=interval//60)

                if not anomalies.empty:
                    self._handle_anomalies(anomalies)

                # Sleep until next check
                logger.info(f"\n💤 Sleeping for {interval} seconds...")
                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("\n⏹ Monitoring stopped by user")

    def _handle_anomalies(self, anomalies: pd.DataFrame):
        """Handle detected anomalies"""
        # Log top anomalies
        logger.warning(f"\n🚨 ANOMALIES DETECTED: {len(anomalies)}")

        for idx, row in anomalies.iterrows():
            logger.warning(
                f"   [{idx+1}] {row['id.orig_h']} → {row['id.resp_h']}:{row['id.resp_p']} "
                f"| Score: {row['normalized_score']:.4f} "
                f"| Bytes: {row.get('orig_bytes', 0) + row.get('resp_bytes', 0):.0f} "
                f"| Proto: {row.get('proto', 'unknown')}"
            )

        # TODO: Send alerts (Telegram, Email)
        # self._send_alerts(anomalies)

        # Save to file
        self._save_anomalies(anomalies)

    def _save_anomalies(self, anomalies: pd.DataFrame):
        """Save anomalies to file"""
        output_dir = Path('logs/anomalies')
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f'anomalies_{timestamp}.csv'

        anomalies.to_csv(output_file, index=False)
        logger.info(f"💾 Anomalies saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect anomalies trong network traffic'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='models/isolation_forest.pkl',
        help='Path to trained model'
    )
    parser.add_argument(
        '--zeek-logs',
        type=str,
        default='/opt/zeek/logs',
        help='Path to Zeek logs directory'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=0.3,
        help='Anomaly score threshold (0-1, lower = more strict)'
    )
    parser.add_argument(
        '--mode',
        type=str,
        choices=['batch', 'continuous'],
        default='batch',
        help='Detection mode: batch (one-time) or continuous (monitoring)'
    )
    parser.add_argument(
        '--minutes',
        type=int,
        default=5,
        help='Minutes of traffic to analyze (batch mode)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Check interval in seconds (continuous mode)'
    )

    args = parser.parse_args()

    # Check if model exists
    if not Path(args.model).exists():
        logger.error(f"❌ Model not found: {args.model}")
        logger.error("Train model trước: python src/analyzer/train_model.py")
        sys.exit(1)

    # Create monitor
    monitor = AnomalyMonitor(
        model_path=args.model,
        zeek_logs=args.zeek_logs,
        threshold=args.threshold
    )

    # Run detection
    if args.mode == 'batch':
        logger.info(f"🔍 Running batch detection on last {args.minutes} minutes")
        anomalies = monitor.check_recent_traffic(minutes=args.minutes)

        if not anomalies.empty:
            monitor._handle_anomalies(anomalies)
        else:
            logger.info("✅ No anomalies detected in this time window")

    else:  # continuous
        monitor.monitor_continuous(interval=args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
