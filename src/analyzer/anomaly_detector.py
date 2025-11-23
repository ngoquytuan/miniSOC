#!/usr/bin/env python3
"""
Anomaly Detector
Sử dụng Isolation Forest để phát hiện traffic bất thường
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from typing import Tuple, Optional
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest-based anomaly detector"""

    def __init__(self,
                 contamination: float = 0.05,
                 n_estimators: int = 100,
                 random_state: int = 42):
        """
        Args:
            contamination: Tỷ lệ anomaly expected (0.01 - 0.1)
            n_estimators: Số trees trong forest
            random_state: Random seed
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.model = None
        self.scaler = None
        self.feature_columns = None

    def train(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> Dict:
        """
        Train Isolation Forest model

        Args:
            X: Feature dataframe
            y: Labels (không sử dụng, vì unsupervised)

        Returns:
            Training metrics
        """
        logger.info(f"Training Isolation Forest on {len(X)} samples...")

        # Lưu feature columns
        self.feature_columns = X.columns.tolist()

        # Standardize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
            verbose=1
        )

        self.model.fit(X_scaled)

        # Evaluate on training data
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)

        n_anomalies = (predictions == -1).sum()
        anomaly_rate = n_anomalies / len(X) * 100

        metrics = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_anomalies': int(n_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'avg_score': float(np.mean(anomaly_scores)),
            'std_score': float(np.std(anomaly_scores)),
            'contamination': self.contamination
        }

        logger.info(f"✅ Training completed:")
        logger.info(f"   - Anomalies detected: {n_anomalies} ({anomaly_rate:.2f}%)")
        logger.info(f"   - Avg anomaly score: {metrics['avg_score']:.4f}")

        return metrics

    def predict(self, X: pd.DataFrame,
                return_scores: bool = False) -> np.ndarray:
        """
        Predict anomalies

        Args:
            X: Feature dataframe
            return_scores: Nếu True, return anomaly scores thay vì labels

        Returns:
            Array of predictions (-1 = anomaly, 1 = normal)
            hoặc anomaly scores
        """
        if self.model is None:
            raise ValueError("Model chưa được train! Call train() trước.")

        # Ensure same features
        X = X[self.feature_columns]

        # Scale features
        X_scaled = self.scaler.transform(X)

        if return_scores:
            # Return anomaly scores (càng âm = càng anomalous)
            scores = self.model.score_samples(X_scaled)
            # Normalize to [0, 1] (0 = anomaly, 1 = normal)
            normalized_scores = 1 / (1 + np.exp(-scores))
            return normalized_scores
        else:
            # Return labels
            return self.model.predict(X_scaled)

    def get_anomaly_scores(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Get detailed anomaly scores với metadata

        Returns:
            DataFrame với scores và predictions
        """
        scores = self.model.score_samples(self.scaler.transform(X[self.feature_columns]))
        predictions = self.model.predict(self.scaler.transform(X[self.feature_columns]))

        result = pd.DataFrame({
            'anomaly_score': scores,
            'normalized_score': 1 / (1 + np.exp(-scores)),
            'is_anomaly': (predictions == -1).astype(int),
            'prediction': predictions
        })

        return result

    def save(self, filepath: str):
        """Save model và scaler"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'contamination': self.contamination,
            'n_estimators': self.n_estimators
        }

        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"✅ Model saved to {filepath}")

    def load(self, filepath: str):
        """Load model và scaler"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        self.contamination = model_data.get('contamination', 0.05)
        self.n_estimators = model_data.get('n_estimators', 100)

        logger.info(f"✅ Model loaded from {filepath}")
        logger.info(f"   - Features: {len(self.feature_columns)}")


class AnomalyAnalyzer:
    """Phân tích và explain anomalies"""

    def __init__(self, detector: AnomalyDetector):
        self.detector = detector

    def analyze_anomalies(self,
                         X: pd.DataFrame,
                         top_n: int = 10) -> pd.DataFrame:
        """
        Phân tích top anomalies

        Args:
            X: Feature dataframe
            top_n: Số lượng top anomalies cần analyze

        Returns:
            DataFrame với top anomalies và feature contributions
        """
        # Get scores
        result = self.detector.get_anomaly_scores(X)

        # Get only anomalies
        anomalies = result[result['is_anomaly'] == 1].copy()

        if len(anomalies) == 0:
            logger.info("No anomalies detected")
            return pd.DataFrame()

        # Sort by score (most anomalous first)
        anomalies = anomalies.sort_values('anomaly_score')

        # Add original features
        anomalies = pd.concat([
            anomalies.reset_index(drop=True),
            X.iloc[anomalies.index].reset_index(drop=True)
        ], axis=1)

        logger.info(f"Found {len(anomalies)} anomalies, analyzing top {top_n}")
        return anomalies.head(top_n)

    def explain_anomaly(self,
                       X_sample: pd.Series,
                       baseline: pd.DataFrame) -> Dict:
        """
        Explain tại sao một sample bị coi là anomaly

        Args:
            X_sample: Single sample (Series)
            baseline: Normal data để so sánh

        Returns:
            Dictionary với explanation
        """
        explanation = {}

        # Compute stats cho từng feature
        for col in X_sample.index:
            if col not in baseline.columns:
                continue

            sample_val = X_sample[col]
            mean_val = baseline[col].mean()
            std_val = baseline[col].std()

            # Z-score
            z_score = (sample_val - mean_val) / std_val if std_val > 0 else 0

            # Percentile
            percentile = (baseline[col] < sample_val).sum() / len(baseline) * 100

            if abs(z_score) > 2:  # Significant deviation
                explanation[col] = {
                    'value': float(sample_val),
                    'mean': float(mean_val),
                    'std': float(std_val),
                    'z_score': float(z_score),
                    'percentile': float(percentile)
                }

        # Sort by absolute z-score
        explanation = dict(sorted(
            explanation.items(),
            key=lambda x: abs(x[1]['z_score']),
            reverse=True
        ))

        return explanation


def main():
    """Test anomaly detector"""
    from zeek_parser import ZeekLogParser
    from feature_extractor import FeatureExtractor

    # Load data
    parser = ZeekLogParser()
    extractor = FeatureExtractor()

    df_conn = parser.read_conn_log(hours=24)
    if df_conn.empty:
        logger.error("No connection data found")
        return

    # Extract features
    X = extractor.extract_features(df_conn)

    # Train model
    detector = AnomalyDetector(contamination=0.05)
    metrics = detector.train(X)

    print(f"\n📊 Training metrics:")
    for key, value in metrics.items():
        print(f"   {key}: {value}")

    # Analyze anomalies
    analyzer = AnomalyAnalyzer(detector)
    anomalies = analyzer.analyze_anomalies(X, top_n=5)

    if not anomalies.empty:
        print(f"\n🚨 Top 5 anomalies:")
        print(anomalies[['anomaly_score', 'normalized_score', 'total_bytes', 'duration']])

        # Explain first anomaly
        print(f"\n🔍 Explaining first anomaly:")
        explanation = analyzer.explain_anomaly(
            X.iloc[anomalies.index[0]],
            X
        )
        for feature, stats in list(explanation.items())[:5]:
            print(f"   {feature}:")
            print(f"      Value: {stats['value']:.2f} (mean: {stats['mean']:.2f}, z-score: {stats['z_score']:.2f})")

    # Save model
    detector.save('models/isolation_forest.pkl')


if __name__ == "__main__":
    main()
