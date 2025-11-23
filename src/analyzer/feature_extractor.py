#!/usr/bin/env python3
"""
Feature Extractor
Trích xuất features từ Zeek logs để sử dụng cho ML models
"""

import pandas as pd
import numpy as np
from typing import Dict, List
import logging
from collections import Counter
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Trích xuất features từ connection data"""

    def __init__(self):
        # Top 1 million domains (simplified - trong thực tế load từ file)
        self.popular_domains = self._load_popular_domains()
        self.known_services = {'http', 'https', 'dns', 'ssh', 'smtp', 'ftp'}

    def extract_features(self, df_conn: pd.DataFrame,
                        df_dns: pd.DataFrame = None) -> pd.DataFrame:
        """
        Extract features từ connection dataframe

        Args:
            df_conn: DataFrame từ conn.log
            df_dns: DataFrame từ dns.log (optional)

        Returns:
            DataFrame với features cho ML
        """
        logger.info(f"Extracting features from {len(df_conn)} connections...")

        features = pd.DataFrame()

        # === Basic features ===
        features['duration'] = df_conn['duration'].fillna(0)
        features['orig_bytes'] = df_conn['orig_bytes'].fillna(0)
        features['resp_bytes'] = df_conn['resp_bytes'].fillna(0)
        features['orig_pkts'] = df_conn['orig_pkts'].fillna(0)
        features['resp_pkts'] = df_conn['resp_pkts'].fillna(0)

        # === Derived features ===
        # Tỷ lệ bytes gửi/nhận
        features['bytes_ratio'] = self._safe_divide(
            features['orig_bytes'],
            features['resp_bytes']
        )

        # Bytes per packet
        features['orig_bytes_per_pkt'] = self._safe_divide(
            features['orig_bytes'],
            features['orig_pkts']
        )
        features['resp_bytes_per_pkt'] = self._safe_divide(
            features['resp_bytes'],
            features['resp_pkts']
        )

        # Total bytes
        features['total_bytes'] = features['orig_bytes'] + features['resp_bytes']

        # === Protocol features ===
        features['proto_tcp'] = (df_conn['proto'] == 'tcp').astype(int)
        features['proto_udp'] = (df_conn['proto'] == 'udp').astype(int)
        features['proto_icmp'] = (df_conn['proto'] == 'icmp').astype(int)

        # === Service features ===
        features['service_known'] = df_conn['service'].isin(self.known_services).astype(int)

        # === Connection state ===
        features['conn_state_sf'] = (df_conn['conn_state'] == 'SF').astype(int)  # Successful
        features['conn_state_rej'] = (df_conn['conn_state'] == 'REJ').astype(int)  # Rejected
        features['conn_state_s0'] = (df_conn['conn_state'] == 'S0').astype(int)  # No response

        # === Port features ===
        features['orig_port'] = df_conn['id.orig_p'].fillna(0)
        features['resp_port'] = df_conn['id.resp_p'].fillna(0)

        # Common ports
        features['resp_port_80'] = (df_conn['id.resp_p'] == 80).astype(int)
        features['resp_port_443'] = (df_conn['id.resp_p'] == 443).astype(int)
        features['resp_port_22'] = (df_conn['id.resp_p'] == 22).astype(int)
        features['resp_port_high'] = (df_conn['id.resp_p'] > 1024).astype(int)

        # === Time-based features ===
        if 'ts' in df_conn.columns:
            features['hour'] = df_conn['ts'].dt.hour
            features['is_night'] = features['hour'].apply(
                lambda h: 1 if h < 6 or h > 22 else 0
            )

        # === IP-based features ===
        features['is_local_orig'] = df_conn['id.orig_h'].apply(
            self._is_private_ip
        ).astype(int)
        features['is_local_resp'] = df_conn['id.resp_h'].apply(
            self._is_private_ip
        ).astype(int)

        # === DNS features (if available) ===
        if df_dns is not None and not df_dns.empty:
            dns_features = self._extract_dns_features(df_conn, df_dns)
            features = pd.concat([features, dns_features], axis=1)

        # Fill NaN values
        features = features.fillna(0)

        # Replace infinity values
        features = features.replace([np.inf, -np.inf], 0)

        logger.info(f"Extracted {len(features.columns)} features")
        return features

    def extract_per_host_features(self, df_conn: pd.DataFrame,
                                  time_window: str = '1H') -> pd.DataFrame:
        """
        Aggregate features per host trong time window

        Args:
            df_conn: Connection dataframe
            time_window: Time window (vd: '1H', '5T')

        Returns:
            DataFrame với aggregated features per host
        """
        logger.info(f"Extracting per-host features with {time_window} window")

        # Group by source IP và time window
        df_conn['time_bin'] = df_conn['ts'].dt.floor(time_window)

        agg_features = df_conn.groupby(['id.orig_h', 'time_bin']).agg({
            'id.resp_h': 'nunique',  # Unique destinations
            'id.resp_p': 'nunique',  # Unique dest ports
            'orig_bytes': ['sum', 'mean', 'std'],
            'resp_bytes': ['sum', 'mean', 'std'],
            'duration': ['mean', 'std'],
            'conn_state': lambda x: (x == 'SF').sum() / len(x) if len(x) > 0 else 0  # Success rate
        }).reset_index()

        # Flatten column names
        agg_features.columns = ['_'.join(col).strip('_') for col in agg_features.columns.values]

        return agg_features

    def _extract_dns_features(self, df_conn: pd.DataFrame,
                              df_dns: pd.DataFrame) -> pd.DataFrame:
        """Extract DNS-specific features"""
        dns_features = pd.DataFrame(index=df_conn.index)

        # Map DNS queries to connections by UID
        dns_map = df_dns.groupby('uid')['query'].apply(list).to_dict()

        dns_features['has_dns'] = df_conn['uid'].isin(dns_map.keys()).astype(int)

        # Domain popularity (simplified)
        def get_domain_popularity(uid):
            if uid not in dns_map:
                return 0
            domains = dns_map[uid]
            # Check if any domain is in popular list
            for domain in domains:
                if domain in self.popular_domains:
                    return 1
            return 0

        dns_features['domain_is_popular'] = df_conn['uid'].apply(get_domain_popularity)

        # Domain length
        def get_avg_domain_len(uid):
            if uid not in dns_map:
                return 0
            domains = dns_map[uid]
            return np.mean([len(d) for d in domains]) if domains else 0

        dns_features['avg_domain_len'] = df_conn['uid'].apply(get_avg_domain_len)

        return dns_features

    @staticmethod
    def _safe_divide(a: pd.Series, b: pd.Series, default: float = 0) -> pd.Series:
        """Safe division để tránh divide by zero"""
        result = a / b.replace(0, np.nan)
        return result.fillna(default)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private (RFC1918)"""
        if pd.isna(ip):
            return False

        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            return False
        except:
            return False

    @staticmethod
    def _load_popular_domains() -> set:
        """
        Load top popular domains
        Trong thực tế nên load từ file (Alexa/Cisco Umbrella top 1M)
        """
        # Simplified list
        return {
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'wikipedia.org', 'reddit.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'netflix.com', 'apple.com', 'microsoft.com',
            'github.com', 'stackoverflow.com', 'cloudflare.com'
        }


def main():
    """Test feature extractor"""
    from zeek_parser import ZeekLogParser

    parser = ZeekLogParser()
    extractor = FeatureExtractor()

    # Load data
    df_conn = parser.read_conn_log(hours=1)
    df_dns = parser.read_dns_log(hours=1)

    if not df_conn.empty:
        # Extract features
        features = extractor.extract_features(df_conn, df_dns)
        print(f"\n✅ Extracted features shape: {features.shape}")
        print(f"\nFeature columns:")
        print(features.columns.tolist())
        print(f"\nSample features:")
        print(features.head())

        # Per-host features
        host_features = extractor.extract_per_host_features(df_conn, time_window='5T')
        print(f"\n✅ Per-host features shape: {host_features.shape}")
        print(host_features.head())


if __name__ == "__main__":
    main()
