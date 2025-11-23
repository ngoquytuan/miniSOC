#!/usr/bin/env python3
"""
Zeek Log Parser
Đọc và parse các log files từ Zeek IDS
"""

import os
import json
import gzip
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZeekLogParser:
    """Parse Zeek logs (conn.log, dns.log, http.log, etc.)"""

    def __init__(self, log_dir: str = "/opt/zeek/logs"):
        self.log_dir = Path(log_dir)

    def read_conn_log(self,
                      log_path: Optional[str] = None,
                      hours: int = 24) -> pd.DataFrame:
        """
        Đọc conn.log (connection records)

        Args:
            log_path: Path cụ thể tới conn.log, hoặc None để auto-detect
            hours: Số giờ gần nhất cần lấy

        Returns:
            DataFrame với connection data
        """
        if log_path is None:
            log_path = self.log_dir / "current" / "conn.log"

        logger.info(f"Reading conn.log from {log_path}")

        # Zeek logs thường là TSV với header
        try:
            # Skip các dòng comments (#)
            df = pd.read_csv(
                log_path,
                sep='\t',
                comment='#',
                names=self._get_conn_columns(),
                na_values=['-', '(empty)'],
                low_memory=False
            )

            # Convert timestamp
            df['ts'] = pd.to_datetime(df['ts'], unit='s')

            # Filter by time window
            cutoff = datetime.now() - timedelta(hours=hours)
            df = df[df['ts'] >= cutoff]

            logger.info(f"Loaded {len(df)} connections from last {hours} hours")
            return df

        except Exception as e:
            logger.error(f"Error reading conn.log: {e}")
            return pd.DataFrame()

    def read_dns_log(self, hours: int = 24) -> pd.DataFrame:
        """Đọc dns.log"""
        log_path = self.log_dir / "current" / "dns.log"

        try:
            df = pd.read_csv(
                log_path,
                sep='\t',
                comment='#',
                names=self._get_dns_columns(),
                na_values=['-', '(empty)'],
                low_memory=False
            )

            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            cutoff = datetime.now() - timedelta(hours=hours)
            df = df[df['ts'] >= cutoff]

            logger.info(f"Loaded {len(df)} DNS queries")
            return df

        except Exception as e:
            logger.error(f"Error reading dns.log: {e}")
            return pd.DataFrame()

    def read_http_log(self, hours: int = 24) -> pd.DataFrame:
        """Đọc http.log"""
        log_path = self.log_dir / "current" / "http.log"

        try:
            df = pd.read_csv(
                log_path,
                sep='\t',
                comment='#',
                names=self._get_http_columns(),
                na_values=['-', '(empty)'],
                low_memory=False
            )

            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            cutoff = datetime.now() - timedelta(hours=hours)
            df = df[df['ts'] >= cutoff]

            logger.info(f"Loaded {len(df)} HTTP requests")
            return df

        except Exception as e:
            logger.error(f"Error reading http.log: {e}")
            return pd.DataFrame()

    def read_archived_logs(self,
                          log_type: str = "conn",
                          days: int = 7) -> pd.DataFrame:
        """
        Đọc archived logs (*.gz) từ nhiều ngày

        Args:
            log_type: 'conn', 'dns', 'http'
            days: Số ngày cần lấy
        """
        dfs = []

        # Pattern: 2024-01-15/conn.12:00:00-13:00:00.log.gz
        for day in range(days):
            date = datetime.now() - timedelta(days=day)
            date_str = date.strftime("%Y-%m-%d")
            date_dir = self.log_dir / date_str

            if not date_dir.exists():
                continue

            # Tìm tất cả log files của type này
            pattern = f"{log_type}.*.log.gz"
            for log_file in date_dir.glob(pattern):
                try:
                    df = self._read_gzip_log(log_file, log_type)
                    if not df.empty:
                        dfs.append(df)
                except Exception as e:
                    logger.warning(f"Error reading {log_file}: {e}")

        if dfs:
            combined = pd.concat(dfs, ignore_index=True)
            logger.info(f"Loaded {len(combined)} records from {days} days")
            return combined
        else:
            logger.warning(f"No archived logs found for {log_type}")
            return pd.DataFrame()

    def _read_gzip_log(self, path: Path, log_type: str) -> pd.DataFrame:
        """Đọc compressed log file"""
        import gzip

        columns = {
            'conn': self._get_conn_columns(),
            'dns': self._get_dns_columns(),
            'http': self._get_http_columns()
        }.get(log_type, [])

        with gzip.open(path, 'rt') as f:
            df = pd.read_csv(
                f,
                sep='\t',
                comment='#',
                names=columns,
                na_values=['-', '(empty)'],
                low_memory=False
            )
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            return df

    @staticmethod
    def _get_conn_columns() -> List[str]:
        """Column names cho conn.log"""
        return [
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
            'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
            'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
            'tunnel_parents'
        ]

    @staticmethod
    def _get_dns_columns() -> List[str]:
        """Column names cho dns.log"""
        return [
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
            'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
            'RA', 'Z', 'answers', 'TTLs', 'rejected'
        ]

    @staticmethod
    def _get_http_columns() -> List[str]:
        """Column names cho http.log"""
        return [
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'trans_depth', 'method', 'host', 'uri', 'referrer', 'version',
            'user_agent', 'origin', 'request_body_len', 'response_body_len',
            'status_code', 'status_msg', 'info_code', 'info_msg', 'tags',
            'username', 'password', 'proxied', 'orig_fuids', 'orig_filenames',
            'orig_mime_types', 'resp_fuids', 'resp_filenames', 'resp_mime_types'
        ]


def main():
    """Test parser"""
    parser = ZeekLogParser()

    # Test reading conn.log
    df_conn = parser.read_conn_log(hours=1)
    if not df_conn.empty:
        print(f"\n✅ Loaded {len(df_conn)} connections")
        print(df_conn.head())

        # Top talkers
        top_src = df_conn['id.orig_h'].value_counts().head(5)
        print(f"\n📊 Top 5 source IPs:")
        print(top_src)

    # Test reading DNS
    df_dns = parser.read_dns_log(hours=1)
    if not df_dns.empty:
        print(f"\n✅ Loaded {len(df_dns)} DNS queries")
        top_domains = df_dns['query'].value_counts().head(5)
        print(f"\n🌐 Top 5 queried domains:")
        print(top_domains)


if __name__ == "__main__":
    main()
