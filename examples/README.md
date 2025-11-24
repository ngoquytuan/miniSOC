# Mini-SOC Examples

Thư mục này chứa các examples và demos để hiểu cách hoạt động của từng component trong Mini-SOC.

## 📂 Cấu trúc

```
examples/
├── sample_data/              # Sample Zeek logs cho testing
│   ├── conn.log             # Connection log (15 entries, bao gồm anomalies)
│   └── dns.log              # DNS log (9 entries, bao gồm suspicious domains)
│
├── 01_zeek_parser/          # Demo Zeek log parsing
│   └── demo_zeek_parser.py
│
├── 02_ml_detector/          # Demo ML anomaly detection
│   └── demo_ml_anomaly_detection.py
│
├── 03_device_scanner/       # Demo network device scanning
│   └── demo_device_scanner.py
│
├── 04_alerting/             # Demo alert system
│   └── demo_alerting.py
│
├── 05_end_to_end/           # Full pipeline demo
│   └── demo_full_pipeline.py
│
└── README.md                # This file
```

## 🚀 Quick Start

### Prerequisites

```bash
# Từ root directory của miniSOC
cd miniSOC

# Activate virtual environment (nếu chưa)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Chạy Examples

Mỗi example có thể chạy độc lập:

```bash
# Example 1: Zeek Parser
python examples/01_zeek_parser/demo_zeek_parser.py

# Example 2: ML Anomaly Detection
python examples/02_ml_detector/demo_ml_anomaly_detection.py

# Example 3: Device Scanner
python examples/03_device_scanner/demo_device_scanner.py

# Example 4: Alerting
python examples/04_alerting/demo_alerting.py

# Example 5: Full Pipeline (recommended để bắt đầu)
python examples/05_end_to_end/demo_full_pipeline.py
```

## 📚 Chi tiết từng Example

### 1️⃣ Zeek Parser (`01_zeek_parser/`)

**Mục đích:** Học cách parse và phân tích Zeek logs

**Nội dung:**
- Parse conn.log và dns.log
- Thống kê traffic cơ bản
- Top talkers analysis
- Identify large data transfers
- Correlate connection và DNS data

**Chạy:**
```bash
python examples/01_zeek_parser/demo_zeek_parser.py
```

**Output:**
- Parsed connections và DNS queries
- Traffic statistics
- Top source/destination IPs
- Suspicious domain detection

---

### 2️⃣ ML Anomaly Detection (`02_ml_detector/`)

**Mục đích:** Học cách train và sử dụng Isolation Forest

**Nội dung:**
- Load và parse Zeek logs
- Extract 25+ features cho ML
- Train Isolation Forest model
- Detect anomalies với scores
- Explain tại sao connection là anomaly
- Score distribution visualization

**Chạy:**
```bash
python examples/02_ml_detector/demo_ml_anomaly_detection.py
```

**Output:**
- Trained model (saved to `demo_model.pkl`)
- Top anomalies với details
- Feature importance explanation
- Anomaly score distribution

**Học được:**
- Feature engineering cho network traffic
- Unsupervised learning với Isolation Forest
- Anomaly explanation
- Model evaluation

---

### 3️⃣ Device Scanner (`03_device_scanner/`)

**Mục đích:** Học cách scan và inventory network devices

**Nội dung:**
- Network scanning simulation
- Device categorization (router, computer, camera, phone...)
- Security analysis (insecure services, unknown devices)
- Device inventory management
- Security report generation

**Chạy:**
```bash
python examples/03_device_scanner/demo_device_scanner.py
```

**Output:**
- Device inventory JSON
- Security report
- Risk analysis

**Note:** Example này sử dụng simulated data. Real scanning cần:
- Sudo privileges
- `nmap` installed
- Network access

---

### 4️⃣ Alerting System (`04_alerting/`)

**Mục đích:** Học cách gửi alerts qua nhiều channels

**Nội dung:**
- 6 loại alerts khác nhau:
  1. Anomaly detection
  2. New device
  3. Port scan
  4. Suspicious domain
  5. Brute force attack
  6. Weekly summary
- Alert routing theo severity
- Multiple channels (Telegram, Email, Log)
- Alert best practices

**Chạy:**
```bash
# Demo mode (simulated)
python examples/04_alerting/demo_alerting.py

# Test real Telegram alert (cần config)
export TELEGRAM_BOT_TOKEN="your_token"
export TELEGRAM_CHAT_ID="your_chat_id"
python src/alerting/alert_manager.py --type telegram
```

**Output:**
- Simulated alerts với different severities
- Configuration instructions
- Best practices guide

---

### 5️⃣ End-to-End Pipeline (`05_end_to_end/`)

**Mục đích:** Demo toàn bộ workflow của Mini-SOC

**Nội dung:**
Kết hợp tất cả components trong một pipeline hoàn chỉnh:
1. Load Zeek logs
2. Extract features
3. Train ML model
4. Detect anomalies
5. Analyze devices
6. Generate alerts
7. Create security report

**Chạy:**
```bash
python examples/05_end_to_end/demo_full_pipeline.py
```

**Output:**
- Step-by-step interactive demo
- Security summary report
- Alert generation
- Complete workflow visualization

**Recommended:** Bắt đầu với example này để có overview toàn bộ system!

---

## 🧪 Sample Data

Thư mục `sample_data/` chứa realistic Zeek logs với:

**conn.log:**
- 15 connections
- Normal traffic: SSH, HTTP, HTTPS, DNS
- Anomalous traffic:
  - Large data transfers (>1MB)
  - Connections tới suspicious IPs
  - Failed connections (S0, REJ states)

**dns.log:**
- 9 DNS queries
- Normal domains: google.com, github.com, facebook.com
- Suspicious domains:
  - `malicious-c2-server-xyz123.com`
  - `random-dga-generated-domain-abc456.net`
  - `suspicious-phishing-site789.org`

### Customize Sample Data

Để test với data khác:

```python
# Edit sample_data/conn.log hoặc dns.log
# Hoặc point tới Zeek logs thật:

parser = ZeekLogParser(log_dir='/opt/zeek/logs/current')
df = parser.read_conn_log(hours=24)
```

---

## 💡 Tips & Tricks

### Debug Mode

Thêm verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Interactive Exploration

Sử dụng IPython để explore:

```bash
pip install ipython
ipython

# Trong IPython:
from analyzer.zeek_parser import ZeekLogParser
parser = ZeekLogParser('examples/sample_data')
df = parser.read_conn_log(log_path='examples/sample_data/conn.log')
df.head()
```

### Modify Parameters

Thay đổi ML parameters:

```python
# Trong demo scripts
detector = AnomalyDetector(
    contamination=0.20,  # Tăng từ 0.15 → detect more anomalies
    n_estimators=200     # Tăng từ 100 → better accuracy
)
```

### Real Data Testing

Test với Zeek logs thật:

```bash
# Assuming Zeek đang chạy
python examples/02_ml_detector/demo_ml_anomaly_detection.py

# Modify script để point tới /opt/zeek/logs/current/
```

---

## 🐛 Troubleshooting

### Issue: Import errors

```bash
# Make sure trong miniSOC root directory
cd /path/to/miniSOC

# Activate venv
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

### Issue: "No module named 'analyzer'"

```bash
# Scripts tự động add src/ to path, nhưng check:
cd miniSOC  # Phải ở root directory
python examples/01_zeek_parser/demo_zeek_parser.py
```

### Issue: Empty dataframes

```bash
# Check sample data exists
ls -l examples/sample_data/

# Should see:
# conn.log
# dns.log
```

### Issue: Model performance không tốt

Với sample data nhỏ, model có thể không accurate. Solutions:

1. Train với more data (real Zeek logs 7 days)
2. Adjust contamination parameter
3. Feature engineering (thêm features)

---

## 📖 Learning Path

**Beginner:** Bắt đầu theo thứ tự:
1. Example 5 (End-to-end) - Overview
2. Example 1 (Zeek Parser) - Basics
3. Example 4 (Alerting) - Notifications

**Intermediate:**
4. Example 2 (ML Detector) - Machine Learning
5. Example 3 (Device Scanner) - Network Analysis

**Advanced:**
- Modify examples cho use case riêng
- Integrate với real Zeek deployment
- Customize ML models
- Build custom dashboards

---

## 🎯 Next Steps

Sau khi chạy examples:

1. **Deploy Production:**
   ```bash
   # Xem QUICKSTART.md
   ./scripts/install.sh
   docker-compose up -d
   ```

2. **Configure Mikrotik:**
   - Xem `docs/MIKROTIK_CONFIG.md`
   - Setup port mirroring

3. **Train Real Model:**
   ```bash
   # Collect 7 days data, then:
   python src/analyzer/train_model.py --days 7
   ```

4. **Setup Alerts:**
   - Configure Telegram bot
   - Setup email SMTP
   - Test alerts

5. **Monitor Dashboard:**
   - Access Grafana: http://192.168.1.70:3000
   - Review metrics
   - Check alerts

---

## 🤝 Contributing

Có ý tưởng cho examples mới? Contributions welcome!

Ideas:
- Jupyter notebooks với interactive visualization
- Autoencoder-based detection
- Threat intelligence integration
- Custom feature engineering examples

---

## 📞 Support

Nếu gặp issues với examples:

1. Check [Troubleshooting](#-troubleshooting) section
2. Review main docs: `docs/DEPLOYMENT_GUIDE.md`
3. Check source code comments
4. Open GitHub issue

---

**Happy Learning! 🚀**

Các examples này được thiết kế để học và test. Trong production, sử dụng Docker Compose deployment với configuration đầy đủ.
