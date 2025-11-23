# Hướng dẫn Triển khai Mini-SOC Chi tiết

## 📋 Mục lục

1. [Tổng quan](#tổng-quan)
2. [Chuẩn bị](#chuẩn-bị)
3. [Cấu hình Mikrotik](#bước-1-cấu-hình-mikrotik-router)
4. [Cài đặt Security Box](#bước-2-cài-đặt-security-box)
5. [Triển khai Services](#bước-3-triển-khai-services)
6. [Huấn luyện ML Models](#bước-4-huấn-luyện-ml-models)
7. [Cấu hình Alerts](#bước-5-cấu-hình-alerts)
8. [Testing](#bước-6-testing)
9. [Maintenance](#bảo-trì)

---

## Tổng quan

Mini-SOC này được thiết kế để chạy trên Debian server có sẵn (192.168.1.70) của bạn, tận dụng luồng traffic được mirror từ Mikrotik router.

### Luồng dữ liệu

```
Internet → Router Nhà mạng → Mikrotik Router
                                │
                                ├─→ LAN Devices
                                │
                                └─→ [Port Mirror] → Security Box (192.168.1.70)
                                                      │
                                                      ├─→ Zeek IDS
                                                      ├─→ ML Models
                                                      ├─→ Device Scanner
                                                      └─→ Alerts & Dashboard
```

---

## Chuẩn bị

### 1. Kiểm tra môi trường

Trên Debian server (192.168.1.70):

```bash
# Kiểm tra OS version
cat /etc/os-release

# Kiểm tra RAM (cần ít nhất 4GB)
free -h

# Kiểm tra disk space (cần ít nhất 50GB)
df -h

# Kiểm tra network interfaces
ip addr
```

### 2. Xác định network layout

```bash
# Xác định IP range của mạng LAN
ip route | grep default

# Thường sẽ là: 192.168.1.0/24
```

**Lưu ý các thông tin:**
- Router IP: `_____________` (thường là 192.168.1.1)
- Security Box IP: `192.168.1.70` (fixed)
- LAN subnet: `_____________` (vd: 192.168.1.0/24)

### 3. Cài đặt prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y \
    git curl wget vim \
    build-essential \
    python3 python3-pip python3-venv \
    tcpdump nmap arp-scan \
    docker.io docker-compose

# Enable và start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
# Logout và login lại để apply
```

---

## Bước 1: Cấu hình Mikrotik Router

### 1.1. Xác định interface

Kết nối vào Mikrotik qua Winbox hoặc SSH:

```bash
ssh admin@192.168.1.1
```

Liệt kê các interfaces:

```
/interface print
```

Giả sử:
- `ether1`: WAN (kết nối router nhà mạng)
- `ether2`, `ether3`, `ether4`: LAN devices
- `ether5`: Kết nối tới Security Box (192.168.1.70)

### 1.2. Cấu hình Port Mirroring (SPAN)

**Option 1: Mirror toàn bộ traffic**

```mikrotik
# Tạo bridge nếu chưa có
/interface bridge add name=bridge-lan

# Add các LAN ports vào bridge
/interface bridge port
add bridge=bridge-lan interface=ether2
add bridge=bridge-lan interface=ether3
add bridge=bridge-lan interface=ether4

# Thiết lập port mirroring từ bridge sang ether5 (Security Box)
/interface bridge port
set [find interface=ether5] mirror-source=bridge-lan
```

**Option 2: Sử dụng Packet Sniffer (linh hoạt hơn)**

```mikrotik
/tool sniffer
set filter-stream=yes streaming-enabled=yes streaming-server=192.168.1.70:4739
set filter-interface=bridge-lan

# Start sniffer
/tool sniffer start
```

### 1.3. Verify cấu hình

```mikrotik
# Kiểm tra sniffer đang chạy
/tool sniffer print

# Kiểm tra traffic count
/tool sniffer packet print
```

### 1.4. Cấu hình Firewall (quan trọng!)

Đảm bảo Security Box không bị block:

```mikrotik
# Cho phép Security Box truy cập mọi nơi trong LAN
/ip firewall filter
add chain=forward src-address=192.168.1.70 action=accept comment="Allow Security Box"
add chain=input src-address=192.168.1.70 action=accept
```

### 1.5. Optional: NetFlow/sFlow

Nếu muốn gửi flow data thay vì raw packets (nhẹ hơn):

```mikrotik
# Cấu hình NetFlow
/ip traffic-flow
set enabled=yes interfaces=bridge-lan

/ip traffic-flow target
add address=192.168.1.70:2055 version=9
```

---

## Bước 2: Cài đặt Security Box

### 2.1. Clone repository

```bash
cd ~
git clone https://github.com/yourusername/miniSOC.git
cd miniSOC
```

### 2.2. Chạy script cài đặt tự động

```bash
sudo ./scripts/install.sh
```

Script này sẽ:
- Cài đặt Zeek
- Cài đặt Python dependencies
- Setup systemd services
- Tạo directories cần thiết

### 2.3. Hoặc cài đặt thủ công

#### Cài đặt Zeek

```bash
# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list

# Add GPG key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key | \
    gpg --dearmor | \
    sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Install Zeek
sudo apt update
sudo apt install -y zeek

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

#### Verify Zeek installation

```bash
zeek --version
# Output: zeek version 6.0.x
```

#### Cài đặt Python dependencies

```bash
# Tạo virtual environment
python3 -m venv venv
source venv/bin/activate

# Install packages
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Bước 3: Triển khai Services

### 3.1. Cấu hình environment

```bash
# Copy template
cp configs/.env.example configs/.env

# Edit với thông tin của bạn
nano configs/.env
```

**File `.env` cần điền:**

```bash
# Network
NETWORK_INTERFACE=eth0        # Interface nhận mirror traffic
LAN_SUBNET=192.168.1.0/24    # Subnet của mạng LAN

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# Email (optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
ALERT_EMAIL=your_email@gmail.com

# Thresholds
ANOMALY_THRESHOLD=0.7         # Isolation Forest threshold
NEW_DEVICE_ALERT=true
RARE_DOMAIN_THRESHOLD=100     # Alert nếu domain có rank > 100k

# Zeek
ZEEK_LOG_DIR=/opt/zeek/logs/current
ZEEK_SCRIPTS_DIR=/opt/zeek/share/zeek/site

# Database
POSTGRES_USER=minisoc
POSTGRES_PASSWORD=change_this_password
POSTGRES_DB=minisoc_db

# Grafana
GRAFANA_ADMIN_PASSWORD=change_this_password
```

### 3.2. Tạo Telegram Bot (nếu dùng Telegram alerts)

1. Mở Telegram, chat với `@BotFather`
2. Gửi `/newbot` và làm theo hướng dẫn
3. Lưu lại token (dạng: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)
4. Tạo group hoặc chat với bot, gửi một message
5. Lấy chat_id:

```bash
# Thay YOUR_BOT_TOKEN
curl https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
# Tìm "chat":{"id":123456789,...}
```

### 3.3. Khởi động services với Docker Compose

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3.4. Verify services đang chạy

```bash
# Zeek
docker-compose exec zeek zeekctl status

# Check logs được tạo
ls -lh /opt/zeek/logs/current/

# Python services
docker-compose logs analyzer
docker-compose logs scanner

# Grafana
curl http://192.168.1.70:3000
```

---

## Bước 4: Huấn luyện ML Models

### 4.1. Thu thập baseline data

Để Isolation Forest học được "bình thường", cần thu thập traffic ít nhất **3-7 ngày**:

```bash
# Chạy Zeek để collect logs
docker-compose exec zeek zeekctl deploy

# Đợi vài ngày để collect data...
```

### 4.2. Train model

Sau khi có đủ data:

```bash
# Activate venv
source venv/bin/activate

# Run training script
python src/analyzer/train_model.py \
    --zeek-logs /opt/zeek/logs/ \
    --output models/isolation_forest.pkl \
    --days 7
```

Output:

```
Loading Zeek logs from last 7 days...
Found 125,432 connections
Extracting features...
Training Isolation Forest...
Model trained successfully!
Accuracy on validation: 94.3%
Anomaly rate: 2.1%
Model saved to models/isolation_forest.pkl
```

### 4.3. Test model

```bash
# Test với live traffic
python src/analyzer/test_model.py \
    --model models/isolation_forest.pkl \
    --test-data /opt/zeek/logs/current/conn.log
```

### 4.4. Schedule retraining

Thêm vào crontab để retrain hàng tuần:

```bash
crontab -e
```

Thêm dòng:

```
# Retrain ML model mỗi Chủ nhật 2AM
0 2 * * 0 cd /home/user/miniSOC && ./scripts/retrain_model.sh >> logs/training.log 2>&1
```

---

## Bước 5: Cấu hình Alerts

### 5.1. Alert Rules

Edit file `configs/alert_rules.yaml`:

```yaml
rules:
  # Thiết bị mới
  - name: new_device
    enabled: true
    severity: medium
    channels: [telegram, email]

  # Anomaly score cao
  - name: high_anomaly_score
    enabled: true
    threshold: 0.8
    severity: high
    channels: [telegram]

  # Kết nối tới IP/domain lạ
  - name: suspicious_connection
    enabled: true
    conditions:
      - rare_domain: true
      - foreign_country: true
    severity: high
    channels: [telegram, email]

  # Port scan
  - name: port_scan
    enabled: true
    threshold: 50  # > 50 ports trong 5 phút
    severity: high
    channels: [telegram]

  # Malware indicators
  - name: malware_ioc
    enabled: true
    ioc_sources: [abuse.ch, alienvault]
    severity: critical
    channels: [telegram, email]
```

### 5.2. Test alerts

```bash
# Test Telegram
python src/alerting/test_telegram.py

# Test Email
python src/alerting/test_email.py

# Simulate alert
python src/alerting/send_alert.py \
    --type new_device \
    --device-ip 192.168.1.99 \
    --device-mac "00:11:22:33:44:55"
```

---

## Bước 6: Testing

### 6.1. Test traffic mirroring

Trên Security Box:

```bash
# Capture traffic trên interface nhận mirror
sudo tcpdump -i eth0 -c 100

# Nên thấy traffic từ nhiều IPs khác nhau trong LAN
```

### 6.2. Test Zeek đang parse

```bash
# Check Zeek logs
tail -f /opt/zeek/logs/current/conn.log
tail -f /opt/zeek/logs/current/dns.log
tail -f /opt/zeek/logs/current/http.log

# Parse một vài dòng
cat /opt/zeek/logs/current/conn.log | zeek-cut id.orig_h id.resp_h proto service
```

### 6.3. Test device scanner

```bash
# Manual scan
python src/scanner/scan_network.py --subnet 192.168.1.0/24

# Output:
# Found 12 devices:
# 192.168.1.1   - aa:bb:cc:dd:ee:ff - Mikrotik
# 192.168.1.70  - 11:22:33:44:55:66 - Debian (This box)
# ...
```

### 6.4. Test ML detection

```bash
# Inject một test anomaly (VD: kết nối tới random domain)
curl http://random-malicious-domain-$(date +%s).com

# Check logs
docker-compose logs analyzer | grep -i anomaly
```

### 6.5. Test alert flow

Simulate các scenarios:

```bash
# 1. Thiết bị mới
# - Kết nối điện thoại mới vào WiFi
# - Đợi 1-2 phút
# - Check Telegram/Email

# 2. Port scan
nmap -p 1-1000 192.168.1.70
# Nên trigger alert

# 3. Suspicious domain
curl http://evil-test-domain-$(openssl rand -hex 8).com
```

---

## Bước 7: Dashboard

### 7.1. Truy cập Grafana

Mở browser: `http://192.168.1.70:3000`

**Login:**
- Username: `admin`
- Password: (từ file `.env`)

### 7.2. Import dashboards

1. Click **+** → **Import**
2. Upload file `configs/grafana/dashboards/minisoc_overview.json`
3. Select Prometheus datasource
4. Click **Import**

### 7.3. Các dashboard có sẵn

**Mini-SOC Overview:**
- Total Connections (24h)
- Unique IPs
- Top Talkers
- Anomaly Score Timeline
- Alert Count

**Device Inventory:**
- Known Devices List
- New Devices (last 7 days)
- Device Activity Heatmap

**Threat Detection:**
- Anomaly Score Distribution
- Suspicious Connections
- Port Scan Attempts
- Malware IOC Matches

---

## Bảo trì

### Daily

```bash
# Check services health
docker-compose ps

# Check alert logs
tail -f logs/alerts.log

# Disk usage
df -h
```

### Weekly

```bash
# Review alerts
cat logs/alerts.log | grep -i "severity: high"

# Update known devices
python src/scanner/update_known_devices.py

# Backup configs
./scripts/backup.sh
```

### Monthly

```bash
# Retrain ML model
./scripts/retrain_model.sh

# Update software
docker-compose pull
docker-compose up -d

# Rotate logs
find /opt/zeek/logs -name "*.log" -mtime +30 -delete

# Review performance
docker stats
```

---

## Troubleshooting

### Issue: Không thấy traffic trong Zeek logs

**Check:**
1. Mikrotik port mirroring đang hoạt động:
   ```mikrotik
   /tool sniffer print
   ```
2. Interface đúng trên Security Box:
   ```bash
   sudo tcpdump -i eth0
   ```
3. Zeek đang chạy:
   ```bash
   docker-compose logs zeek
   ```

### Issue: ML model cho anomaly score quá cao/thấp

**Fix:**
- Điều chỉnh threshold trong `.env`: `ANOMALY_THRESHOLD`
- Retrain với data mới hơn
- Kiểm tra features có bị skew không

### Issue: Quá nhiều false positives

**Fix:**
- Thêm IPs/domains vào whitelist: `configs/whitelist.yaml`
- Điều chỉnh alert rules
- Increase thresholds

### Issue: Không nhận được alerts

**Check:**
1. Test Telegram bot:
   ```bash
   python src/alerting/test_telegram.py
   ```
2. Check logs:
   ```bash
   docker-compose logs alerting
   ```
3. Verify config trong `.env`

---

## Nâng cao

### 1. Thêm Suricata IDS

```bash
# Install Suricata
sudo apt install -y suricata

# Update rules
sudo suricata-update

# Run alongside Zeek
sudo systemctl enable suricata
sudo systemctl start suricata
```

### 2. Threat Intelligence feeds

Edit `configs/threat_intel.yaml`:

```yaml
feeds:
  - name: abuse.ch
    url: https://urlhaus.abuse.ch/downloads/csv_recent/
    type: domain
    refresh: 1h

  - name: alienvault
    url: https://reputation.alienvault.com/reputation.generic
    type: ip
    refresh: 24h
```

### 3. VLAN segmentation cho IoT

Trên Mikrotik:

```mikrotik
# Tạo VLAN cho IoT
/interface vlan add name=vlan-iot vlan-id=10 interface=bridge-lan

# Firewall rules: IoT không access LAN
/ip firewall filter
add chain=forward src-address=192.168.10.0/24 dst-address=192.168.1.0/24 action=drop
```

---

## Kết luận

Sau khi hoàn thành các bước trên, bạn sẽ có một mini-SOC hoạt động với:

✅ Traffic monitoring real-time từ Mikrotik
✅ Zeek IDS phân tích tầng ứng dụng
✅ ML anomaly detection
✅ Device inventory tự động
✅ Alert qua Telegram/Email
✅ Dashboard trực quan trên Grafana

**Thời gian triển khai:** 2-4 giờ (không tính training data collection)
**Maintenance effort:** ~30 phút/tuần

Enjoy your mini-SOC! 🚀🔒
