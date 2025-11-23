# Quick Start Guide - Mini-SOC

Hướng dẫn nhanh để triển khai Mini-SOC trong 30 phút.

## 🎯 Prerequisites

- DietPi server (192.168.1.70) đã cài đặt và kết nối mạng
- Mikrotik router/PC (192.168.1.101)
- Truy cập SSH tới cả hai máy
- Đã có Telegram account (để nhận alerts)

## 🚀 Triển khai 5 bước

### Bước 1: Clone repository (2 phút)

Trên DietPi server (192.168.1.70):

```bash
# SSH vào server
ssh user@192.168.1.70

# Clone repo
git clone https://github.com/yourusername/miniSOC.git
cd miniSOC
```

### Bước 2: Chạy script cài đặt (10 phút)

```bash
# Chạy install script
sudo ./scripts/install.sh

# Script sẽ cài:
# - Docker & Docker Compose
# - Zeek IDS
# - Python dependencies
# - Tạo directories cần thiết
```

Sau khi script chạy xong:
- Logout và login lại (để apply Docker group)
- Source bashrc: `source ~/.bashrc`

### Bước 3: Cấu hình (5 phút)

#### 3.1. Tạo Telegram Bot

1. Mở Telegram, chat với **@BotFather**
2. Gửi `/newbot` và làm theo hướng dẫn
3. Lưu lại **bot token** (dạng: `123456789:ABCdef...`)
4. Tạo group hoặc chat với bot
5. Lấy **chat_id**:
   ```bash
   curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   # Tìm "chat":{"id":123456789,...}
   ```

#### 3.2. Cập nhật config

```bash
# Copy template
cp configs/.env.example configs/.env

# Edit config
nano configs/.env
```

Điền **tối thiểu** 2 thông tin:
```bash
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

Optional: Email settings nếu muốn nhận email alerts.

### Bước 4: Cấu hình Mikrotik (5 phút)

**Option A: Nếu có Mikrotik RouterOS**

Kết nối vào Mikrotik (SSH/Winbox):

```mikrotik
# Enable packet sniffer
/tool sniffer set \
  filter-interface=bridge-lan \
  filter-stream=yes \
  streaming-enabled=yes \
  streaming-server=192.168.1.70:4739

/tool sniffer start
```

**Option B: Nếu Mikrotik PC chạy Linux**

```bash
ssh user@192.168.1.101

# Forward traffic
sudo iptables -t mangle -A PREROUTING -j TEE --gateway 192.168.1.70
sudo iptables -t mangle -A POSTROUTING -j TEE --gateway 192.168.1.70
```

Chi tiết: [docs/MIKROTIK_CONFIG.md](docs/MIKROTIK_CONFIG.md)

### Bước 5: Start services (5 phút)

```bash
# Start Zeek
sudo zeekctl deploy

# Wait 3-5 minutes để Zeek thu thập baseline traffic
# Trong lúc đó, có thể test Telegram bot:
source venv/bin/activate
python src/alerting/alert_manager.py --type telegram

# Start Docker services
docker-compose up -d

# Check status
docker-compose ps
```

## ✅ Verify

### 1. Check Zeek đang thu thập logs

```bash
ls -lh /opt/zeek/logs/current/
# Nên thấy: conn.log, dns.log, http.log...

tail -20 /opt/zeek/logs/current/conn.log
```

### 2. Check services đang chạy

```bash
docker-compose ps

# Tất cả services nên có status "Up"
```

### 3. Truy cập Grafana

Mở browser: **http://192.168.1.70:3000**
- Username: `admin`
- Password: `admin` (hoặc giá trị trong `.env`)

## 🎓 Training ML Model (Bước bổ sung)

Để ML anomaly detection hoạt động, cần train model:

**Option 1: Train ngay (với ít data)**
```bash
source venv/bin/activate
python src/analyzer/train_model.py --use-current
```

**Option 2: Đợi thu thập 7 ngày data (khuyến nghị)**
```bash
# Đợi 7 ngày, sau đó:
python src/analyzer/train_model.py --days 7
```

Model sẽ được lưu tại `models/isolation_forest.pkl`

Restart analyzer service để sử dụng model mới:
```bash
docker-compose restart analyzer
```

## 📊 Sử dụng hàng ngày

### Xem alerts

```bash
# Real-time logs
docker-compose logs -f analyzer
docker-compose logs -f scanner

# Alert log file
tail -f logs/alerts.log
```

### Xem devices trong mạng

```bash
cat data/device_inventory.json | python -m json.tool
```

### Check anomalies

```bash
source venv/bin/activate
python src/analyzer/detect_anomalies.py --mode batch --minutes 60
```

### Grafana Dashboards

- **Overview**: http://192.168.1.70:3000/d/minisoc-overview
- **Devices**: http://192.168.1.70:3000/d/minisoc-devices
- **Threats**: http://192.168.1.70:3000/d/minisoc-threats

## 🔧 Troubleshooting

### Không thấy traffic trong Zeek logs

```bash
# 1. Check Zeek đang chạy
sudo zeekctl status

# 2. Check interface
cat /opt/zeek/etc/node.cfg

# 3. Capture trực tiếp để test
sudo tcpdump -i eth0 -c 100
```

### Không nhận được Telegram alerts

```bash
# Test bot
source venv/bin/activate
python src/alerting/alert_manager.py --type telegram

# Check logs
docker-compose logs alerting
```

### Services không start

```bash
# Check logs
docker-compose logs

# Restart specific service
docker-compose restart analyzer

# Rebuild if needed
docker-compose build --no-cache
docker-compose up -d
```

## 📚 Tài liệu đầy đủ

- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) - Chi tiết từng bước
- [Mikrotik Config](docs/MIKROTIK_CONFIG.md) - Cấu hình Mikrotik
- [README](README.md) - Overview dự án

## 🆘 Support

Nếu gặp vấn đề:
1. Check [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) phần Troubleshooting
2. Review logs: `docker-compose logs`
3. Open issue trên GitHub

---

**Chúc bạn triển khai thành công! 🎉**
