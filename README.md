# Mini-SOC cho Mạng LAN Gia Đình

Hệ thống Security Operations Center (SOC) nhỏ gọn, nhẹ, dễ triển khai cho mạng gia đình sử dụng AI/ML để phát hiện bất thường, thiết bị lạ và malware.

## 🎯 Mục tiêu

- **Nhẹ và dễ triển khai**: Chạy trên hardware có sẵn
- **Ít bảo trì**: Tự động hóa cao, cấu hình một lần
- **Hiệu quả**: Phát hiện thực sự các mối đe dọa:
  - Thiết bị lạ/gián điệp trong mạng
  - Traffic bất thường (malware, C2, botnet)
  - Quét port, brute force
  - IoT devices có hành vi lạ

## 🏗️ Kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
              ┌──────▼──────┐
              │   Router    │
              │  Nhà mạng   │
              └──────┬──────┘
                     │
              ┌──────▼──────────────┐
              │   Mikrotik Router   │
              │   (4 LAN 2.5G)      │
              │  Port Mirroring     │
              └──┬───┬───┬────┬─────┘
                 │   │   │    │
       ┌─────────┘   │   │    └─────────────┐
       │             │   │                  │
  ┌────▼────┐  ┌────▼───▼────┐      ┌──────▼──────┐
  │ Devices │  │ WiFi Phụ    │      │ Security    │
  │ (PC,IoT)│  │             │      │ Box         │
  └─────────┘  └─────────────┘      │ (Debian)    │
                                     │ 192.168.1.70│
                                     │             │
                                     │ • Zeek IDS  │
                                     │ • ML Models │
                                     │ • Scanner   │
                                     │ • Grafana   │
                                     └─────────────┘
```

## 🛠️ Thành phần

### 1. Network IDS
- **Zeek**: Phân tích traffic tầng ứng dụng (HTTP, DNS, SSL, SSH...)
- **Suricata** (tùy chọn): Signature-based detection

### 2. Machine Learning
- **Isolation Forest**: Phát hiện anomaly không cần label
- **Autoencoder** (nâng cao): Deep learning cho pattern recognition

### 3. Device Management
- **Network Scanner**: Quét định kỳ, inventory thiết bị
- **Device Profiling**: Phân loại thiết bị dựa trên MAC vendor và behavior

### 4. Alerting
- **Telegram Bot**: Thông báo real-time
- **Email**: Báo cáo hàng ngày/tuần
- **Web Dashboard**: Grafana + Prometheus

### 5. Infrastructure
- **Docker Compose**: Triển khai dễ dàng
- **Prometheus**: Thu thập metrics
- **Grafana**: Visualization

## 📋 Yêu cầu hệ thống

### Phần cứng
- **Security Box**:
  - CPU: 2+ cores
  - RAM: 4GB+ (8GB khuyến nghị)
  - Disk: 50GB+
  - Network: 1Gbps+ NIC
- **Router**: Mikrotik hỗ trợ port mirroring

### Phần mềm
- Debian/Ubuntu 20.04+
- Docker & Docker Compose
- Python 3.8+

## 🚀 Cài đặt nhanh

```bash
# 1. Clone repository
git clone https://github.com/yourusername/miniSOC.git
cd miniSOC

# 2. Chạy script cài đặt
sudo ./scripts/install.sh

# 3. Cấu hình
cp configs/.env.example configs/.env
nano configs/.env  # Điền thông tin Telegram, email...

# 4. Khởi động services
docker-compose up -d

# 5. Truy cập dashboard
# Grafana: http://192.168.1.70:3000
# Credentials: admin/admin (đổi ngay sau khi đăng nhập)
```

## 📚 Tài liệu

- [**Hướng dẫn triển khai chi tiết**](docs/DEPLOYMENT_GUIDE.md)
- [Cấu hình Mikrotik](docs/MIKROTIK_CONFIG.md)
- [Cấu hình Zeek](docs/ZEEK_CONFIG.md)
- [Huấn luyện ML Models](docs/ML_TRAINING.md)
- [Tùy chỉnh Alert Rules](docs/ALERT_RULES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 📊 Features

### ✅ Đã triển khai
- [x] Zeek IDS với log parsing
- [x] Isolation Forest anomaly detection
- [x] Device scanner và inventory
- [x] Telegram alerts
- [x] Grafana dashboards
- [x] Docker containerization

### 🚧 Roadmap
- [ ] Autoencoder model
- [ ] Threat intelligence integration
- [ ] Mobile app
- [ ] ML model auto-retraining

## 🔒 Security Notes

- **Không expose services ra Internet**: Chỉ truy cập từ LAN
- **Đổi mật khẩu mặc định**: Grafana, databases...
- **Backup định kỳ**: Models, configs, logs
- **Update thường xuyên**: Security patches

## 🤝 Contributing

Đây là dự án học tập/cá nhân. Mọi đóng góp đều được chào đón!

## 📝 License

MIT License - Xem file [LICENSE](LICENSE)

## 👤 Tác giả

Dự án mini-SOC cho mạng gia đình

## 🙏 Credits

- [Zeek Network Security Monitor](https://zeek.org/)
- [Suricata IDS](https://suricata.io/)
- [scikit-learn](https://scikit-learn.org/)
- [Grafana](https://grafana.com/)
