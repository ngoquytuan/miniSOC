# Hướng dẫn Cấu hình Mikrotik Router

Tài liệu này hướng dẫn chi tiết cách cấu hình Mikrotik Router để mirror traffic về Security Box.

## Topology

```
Internet → Router Nhà mạng → Mikrotik Router/PC (192.168.1.101)
                                │
                                ├─→ LAN Devices
                                │
                                └─→ [Mirror Traffic] → DietPi Security Box (192.168.1.70)
```

## Option 1: Sử dụng Mikrotik RouterOS

Nếu bạn có Mikrotik router chạy RouterOS:

### 1. Kết nối vào Mikrotik

**Via Winbox:**
- Download Winbox từ mikrotik.com
- Kết nối tới 192.168.1.101
- Login (user: admin, password: <your-password>)

**Via SSH:**
```bash
ssh admin@192.168.1.101
```

**Via Web:**
- Truy cập http://192.168.1.101

### 2. Kiểm tra Interfaces

```mikrotik
/interface print
```

Ví dụ output:
```
0  R  ether1    1500  auto  no  auto  yes
1     ether2    1500  auto  no  auto  yes
2     ether3    1500  auto  no  auto  yes
3     ether4    1500  auto  no  auto  yes
```

Giả sử:
- `ether1`: WAN (kết nối router nhà mạng)
- `ether2-4`: LAN devices
- Cần mirror traffic từ ether2-4 về DietPi box

### 3. Tạo Bridge cho LAN

```mikrotik
# Tạo bridge
/interface bridge add name=bridge-lan

# Add LAN ports vào bridge
/interface bridge port
add bridge=bridge-lan interface=ether2
add bridge=bridge-lan interface=ether3
add bridge=bridge-lan interface=ether4

# Assign IP cho bridge
/ip address add address=192.168.1.101/24 interface=bridge-lan
```

### 4. Cấu hình Port Mirroring

**Method A: Packet Sniffer (Khuyến nghị)**

```mikrotik
# Configure packet sniffer
/tool sniffer set \
  filter-interface=bridge-lan \
  filter-stream=yes \
  streaming-enabled=yes \
  streaming-server=192.168.1.70:4739

# Start sniffer
/tool sniffer start

# Verify
/tool sniffer print
```

Output mong đợi:
```
  filter-interface: bridge-lan
  streaming-enabled: yes
  streaming-server: 192.168.1.70:4739
```

**Method B: Port Mirroring (Alternative)**

Nếu bạn có port riêng kết nối tới Security Box:

```mikrotik
# Giả sử ether5 kết nối tới Security Box
/interface ethernet
set ether5 master-port=none

# Mirror traffic từ bridge sang ether5
/interface bridge port
add bridge=bridge-lan interface=ether5
set [find interface=ether5] mirror-target=ether5
set [find interface=ether2] mirror-source=yes
set [find interface=ether3] mirror-source=yes
set [find interface=ether4] mirror-source=yes
```

### 5. Cấu hình NetFlow/sFlow (Optional)

Nếu muốn gửi flow data thay vì raw packets (nhẹ hơn):

```mikrotik
# Enable traffic flow
/ip traffic-flow set enabled=yes interfaces=bridge-lan

# Add flow target
/ip traffic-flow target
add address=192.168.1.70:2055 version=9

# Verify
/ip traffic-flow print
/ip traffic-flow target print
```

### 6. Firewall Rules

Đảm bảo Security Box không bị block:

```mikrotik
# Allow Security Box full access
/ip firewall filter
add chain=input src-address=192.168.1.70 action=accept \
  comment="Allow Security Box" place-before=0

add chain=forward src-address=192.168.1.70 action=accept \
  comment="Allow Security Box" place-before=0

# Allow mirrored traffic
add chain=input protocol=udp dst-port=4739 action=accept \
  comment="Zeek packet stream"
```

### 7. Verify Traffic Mirroring

Trên Security Box (192.168.1.70):

```bash
# Listen for mirrored packets
sudo tcpdump -i any port 4739 -c 10

# Hoặc nếu dùng direct mirror
sudo tcpdump -i eth0 -c 100
```

Bạn nên thấy traffic từ nhiều IP khác nhau trong LAN.

---

## Option 2: Mikrotik PC (Linux với Mikrotik Tools)

Nếu Mikrotik PC (192.168.1.101) đang chạy Linux (không phải RouterOS):

### 1. Install tcpdump/tshark

```bash
ssh user@192.168.1.101
sudo apt install -y tcpdump tshark
```

### 2. Forward traffic tới Security Box

**Method A: Port Mirroring với iptables**

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Mirror traffic using iptables TEE
sudo iptables -t mangle -A PREROUTING -j TEE --gateway 192.168.1.70
sudo iptables -t mangle -A POSTROUTING -j TEE --gateway 192.168.1.70

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**Method B: Bridge và tcpdump**

```bash
# Tạo bridge
sudo ip link add name br0 type bridge
sudo ip link set br0 up

# Add interfaces vào bridge
sudo ip link set eth1 master br0
sudo ip link set eth2 master br0

# Capture và forward
sudo tcpdump -i br0 -w - | nc 192.168.1.70 4739
```

**Method C: Sử dụng như sensor node**

Cài Zeek trực tiếp trên Mikrotik PC và gửi logs về Security Box:

```bash
# Install Zeek
sudo apt install -y zeek

# Configure Zeek to listen on main interface
sudo zeekctl deploy

# Rsync logs về Security Box
rsync -avz /opt/zeek/logs/ user@192.168.1.70:/opt/zeek/logs-remote/
```

---

## Testing

### Test 1: Verify mirroring đang hoạt động

Trên Security Box:

```bash
# Capture packets
sudo tcpdump -i eth0 -nn -c 100

# Hoặc nếu dùng packet stream
sudo tcpdump -i any port 4739 -nn -c 100
```

Bạn nên thấy traffic từ nhiều IP trong LAN (không chỉ từ Security Box).

### Test 2: Verify Zeek nhận được traffic

```bash
# Start Zeek
sudo zeekctl deploy

# Wait 1-2 minutes, then check logs
ls -lh /opt/zeek/logs/current/

# Should see files like:
# conn.log, dns.log, http.log, etc.

# Check connection log
tail -20 /opt/zeek/logs/current/conn.log
```

### Test 3: Generate test traffic

Từ một máy khác trong LAN:

```bash
# Generate HTTP traffic
curl http://example.com

# Generate DNS queries
nslookup google.com

# Ping test
ping -c 10 8.8.8.8
```

Check trong Zeek logs xem có bắt được không.

---

## Architecture: Sử dụng cả 2 máy

Bạn có thể tận dụng cả Mikrotik PC (192.168.1.101) và DietPi (192.168.1.70):

### Option A: Distributed Sensing

```
Mikrotik PC (192.168.1.101)        DietPi Security Box (192.168.1.70)
┌─────────────────────────┐       ┌──────────────────────────┐
│ - Zeek Sensor           │──────>│ - Central Analysis       │
│ - Network Scanner       │  logs │ - ML Models              │
│ - Flow Collector        │       │ - Grafana Dashboard      │
└─────────────────────────┘       │ - Alert Manager          │
                                  └──────────────────────────┘
```

**Mikrotik PC chạy:**
- Zeek sensor (thu thập logs)
- Network scanner
- Gửi logs về DietPi

**DietPi chạy:**
- ML anomaly detection
- Alert management
- Grafana dashboard
- Centralized storage

### Option B: Mikrotik as Gateway/Forwarder

```
Internet → Mikrotik PC → DietPi Security Box
                ↓
           LAN Devices
```

Mikrotik PC làm gateway/router chính, mirror/forward traffic về DietPi.

---

## Troubleshooting

### Issue: Không thấy mirrored traffic

**Check:**
1. Port mirroring có đang enabled?
   ```mikrotik
   /tool sniffer print
   ```

2. Firewall có block không?
   ```mikrotik
   /ip firewall filter print
   ```

3. Interface đúng chưa?
   ```mikrotik
   /interface print
   ```

### Issue: Zeek không generate logs

**Check:**
1. Zeek có đang chạy?
   ```bash
   sudo zeekctl status
   ```

2. Interface đúng trong config?
   ```bash
   cat /opt/zeek/etc/node.cfg
   ```

3. Permissions?
   ```bash
   ls -ld /opt/zeek/logs/
   ```

### Issue: Too much traffic, performance issues

**Solutions:**
- Sử dụng NetFlow/sFlow thay vì raw packet mirroring
- Filter traffic: chỉ mirror specific ports/protocols
- Tăng RAM cho Security Box
- Sampling: chỉ capture 1/N packets

```mikrotik
# Sample 1 in 10 packets
/tool sniffer set filter-stream=yes streaming-enabled=yes streaming-server=192.168.1.70:4739 filter-stream-sampling=10
```

---

## Best Practices

1. **Test trước khi production**: Test cấu hình trên một port trước
2. **Monitor performance**: Theo dõi CPU/RAM của cả Mikrotik và Security Box
3. **Backup config**: Luôn backup Mikrotik config trước khi thay đổi
   ```mikrotik
   /export file=backup-$(date +%Y%m%d)
   ```
4. **Security**:
   - Đổi password mặc định
   - Disable unused services
   - Update firmware thường xuyên

---

## References

- [Mikrotik Port Mirroring](https://wiki.mikrotik.com/wiki/Manual:Switch_Chip_Features#Port_Mirroring)
- [Mikrotik Packet Sniffer](https://wiki.mikrotik.com/wiki/Manual:Tools/Packet_Sniffer)
- [Zeek Documentation](https://docs.zeek.org/)
