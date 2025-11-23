#!/bin/bash

# Mini-SOC Installation Script
# Cài đặt dependencies và setup environment

set -e  # Exit on error

echo "===================================================="
echo "        Mini-SOC Installation Script"
echo "===================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}⚠ Please do not run this script as root${NC}"
    echo "Run as normal user with sudo privileges"
    exit 1
fi

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Detected OS: $OS $VER"

# Update system
echo ""
echo "📦 Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install basic dependencies
echo ""
echo "📦 Installing basic dependencies..."
sudo apt install -y \
    curl \
    wget \
    git \
    vim \
    net-tools \
    tcpdump \
    nmap \
    arp-scan \
    build-essential \
    python3 \
    python3-pip \
    python3-venv

# Install Docker
if ! command -v docker &> /dev/null; then
    echo ""
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}✓${NC} Docker installed"
else
    echo -e "${GREEN}✓${NC} Docker already installed"
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo ""
    echo "🐳 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}✓${NC} Docker Compose installed"
else
    echo -e "${GREEN}✓${NC} Docker Compose already installed"
fi

# Install Zeek
if ! command -v zeek &> /dev/null; then
    echo ""
    echo "🔍 Installing Zeek IDS..."

    if [ "$OS" = "debian" ] || [ "$OS" = "ubuntu" ]; then
        # Add Zeek repository
        echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' | \
            sudo tee /etc/apt/sources.list.d/security:zeek.list

        # Add GPG key
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key | \
            gpg --dearmor | \
            sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

        # Install
        sudo apt update
        sudo apt install -y zeek
    else
        echo -e "${YELLOW}⚠ Please install Zeek manually for your OS${NC}"
        echo "Visit: https://zeek.org/get-zeek/"
    fi

    # Add Zeek to PATH
    if ! grep -q "/opt/zeek/bin" ~/.bashrc; then
        echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
    fi

    echo -e "${GREEN}✓${NC} Zeek installed"
else
    echo -e "${GREEN}✓${NC} Zeek already installed"
fi

# Create Python virtual environment
echo ""
echo "🐍 Setting up Python virtual environment..."
cd "$(dirname "$0")/.."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}✓${NC} Python environment ready"

# Create necessary directories
echo ""
echo "📁 Creating directories..."
mkdir -p logs/{anomalies,alerts,scanner}
mkdir -p data
mkdir -p models
mkdir -p /opt/zeek/logs 2>/dev/null || sudo mkdir -p /opt/zeek/logs

echo -e "${GREEN}✓${NC} Directories created"

# Setup config file
echo ""
echo "⚙️  Setting up configuration..."
if [ ! -f configs/.env ]; then
    cp configs/.env.example configs/.env
    echo -e "${YELLOW}⚠ Please edit configs/.env with your settings${NC}"
    echo "   - Telegram bot token & chat ID"
    echo "   - Email settings (optional)"
    echo "   - Network subnet"
else
    echo -e "${GREEN}✓${NC} Config file exists"
fi

# Configure Zeek
echo ""
echo "🔍 Configuring Zeek..."

# Detect network interface
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected network interface: $DEFAULT_IFACE"

# Update Zeek node config
if [ -f /opt/zeek/etc/node.cfg ]; then
    sudo sed -i "s/interface=.*/interface=$DEFAULT_IFACE/" /opt/zeek/etc/node.cfg
    echo -e "${GREEN}✓${NC} Zeek configured"
else
    echo -e "${YELLOW}⚠ Zeek config not found at /opt/zeek/etc/node.cfg${NC}"
    echo "Please configure manually"
fi

# Setup systemd services (optional)
echo ""
read -p "Install systemd services? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📋 Installing systemd services..."

    # Zeek service
    sudo tee /etc/systemd/system/zeek.service > /dev/null <<EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl deploy
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable zeek
    echo -e "${GREEN}✓${NC} Zeek service installed"
fi

# Summary
echo ""
echo "===================================================="
echo "         Installation Complete! ✓"
echo "===================================================="
echo ""
echo "Next steps:"
echo "  1. Edit configs/.env with your settings"
echo "  2. Configure Mikrotik port mirroring (see docs/DEPLOYMENT_GUIDE.md)"
echo "  3. Start Zeek: sudo zeekctl deploy"
echo "  4. Train ML model: source venv/bin/activate && python src/analyzer/train_model.py"
echo "  5. Start services: docker-compose up -d"
echo "  6. Access Grafana: http://192.168.1.70:3000 (admin/admin)"
echo ""
echo "Documentation: docs/DEPLOYMENT_GUIDE.md"
echo ""
echo -e "${YELLOW}⚠ You may need to logout and login again for Docker group changes${NC}"
echo ""
