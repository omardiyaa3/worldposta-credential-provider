#!/bin/bash
#
# WorldPosta Authentication Proxy - Installation Script
# For Linux (Ubuntu/Debian, RHEL/CentOS)
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/worldposta-authproxy"
CONFIG_DIR="/etc/worldposta"
LOG_DIR="/var/log/worldposta"
SERVICE_USER="worldposta"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo "========================================"
echo "  WorldPosta Authentication Proxy"
echo "  Installation Script"
echo "========================================"
echo ""

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt-get"
    echo "Detected: Debian/Ubuntu"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    PKG_MANAGER="yum"
    echo "Detected: RHEL/CentOS"
else
    echo -e "${YELLOW}Warning: Unknown OS, proceeding anyway${NC}"
    OS="unknown"
fi

echo ""

# Install system dependencies
echo "Installing system dependencies..."
if [ "$OS" = "debian" ]; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv
elif [ "$OS" = "redhat" ]; then
    yum install -y -q python3 python3-pip
fi
echo -e "${GREEN}Dependencies installed${NC}"

# Create service user
echo "Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
    echo -e "${GREEN}Created user: $SERVICE_USER${NC}"
else
    echo "User $SERVICE_USER already exists"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

# Copy files
echo "Installing application..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Create virtual environment
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install Python dependencies
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"

# Copy source code
cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"

# Copy example config if no config exists
if [ ! -f "$CONFIG_DIR/authproxy.cfg" ]; then
    cp "$SCRIPT_DIR/config/authproxy.cfg.example" "$CONFIG_DIR/authproxy.cfg"
    chmod 600 "$CONFIG_DIR/authproxy.cfg"
    chown root:root "$CONFIG_DIR/authproxy.cfg"
    echo -e "${YELLOW}Created example config: $CONFIG_DIR/authproxy.cfg${NC}"
    echo -e "${YELLOW}Please edit this file with your settings${NC}"
fi

# Create wrapper script
cat > "$INSTALL_DIR/run.sh" << 'EOF'
#!/bin/bash
cd /opt/worldposta-authproxy
source venv/bin/activate
exec python -m src.main -c /etc/worldposta/authproxy.cfg "$@"
EOF
chmod +x "$INSTALL_DIR/run.sh"

# Create symlink
ln -sf "$INSTALL_DIR/run.sh" /usr/local/bin/worldposta-authproxy

# Install systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/worldposta-authproxy.service << EOF
[Unit]
Description=WorldPosta Authentication Proxy
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_DIR/run.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR
PrivateTmp=true

# Allow binding to privileged ports (if needed)
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Fix permissions
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# Reload systemd
systemctl daemon-reload

echo ""
echo "========================================"
echo -e "  ${GREEN}Installation Complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Edit the configuration file:"
echo "   sudo nano $CONFIG_DIR/authproxy.cfg"
echo ""
echo "2. Add your WorldPosta API credentials:"
echo "   - integration_key"
echo "   - secret_key"
echo ""
echo "3. Configure your Active Directory settings"
echo ""
echo "4. Add your RADIUS clients (VPN/firewall IPs and secrets)"
echo ""
echo "5. Test the configuration:"
echo "   worldposta-authproxy --test-config"
echo ""
echo "6. Start the service:"
echo "   sudo systemctl start worldposta-authproxy"
echo "   sudo systemctl enable worldposta-authproxy"
echo ""
echo "7. Check status:"
echo "   sudo systemctl status worldposta-authproxy"
echo "   sudo journalctl -u worldposta-authproxy -f"
echo ""
