#!/bin/bash
#
# WorldPosta Authentication Proxy - Uninstallation Script
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
echo "  Uninstallation Script"
echo "========================================"
echo ""

# Stop service
echo "Stopping service..."
systemctl stop worldposta-authproxy 2>/dev/null || true
systemctl disable worldposta-authproxy 2>/dev/null || true

# Remove systemd service
echo "Removing systemd service..."
rm -f /etc/systemd/system/worldposta-authproxy.service
systemctl daemon-reload

# Remove symlink
rm -f /usr/local/bin/worldposta-authproxy

# Remove installation directory
echo "Removing installation directory..."
rm -rf "$INSTALL_DIR"

# Ask about config
echo ""
if [ -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}Configuration directory found: $CONFIG_DIR${NC}"
    read -p "Remove configuration files? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}Configuration removed${NC}"
    else
        echo "Configuration preserved"
    fi
fi

# Ask about logs
if [ -d "$LOG_DIR" ]; then
    echo -e "${YELLOW}Log directory found: $LOG_DIR${NC}"
    read -p "Remove log files? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
        echo -e "${GREEN}Logs removed${NC}"
    else
        echo "Logs preserved"
    fi
fi

# Remove service user
echo ""
if id "$SERVICE_USER" &>/dev/null; then
    read -p "Remove service user '$SERVICE_USER'? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        echo -e "${GREEN}User removed${NC}"
    else
        echo "User preserved"
    fi
fi

echo ""
echo "========================================"
echo -e "  ${GREEN}Uninstallation Complete!${NC}"
echo "========================================"
echo ""
