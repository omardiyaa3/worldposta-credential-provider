#!/bin/bash
#
# WorldPosta SSH MFA - Installation Script
# Copyright (c) 2024 WorldPosta
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

echo "========================================"
echo "  WorldPosta SSH MFA Installer"
echo "========================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if pam_worldposta.so exists
if [ ! -f "$SCRIPT_DIR/pam_worldposta.so" ]; then
    echo -e "${RED}Error: pam_worldposta.so not found${NC}"
    exit 1
fi

# Detect PAM security directory
if [ -d "/lib/x86_64-linux-gnu/security" ]; then
    LIBDIR="/lib/x86_64-linux-gnu/security"
elif [ -d "/lib64/security" ]; then
    LIBDIR="/lib64/security"
elif [ -d "/lib/security" ]; then
    LIBDIR="/lib/security"
else
    echo -e "${RED}Error: Could not find PAM security directory${NC}"
    exit 1
fi

echo "Installing to: $LIBDIR"
echo ""

# Create config directory
echo "Creating /etc/worldposta..."
mkdir -p /etc/worldposta

# Copy PAM module
echo "Installing PAM module..."
cp "$SCRIPT_DIR/pam_worldposta.so" "$LIBDIR/"
chmod 644 "$LIBDIR/pam_worldposta.so"

# Copy config if not exists
if [ ! -f /etc/worldposta/worldposta.conf ]; then
    echo "Installing sample config..."
    cp "$SCRIPT_DIR/worldposta.conf" /etc/worldposta/
    chmod 600 /etc/worldposta/worldposta.conf
else
    echo "Config already exists, skipping..."
fi

# Copy uninstall script
cp "$SCRIPT_DIR/uninstall.sh" /etc/worldposta/
chmod 755 /etc/worldposta/uninstall.sh

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "========================================"
echo "  Next Steps"
echo "========================================"
echo ""
echo "1. Edit the config file with your API keys:"
echo -e "   ${YELLOW}sudo nano /etc/worldposta/worldposta.conf${NC}"
echo ""
echo "2. Add this line to /etc/pam.d/sshd (after @include common-auth):"
echo -e "   ${YELLOW}auth required pam_worldposta.so${NC}"
echo ""
echo "3. Ensure /etc/ssh/sshd_config has:"
echo "   ChallengeResponseAuthentication yes"
echo "   UsePAM yes"
echo ""
echo "4. Restart SSH:"
echo -e "   ${YELLOW}sudo systemctl restart sshd${NC}"
echo ""
echo "To uninstall: sudo /etc/worldposta/uninstall.sh"
echo ""
