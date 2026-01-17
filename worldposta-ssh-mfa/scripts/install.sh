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

# Prompt for API credentials
echo "Please enter your WorldPosta API credentials:"
echo ""

read -p "API Endpoint [https://api.worldposta.com]: " ENDPOINT
ENDPOINT=${ENDPOINT:-https://api.worldposta.com}

read -p "Integration Key: " INTEGRATION_KEY
while [ -z "$INTEGRATION_KEY" ]; do
    echo -e "${RED}Integration key is required${NC}"
    read -p "Integration Key: " INTEGRATION_KEY
done

read -p "Secret Key: " SECRET_KEY
while [ -z "$SECRET_KEY" ]; do
    echo -e "${RED}Secret key is required${NC}"
    read -p "Secret Key: " SECRET_KEY
done

echo ""
echo "Installing to: $LIBDIR"
echo ""

# Create config directory
echo "Creating /etc/worldposta..."
mkdir -p /etc/worldposta

# Copy PAM module
echo "Installing PAM module..."
cp "$SCRIPT_DIR/pam_worldposta.so" "$LIBDIR/"
chmod 644 "$LIBDIR/pam_worldposta.so"

# Create config file with user's credentials
echo "Creating config file..."
cat > /etc/worldposta/worldposta.conf << EOF
# WorldPosta SSH MFA Configuration

[api]
endpoint = $ENDPOINT
integration_key = $INTEGRATION_KEY
secret_key = $SECRET_KEY
timeout = 60

[auth]
auth_methods = both
service_name = Linux SSH Login

[options]
exclude_users =
require_groups =
log_level = info
EOF
chmod 600 /etc/worldposta/worldposta.conf

# Copy uninstall script
cp "$SCRIPT_DIR/uninstall.sh" /etc/worldposta/
chmod 755 /etc/worldposta/uninstall.sh

# Configure PAM
echo ""
PAM_FILE="/etc/pam.d/sshd"
PAM_LINE="auth required pam_worldposta.so"

if grep -q "pam_worldposta.so" "$PAM_FILE" 2>/dev/null; then
    echo "PAM already configured for WorldPosta"
else
    read -p "Configure PAM automatically? [Y/n]: " CONFIGURE_PAM
    CONFIGURE_PAM=${CONFIGURE_PAM:-Y}

    if [[ $CONFIGURE_PAM =~ ^[Yy]$ ]]; then
        cp "$PAM_FILE" "${PAM_FILE}.bak"

        if grep -q "@include common-auth" "$PAM_FILE"; then
            sed -i '/@include common-auth/a '"$PAM_LINE" "$PAM_FILE"
        elif grep -q "pam_unix.so" "$PAM_FILE"; then
            sed -i '/pam_unix.so/a '"$PAM_LINE" "$PAM_FILE"
        else
            echo "$PAM_LINE" >> "$PAM_FILE"
        fi
        echo -e "${GREEN}PAM configured (backup: ${PAM_FILE}.bak)${NC}"
    fi
fi

# Configure SSHD for keyboard-interactive authentication
SSHD_CONFIG="/etc/ssh/sshd_config"
echo ""
echo "Configuring SSH for MFA..."
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

# Enable KbdInteractiveAuthentication
sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$SSHD_CONFIG"
if ! grep -q "^KbdInteractiveAuthentication" "$SSHD_CONFIG"; then
    echo "KbdInteractiveAuthentication yes" >> "$SSHD_CONFIG"
fi

# Enable ChallengeResponseAuthentication
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONFIG"
if ! grep -q "^ChallengeResponseAuthentication" "$SSHD_CONFIG"; then
    echo "ChallengeResponseAuthentication yes" >> "$SSHD_CONFIG"
fi

echo -e "${GREEN}SSH configured for MFA (backup: ${SSHD_CONFIG}.bak)${NC}"

# Restart SSH
echo ""
read -p "Restart SSH service now? [Y/n]: " RESTART_SSH
RESTART_SSH=${RESTART_SSH:-Y}

if [[ $RESTART_SSH =~ ^[Yy]$ ]]; then
    systemctl restart sshd
    echo -e "${GREEN}SSH service restarted${NC}"
fi

echo ""
echo "========================================"
echo -e "  ${GREEN}Installation Complete!${NC}"
echo "========================================"
echo ""
echo "WorldPosta SSH MFA is now active."
echo ""
echo "Config file: /etc/worldposta/worldposta.conf"
echo "To uninstall: sudo /etc/worldposta/uninstall.sh"
echo ""
echo -e "${YELLOW}IMPORTANT: Test SSH login from another terminal before closing this session!${NC}"
echo ""
