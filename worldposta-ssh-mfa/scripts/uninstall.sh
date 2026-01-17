#!/bin/bash
#
# WorldPosta SSH MFA - Uninstallation Script
# Copyright (c) 2024 WorldPosta
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo "========================================"
echo "  WorldPosta SSH MFA Uninstaller"
echo "========================================"
echo ""

# Find and remove the PAM module
remove_module() {
    echo "Removing PAM module..."

    # Check common locations
    LOCATIONS=(
        "/lib/x86_64-linux-gnu/security/pam_worldposta.so"
        "/lib/aarch64-linux-gnu/security/pam_worldposta.so"
        "/lib64/security/pam_worldposta.so"
        "/lib/security/pam_worldposta.so"
    )

    for loc in "${LOCATIONS[@]}"; do
        if [ -f "$loc" ]; then
            rm -f "$loc"
            echo -e "${GREEN}Removed: $loc${NC}"
        fi
    done
}

# Remove from PAM config
remove_pam_config() {
    echo ""
    echo "Checking PAM configuration..."

    PAM_FILE="/etc/pam.d/sshd"

    if grep -q "pam_worldposta.so" "$PAM_FILE" 2>/dev/null; then
        echo -e "${YELLOW}Found WorldPosta in $PAM_FILE${NC}"
        read -p "Remove from PAM config? [y/N] " -n 1 -r
        echo ""

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Backup
            cp "$PAM_FILE" "${PAM_FILE}.bak.uninstall"
            # Remove the line
            sed -i '/pam_worldposta.so/d' "$PAM_FILE"
            echo -e "${GREEN}Removed from PAM config${NC}"
        fi
    else
        echo "WorldPosta not found in PAM config"
    fi
}

# Ask about config files
remove_config() {
    echo ""

    if [ -d "/etc/worldposta" ]; then
        echo -e "${YELLOW}Config directory found: /etc/worldposta${NC}"
        read -p "Remove configuration files? [y/N] " -n 1 -r
        echo ""

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf /etc/worldposta
            echo -e "${GREEN}Removed /etc/worldposta${NC}"
        else
            echo "Config files preserved"
        fi
    fi
}

# Main
main() {
    remove_module
    remove_pam_config
    remove_config

    echo ""
    echo "========================================"
    echo -e "  ${GREEN}Uninstallation Complete!${NC}"
    echo "========================================"
    echo ""
    echo "SSH will no longer require WorldPosta 2FA"
    echo ""
}

main "$@"
