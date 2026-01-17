#!/bin/bash
#
# WorldPosta SSH MFA - Installation Script
# Copyright (c) 2024 WorldPosta
#
# This script installs the WorldPosta PAM module for SSH 2FA
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo "========================================"
echo "  WorldPosta SSH MFA Installer"
echo "========================================"
echo ""

# Detect distribution
detect_distro() {
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        PKG_MANAGER="apt-get"
        PACKAGES="build-essential libpam0g-dev libcurl4-openssl-dev libssl-dev libjson-c-dev"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
        if command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
        else
            PKG_MANAGER="yum"
        fi
        PACKAGES="gcc make pam-devel libcurl-devel openssl-devel json-c-devel"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
        PKG_MANAGER="pacman"
        PACKAGES="base-devel pam curl openssl json-c"
    elif [ -f /etc/alpine-release ]; then
        DISTRO="alpine"
        PKG_MANAGER="apk"
        PACKAGES="build-base linux-pam-dev curl-dev openssl-dev json-c-dev"
    else
        echo -e "${RED}Error: Unsupported distribution${NC}"
        echo "Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch Linux, Alpine"
        exit 1
    fi

    echo -e "${GREEN}Detected distribution: ${DISTRO}${NC}"
}

# Install dependencies
install_deps() {
    echo ""
    echo "Installing dependencies..."

    case $PKG_MANAGER in
        apt-get)
            apt-get update
            apt-get install -y $PACKAGES
            ;;
        dnf|yum)
            $PKG_MANAGER install -y $PACKAGES
            ;;
        pacman)
            pacman -Syu --noconfirm $PACKAGES
            ;;
        apk)
            apk add --no-cache $PACKAGES
            ;;
    esac

    echo -e "${GREEN}Dependencies installed successfully${NC}"
}

# Build the module
build_module() {
    echo ""
    echo "Building PAM module..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    cd "$PROJECT_DIR"
    make clean 2>/dev/null || true
    make

    if [ ! -f "pam_worldposta.so" ]; then
        echo -e "${RED}Error: Build failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}Build successful${NC}"
}

# Install the module
install_module() {
    echo ""
    echo "Installing PAM module..."

    make install

    echo -e "${GREEN}PAM module installed${NC}"
}

# Configure PAM
configure_pam() {
    echo ""
    echo -e "${YELLOW}PAM Configuration${NC}"
    echo ""

    PAM_FILE="/etc/pam.d/sshd"
    PAM_LINE="auth required pam_worldposta.so"

    if grep -q "pam_worldposta.so" "$PAM_FILE" 2>/dev/null; then
        echo "PAM already configured for WorldPosta"
    else
        echo "To enable WorldPosta 2FA, add this line to $PAM_FILE"
        echo "(after pam_unix.so or @include common-auth):"
        echo ""
        echo -e "  ${GREEN}$PAM_LINE${NC}"
        echo ""
        read -p "Would you like to add this automatically? [y/N] " -n 1 -r
        echo ""

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Backup original
            cp "$PAM_FILE" "${PAM_FILE}.bak"

            # Add after common-auth or pam_unix.so
            if grep -q "@include common-auth" "$PAM_FILE"; then
                sed -i '/@include common-auth/a '"$PAM_LINE" "$PAM_FILE"
            elif grep -q "pam_unix.so" "$PAM_FILE"; then
                sed -i '/pam_unix.so/a '"$PAM_LINE" "$PAM_FILE"
            else
                # Just append
                echo "$PAM_LINE" >> "$PAM_FILE"
            fi

            echo -e "${GREEN}PAM configured (backup saved to ${PAM_FILE}.bak)${NC}"
        fi
    fi
}

# Configure SSHD
configure_sshd() {
    echo ""
    echo -e "${YELLOW}SSH Configuration${NC}"
    echo ""

    SSHD_CONFIG="/etc/ssh/sshd_config"
    CHANGES_MADE=0

    # Check ChallengeResponseAuthentication or KbdInteractiveAuthentication
    if grep -qE "^ChallengeResponseAuthentication\s+yes" "$SSHD_CONFIG" || \
       grep -qE "^KbdInteractiveAuthentication\s+yes" "$SSHD_CONFIG"; then
        echo "Challenge-response authentication: OK"
    else
        echo -e "${YELLOW}Challenge-response authentication needs to be enabled${NC}"
        CHANGES_MADE=1
    fi

    # Check UsePAM
    if grep -qE "^UsePAM\s+yes" "$SSHD_CONFIG"; then
        echo "UsePAM: OK"
    else
        echo -e "${YELLOW}UsePAM needs to be set to yes${NC}"
        CHANGES_MADE=1
    fi

    if [ $CHANGES_MADE -eq 1 ]; then
        echo ""
        echo "Please ensure the following settings in $SSHD_CONFIG:"
        echo "  ChallengeResponseAuthentication yes"
        echo "  UsePAM yes"
        echo ""
        echo "Then restart sshd: systemctl restart sshd"
    fi
}

# Main
main() {
    detect_distro
    install_deps
    build_module
    install_module
    configure_pam
    configure_sshd

    echo ""
    echo "========================================"
    echo -e "  ${GREEN}Installation Complete!${NC}"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "1. Edit /etc/worldposta/worldposta.conf"
    echo "   - Add your integration_key"
    echo "   - Add your secret_key"
    echo ""
    echo "2. Verify PAM is configured in /etc/pam.d/sshd"
    echo ""
    echo "3. Restart SSH: systemctl restart sshd"
    echo ""
    echo "4. Test from another terminal before logging out!"
    echo ""
}

main "$@"
