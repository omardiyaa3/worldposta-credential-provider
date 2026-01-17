# WorldPosta SSH MFA - PAM Module
# Copyright (c) 2024 WorldPosta

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -fno-strict-aliasing
LDFLAGS = -shared -Wl,-soname,pam_worldposta.so

# Libraries
LIBS = -lpam -lcurl -lssl -lcrypto -ljson-c

# Directories
SRCDIR = src
OBJDIR = obj
DESTDIR ?=

# Detect architecture for library path
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    LIBDIR = /lib/x86_64-linux-gnu/security
    LIBDIR_ALT = /lib64/security
else ifeq ($(ARCH),aarch64)
    LIBDIR = /lib/aarch64-linux-gnu/security
    LIBDIR_ALT = /lib64/security
else
    LIBDIR = /lib/security
    LIBDIR_ALT = /lib/security
endif

# Detect distro for correct library path
ifneq ($(wildcard /etc/debian_version),)
    # Debian/Ubuntu
    INSTALL_LIBDIR = $(LIBDIR)
else ifneq ($(wildcard /etc/redhat-release),)
    # RHEL/CentOS/Fedora
    INSTALL_LIBDIR = $(LIBDIR_ALT)
else
    INSTALL_LIBDIR = $(LIBDIR)
endif

# Source files
SRCS = $(SRCDIR)/pam_worldposta.c \
       $(SRCDIR)/config.c \
       $(SRCDIR)/api.c \
       $(SRCDIR)/crypto.c

OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Targets
TARGET = pam_worldposta.so

.PHONY: all clean install uninstall deps

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -rf $(OBJDIR) $(TARGET)

# Install dependencies (Debian/Ubuntu)
deps-debian:
	apt-get update
	apt-get install -y libpam0g-dev libcurl4-openssl-dev libssl-dev libjson-c-dev

# Install dependencies (RHEL/CentOS/Fedora)
deps-redhat:
	dnf install -y pam-devel libcurl-devel openssl-devel json-c-devel

# Install the PAM module
install: $(TARGET)
	@echo "Installing WorldPosta PAM module..."
	install -d $(DESTDIR)/etc/worldposta
	install -d $(DESTDIR)$(INSTALL_LIBDIR)
	install -m 644 $(TARGET) $(DESTDIR)$(INSTALL_LIBDIR)/
	@if [ ! -f $(DESTDIR)/etc/worldposta/worldposta.conf ]; then \
		install -m 600 config/worldposta.conf $(DESTDIR)/etc/worldposta/; \
	else \
		echo "Config file already exists, not overwriting"; \
	fi
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit /etc/worldposta/worldposta.conf with your API credentials"
	@echo "2. Add the following line to /etc/pam.d/sshd (after pam_unix.so):"
	@echo "   auth required pam_worldposta.so"
	@echo "3. Ensure /etc/ssh/sshd_config has:"
	@echo "   ChallengeResponseAuthentication yes"
	@echo "   UsePAM yes"
	@echo "4. Restart sshd: systemctl restart sshd"

uninstall:
	@echo "Uninstalling WorldPosta PAM module..."
	rm -f $(DESTDIR)$(INSTALL_LIBDIR)/pam_worldposta.so
	@echo "Note: Config files in /etc/worldposta were not removed"
	@echo ""
	@echo "Don't forget to remove the pam_worldposta.so line from /etc/pam.d/sshd"

# Show info
info:
	@echo "WorldPosta SSH MFA PAM Module"
	@echo "Architecture: $(ARCH)"
	@echo "Install path: $(INSTALL_LIBDIR)"
