#!/bin/bash

# Password Vault Uninstall Script
# This script removes the password manager from your Linux system

set -e

SERVICE_NAME="password-vault"
USER_SERVICE_DIR="$HOME/.config/systemd/user"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons"
BIN_DIR="$HOME/.local/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🗑️  Uninstalling Password Vault..."

# Ask for confirmation
echo ""
print_warning "This will remove Password Vault from your system."
print_warning "Your password database and encryption keys will be preserved."
echo ""
read -p "Are you sure you want to continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

# Stop and disable service
print_status "Stopping and disabling service..."
if systemctl --user is-active --quiet $SERVICE_NAME 2>/dev/null; then
    systemctl --user stop $SERVICE_NAME
    print_success "Stopped service"
fi

if systemctl --user is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
    systemctl --user disable $SERVICE_NAME
    print_success "Disabled service"
fi

# Remove service file
if [[ -f "$USER_SERVICE_DIR/$SERVICE_NAME.service" ]]; then
    rm "$USER_SERVICE_DIR/$SERVICE_NAME.service"
    systemctl --user daemon-reload
    print_success "Removed systemd service"
fi

# Remove desktop entry
if [[ -f "$DESKTOP_DIR/password-vault.desktop" ]]; then
    rm "$DESKTOP_DIR/password-vault.desktop"
    print_success "Removed desktop entry"
fi

# Remove icon
if [[ -f "$ICON_DIR/password-vault.svg" ]]; then
    rm "$ICON_DIR/password-vault.svg"
    print_success "Removed application icon"
fi

# Remove launcher script
if [[ -f "$BIN_DIR/password-vault" ]]; then
    rm "$BIN_DIR/password-vault"
    print_success "Removed launcher script"
fi

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

print_success "Uninstall completed successfully!"

echo ""
echo "🎉 Password Vault has been removed from your system."
echo ""
echo "📁 Preserved files in $(pwd):"
echo "   • passwords.db (your encrypted database)"
echo "   • .secret.key (your encryption key)"
echo "   • .env (your configuration)"
echo "   • All source files"
echo ""
echo "💡 To completely remove everything:"
echo "   cd .. && rm -rf password_saver"
echo ""
echo "🔄 To reinstall later:"
echo "   ./install.sh"
echo "" 