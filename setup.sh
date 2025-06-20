#!/bin/bash

# Password Vault - Universal Setup Script
# This script can be run from any directory and will work for any user
# Just clone the repo and run: ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔐 Password Vault - Universal Setup"
echo "📁 Directory: $SCRIPT_DIR"
echo "👤 User: $USER"
echo "🏠 Home: $HOME"
echo ""

# Check if we're in the right directory
if [[ ! -f "$SCRIPT_DIR/app.py" ]]; then
    print_error "app.py not found in current directory"
    print_error "Make sure you're running this from the password_saver directory"
    exit 1
fi

# Check if install.sh exists
if [[ ! -f "$SCRIPT_DIR/install.sh" ]]; then
    print_error "install.sh not found"
    exit 1
fi

print_status "Found all required files"

# Make sure install.sh is executable
chmod +x "$SCRIPT_DIR/install.sh"

# Check if already installed
if systemctl --user is-enabled password-vault &>/dev/null; then
    print_status "Password Vault is already installed"
    echo ""
    echo "🔧 Available commands:"
    echo "   password-vault start    # Start the service"
    echo "   password-vault stop     # Stop the service"
    echo "   password-vault status   # Check status"
    echo "   password-vault open     # Open in browser"
    echo ""
    read -p "Would you like to reinstall? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled. Use 'password-vault' commands to manage the service."
        exit 0
    fi
fi

# Run the installation
print_status "Running installation..."
"$SCRIPT_DIR/install.sh"

print_success "Setup completed!"
echo ""
echo "🎉 Your Password Vault is ready to use!"
echo ""
echo "🚀 Quick commands:"
echo "   password-vault start    # Start the service"
echo "   password-vault open     # Open in browser"
echo "   password-vault status   # Check if running"
echo ""
echo "📍 App location: $SCRIPT_DIR"
echo "🌐 Web interface: http://localhost:5000" 