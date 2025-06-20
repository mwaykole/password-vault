#!/bin/bash

# Password Vault Linux Installation Script
# This script installs the password manager as a proper Linux application
# Works for any user and any directory location

set -e

APP_NAME="Password Vault"
SERVICE_NAME="password-vault"
USER_SERVICE_DIR="$HOME/.config/systemd/user"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons"
BIN_DIR="$HOME/.local/bin"

# Get the current directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR"

echo "🔐 Installing $APP_NAME..."
echo "📁 Application directory: $APP_DIR"
echo "👤 Installing for user: $USER"

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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root for security reasons"
    print_status "Run as your regular user: ./install.sh"
    exit 1
fi

# Check dependencies
print_status "Checking dependencies..."

check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed"
        return 1
    fi
}

MISSING_DEPS=0

if ! check_command python3; then
    print_error "Python 3 is required"
    MISSING_DEPS=1
fi

if ! check_command pip3; then
    print_error "pip3 is required"
    MISSING_DEPS=1
fi

if ! check_command systemctl; then
    print_error "systemd is required"
    MISSING_DEPS=1
fi

if [[ $MISSING_DEPS -eq 1 ]]; then
    print_error "Please install missing dependencies first"
    echo "On Ubuntu/Debian: sudo apt install python3 python3-pip systemd"
    echo "On Fedora: sudo dnf install python3 python3-pip systemd"
    echo "On Arch: sudo pacman -S python python-pip systemd"
    exit 1
fi

print_success "All dependencies found"

# Install Python packages
print_status "Installing Python dependencies..."
pip3 install --user -r requirements.txt

# Create directories
print_status "Creating directories..."
mkdir -p "$USER_SERVICE_DIR"
mkdir -p "$DESKTOP_DIR"
mkdir -p "$ICON_DIR"
mkdir -p "$BIN_DIR"

# Generate secure keys if not exists
print_status "Setting up encryption..."
if [[ ! -f "$APP_DIR/.secret.key" ]]; then
    python3 -c "
from cryptography.fernet import Fernet
import secrets
key = Fernet.generate_key()
with open('$APP_DIR/.secret.key', 'wb') as f:
    f.write(key)
print('Generated new encryption key')
"
    chmod 600 "$APP_DIR/.secret.key"
    print_success "Generated new encryption key"
else
    print_success "Using existing encryption key"
fi

# Set up environment file
print_status "Creating environment configuration..."
if [[ ! -f "$APP_DIR/.env" ]]; then
    FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$APP_DIR/.env" << EOF
# Security Configuration
FLASK_SECRET=$FLASK_SECRET
HTTPS=0
DEBUG=0

# Session Configuration
SESSION_TIMEOUT=30
CSRF_TIME_LIMIT=3600

# Performance
MAX_CONTENT_LENGTH=5242880
EOF
    chmod 600 "$APP_DIR/.env"
    print_success "Created environment configuration"
else
    print_success "Using existing environment configuration"
fi

# Create systemd service file with dynamic paths
print_status "Installing systemd service..."
cat > "$USER_SERVICE_DIR/$SERVICE_NAME.service" << EOF
[Unit]
Description=Password Vault - Secure Password Manager
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PYTHONPATH=$APP_DIR
Environment=FLASK_ENV=production
Environment=FLASK_SECRET=your_secure_secret_key_here_change_this
Environment=HTTPS=0
ExecStart=/usr/bin/python3 app.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

# Security settings (simplified for user service)
NoNewPrivileges=yes
PrivateTmp=yes

# Resource limits for optimization
MemoryLimit=64M
CPUQuota=50%
TasksMax=10

[Install]
WantedBy=default.target
EOF

# Reload systemd and enable service
systemctl --user daemon-reload
systemctl --user enable $SERVICE_NAME
print_success "Installed systemd service"

# Create launcher script
print_status "Creating launcher script..."
cat > "$BIN_DIR/password-vault" << EOF
#!/bin/bash
# Password Vault Launcher

APP_DIR="$APP_DIR"

case "\$1" in
    start)
        echo "Starting Password Vault..."
        systemctl --user start password-vault
        sleep 2
        if systemctl --user is-active --quiet password-vault; then
            echo "✅ Password Vault started successfully"
            echo "🌐 Access at: http://localhost:5000"
        else
            echo "❌ Failed to start Password Vault"
            systemctl --user status password-vault
        fi
        ;;
    stop)
        echo "Stopping Password Vault..."
        systemctl --user stop password-vault
        echo "✅ Password Vault stopped"
        ;;
    restart)
        echo "Restarting Password Vault..."
        systemctl --user restart password-vault
        sleep 2
        if systemctl --user is-active --quiet password-vault; then
            echo "✅ Password Vault restarted successfully"
        else
            echo "❌ Failed to restart Password Vault"
        fi
        ;;
    status)
        systemctl --user status password-vault
        ;;
    logs)
        journalctl --user -u password-vault -f
        ;;
    open)
        if systemctl --user is-active --quiet password-vault; then
            if command -v google-chrome >/dev/null; then
                google-chrome --app=http://localhost:5000 --new-window
            elif command -v chromium >/dev/null; then
                chromium --app=http://localhost:5000 --new-window
            else
                xdg-open http://localhost:5000
            fi
        else
            echo "❌ Password Vault is not running"
            echo "Start it with: password-vault start"
        fi
        ;;
    install)
        echo "Installing desktop integration..."
        cd "\$APP_DIR"
        ./install.sh
        ;;
    *)
        echo "Password Vault - Secure Password Manager"
        echo ""
        echo "Usage: \$0 {start|stop|restart|status|logs|open|install}"
        echo ""
        echo "Commands:"
        echo "  start    - Start the Password Vault service"
        echo "  stop     - Stop the Password Vault service"
        echo "  restart  - Restart the Password Vault service"
        echo "  status   - Show service status"
        echo "  logs     - Show live logs"
        echo "  open     - Open Password Vault in browser"
        echo "  install  - Install desktop integration"
        echo ""
        echo "Access URL: http://localhost:5000"
        echo "App Directory: $APP_DIR"
        ;;
esac
EOF

chmod +x "$BIN_DIR/password-vault"
print_success "Created launcher script at $BIN_DIR/password-vault"

# Create desktop entry with dynamic paths
print_status "Installing desktop integration..."
cat > "$DESKTOP_DIR/password-vault.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Password Vault
Comment=Secure Password Manager with File Storage
GenericName=Password Manager
Icon=password-vault
Exec=sh -c 'if command -v google-chrome >/dev/null; then google-chrome --app=http://localhost:5000 --new-window --disable-web-security --disable-features=TranslateUI --disable-extensions --disable-plugins --disable-default-apps; elif command -v chromium >/dev/null; then chromium --app=http://localhost:5000 --new-window --disable-web-security --disable-features=TranslateUI --disable-extensions --disable-plugins --disable-default-apps; elif command -v firefox >/dev/null; then firefox --new-window --kiosk http://localhost:5000; else xdg-open http://localhost:5000; fi'
StartupNotify=true
Categories=Utility;Security;Office;
Keywords=password;security;vault;encryption;manager;
MimeType=text/plain;application/json;

[Desktop Action OpenVault]
Name=Open Password Vault
Exec=sh -c 'if command -v google-chrome >/dev/null; then google-chrome --app=http://localhost:5000 --new-window; elif command -v chromium >/dev/null; then chromium --app=http://localhost:5000 --new-window; else xdg-open http://localhost:5000; fi'

[Desktop Action StartService]
Name=Start Service
Exec=systemctl --user start password-vault

[Desktop Action StopService]
Name=Stop Service
Exec=systemctl --user stop password-vault

Actions=OpenVault;StartService;StopService;
EOF

print_success "Installed desktop entry"

# Create application icon (simple SVG)
print_status "Creating application icon..."
cat > "$ICON_DIR/password-vault.svg" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#667eea;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#764ba2;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <!-- Shield background -->
  <path d="M32 4 L52 12 L52 32 C52 48 32 60 32 60 C32 60 12 48 12 32 L12 12 Z" 
        fill="url(#grad1)" stroke="#333" stroke-width="2"/>
  
  <!-- Lock icon -->
  <rect x="24" y="28" width="16" height="12" rx="2" fill="white" stroke="#333" stroke-width="1.5"/>
  <path d="M28 28 L28 24 C28 21.8 29.8 20 32 20 C34.2 20 36 21.8 36 24 L36 28" 
        fill="none" stroke="white" stroke-width="2" stroke-linecap="round"/>
  <circle cx="32" cy="34" r="2" fill="#333"/>
  
  <!-- Key hole -->
  <path d="M32 36 L32 38" stroke="#333" stroke-width="1.5" stroke-linecap="round"/>
</svg>
EOF

print_success "Created application icon"

# Set proper permissions
print_status "Setting file permissions..."
chmod 600 "$APP_DIR/.secret.key" "$APP_DIR/passwords.db" 2>/dev/null || true
chmod 644 "$DESKTOP_DIR/password-vault.desktop"
chmod 644 "$USER_SERVICE_DIR/$SERVICE_NAME.service"

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

print_success "Installation completed successfully!"

echo ""
echo "🎉 Password Vault has been installed as a Linux application!"
echo ""
echo "📁 Installation Details:"
echo "   • App Directory: $APP_DIR"
echo "   • User: $USER"
echo "   • Service: $USER_SERVICE_DIR/$SERVICE_NAME.service"
echo "   • Launcher: $BIN_DIR/password-vault"
echo ""
echo "📋 Quick Start:"
echo "   Start service: password-vault start"
echo "   Open in browser: password-vault open"
echo "   View status: password-vault status"
echo "   View logs: password-vault logs"
echo ""
echo "🖥️  Desktop Integration:"
echo "   • Application menu entry added"
echo "   • Desktop file: $DESKTOP_DIR/password-vault.desktop"
echo "   • Launcher: $BIN_DIR/password-vault"
echo ""
echo "🔧 Service Management:"
echo "   • Service file: $USER_SERVICE_DIR/$SERVICE_NAME.service"
echo "   • Auto-start on login: systemctl --user enable password-vault"
echo "   • Manual start: systemctl --user start password-vault"
echo ""
echo "🔒 Security Features:"
echo "   • Encrypted database and files"
echo "   • Secure file permissions (600)"
echo "   • Memory limit: 64MB"
echo "   • CPU limit: 50%"
echo ""
echo "🌐 Access your vault at: http://localhost:5000"
echo ""

# Ask if user wants to start the service now
read -p "Would you like to start the Password Vault service now? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    print_status "Starting Password Vault service..."
    password-vault start
    echo ""
    echo "🚀 Password Vault is now running!"
    echo "🌐 Open http://localhost:5000 in your browser"
fi 