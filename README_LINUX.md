# 🔐 Password Vault - Linux Application

A secure, optimized password manager designed specifically for Linux systems with minimal resource usage and maximum security.

## 🚀 Features

- **🔒 Military-grade encryption** (AES-256 via Fernet)
- **📁 File storage** with encrypted file management
- **🌐 Web-based interface** accessible via browser
- **⚡ Optimized performance** (15MB RAM usage)
- **🛡️ Enhanced security** with CSRF protection and rate limiting
- **🐧 Native Linux integration** with systemd service
- **📱 Desktop integration** with application menu entry
- **🔧 Easy management** via command-line tools

## 📋 System Requirements

- **OS**: Linux with systemd (Ubuntu 18.04+, Fedora 28+, Arch, etc.)
- **Python**: 3.8 or higher
- **RAM**: Minimum 32MB, Recommended 64MB
- **Storage**: 50MB for application + your data
- **Network**: Local access (127.0.0.1:5000)

## 🔧 Quick Installation

### 1. Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip systemd git
```

**Fedora:**
```bash
sudo dnf install python3 python3-pip systemd git
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip systemd git
```

### 2. Clone and Install

```bash
# Clone the repository (if not already done)
git clone <repository-url>
cd password_saver/password_saver

# Run the installation script
./install.sh
```

The installer will:
- ✅ Check system dependencies
- ✅ Install Python packages
- ✅ Generate encryption keys
- ✅ Create systemd service
- ✅ Set up desktop integration
- ✅ Configure security settings

## 🎮 Usage

### Command Line Interface

After installation, use the `password-vault` command:

```bash
# Start the service
password-vault start

# Stop the service  
password-vault stop

# Restart the service
password-vault restart

# Check status
password-vault status

# View live logs
password-vault logs

# Open in browser
password-vault open
```

### Desktop Integration

- **Application Menu**: Find "Password Vault" in your applications
- **Quick Actions**: Right-click for start/stop options
- **Auto-start**: Service can auto-start on login

### Web Interface

Access your vault at: **http://localhost:5000**

1. **Register** a new account (first time)
2. **Login** with your credentials
3. **Add passwords** or upload files
4. **Manage** your encrypted vault

## 🔒 Security Features

### Built-in Security
- **AES-256 encryption** for all data
- **PBKDF2 password hashing** with salt
- **CSRF protection** on all forms
- **Rate limiting** (5 login attempts/minute)
- **Secure session management**
- **Input sanitization** against XSS
- **Security headers** for web protection

### File Permissions
```bash
# Automatically set by installer
-rw------- .secret.key    # Encryption key (600)
-rw------- passwords.db   # Database (600)
-rw------- .env          # Configuration (600)
```

### Resource Limits
- **Memory**: Limited to 64MB
- **CPU**: Limited to 50% of one core
- **Tasks**: Maximum 10 concurrent processes

## ⚙️ Configuration

### Environment Variables (.env)
```bash
# Security
FLASK_SECRET=your_secure_secret_key
HTTPS=1                    # Enable for production
DEBUG=0                    # Never enable in production

# Performance
SESSION_TIMEOUT=30         # Minutes
MAX_CONTENT_LENGTH=5242880 # 5MB file limit

# Rate Limiting
CSRF_TIME_LIMIT=3600      # 1 hour
```

### Service Configuration
```bash
# View service status
systemctl --user status password-vault

# Enable auto-start on login
systemctl --user enable password-vault

# Disable auto-start
systemctl --user disable password-vault

# View logs
journalctl --user -u password-vault -f
```

## 🔧 Maintenance

### Regular Tasks

**Weekly:**
```bash
# Check service status
password-vault status

# Review logs for security events
password-vault logs | grep -i "error\|warning\|failed"
```

**Monthly:**
```bash
# Update dependencies
pip3 install --user --upgrade -r requirements.txt

# Backup your vault
cp passwords.db passwords.db.backup.$(date +%Y%m%d)
cp .secret.key .secret.key.backup.$(date +%Y%m%d)
```

**Quarterly:**
```bash
# Security audit
python security_audit.py

# Performance optimization
python optimize_performance.py
```

### Backup Strategy

**Important Files to Backup:**
- `passwords.db` - Your encrypted password database
- `.secret.key` - Your encryption key (CRITICAL!)
- `.env` - Your configuration

**Backup Script:**
```bash
#!/bin/bash
BACKUP_DIR="$HOME/password_vault_backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
cd /path/to/password_saver/password_saver

tar -czf "$BACKUP_DIR/password_vault_$DATE.tar.gz" \
    passwords.db .secret.key .env

echo "Backup created: $BACKUP_DIR/password_vault_$DATE.tar.gz"
```

## 🛠️ Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check logs
journalctl --user -u password-vault -n 50

# Verify permissions
ls -la .secret.key passwords.db

# Test manually
python3 app.py
```

**Can't access web interface:**
```bash
# Check if service is running
password-vault status

# Verify port is listening
ss -tlnp | grep 5000

# Check firewall (if applicable)
sudo ufw status
```

**Permission denied errors:**
```bash
# Fix file permissions
chmod 600 .secret.key passwords.db .env
chmod 755 install.sh uninstall.sh
```

**High memory usage:**
```bash
# Check current usage
password-vault status

# Restart service to clear memory
password-vault restart

# Run optimization
python optimize_performance.py
```

### Performance Optimization

**If experiencing slow performance:**

1. **Check system resources:**
   ```bash
   htop
   df -h
   free -h
   ```

2. **Optimize database:**
   ```bash
   python optimize_performance.py
   ```

3. **Review logs for errors:**
   ```bash
   password-vault logs | tail -100
   ```

## 🗑️ Uninstallation

To remove Password Vault from your system:

```bash
# Run uninstall script
./uninstall.sh
```

This will:
- ✅ Stop and disable the service
- ✅ Remove desktop integration
- ✅ Remove systemd service file
- ✅ Remove launcher script
- ✅ **Preserve** your data files

**To completely remove everything:**
```bash
./uninstall.sh
cd ..
rm -rf password_saver  # WARNING: This deletes ALL data!
```

## 🔍 Advanced Configuration

### HTTPS Setup (Production)

1. **Generate SSL certificate:**
   ```bash
   # Self-signed for testing
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
   
   # Or use Let's Encrypt for production
   sudo certbot certonly --standalone -d your-domain.com
   ```

2. **Update service configuration:**
   ```bash
   # Edit .env
   HTTPS=1
   SSL_CERT=/path/to/cert.pem
   SSL_KEY=/path/to/key.pem
   ```

### Reverse Proxy Setup (nginx)

```nginx
server {
    listen 443 ssl;
    server_name vault.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📚 Additional Resources

- **Security Checklist**: `SECURITY_CHECKLIST.md`
- **Performance Guide**: `optimize_performance.py`
- **Penetration Test Report**: `penetration_test_report.md`
- **Source Code**: `app.py` (main application)

## 🆘 Support

### Getting Help

1. **Check logs first:**
   ```bash
   password-vault logs
   ```

2. **Run diagnostics:**
   ```bash
   python security_audit.py
   ```

3. **Performance check:**
   ```bash
   python optimize_performance.py
   ```

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Python version (`python3 --version`)
- Service status (`password-vault status`)
- Recent logs (`password-vault logs | tail -50`)
- Steps to reproduce the issue

---

## 🎉 Enjoy Your Secure Password Vault!

Your passwords are now protected with military-grade encryption and accessible through a beautiful, optimized web interface. The application uses minimal system resources while providing maximum security.

**Remember**: Keep your `.secret.key` file safe - it's the only way to decrypt your data! 