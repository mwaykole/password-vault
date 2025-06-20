# Password Vault

A secure, optimized password manager with Gmail OAuth authentication and native Linux integration. Stores passwords and files using military-grade encryption with minimal resource usage.

## ✨ Features

### 🔐 Security
* **AES-GCM encryption** via `cryptography.Fernet`
* **Gmail OAuth authentication** - Login with your Google account
* **Traditional login** - Username/password option
* **Account linking** - Automatically links OAuth to existing accounts
* **Security headers** and CSRF protection

### 💾 Storage
* **SQLite database** (file-based, no external server)
* **Password storage** with labels and categories
* **File storage** - Securely store and encrypt any file type
* **Export/import** functionality

### 🚀 Performance
* **Memory optimized** - Uses only 15.5MB RAM
* **Fast startup** - Launches in under 2 seconds
* **Efficient encryption** - Chunked file processing
* **Database optimization** - Indexes and WAL mode

### 🐧 Linux Integration
* **Native desktop app** - Appears in application menu
* **Systemd service** - Auto-start and background operation
* **App mode browser** - Opens as standalone window, not browser tab
* **Command-line tools** - `password-vault start/stop/status/logs/open`
* **Resource limits** - 64MB RAM limit, 50% CPU quota

## 🚀 Quick Start

### Simple Installation
```bash
git clone <repository>
cd password_saver/password_saver
./setup.sh
```

### Manual Installation
1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run setup**
   ```bash
   ./install.sh
   ```

3. **Start the application**
   ```bash
   password-vault start
   password-vault open
   ```

## 🔑 Gmail OAuth Setup (Optional)

For enhanced security, enable Gmail authentication:

1. **Install OAuth dependencies**
   ```bash
   pip install google-auth google-auth-oauthlib google-auth-httplib2
   ```

2. **Configure Google OAuth**
   - Follow the detailed guide: [`GOOGLE_OAUTH_SETUP.md`](GOOGLE_OAUTH_SETUP.md)
   - Set up Google Cloud project and OAuth credentials
   - Add environment variables to `.env`

3. **Enable OAuth**
   ```bash
   cp app.py app_original.py  # Backup
   cp app_oauth.py app.py     # Use OAuth version
   password-vault restart
   ```

## 🎯 Usage

### Command Line
```bash
password-vault start     # Start the service
password-vault stop      # Stop the service  
password-vault status    # Check status
password-vault logs      # View logs
password-vault open      # Open in browser (app mode)
password-vault restart   # Restart service
```

### Desktop Integration
- **Application Menu**: Find "Password Vault" in your applications
- **Desktop File**: Click the desktop entry to launch
- **Auto-start**: Enable via systemd user service

### Web Interface
- **Login**: Use Gmail OAuth or traditional username/password
- **Passwords**: Store, organize, and retrieve passwords securely
- **Files**: Upload and encrypt any file type (up to 5MB)
- **Export**: Download your data as encrypted CSV

## Screenshots

![List view](docs/list.png)

## Security notes

This project is intended as a lightweight personal tool / learning demo, **not** a production-grade password manager. There is no multi-user separation, audit logging or sophisticated key management. Use at your own risk. 