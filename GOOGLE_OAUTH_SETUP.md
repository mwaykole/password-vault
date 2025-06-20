# Google OAuth Setup Guide

This guide will help you set up Gmail authentication for your Password Vault application.

## 🚀 Quick Setup

### Step 1: Install OAuth Dependencies

```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 requests
```

### Step 2: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API (or Google Identity API)

### Step 3: Create OAuth Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth client ID**
3. Choose **Web application**
4. Set up the OAuth consent screen if prompted
5. Add authorized redirect URIs:
   - `http://localhost:5000/oauth/callback` (for local development)
   - `http://127.0.0.1:5000/oauth/callback` (alternative local)

### Step 4: Configure Environment Variables

Add these to your `.env` file:

```bash
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here

# Existing configuration...
FLASK_SECRET=your_existing_secret
HTTPS=0
DEBUG=0
```

### Step 5: Use OAuth-Enabled App

Replace `app.py` with `app_oauth.py`:

```bash
# Backup original
cp app.py app_original.py

# Use OAuth version
cp app_oauth.py app.py

# Restart the service
password-vault restart
```

## 🔧 Detailed Configuration

### OAuth Consent Screen Setup

1. **Application type**: Internal (for organization) or External (for public use)
2. **Application name**: "Password Vault"
3. **User support email**: Your email
4. **Developer contact**: Your email
5. **Scopes**: Add these scopes:
   - `openid`
   - `email`
   - `profile`

### Security Considerations

#### Redirect URI Security
- Always use HTTPS in production
- Whitelist only necessary redirect URIs
- Use specific paths, not wildcards

#### Client Secret Protection
- Never commit secrets to version control
- Use environment variables
- Rotate secrets regularly

#### Scope Limitations
- Request minimal necessary scopes
- Current scopes: `openid`, `email`, `profile`
- No access to Gmail content or other Google services

## 🔐 Security Features

### OAuth Flow Security
- **State parameter**: Prevents CSRF attacks
- **PKCE**: Code challenge for additional security
- **Token validation**: Verify tokens from Google
- **Secure sessions**: Encrypted session storage

### User Data Handling
- **Minimal data**: Only email, name, and profile picture
- **No password storage**: OAuth users don't have local passwords
- **Existing account linking**: Links OAuth to existing accounts by email

## 🎯 User Experience

### Login Options
1. **Google OAuth**: One-click login with Gmail account
2. **Traditional**: Username/password for existing accounts
3. **Account linking**: Automatically links OAuth to existing accounts

### Account Creation
- **Automatic**: Creates account on first OAuth login
- **Unique usernames**: Auto-generates if email username exists
- **Profile integration**: Uses Google profile picture

## 🛠️ Troubleshooting

### Common Issues

#### "OAuth not configured" Error
```bash
# Check environment variables
echo $GOOGLE_CLIENT_ID
echo $GOOGLE_CLIENT_SECRET

# Ensure packages are installed
pip list | grep google-auth
```

#### "Invalid redirect URI" Error
- Verify redirect URI in Google Console matches exactly
- Check for trailing slashes
- Ensure protocol (http/https) matches

#### "OAuth state mismatch" Error
- Clear browser cookies and sessions
- Check session configuration
- Verify FLASK_SECRET is set

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Testing OAuth Flow

1. Start application: `password-vault start`
2. Open: `http://localhost:5000`
3. Click "Continue with Google"
4. Authorize application
5. Should redirect back and log you in

## 🔄 Migration Guide

### From Traditional to OAuth

1. **Backup database**: `cp passwords.db passwords.db.backup`
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Configure OAuth**: Set up Google credentials
4. **Switch app**: Use `app_oauth.py`
5. **Test login**: Both methods should work

### Existing Users

- **Traditional users**: Can continue using username/password
- **OAuth linking**: If email matches, accounts are linked
- **Dual support**: Both login methods work simultaneously

## 📋 Production Checklist

- [ ] Google Cloud project created
- [ ] OAuth consent screen configured
- [ ] Client ID and secret generated
- [ ] Environment variables set
- [ ] HTTPS enabled (production)
- [ ] Redirect URIs updated for production domain
- [ ] Dependencies installed
- [ ] Application tested
- [ ] Backup created

## 🌐 Production Deployment

### HTTPS Configuration

```bash
# Update .env for production
HTTPS=1
GOOGLE_CLIENT_ID=your_production_client_id
GOOGLE_CLIENT_SECRET=your_production_client_secret
```

### Domain Configuration

Update redirect URIs in Google Console:
- `https://yourdomain.com/oauth/callback`

### Security Headers

The app automatically includes security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

## 📞 Support

If you encounter issues:

1. Check the console logs: `password-vault logs`
2. Verify environment variables
3. Test with traditional login first
4. Check Google Cloud Console for API quotas
5. Review redirect URI configuration

## 🎉 Benefits

### For Users
- **No passwords to remember**: Use existing Gmail account
- **Faster login**: One-click authentication
- **Secure**: Google's enterprise-grade security
- **Profile integration**: Automatic profile picture

### For Administrators
- **Reduced support**: Fewer password reset requests
- **Better security**: No weak passwords
- **Audit trail**: Google provides login logs
- **SSO ready**: Can integrate with Google Workspace 