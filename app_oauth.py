import os
import sqlite3
from pathlib import Path
import hashlib
import secrets
from datetime import datetime, timedelta
import json
import base64
import csv
import io

from cryptography.fernet import Fernet
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    flash,
    session,
    send_file,
    make_response,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Google OAuth imports
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    import google.auth.transport.requests
    import requests
    OAUTH_AVAILABLE = True
except ImportError:
    OAUTH_AVAILABLE = False
    print("[WARNING] Google OAuth packages not installed. OAuth features disabled.")

# ----------------------------------------------------------------------------
# Configuration helpers
# ----------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "passwords.db"
KEY_FILE = BASE_DIR / ".secret.key"

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid_configuration"

def _load_or_create_key() -> bytes:
    """Load encryption key, create a new one if it does not exist."""
    if "ENCRYPTION_KEY" in os.environ and os.environ["ENCRYPTION_KEY"].strip():
        return os.environ["ENCRYPTION_KEY"].encode()

    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    # Generate new key
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    print(
        "[INFO] Generated new encryption key and saved to .secret.key. "
        "You can move this file somewhere safe or set ENCRYPTION_KEY env var."
    )
    return key

# Initialize crypto and database
fernet = Fernet(_load_or_create_key())

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, email, oauth_provider=None):
        self.id = user_id
        self.username = username
        self.email = email
        self.oauth_provider = oauth_provider

def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    conn = _get_connection()
    cur = conn.cursor()
    
    # Users table (updated for OAuth)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            oauth_provider TEXT,
            oauth_id TEXT,
            profile_picture TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
        """
    )
    
    # Add OAuth columns to existing table if they don't exist
    try:
        cur.execute("ALTER TABLE users ADD COLUMN oauth_provider TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cur.execute("ALTER TABLE users ADD COLUMN oauth_id TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cur.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
    except sqlite3.OperationalError:
        pass
    
    # Passwords table (same as original)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            secret BLOB NOT NULL,
            is_file BOOLEAN DEFAULT 0,
            file_name TEXT,
            file_type TEXT,
            file_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, label)
        )
        """
    )
    
    # Add file columns if they don't exist
    try:
        cur.execute("ALTER TABLE passwords ADD COLUMN is_file BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    try:
        cur.execute("ALTER TABLE passwords ADD COLUMN file_name TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cur.execute("ALTER TABLE passwords ADD COLUMN file_type TEXT")
    except sqlite3.OperationalError:
        pass
    
    try:
        cur.execute("ALTER TABLE passwords ADD COLUMN file_size INTEGER")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

_init_db()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access your passwords.'
login_manager.login_message_category = 'info'

# Security configuration
app.config.update(
    SESSION_COOKIE_SECURE=True if os.getenv('HTTPS') == '1' else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

@login_manager.user_loader
def load_user(user_id):
    with _get_connection() as conn:
        row = conn.execute("SELECT id, username, email, oauth_provider FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return User(row['id'], row['username'], row['email'], row['oauth_provider'])
    return None

# OAuth helper functions
def get_google_provider_cfg():
    """Get Google OAuth configuration"""
    if not OAUTH_AVAILABLE:
        return None
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except:
        return None

def create_oauth_flow():
    """Create Google OAuth flow"""
    if not OAUTH_AVAILABLE or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return None
    
    google_provider_cfg = get_google_provider_cfg()
    if not google_provider_cfg:
        return None
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": google_provider_cfg["authorization_endpoint"],
                "token_uri": google_provider_cfg["token_endpoint"],
            }
        },
        scopes=["openid", "email", "profile"],
    )
    
    flow.redirect_uri = url_for("oauth_callback", _external=True)
    return flow

def is_account_locked(username):
    """Check if account is locked due to failed attempts."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE username = ?", 
            (username,)
        ).fetchone()
        if row and row['locked_until']:
            locked_until = datetime.fromisoformat(row['locked_until'])
            if datetime.now() < locked_until:
                return True, locked_until
    return False, None

def record_failed_login(username):
    """Record failed login attempt and lock account if needed."""
    with _get_connection() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
            (username,)
        )
        
        # Lock account after 5 failed attempts for 15 minutes
        row = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,)).fetchone()
        if row and row['failed_attempts'] >= 5:
            locked_until = datetime.now() + timedelta(minutes=15)
            conn.execute(
                "UPDATE users SET locked_until = ? WHERE username = ?",
                (locked_until.isoformat(), username)
            )

def reset_failed_attempts(username):
    """Reset failed login attempts on successful login."""
    with _get_connection() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )

# OAuth Routes
@app.route("/oauth/google")
def oauth_google():
    """Initiate Google OAuth flow"""
    if not OAUTH_AVAILABLE or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth is not configured. Please contact the administrator.", "error")
        return redirect(url_for("login"))
    
    try:
        flow = create_oauth_flow()
        if not flow:
            flash("OAuth configuration error.", "error")
            return redirect(url_for("login"))
            
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true"
        )
        session["oauth_state"] = state
        return redirect(authorization_url)
    except Exception as e:
        flash(f"OAuth error: {str(e)}", "error")
        return redirect(url_for("login"))

@app.route("/oauth/callback")
def oauth_callback():
    """Handle OAuth callback"""
    if not OAUTH_AVAILABLE or not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth is not configured.", "error")
        return redirect(url_for("login"))
    
    # Verify state parameter
    if request.args.get("state") != session.get("oauth_state"):
        flash("Invalid OAuth state. Please try again.", "error")
        return redirect(url_for("login"))
    
    try:
        flow = create_oauth_flow()
        if not flow:
            flash("OAuth configuration error.", "error")
            return redirect(url_for("login"))
            
        flow.fetch_token(authorization_response=request.url)
        
        # Get user info from Google
        credentials = flow.credentials
        request_session = requests.Session()
        
        # Get user info
        userinfo_endpoint = get_google_provider_cfg()["userinfo_endpoint"]
        userinfo_response = request_session.get(
            userinfo_endpoint,
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        
        if userinfo_response.status_code != 200:
            flash("Failed to get user information from Google.", "error")
            return redirect(url_for("login"))
        
        userinfo = userinfo_response.json()
        
        # Extract user data
        google_id = userinfo["sub"]
        email = userinfo["email"]
        name = userinfo.get("name", email.split("@")[0])
        picture = userinfo.get("picture")
        
        # Check if user exists
        with _get_connection() as conn:
            user_row = conn.execute(
                "SELECT id, username, email, oauth_provider FROM users WHERE email = ? OR oauth_id = ?",
                (email, google_id)
            ).fetchone()
            
            if user_row:
                # Update existing user with OAuth info
                conn.execute(
                    """UPDATE users SET 
                       oauth_provider = 'google', 
                       oauth_id = ?, 
                       profile_picture = ?,
                       last_login = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (google_id, picture, user_row['id'])
                )
                user = User(user_row['id'], user_row['username'], user_row['email'], 'google')
            else:
                # Create new user
                username = email.split("@")[0]
                # Ensure username is unique
                counter = 1
                original_username = username
                while True:
                    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                    if not existing:
                        break
                    username = f"{original_username}{counter}"
                    counter += 1
                
                cursor = conn.execute(
                    """INSERT INTO users (username, email, oauth_provider, oauth_id, profile_picture, created_at, last_login)
                       VALUES (?, ?, 'google', ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                    (username, email, google_id, picture)
                )
                user_id = cursor.lastrowid
                user = User(user_id, username, email, 'google')
        
        # Log in the user
        login_user(user, remember=True)
        session.permanent = True
        
        flash(f"Successfully logged in with Google! Welcome, {name}!", "success")
        return redirect(url_for("index"))
        
    except Exception as e:
        flash(f"OAuth login failed: {str(e)}", "error")
        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("auth/login_oauth.html", 
                                 google_oauth_available=bool(OAUTH_AVAILABLE and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET))

        # Check if account is locked
        locked, locked_until = is_account_locked(username)
        if locked:
            flash(f"Account is locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')} due to too many failed attempts.", "error")
            return render_template("auth/login_oauth.html",
                                 google_oauth_available=bool(OAUTH_AVAILABLE and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET))

        with _get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash, oauth_provider FROM users WHERE username = ?", (username,)
            ).fetchone()

            if row and row['password_hash'] and check_password_hash(row['password_hash'], password):
                # Successful login
                reset_failed_attempts(username)
                user = User(row['id'], row['username'], row['email'], row['oauth_provider'])
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("index"))
            else:
                # Failed login
                record_failed_login(username)
                flash("Invalid username or password.", "error")

    return render_template("auth/login_oauth.html",
                         google_oauth_available=bool(OAUTH_AVAILABLE and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("auth/register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("auth/register.html")

        # Check if user exists
        with _get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if existing:
                flash("Username or email already exists.", "error")
                return render_template("auth/register.html")

            # Create user
            password_hash = generate_password_hash(password)
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (username, email, password_hash),
            )

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("auth/register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT id, label, is_file, file_name, file_type, file_size, created_at FROM passwords WHERE user_id = ? ORDER BY created_at DESC",
            (current_user.id,)
        ).fetchall()
    
    return render_template("index.html", passwords=rows)

@app.route("/password/<int:pid>")
@login_required
def get_password(pid):
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT secret, is_file FROM passwords WHERE id = ? AND user_id = ?", (pid, current_user.id)
        ).fetchone()
        
        if not row:
            return jsonify({"error": "Password not found"}), 404
        
        if row['is_file']:
            return jsonify({"error": "This is a file, not a password"}), 400
        
        try:
            decrypted = fernet.decrypt(row['secret']).decode()
            return jsonify({"password": decrypted})
        except Exception as e:
            return jsonify({"error": "Failed to decrypt password"}), 500

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_password():
    if request.method == "POST":
        label = request.form.get("label", "").strip()
        password = request.form.get("password", "")
        file = request.files.get("file")

        if not label:
            flash("Label is required.", "error")
            return render_template("add_edit.html")

        # Check for duplicate label
        with _get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM passwords WHERE user_id = ? AND label = ?", (current_user.id, label)
            ).fetchone()
            if existing:
                flash("A password with this label already exists.", "error")
                return render_template("add_edit.html")

            if file and file.filename:
                # Handle file upload
                if file.content_length and file.content_length > 5 * 1024 * 1024:  # 5MB limit
                    flash("File size must be less than 5MB.", "error")
                    return render_template("add_edit.html")

                filename = secure_filename(file.filename)
                file_content = file.read()
                
                encrypted_content = fernet.encrypt(file_content)
                
                conn.execute(
                    """INSERT INTO passwords (user_id, label, secret, is_file, file_name, file_type, file_size, created_at, updated_at)
                       VALUES (?, ?, ?, 1, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                    (current_user.id, label, encrypted_content, filename, file.content_type, len(file_content))
                )
                flash(f"File '{filename}' added successfully!", "success")
            else:
                # Handle password
                if not password:
                    flash("Password is required.", "error")
                    return render_template("add_edit.html")

                encrypted_password = fernet.encrypt(password.encode())
                conn.execute(
                    "INSERT INTO passwords (user_id, label, secret, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                    (current_user.id, label, encrypted_password),
                )
                flash("Password added successfully!", "success")

        return redirect(url_for("index"))

    return render_template("add_edit.html")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug) 