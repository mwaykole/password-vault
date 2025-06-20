import os
import sqlite3
from pathlib import Path
import secrets
from datetime import datetime, timedelta
import base64
import csv
import io
import json
import hashlib
import re
import urllib.parse
import zipfile
import tempfile
from collections import Counter

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

# ----------------------------------------------------------------------------
# Configuration helpers
# ----------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "passwords.db"
KEY_FILE = BASE_DIR / ".secret.key"
BACKUP_DIR = BASE_DIR / "backups"

# Create backup directory if it doesn't exist
BACKUP_DIR.mkdir(exist_ok=True)

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
    def __init__(self, user_id, username, email):
        self.id = user_id
        self.username = username
        self.email = email

def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    conn = _get_connection()
    cur = conn.cursor()
    
    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            settings TEXT DEFAULT '{}'
        )
        """
    )
    
    # Enhanced passwords table with new fields
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
            category TEXT DEFAULT 'General',
            tags TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            url TEXT DEFAULT '',
            username TEXT DEFAULT '',
            is_favorite BOOLEAN DEFAULT 0,
            password_strength INTEGER DEFAULT 0,
            last_accessed TIMESTAMP,
            access_count INTEGER DEFAULT 0,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, label)
        )
        """
    )
    
    # Categories table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            color TEXT DEFAULT '#007bff',
            icon TEXT DEFAULT 'fas fa-folder',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, name)
        )
        """
    )
    
    # Secure notes table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content BLOB NOT NULL,
            category TEXT DEFAULT 'General',
            tags TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_favorite BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    
    # Activity logs table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    
    # Backups table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            backup_type TEXT DEFAULT 'manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    
    # Add new columns to existing tables if they don't exist
    new_columns = [
        ("passwords", "category", "TEXT DEFAULT 'General'"),
        ("passwords", "tags", "TEXT DEFAULT ''"),
        ("passwords", "notes", "TEXT DEFAULT ''"),
        ("passwords", "url", "TEXT DEFAULT ''"),
        ("passwords", "username", "TEXT DEFAULT ''"),
        ("passwords", "is_favorite", "BOOLEAN DEFAULT 0"),
        ("passwords", "password_strength", "INTEGER DEFAULT 0"),
        ("passwords", "last_accessed", "TIMESTAMP"),
        ("passwords", "access_count", "INTEGER DEFAULT 0"),
        ("passwords", "expires_at", "TIMESTAMP"),
        ("passwords", "is_file", "BOOLEAN DEFAULT 0"),
        ("passwords", "file_name", "TEXT"),
        ("passwords", "file_type", "TEXT"),
        ("passwords", "file_size", "INTEGER"),
        ("users", "settings", "TEXT DEFAULT '{}'"),
    ]
    
    for table, column, definition in new_columns:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    # Create indexes for better performance
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_passwords_category ON passwords(category)",
        "CREATE INDEX IF NOT EXISTS idx_passwords_tags ON passwords(tags)",
        "CREATE INDEX IF NOT EXISTS idx_passwords_favorite ON passwords(is_favorite)",
        "CREATE INDEX IF NOT EXISTS idx_passwords_accessed ON passwords(last_accessed)",
        "CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at)",
    ]
    
    for index_sql in indexes:
        cur.execute(index_sql)
    
    # Insert default categories for existing users
    cur.execute("""
        INSERT OR IGNORE INTO categories (user_id, name, color, icon)
        SELECT DISTINCT user_id, 'Personal', '#28a745', 'fas fa-user' FROM passwords
        UNION
        SELECT DISTINCT user_id, 'Work', '#007bff', 'fas fa-briefcase' FROM passwords
        UNION
        SELECT DISTINCT user_id, 'Banking', '#dc3545', 'fas fa-university' FROM passwords
        UNION
        SELECT DISTINCT user_id, 'Social', '#6f42c1', 'fas fa-users' FROM passwords
        UNION
        SELECT DISTINCT user_id, 'Shopping', '#fd7e14', 'fas fa-shopping-cart' FROM passwords
    """)
    
    conn.commit()
    conn.close()

# Helper functions for new features
def log_activity(user_id, action, resource_type, resource_id=None, details=None):
    """Log user activity with automatic cleanup of old logs."""
    try:
        with _get_connection() as conn:
            # Log the activity
            conn.execute(
                """INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, 
                   ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, action, resource_type, resource_id, details, 
                 request.remote_addr if request else None,
                 request.headers.get('User-Agent', '') if request else '')
            )
            conn.commit()
            
            # Cleanup old activity logs (older than 10 days) for this user
            cleanup_old_activity_logs(user_id, conn)
            
    except Exception as e:
        print(f"Error logging activity: {e}")

def cleanup_old_activity_logs(user_id=None, conn=None):
    """Clean up activity logs older than 10 days."""
    should_close_conn = False
    if conn is None:
        conn = _get_connection()
        should_close_conn = True
    
    try:
        # Calculate cutoff date (10 days ago)
        cutoff_date = datetime.now() - timedelta(days=10)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
        
        if user_id:
            # Clean up for specific user
            result = conn.execute(
                "DELETE FROM activity_logs WHERE user_id = ? AND created_at < ?",
                (user_id, cutoff_str)
            )
            deleted_count = result.rowcount
        else:
            # Clean up for all users
            result = conn.execute(
                "DELETE FROM activity_logs WHERE created_at < ?",
                (cutoff_str,)
            )
            deleted_count = result.rowcount
        
        if should_close_conn:
            conn.commit()
            
        if deleted_count > 0:
            print(f"Cleaned up {deleted_count} old activity log entries")
            
    except Exception as e:
        print(f"Error cleaning up activity logs: {e}")
    finally:
        if should_close_conn:
            conn.close()

def calculate_password_strength(password):
    """Calculate password strength using zxcvbn."""
    try:
        result = zxcvbn.password_strength(password)
        return result['score']  # 0-4 scale
    except:
        # Fallback basic strength calculation
        score = 0
        if len(password) >= 8:
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        return min(score, 4)

def check_password_breached(password):
    """Disabled for resource optimization - always returns False."""
    # API calls disabled to reduce resource usage and prevent system hanging
    return False, 0

def find_duplicates(user_id):
    """Simplified duplicate detection - limited to 50 passwords for performance."""
    try:
        with _get_connection() as conn:
            # Limit to 50 passwords to prevent system hanging
            rows = conn.execute(
                "SELECT id, label, secret FROM passwords WHERE user_id = ? AND is_file = 0 LIMIT 50",
                (user_id,)
            ).fetchall()
        
        password_groups = {}
        for row in rows:
            try:
                decrypted = fernet.decrypt(row['secret']).decode()
                if decrypted in password_groups:
                    password_groups[decrypted].append({'id': row['id'], 'label': row['label']})
                else:
                    password_groups[decrypted] = [{'id': row['id'], 'label': row['label']}]
            except:
                continue
        
        # Return only groups with duplicates
        return {k: v for k, v in password_groups.items() if len(v) > 1}
    except:
        return {}

def generate_enhanced_password(length=16, include_symbols=True, include_numbers=True, 
                             include_uppercase=True, include_lowercase=True, 
                             exclude_ambiguous=False, custom_chars=""):
    """Enhanced password generator with more options."""
    chars = ""
    
    if include_lowercase:
        chars += "abcdefghijklmnopqrstuvwxyz"
    if include_uppercase:
        chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if include_numbers:
        chars += "0123456789"
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if custom_chars:
        chars = custom_chars
    
    if exclude_ambiguous:
        ambiguous = "0O1lI"
        chars = ''.join(c for c in chars if c not in ambiguous)
    
    if not chars:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_passphrase(word_count=4, separator="-", capitalize=False):
    """Generate a memorable passphrase."""
    # Common word list (simplified)
    words = [
        "apple", "banana", "cherry", "dragon", "elephant", "forest", "guitar", "honey",
        "island", "jungle", "kitten", "lemon", "mountain", "ocean", "piano", "rainbow",
        "sunset", "tiger", "universe", "violet", "wizard", "yellow", "zebra", "castle",
        "bridge", "garden", "silver", "golden", "crystal", "thunder", "lightning", "star"
    ]
    
    selected_words = [secrets.choice(words) for _ in range(word_count)]
    
    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]
    
    return separator.join(selected_words)

_init_db()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access your passwords.'
login_manager.login_message_category = 'info'

# Security configuration - Optimized for minimal resource usage
app.config.update(
    SESSION_COOKIE_SECURE=True if os.getenv('HTTPS') == '1' else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # Reduced from 2 hours
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # Reduced from 16MB to 4MB
    SEND_FILE_MAX_AGE_DEFAULT=300,  # 5 minutes cache
)

@login_manager.user_loader
def load_user(user_id):
    with _get_connection() as conn:
        row = conn.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return User(row['id'], row['username'], row['email'])
    return None

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
        
        # Lock account after 5 failed attempts for 30 minutes
        row = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,)).fetchone()
        if row and row['failed_attempts'] >= 5:
            locked_until = datetime.now() + timedelta(minutes=30)
            conn.execute(
                "UPDATE users SET locked_until = ? WHERE username = ?",
                (locked_until.isoformat(), username)
            )
        conn.commit()

def reset_failed_attempts(username):
    """Reset failed attempts on successful login."""
    with _get_connection() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )
        conn.commit()

# ----------------------------------------------------------------------------
# Authentication Routes
# ----------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash("All fields are required", "error")
            return render_template("auth/register.html")
        
        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("auth/register.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("auth/register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("auth/register.html")
        
        # Check if user exists
        with _get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?", 
                (username, email)
            ).fetchone()
            
            if existing:
                flash("Username or email already exists", "error")
                return render_template("auth/register.html")
            
            # Create user
            password_hash = generate_password_hash(password)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            user_id = cur.lastrowid
            
            # Create default categories
            default_categories = [
                ("Personal", "#28a745", "fas fa-user"),
                ("Work", "#007bff", "fas fa-briefcase"),
                ("Banking", "#dc3545", "fas fa-university"),
                ("Social", "#6f42c1", "fas fa-users"),
                ("Shopping", "#fd7e14", "fas fa-shopping-cart"),
            ]
            
            for name, color, icon in default_categories:
                cur.execute(
                    "INSERT INTO categories (user_id, name, color, icon) VALUES (?, ?, ?, ?)",
                    (user_id, name, color, icon)
                )
            
            conn.commit()
        
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("auth/register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("auth/login_oauth.html", google_oauth_available=False)
        
        # Check if account is locked
        is_locked, locked_until = is_account_locked(username)
        if is_locked:
            flash(f"Account is locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}", "error")
            return render_template("auth/login_oauth.html", google_oauth_available=False)
        
        # Verify user
        with _get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if row and check_password_hash(row['password_hash'], password):
                user = User(row['id'], row['username'], row['email'])
                login_user(user, remember=True)
                reset_failed_attempts(username)
                log_activity(user.id, "login", "user")
                
                # Automatic cleanup of old activity logs on login
                try:
                    cleanup_old_activity_logs(user.id)
                except Exception as e:
                    print(f"Failed to cleanup old logs on login: {e}")
                
                flash(f"Welcome back, {user.username}!", "success")
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                record_failed_login(username)
                flash("Invalid username or password", "error")
    
    return render_template("auth/login_oauth.html", google_oauth_available=False)

@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.id, "logout", "user")
    logout_user()
    flash("You have been logged out successfully", "info")
    return redirect(url_for("login"))

# ----------------------------------------------------------------------------
# Main Routes (now with authentication)
# ----------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    # Get filter parameters
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    tag = request.args.get('tag', '')
    favorites_only = request.args.get('favorites') == '1'
    sort_by = request.args.get('sort', 'label')
    sort_order = request.args.get('order', 'asc')
    
    # Build query
    query = """
        SELECT p.*, c.color as category_color, c.icon as category_icon
        FROM passwords p
        LEFT JOIN categories c ON p.category = c.name AND c.user_id = p.user_id
        WHERE p.user_id = ?
    """
    params = [current_user.id]
    
    # Apply filters
    if search:
        query += " AND (p.label LIKE ? OR p.notes LIKE ? OR p.url LIKE ? OR p.username LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param, search_param])
    
    if category:
        query += " AND p.category = ?"
        params.append(category)
    
    if tag:
        query += " AND p.tags LIKE ?"
        params.append(f"%{tag}%")
    
    if favorites_only:
        query += " AND p.is_favorite = 1"
    
    # Apply sorting
    valid_sorts = ['label', 'created_at', 'updated_at', 'last_accessed', 'password_strength', 'category']
    if sort_by in valid_sorts:
        query += f" ORDER BY p.{sort_by}"
        if sort_order == 'desc':
            query += " DESC"
        else:
            query += " ASC"
    else:
        query += " ORDER BY p.label ASC"
    
    with _get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        
        # Get categories for filter dropdown
        categories = conn.execute(
            "SELECT DISTINCT name, color, icon FROM categories WHERE user_id = ? ORDER BY name",
            (current_user.id,)
        ).fetchall()
        
        # Get all unique tags
        tag_rows = conn.execute(
            "SELECT DISTINCT tags FROM passwords WHERE user_id = ? AND tags != ''",
            (current_user.id,)
        ).fetchall()
        
        all_tags = set()
        for row in tag_rows:
            if row['tags']:
                all_tags.update(tag.strip() for tag in row['tags'].split(','))
        tags = sorted(all_tags)

    return render_template("index.html", 
                         passwords=rows,  # Changed from rows to passwords
                         rows=rows,       # Keep rows as well for backward compatibility
                         categories=categories, 
                         tags=tags,
                         current_search=search,
                         current_category=category,
                         current_tag=tag,
                         favorites_only=favorites_only,
                         sort_by=sort_by,
                         sort_order=sort_order)

@app.route("/password/<int:pid>")
@login_required
def get_password_simple(pid):
    """Return decrypted password JSON (used for AJAX) - simple version."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT secret, is_file FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        ).fetchone()
    if row is None:
        return jsonify({"error": "Not found"}), 404

    if row["is_file"]:
        return jsonify({"error": "This is a file, use the file viewer"}), 400
    
    decrypted = fernet.decrypt(row["secret"]).decode()
    return jsonify({"password": decrypted})

@app.route("/file/<int:pid>/download")
@login_required
def download_file(pid):
    """Download a file."""
    with _get_connection() as conn:
        row = conn.execute(
            """SELECT secret, file_name, file_type, is_file 
               FROM passwords WHERE id = ? AND user_id = ?""", 
            (pid, current_user.id)
        ).fetchone()
    
    if row is None:
        flash("File not found", "error")
        return redirect(url_for("index"))
    
    if not row["is_file"]:
        flash("This is not a file", "error")
        return redirect(url_for("index"))
    
    # Decrypt file content
    decrypted_content = fernet.decrypt(row["secret"])
    
    # Create response
    response = make_response(decrypted_content)
    response.headers['Content-Type'] = row["file_type"]
    response.headers['Content-Disposition'] = f'attachment; filename="{row["file_name"]}"'
    
    return response

@app.route("/file/<int:pid>/view")
@login_required
def view_file(pid):
    """View a file in the browser."""
    with _get_connection() as conn:
        row = conn.execute(
            """SELECT secret, file_name, file_type, is_file, label, file_size
               FROM passwords WHERE id = ? AND user_id = ?""", 
            (pid, current_user.id)
        ).fetchone()
    
    if row is None:
        flash("File not found", "error")
        return redirect(url_for("index"))
    
    if not row["is_file"]:
        flash("This is not a file", "error")
        return redirect(url_for("index"))
    
    # Decrypt file content
    decrypted_content = fernet.decrypt(row["secret"])
    
    # Check if it's a text file that can be displayed
    text_types = [
        'text/', 'application/json', 'application/xml', 'application/javascript',
        'application/sql', 'application/x-sh', 'application/x-yaml'
    ]
    
    is_text = any(row["file_type"].startswith(t) for t in text_types)
    
    file_info = {
        'id': pid,
        'name': row["file_name"],
        'type': row["file_type"],
        'size': row["file_size"],
        'label': row["label"],
        'is_text': is_text
    }
    
    if is_text:
        try:
            file_info['content'] = decrypted_content.decode('utf-8')
        except UnicodeDecodeError:
            file_info['content'] = base64.b64encode(decrypted_content).decode()
            file_info['is_text'] = False
    else:
        file_info['content'] = base64.b64encode(decrypted_content).decode()
    
    # Update access tracking
    with _get_connection() as conn:
        conn.execute(
            "UPDATE passwords SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 WHERE id = ?",
            (pid,)
        )
        conn.commit()
    
    log_activity(current_user.id, "view_file", "file", pid)
    return render_template("file_viewer.html", file=file_info)

@app.route("/file/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def edit_file(pid):
    """Edit a text file."""
    with _get_connection() as conn:
        row = conn.execute(
            """SELECT secret, file_name, file_type, is_file, label
               FROM passwords WHERE id = ? AND user_id = ?""", 
            (pid, current_user.id)
        ).fetchone()
    
    if row is None:
        flash("File not found", "error")
        return redirect(url_for("index"))
    
    if not row["is_file"]:
        flash("This is not a file", "error")
        return redirect(url_for("index"))
    
    # Check if it's a text file
    text_types = [
        'text/', 'application/json', 'application/xml', 'application/javascript',
        'application/sql', 'application/x-sh', 'application/x-yaml'
    ]
    
    is_text = any(row["file_type"].startswith(t) for t in text_types)
    
    if not is_text:
        flash("This file type cannot be edited online", "error")
        return redirect(url_for("view_file", pid=pid))
    
    # Decrypt file content
    decrypted_content = fernet.decrypt(row["secret"])
    
    if request.method == "POST":
        new_content = request.form.get("content", "")
        
        # Encrypt new content
        enc = fernet.encrypt(new_content.encode('utf-8'))
        
        with _get_connection() as conn:
            conn.execute(
                """UPDATE passwords SET secret = ?, file_size = ?, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = ? AND user_id = ?""",
                (enc, len(new_content.encode('utf-8')), pid, current_user.id),
            )
            conn.commit()
        
        flash("File updated successfully", "success")
        log_activity(current_user.id, "edit_file", "file", pid)
        return redirect(url_for("view_file", pid=pid))
    
    try:
        content = decrypted_content.decode('utf-8')
    except UnicodeDecodeError:
        flash("File encoding not supported for editing", "error")
        return redirect(url_for("view_file", pid=pid))
    
    file_info = {
        'id': pid,
        'name': row["file_name"],
        'type': row["file_type"],
        'label': row["label"],
        'content': content
    }
    
    return render_template("file_editor.html", file=file_info)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_password():
    if request.method == "POST":
        label = request.form.get("label", "").strip()
        secret = request.form.get("secret", "")
        storage_type = request.form.get("storage_type", "text")
        uploaded_file = request.files.get("file_upload")
        category = request.form.get("category", "General")
        tags = request.form.get("tags", "").strip()
        notes = request.form.get("notes", "").strip()
        url = request.form.get("url", "").strip()
        username = request.form.get("username", "").strip()
        expires_at = request.form.get("expires_at", "")
        
        if not label:
            flash("Service name cannot be empty", "error")
            return redirect(url_for("add_password"))

        # Handle file upload
        if storage_type == "file" and uploaded_file and uploaded_file.filename:
            if uploaded_file.content_length > 10 * 1024 * 1024:  # 10MB limit
                flash("File size must be less than 10MB", "error")
                return redirect(url_for("add_password"))
            
            filename = secure_filename(uploaded_file.filename)
            file_content = uploaded_file.read()
            file_type = uploaded_file.content_type or "application/octet-stream"
            file_size = len(file_content)
            
            # Encrypt file content
            enc = fernet.encrypt(file_content)
            
            try:
                with _get_connection() as conn:
                    conn.execute(
                        """INSERT INTO passwords (user_id, label, secret, is_file, file_name, file_type, file_size, 
                           category, tags, notes, url, username, expires_at) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (current_user.id, label, enc, True, filename, file_type, file_size,
                         category, tags, notes, url, username, expires_at or None),
                    )
                    conn.commit()
                flash(f"File '{filename}' added successfully", "success")
                log_activity(current_user.id, "add_file", "file", None, f"Added file: {filename}")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Service name already exists", "error")
                return redirect(url_for("add_password"))
        
        # Handle text password
        elif storage_type == "text" and secret:
            # Calculate password strength
            strength = calculate_password_strength(secret)
            enc = fernet.encrypt(secret.encode())
            
            try:
                with _get_connection() as conn:
                    conn.execute(
                        """INSERT INTO passwords (user_id, label, secret, is_file, password_strength,
                           category, tags, notes, url, username, expires_at) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (current_user.id, label, enc, False, strength,
                         category, tags, notes, url, username, expires_at or None),
                    )
                    conn.commit()
                flash("Password added successfully", "success")
                log_activity(current_user.id, "add_password", "password", None, f"Added password: {label}")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Service name already exists", "error")
                return redirect(url_for("add_password"))
        else:
            flash("Please provide either a password or upload a file", "error")
            return redirect(url_for("add_password"))

    # Get categories for dropdown
    with _get_connection() as conn:
        categories = conn.execute(
            "SELECT name, color, icon FROM categories WHERE user_id = ? ORDER BY name",
            (current_user.id,)
        ).fetchall()

    return render_template("add_edit.html", action="Add", form_action=url_for("add_password"), categories=categories)

@app.route("/edit/<int:pid>", methods=["GET", "POST"])
@login_required
def edit_password(pid):
    with _get_connection() as conn:
        row = conn.execute(
            """SELECT label, secret, is_file, category, tags, notes, url, username, expires_at 
               FROM passwords WHERE id = ? AND user_id = ?""", 
            (pid, current_user.id)
        ).fetchone()
        if row is None:
            flash("Password not found", "error")
            return redirect(url_for("index"))

    if request.method == "POST":
        label = request.form.get("label", "").strip()
        secret = request.form.get("secret", "").strip()
        category = request.form.get("category", "General")
        tags = request.form.get("tags", "").strip()
        notes = request.form.get("notes", "").strip()
        url = request.form.get("url", "").strip()
        username = request.form.get("username", "").strip()
        expires_at = request.form.get("expires_at", "")

        if not label:
            flash("Label cannot be empty", "error")
            return redirect(url_for("edit_password", pid=pid))

        # If secret field left blank, keep original secret, otherwise encrypt new one
        if row["is_file"]:
            enc_secret = row["secret"]
            strength = 0
        else:
            if secret:
                strength = calculate_password_strength(secret)
                enc_secret = fernet.encrypt(secret.encode())
            else:
                enc_secret = row["secret"]
                # Calculate strength of existing password
                try:
                    existing_secret = fernet.decrypt(row["secret"]).decode()
                    strength = calculate_password_strength(existing_secret)
                except:
                    strength = 0

        try:
            with _get_connection() as conn:
                conn.execute(
                    """UPDATE passwords SET label = ?, secret = ?, password_strength = ?,
                       category = ?, tags = ?, notes = ?, url = ?, username = ?, expires_at = ?,
                       updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?""",
                    (label, enc_secret, strength, category, tags, notes, url, username, 
                     expires_at or None, pid, current_user.id),
                )
                conn.commit()
            flash("Password updated", "success")
            log_activity(current_user.id, "edit_password", "password", pid, f"Updated password: {label}")
        except sqlite3.IntegrityError:
            flash("Label already exists", "error")
        return redirect(url_for("index"))

    # Pre-fill form with existing data
    if not row["is_file"]:
        decrypted = fernet.decrypt(row["secret"]).decode()
    else:
        decrypted = ""
    
    # Get categories for dropdown
    with _get_connection() as conn:
        categories = conn.execute(
            "SELECT name, color, icon FROM categories WHERE user_id = ? ORDER BY name",
            (current_user.id,)
        ).fetchall()

    return render_template(
        "add_edit.html",
        action="Edit",
        form_action=url_for("edit_password", pid=pid),
        label=row["label"],
        secret=decrypted,
        category=row["category"],
        tags=row["tags"],
        notes=row["notes"],
        url=row["url"],
        username=row["username"],
        expires_at=row["expires_at"],
        categories=categories,
        is_file=row["is_file"]
    )

@app.route("/delete/<int:pid>", methods=["POST"])
@login_required
def delete_password(pid):
    with _get_connection() as conn:
        # Get the label for logging
        row = conn.execute(
            "SELECT label FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        ).fetchone()
        
        if row:
            conn.execute(
                "DELETE FROM passwords WHERE id = ? AND user_id = ?", 
                (pid, current_user.id)
            )
            conn.commit()
            log_activity(current_user.id, "delete_password", "password", pid, f"Deleted: {row['label']}")
            flash("Password deleted", "success")
        else:
            flash("Password not found", "error")
    return redirect(url_for("index"))

@app.route("/password/<int:pid>/get")
@login_required
def get_password(pid):
    """Return decrypted password JSON (used for AJAX) with access logging."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT secret, is_file, label FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        ).fetchone()
    if row is None:
        return jsonify({"error": "Not found"}), 404

    if row["is_file"]:
        return jsonify({"error": "This is a file, use the file viewer"}), 400
    
    decrypted = fernet.decrypt(row["secret"]).decode()
    
    # Update access tracking
    with _get_connection() as conn:
        conn.execute(
            "UPDATE passwords SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 WHERE id = ?",
            (pid,)
        )
        conn.commit()
    
    log_activity(current_user.id, "browser_access", "password", pid, f"Browser access: {row['label']}")
    
    return jsonify({
        "password": decrypted,
        "label": row["label"]
    })

@app.route("/toggle-favorite/<int:pid>", methods=["POST"])
@login_required
def toggle_favorite(pid):
    """Toggle password favorite status."""
    with _get_connection() as conn:
        # Get current favorite status
        row = conn.execute(
            "SELECT is_favorite FROM passwords WHERE id = ? AND user_id = ?",
            (pid, current_user.id)
        ).fetchone()
        
        if row:
            new_status = not bool(row['is_favorite'])
            conn.execute(
                "UPDATE passwords SET is_favorite = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                (new_status, pid, current_user.id)
            )
            conn.commit()
            
            action = "favorited" if new_status else "unfavorited"
            log_activity(current_user.id, "toggle_favorite", "password", pid, f"Password {action}")
            
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({"success": True, "is_favorite": new_status})
            else:
                flash(f"Password {'added to' if new_status else 'removed from'} favorites", "success")
        else:
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({"error": "Password not found"}), 404
            else:
                flash("Password not found", "error")
    
    return redirect(url_for("index"))

@app.route("/update-category/<int:pid>", methods=["POST"])
@login_required
def update_category(pid):
    """Update password category via AJAX."""
    new_category = request.form.get("category", "General")
    
    with _get_connection() as conn:
        # Verify password belongs to current user
        row = conn.execute(
            "SELECT id FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        ).fetchone()
        
        if not row:
            return jsonify({"error": "Password not found"}), 404
        
        # Update category
        conn.execute(
            "UPDATE passwords SET category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
            (new_category, pid, current_user.id)
        )
        conn.commit()
        
        log_activity(current_user.id, "update_category", "password", pid, f"Changed category to: {new_category}")
        
    return jsonify({"success": True, "category": new_category})

@app.route("/duplicates")
@login_required
def view_duplicates():
    """View duplicate passwords."""
    duplicates = find_duplicates(current_user.id)
    return render_template("duplicates.html", duplicates=duplicates)

@app.route("/password-generator")
@login_required
def password_generator():
    """Enhanced password generator page."""
    return render_template("password_generator.html")

@app.route("/api/generate-password", methods=["POST"])
@login_required
def api_generate_password():
    """API endpoint for enhanced password generation."""
    data = request.get_json()
    
    generator_type = data.get("type", "password")
    
    if generator_type == "passphrase":
        word_count = int(data.get("word_count", 4))
        separator = data.get("separator", "-")
        capitalize = data.get("capitalize", False)
        
        password = generate_passphrase(word_count, separator, capitalize)
    else:
        length = int(data.get("length", 16))
        include_symbols = data.get("include_symbols", True)
        include_numbers = data.get("include_numbers", True)
        include_uppercase = data.get("include_uppercase", True)
        include_lowercase = data.get("include_lowercase", True)
        exclude_ambiguous = data.get("exclude_ambiguous", False)
        custom_chars = data.get("custom_chars", "")
        
        password = generate_enhanced_password(
            length, include_symbols, include_numbers, 
            include_uppercase, include_lowercase, 
            exclude_ambiguous, custom_chars
        )
    
    # Calculate strength
    strength = calculate_password_strength(password)
    
    # Check if breached
    is_breached, breach_count = check_password_breached(password)
    
    return jsonify({
        "password": password,
        "strength": strength,
        "is_breached": is_breached,
        "breach_count": breach_count
    })

@app.route("/secure-notes")
@login_required
def secure_notes():
    """List secure notes."""
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    favorites_only = request.args.get('favorites') == '1'
    
    query = "SELECT * FROM secure_notes WHERE user_id = ?"
    params = [current_user.id]
    
    if search:
        query += " AND (title LIKE ? OR content LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param])
    
    if category:
        query += " AND category = ?"
        params.append(category)
    
    if favorites_only:
        query += " AND is_favorite = 1"
    
    query += " ORDER BY updated_at DESC"
    
    with _get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        
        # Decrypt notes content for display
        notes = []
        for row in rows:
            note = dict(row)
            try:
                note['content'] = fernet.decrypt(row['content']).decode()
            except:
                note['content'] = "[Decryption failed]"
            notes.append(note)
    
    return render_template("secure_notes.html", notes=notes)

@app.route("/secure-notes/add", methods=["GET", "POST"])
@login_required
def add_secure_note():
    """Add a new secure note."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        category = request.form.get("category", "General")
        tags = request.form.get("tags", "").strip()
        
        if not title:
            flash("Title cannot be empty", "error")
            return redirect(url_for("add_secure_note"))
        
        # Encrypt content
        enc_content = fernet.encrypt(content.encode())
        
        with _get_connection() as conn:
            conn.execute(
                """INSERT INTO secure_notes (user_id, title, content, category, tags)
                   VALUES (?, ?, ?, ?, ?)""",
                (current_user.id, title, enc_content, category, tags)
            )
            conn.commit()
        
        flash("Note added successfully", "success")
        log_activity(current_user.id, "add_note", "note", None, f"Added note: {title}")
        return redirect(url_for("secure_notes"))
    
    return render_template("add_edit_note.html", action="Add", form_action=url_for("add_secure_note"))

@app.route("/secure-notes/edit/<int:note_id>", methods=["GET", "POST"])
@login_required
def edit_secure_note(note_id):
    """Edit a secure note."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM secure_notes WHERE id = ? AND user_id = ?",
            (note_id, current_user.id)
        ).fetchone()
        
        if not row:
            flash("Note not found", "error")
            return redirect(url_for("secure_notes"))
    
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        category = request.form.get("category", "General")
        tags = request.form.get("tags", "").strip()
        
        if not title:
            flash("Title cannot be empty", "error")
            return redirect(url_for("edit_secure_note", note_id=note_id))
        
        # Encrypt content
        enc_content = fernet.encrypt(content.encode())
        
        with _get_connection() as conn:
            conn.execute(
                """UPDATE secure_notes SET title = ?, content = ?, category = ?, tags = ?,
                   updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?""",
                (title, enc_content, category, tags, note_id, current_user.id)
            )
            conn.commit()
        
        flash("Note updated successfully", "success")
        log_activity(current_user.id, "edit_note", "note", note_id, f"Updated note: {title}")
        return redirect(url_for("secure_notes"))
    
    # Decrypt content for editing
    try:
        decrypted_content = fernet.decrypt(row['content']).decode()
    except:
        decrypted_content = "[Decryption failed]"
    
    return render_template("add_edit_note.html", 
                         action="Edit", 
                         form_action=url_for("edit_secure_note", note_id=note_id),
                         title=row['title'],
                         content=decrypted_content,
                         category=row['category'],
                         tags=row['tags'])

@app.route("/secure-notes/delete/<int:note_id>", methods=["POST"])
@login_required
def delete_secure_note(note_id):
    """Delete a secure note."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT title FROM secure_notes WHERE id = ? AND user_id = ?",
            (note_id, current_user.id)
        ).fetchone()
        
        if row:
            conn.execute(
                "DELETE FROM secure_notes WHERE id = ? AND user_id = ?",
                (note_id, current_user.id)
            )
            conn.commit()
            log_activity(current_user.id, "delete_note", "note", note_id, f"Deleted note: {row['title']}")
            flash("Note deleted successfully", "success")
        else:
            flash("Note not found", "error")
    
    return redirect(url_for("secure_notes"))

@app.route("/bulk-operations", methods=["GET", "POST"])
@login_required
def bulk_operations():
    """Handle bulk operations on passwords."""
    if request.method == "POST":
        action = request.form.get("action")
        selected_ids = request.form.getlist("selected_ids")
        
        if not selected_ids:
            flash("No items selected", "error")
            return redirect(url_for("index"))
        
        selected_ids = [int(id) for id in selected_ids]
        
        with _get_connection() as conn:
            if action == "delete":
                # Get labels for logging
                placeholders = ','.join('?' * len(selected_ids))
                labels = conn.execute(
                    f"SELECT label FROM passwords WHERE id IN ({placeholders}) AND user_id = ?",
                    selected_ids + [current_user.id]
                ).fetchall()
                
                conn.execute(
                    f"DELETE FROM passwords WHERE id IN ({placeholders}) AND user_id = ?",
                    selected_ids + [current_user.id]
                )
                conn.commit()
                
                flash(f"Deleted {len(selected_ids)} items", "success")
                log_activity(current_user.id, "bulk_delete", "password", None, 
                           f"Bulk deleted: {', '.join([l['label'] for l in labels])}")
                
            elif action == "favorite":
                placeholders = ','.join('?' * len(selected_ids))
                conn.execute(
                    f"UPDATE passwords SET is_favorite = 1 WHERE id IN ({placeholders}) AND user_id = ?",
                    selected_ids + [current_user.id]
                )
                conn.commit()
                flash(f"Added {len(selected_ids)} items to favorites", "success")
                
            elif action == "unfavorite":
                placeholders = ','.join('?' * len(selected_ids))
                conn.execute(
                    f"UPDATE passwords SET is_favorite = 0 WHERE id IN ({placeholders}) AND user_id = ?",
                    selected_ids + [current_user.id]
                )
                conn.commit()
                flash(f"Removed {len(selected_ids)} items from favorites", "success")
                
            elif action == "change_category":
                new_category = request.form.get("new_category", "General")
                placeholders = ','.join('?' * len(selected_ids))
                conn.execute(
                    f"UPDATE passwords SET category = ? WHERE id IN ({placeholders}) AND user_id = ?",
                    [new_category] + selected_ids + [current_user.id]
                )
                conn.commit()
                flash(f"Updated category for {len(selected_ids)} items", "success")
        
        return redirect(url_for("index"))
    
    return redirect(url_for("index"))

@app.route("/backup/manage")
@login_required
def backup_management():
    """Manage backups."""
    with _get_connection() as conn:
        backups = conn.execute("""
            SELECT id, filename, backup_type, created_at 
            FROM backups 
            WHERE user_id = ? 
            ORDER BY created_at DESC
            LIMIT 10
        """, (current_user.id,)).fetchall()
    
    return render_template("backup_management.html", backups=backups)

@app.route("/backup/create", methods=["POST"])
@login_required
def create_backup():
    """Create a simple backup of user data."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backup_{current_user.username}_{timestamp}.json"
    
    try:
        with _get_connection() as conn:
            # Simple backup - just get essential data
            passwords = conn.execute("""
                SELECT label, secret, category, url, username, notes
                FROM passwords WHERE user_id = ? AND is_file = 0
            """, (current_user.id,)).fetchall()
        
        # Simple backup data
        backup_data = {
            "export_date": datetime.now().isoformat(),
            "user": current_user.username,
            "passwords": []
        }
        
        # Process passwords (minimal processing)
        for pwd in passwords:
            try:
                backup_data["passwords"].append({
                    "label": pwd["label"],
                    "password": fernet.decrypt(pwd["secret"]).decode(),
                    "category": pwd["category"] or "",
                    "url": pwd["url"] or "",
                    "username": pwd["username"] or "",
                    "notes": pwd["notes"] or ""
                })
            except:
                continue
        
        # Save to file
        backup_path = BACKUP_DIR / filename
        with open(backup_path, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        # Save backup record
        with _get_connection() as conn:
            conn.execute("""
                INSERT INTO backups (user_id, filename, file_path, backup_type)
                VALUES (?, ?, ?, ?)
            """, (current_user.id, filename, str(backup_path), "manual"))
            conn.commit()
        
        flash(f"Simple backup created: {filename}", "success")
        
    except Exception as e:
        flash(f"Backup failed: {str(e)}", "error")
    
    return redirect(url_for("backup_management"))

@app.route("/backup/download/<int:backup_id>")
@login_required
def download_backup(backup_id):
    """Download a backup file."""
    with _get_connection() as conn:
        backup = conn.execute("""
            SELECT filename, file_path FROM backups 
            WHERE id = ? AND user_id = ?
        """, (backup_id, current_user.id)).fetchone()
    
    if not backup:
        flash("Backup not found", "error")
        return redirect(url_for("backup_management"))
    
    backup_path = Path(backup["file_path"])
    if not backup_path.exists():
        flash("Backup file not found", "error")
        return redirect(url_for("backup_management"))
    
    return send_file(backup_path, as_attachment=True, download_name=backup["filename"])

@app.route("/import", methods=["GET", "POST"])
@login_required  
def import_data():
    """Import data from various sources."""
    if request.method == "POST":
        import_type = request.form.get("import_type")
        uploaded_file = request.files.get("import_file")
        
        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file to import", "error")
            return redirect(url_for("import_data"))
        
        try:
            if import_type == "csv":
                content = uploaded_file.read().decode('utf-8')
                csv_reader = csv.DictReader(io.StringIO(content))
                imported_count = 0
                
                for row in csv_reader:
                    label = row.get('Service Name', row.get('label', '')).strip()
                    password = row.get('Content/Password', row.get('password', '')).strip()
                    url = row.get('URL', row.get('url', '')).strip()
                    username = row.get('Username', row.get('username', '')).strip()
                    notes = row.get('Notes', row.get('notes', '')).strip()
                    category = row.get('Category', 'Imported')
                    
                    if label and password:
                        enc_password = fernet.encrypt(password.encode())
                        strength = calculate_password_strength(password)
                        
                        try:
                            with _get_connection() as conn:
                                conn.execute("""
                                    INSERT INTO passwords (user_id, label, secret, password_strength,
                                           category, notes, url, username, is_file)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (current_user.id, label, enc_password, strength, category, 
                                     notes, url, username, False))
                                conn.commit()
                                imported_count += 1
                        except sqlite3.IntegrityError:
                            # Skip duplicate labels
                            continue
                
                flash(f"Successfully imported {imported_count} passwords", "success")
                log_activity(current_user.id, "import_csv", "import", None, f"Imported {imported_count} passwords")
                
            elif import_type == "json":
                content = uploaded_file.read().decode('utf-8')
                data = json.loads(content)
                
                imported_passwords = 0
                imported_notes = 0
                
                # Import passwords
                if "passwords" in data:
                    for pwd_data in data["passwords"]:
                        label = pwd_data.get("label", "").strip()
                        if not label:
                            continue
                            
                        try:
                            if pwd_data.get("is_file", False):
                                # Handle file data
                                secret = base64.b64decode(pwd_data.get("secret", ""))
                                enc_secret = fernet.encrypt(secret)
                            else:
                                # Handle password
                                password = pwd_data.get("secret", "")
                                enc_secret = fernet.encrypt(password.encode())
                            
                            with _get_connection() as conn:
                                conn.execute("""
                                    INSERT INTO passwords (user_id, label, secret, is_file, file_name, 
                                           file_type, category, tags, notes, url, username)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (current_user.id, label, enc_secret, 
                                     pwd_data.get("is_file", False),
                                     pwd_data.get("file_name", ""),
                                     pwd_data.get("file_type", ""),
                                     pwd_data.get("category", "Imported"),
                                     pwd_data.get("tags", ""),
                                     pwd_data.get("notes", ""),
                                     pwd_data.get("url", ""),
                                     pwd_data.get("username", "")))
                                conn.commit()
                                imported_passwords += 1
                        except:
                            continue
                
                # Import notes
                if "notes" in data:
                    for note_data in data["notes"]:
                        title = note_data.get("title", "").strip()
                        content = note_data.get("content", "")
                        
                        if title:
                            try:
                                enc_content = fernet.encrypt(content.encode())
                                with _get_connection() as conn:
                                    conn.execute("""
                                        INSERT INTO secure_notes (user_id, title, content, category, tags)
                                        VALUES (?, ?, ?, ?, ?)
                                    """, (current_user.id, title, enc_content,
                                         note_data.get("category", "Imported"),
                                         note_data.get("tags", "")))
                                    conn.commit()
                                    imported_notes += 1
                            except:
                                continue
                
                flash(f"Successfully imported {imported_passwords} passwords and {imported_notes} notes", "success")
                log_activity(current_user.id, "import_json", "import", None, 
                           f"Imported {imported_passwords} passwords, {imported_notes} notes")
            
        except Exception as e:
            flash(f"Import failed: {str(e)}", "error")
        
        return redirect(url_for("index"))
    
    return render_template("import_data.html")

@app.route("/api/search-suggestions")
@login_required
def search_suggestions():
    """API endpoint for search suggestions."""
    query = request.args.get('q', '').lower()
    if len(query) < 2:
        return jsonify([])
    
    suggestions = []
    
    with _get_connection() as conn:
        # Search in labels
        labels = conn.execute("""
            SELECT DISTINCT label FROM passwords 
            WHERE user_id = ? AND lower(label) LIKE ?
            LIMIT 5
        """, (current_user.id, f"%{query}%")).fetchall()
        
        for label in labels:
            suggestions.append({
                "type": "label",
                "text": label["label"],
                "icon": "fas fa-key"
            })
        
        # Search in URLs
        urls = conn.execute("""
            SELECT DISTINCT url FROM passwords 
            WHERE user_id = ? AND url != '' AND lower(url) LIKE ?
            LIMIT 3
        """, (current_user.id, f"%{query}%")).fetchall()
        
        for url in urls:
            suggestions.append({
                "type": "url",
                "text": url["url"],
                "icon": "fas fa-link"
            })
        
        # Search in categories
        categories = conn.execute("""
            SELECT DISTINCT category FROM passwords 
            WHERE user_id = ? AND lower(category) LIKE ?
            LIMIT 3
        """, (current_user.id, f"%{query}%")).fetchall()
        
        for category in categories:
            suggestions.append({
                "type": "category",
                "text": category["category"],
                "icon": "fas fa-folder"
            })
    
    return jsonify(suggestions[:10])

@app.route("/categories/manage")
@login_required
def manage_categories():
    """Manage categories."""
    with _get_connection() as conn:
        categories = conn.execute("""
            SELECT c.*, COUNT(p.id) as password_count
            FROM categories c
            LEFT JOIN passwords p ON c.name = p.category AND c.user_id = p.user_id
            WHERE c.user_id = ?
            GROUP BY c.id
            ORDER BY c.name
        """, (current_user.id,)).fetchall()
    
    return render_template("manage_categories.html", categories=categories)

@app.route("/categories/add", methods=["POST"])
@login_required
def add_category():
    """Add a new category."""
    name = request.form.get("name", "").strip()
    color = request.form.get("color", "#007bff")
    icon = request.form.get("icon", "fas fa-folder")
    
    if not name:
        flash("Category name is required", "error")
        return redirect(url_for("manage_categories"))
    
    try:
        with _get_connection() as conn:
            conn.execute("""
                INSERT INTO categories (user_id, name, color, icon)
                VALUES (?, ?, ?, ?)
            """, (current_user.id, name, color, icon))
            conn.commit()
        flash(f"Category '{name}' added successfully", "success")
    except sqlite3.IntegrityError:
        flash("Category name already exists", "error")
    
    return redirect(url_for("manage_categories"))

@app.route("/profile")
@login_required
def profile():
    with _get_connection() as conn:
        # Get user stats
        stats = conn.execute("""
            SELECT 
                COUNT(*) as total_passwords,
                COUNT(CASE WHEN is_file = 1 THEN 1 END) as total_files,
                COUNT(CASE WHEN is_favorite = 1 THEN 1 END) as total_favorites
            FROM passwords WHERE user_id = ?
        """, (current_user.id,)).fetchone()
        
        note_count = conn.execute(
            "SELECT COUNT(*) as count FROM secure_notes WHERE user_id = ?", 
            (current_user.id,)
        ).fetchone()['count']
        
        # Get recent activity
        recent_activity = conn.execute(
            """SELECT action, resource_type, details, created_at
               FROM activity_logs 
               WHERE user_id = ? 
               ORDER BY created_at DESC 
               LIMIT 10""",
            (current_user.id,)
        ).fetchall()
    
    return render_template("profile.html", 
                         user=current_user,
                         stats=stats,
                         recent_activity=recent_activity)

@app.route("/admin/cleanup-logs", methods=["POST"])
@login_required
def manual_cleanup_logs():
    """Manual cleanup of old activity logs for current user."""
    try:
        with _get_connection() as conn:
            # Get count before cleanup
            before_count = conn.execute(
                "SELECT COUNT(*) as count FROM activity_logs WHERE user_id = ?",
                (current_user.id,)
            ).fetchone()['count']
            
            # Perform cleanup
            cleanup_old_activity_logs(current_user.id, conn)
            conn.commit()
            
            # Get count after cleanup
            after_count = conn.execute(
                "SELECT COUNT(*) as count FROM activity_logs WHERE user_id = ?",
                (current_user.id,)
            ).fetchone()['count']
            
            deleted_count = before_count - after_count
            
            if deleted_count > 0:
                flash(f"Cleaned up {deleted_count} old activity log entries", "success")
            else:
                flash("No old activity logs found to clean up", "info")
                
    except Exception as e:
        flash(f"Error cleaning up logs: {e}", "error")
    
    return redirect(url_for('profile'))

@app.route("/export/csv")
@login_required
def export_csv():
    """Export all user passwords and files to CSV format."""
    # Get all user's passwords and files
    with _get_connection() as conn:
        rows = conn.execute(
            """SELECT label, secret, is_file, file_name, file_type, file_size, 
                      category, tags, notes, url, username, created_at, updated_at
               FROM passwords WHERE user_id = ? ORDER BY label ASC""", 
            (current_user.id,)
        ).fetchall()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Service Name', 'Type', 'Content/Password', 'File Name', 'File Type', 
        'File Size (KB)', 'Category', 'Tags', 'Notes', 'URL', 'Username',
        'Created Date', 'Updated Date'
    ])
    
    # Write data rows
    for row in rows:
        try:
            # Decrypt the content
            decrypted_content = fernet.decrypt(row["secret"])
            
            if row["is_file"]:
                content_display = f"[FILE: {row['file_name']}]"
                file_size_kb = round(row["file_size"] / 1024, 2) if row["file_size"] else 0
            else:
                content_display = decrypted_content.decode()
                file_size_kb = 0
            
            writer.writerow([
                row["label"],
                "File" if row["is_file"] else "Password", 
                content_display,
                row["file_name"] or "",
                row["file_type"] or "",
                file_size_kb,
                row["category"] or "",
                row["tags"] or "",
                row["notes"] or "",
                row["url"] or "",
                row["username"] or "",
                row["created_at"],
                row["updated_at"]
            ])
        except Exception as e:
            # If decryption fails, still include the row with error info
            writer.writerow([
                row["label"],
                "Error",
                f"[DECRYPTION ERROR: {str(e)}]",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                row["created_at"] if row["created_at"] else "",
                row["updated_at"] if row["updated_at"] else ""
            ])
    
    csv_content = output.getvalue()
    output.close()
    
    # Create response
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="password_vault_export_{current_user.username}_{datetime.now().strftime("%Y%m%d")}.csv"'
    
    log_activity(current_user.id, "export_csv", "export", None, "Exported data to CSV")
    return response

# Browser Extension API endpoints
@app.route("/api/browser/search")
@login_required
def browser_search():
    """API endpoint for browser extension to search passwords by URL."""
    url = request.args.get('url', '').lower()
    if not url:
        return jsonify([])
    
    # Extract domain from URL
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        domain = parsed.netloc.lower()
    except:
        domain = url
    
    with _get_connection() as conn:
        matches = conn.execute("""
            SELECT id, label, username, url
            FROM passwords 
            WHERE user_id = ? AND is_file = 0 
            AND (lower(url) LIKE ? OR lower(label) LIKE ?)
            ORDER BY 
                CASE WHEN lower(url) LIKE ? THEN 1 ELSE 2 END,
                label
            LIMIT 10
        """, (current_user.id, f"%{domain}%", f"%{domain}%", f"%{domain}%")).fetchall()
    
    results = []
    for match in matches:
        results.append({
            "id": match["id"],
            "label": match["label"],
            "username": match["username"] or "",
            "url": match["url"] or "",
            "favicon": f"https://www.google.com/s2/favicons?domain={match['url']}" if match["url"] else ""
        })
    
    return jsonify(results)

@app.route("/api/browser/password/<int:pid>")
@login_required 
def browser_get_password(pid):
    """API endpoint for browser extension to get password."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT secret, is_file, label FROM passwords WHERE id = ? AND user_id = ?",
            (pid, current_user.id)
        ).fetchone()
    
    if not row or row["is_file"]:
        return jsonify({"error": "Not found"}), 404
    
    try:
        password = fernet.decrypt(row["secret"]).decode()
        
        # Update access tracking
        with _get_connection() as conn:
            conn.execute(
                "UPDATE passwords SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 WHERE id = ?",
                (pid,)
            )
            conn.commit()
        
        log_activity(current_user.id, "browser_access", "password", pid, f"Browser access: {row['label']}")
        
        return jsonify({
            "password": password,
            "label": row["label"]
        })
    except:
        return jsonify({"error": "Decryption failed"}), 500

@app.after_request
def security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;"
    return response

@app.route("/bulk-delete", methods=["POST"])
@login_required
def bulk_delete():
    """Delete multiple passwords."""
    password_ids = request.form.getlist("password_ids")
    
    if not password_ids:
        return jsonify({"error": "No passwords selected"}), 400
    
    with _get_connection() as conn:
        # Verify all passwords belong to current user
        placeholders = ",".join("?" * len(password_ids))
        query = f"SELECT id FROM passwords WHERE id IN ({placeholders}) AND user_id = ?"
        params = password_ids + [current_user.id]
        
        valid_ids = [row["id"] for row in conn.execute(query, params).fetchall()]
        
        if len(valid_ids) != len(password_ids):
            return jsonify({"error": "Some passwords not found or access denied"}), 403
        
        # Delete passwords
        delete_query = f"DELETE FROM passwords WHERE id IN ({placeholders}) AND user_id = ?"
        conn.execute(delete_query, params)
        deleted_count = conn.total_changes
        conn.commit()
        
        log_activity(current_user.id, "bulk_delete", "password", None, f"Bulk deleted {deleted_count} passwords")
        
        return jsonify({"success": True, "deleted_count": deleted_count})

@app.route("/bulk-export", methods=["POST"])
@login_required
def bulk_export():
    """Export selected passwords to CSV."""
    password_ids = request.form.getlist("password_ids")
    
    if not password_ids:
        return jsonify({"error": "No passwords selected"}), 400
    
    with _get_connection() as conn:
        # Get passwords for current user
        placeholders = ",".join("?" * len(password_ids))
        query = f"""
            SELECT label, username, secret, url, category, tags, notes, 
                   is_file, file_name, created_at, updated_at
            FROM passwords 
            WHERE id IN ({placeholders}) AND user_id = ?
            ORDER BY label
        """
        params = password_ids + [current_user.id]
        rows = conn.execute(query, params).fetchall()
        
        if not rows:
            return jsonify({"error": "No passwords found"}), 404
        
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Service', 'Username', 'Password', 'URL', 'Category', 
                        'Tags', 'Notes', 'Created', 'Updated'])
        
        # Write data
        for row in rows:
            try:
                # Decrypt password if it's not a file
                if row['is_file']:
                    password_value = f"[FILE: {row['file_name']}]"
                else:
                    password_value = fernet.decrypt(row['secret']).decode()
                
                writer.writerow([
                    row['label'],
                    row['username'] or '',
                    password_value,
                    row['url'] or '',
                    row['category'] or 'General',
                    row['tags'] or '',
                    row['notes'] or '',
                    row['created_at'],
                    row['updated_at']
                ])
            except Exception as e:
                # If decryption fails, include error info
                writer.writerow([
                    row['label'],
                    row['username'] or '',
                    f'[DECRYPTION ERROR: {str(e)}]',
                    row['url'] or '',
                    row['category'] or 'General',
                    row['tags'] or '',
                    row['notes'] or '',
                    row['created_at'],
                    row['updated_at']
                ])
        
        csv_content = output.getvalue()
        output.close()
        
        log_activity(current_user.id, "bulk_export", "export", None, f"Bulk exported {len(rows)} passwords")
        
        # Return CSV file
        from flask import make_response
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=passwords_export_{datetime.now().strftime("%Y%m%d")}.csv'
        
        return response

@app.route("/bulk-favorite", methods=["POST"])
@login_required
def bulk_favorite():
    """Add selected passwords to favorites."""
    password_ids = request.form.getlist("password_ids")
    
    if not password_ids:
        return jsonify({"error": "No passwords selected"}), 400
    
    with _get_connection() as conn:
        # Verify all passwords belong to current user and update favorites
        placeholders = ",".join("?" * len(password_ids))
        query = f"""
            UPDATE passwords 
            SET is_favorite = 1, updated_at = CURRENT_TIMESTAMP 
            WHERE id IN ({placeholders}) AND user_id = ?
        """
        params = password_ids + [current_user.id]
        
        conn.execute(query, params)
        updated_count = conn.total_changes
        conn.commit()
        
        log_activity(current_user.id, "bulk_favorite", "password", None, f"Bulk added {updated_count} passwords to favorites")
        
        return jsonify({"success": True, "updated_count": updated_count})

if __name__ == "__main__":
    import argparse
    import socket
    
    def find_free_port(start_port=5000, max_attempts=100):
        """Find a free port starting from start_port"""
        for port in range(start_port, start_port + max_attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
        raise RuntimeError(f"Could not find a free port in range {start_port}-{start_port + max_attempts}")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Password Vault - Secure Password Manager')
    parser.add_argument('--port', type=int, default=None, help='Port to run the server on')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    # Determine port
    if args.port:
        port = args.port
    else:
        port = find_free_port()
    
    # Initialize database
    _init_db()
    
    print(f"🔐 Password Vault Starting...")
    print(f"📍 Server: http://{args.host}:{port}")
    print(f"🛡️  Security: {'Debug Mode' if args.debug else 'Production Mode'}")
    print(f"💾 Database: {DB_PATH}")
    print(f"🔑 Encryption: {'Environment Variable' if 'ENCRYPTION_KEY' in os.environ else 'Key File'}")
    print("=" * 60)
    
    try:
        app.run(
            host=args.host,
            port=port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
    finally:
        print("👋 Password Vault shutdown complete") 