import os
import sqlite3
from pathlib import Path
import secrets
from datetime import datetime, timedelta
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

# ----------------------------------------------------------------------------
# Configuration helpers
# ----------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "passwords.db"
KEY_FILE = BASE_DIR / ".secret.key"


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
            locked_until TIMESTAMP
        )
        """
    )
    
    # Passwords table (updated to support files)
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
    
    # Add new columns to existing table if they don't exist
    try:
        cur.execute("ALTER TABLE passwords ADD COLUMN is_file BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
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
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
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
    logout_user()
    flash("You have been logged out successfully", "info")
    return redirect(url_for("login"))

# ----------------------------------------------------------------------------
# Main Routes (now with authentication)
# ----------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    with _get_connection() as conn:
        rows = conn.execute(
            """SELECT id, label, is_file, file_name, file_type, file_size 
               FROM passwords WHERE user_id = ? ORDER BY label ASC""", 
            (current_user.id,)
        ).fetchall()
    return render_template("index.html", rows=rows)

@app.route("/password/<int:pid>")
@login_required
def get_password(pid):
    """Return decrypted password JSON (used for AJAX)."""
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
                        """INSERT INTO passwords (user_id, label, secret, is_file, file_name, file_type, file_size) 
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (current_user.id, label, enc, True, filename, file_type, file_size),
                    )
                    conn.commit()
                flash(f"File '{filename}' added successfully", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Service name already exists", "error")
                return redirect(url_for("add_password"))
        
        # Handle text password
        elif storage_type == "text" and secret:
            enc = fernet.encrypt(secret.encode())
            try:
                with _get_connection() as conn:
                    conn.execute(
                        """INSERT INTO passwords (user_id, label, secret, is_file) 
                           VALUES (?, ?, ?, ?)""",
                        (current_user.id, label, enc, False),
                    )
                    conn.commit()
                flash("Password added successfully", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Service name already exists", "error")
                return redirect(url_for("add_password"))
        else:
            flash("Please provide either a password or upload a file", "error")
            return redirect(url_for("add_password"))

    return render_template("add_edit.html", action="Add", form_action=url_for("add_password"))

@app.route("/edit/<int:pid>", methods=["GET", "POST"])
@login_required
def edit_password(pid):
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT label, secret FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        ).fetchone()
        if row is None:
            flash("Password not found", "error")
            return redirect(url_for("index"))

    if request.method == "POST":
        label = request.form.get("label", "").strip()
        secret = request.form.get("secret", "").strip()

        if not label:
            flash("Label cannot be empty", "error")
            return redirect(url_for("edit_password", pid=pid))

        # If secret field left blank, keep original secret
        enc_secret = row["secret"] if not secret else fernet.encrypt(secret.encode())

        try:
            with _get_connection() as conn:
                conn.execute(
                    "UPDATE passwords SET label = ?, secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                    (label, enc_secret, pid, current_user.id),
                )
                conn.commit()
            flash("Password updated", "success")
        except sqlite3.IntegrityError:
            flash("Label already exists", "error")
        return redirect(url_for("index"))

    # Pre-fill form with decrypted secret for editing convenience
    decrypted = fernet.decrypt(row["secret"]).decode()
    return render_template(
        "add_edit.html",
        action="Edit",
        form_action=url_for("edit_password", pid=pid),
        label=row["label"],
        secret=decrypted,
    )

@app.route("/delete/<int:pid>", methods=["POST"])
@login_required
def delete_password(pid):
    with _get_connection() as conn:
        conn.execute(
            "DELETE FROM passwords WHERE id = ? AND user_id = ?", 
            (pid, current_user.id)
        )
        conn.commit()
    flash("Password deleted", "success")
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    with _get_connection() as conn:
        # Get user stats
        password_count = conn.execute(
            "SELECT COUNT(*) as count FROM passwords WHERE user_id = ?", 
            (current_user.id,)
        ).fetchone()['count']
        
        # Get recent sessions
        sessions = conn.execute(
            """SELECT ip_address, user_agent, created_at, is_active 
               FROM user_sessions 
               WHERE user_id = ? 
               ORDER BY created_at DESC 
               LIMIT 10""",
            (current_user.id,)
        ).fetchall()
    
    return render_template("profile.html", 
                         password_count=password_count, 
                         sessions=sessions)

@app.route("/export/csv")
@login_required
def export_csv():
    """Export all user passwords and files to CSV format."""
    # Get all user's passwords and files
    with _get_connection() as conn:
        rows = conn.execute(
            """SELECT label, secret, is_file, file_name, file_type, file_size, created_at, updated_at
               FROM passwords WHERE user_id = ? ORDER BY label ASC""", 
            (current_user.id,)
        ).fetchall()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Service Name', 'Type', 'Content/Password', 'File Name', 'File Type', 
        'File Size (KB)', 'Created Date', 'Updated Date'
    ])
    
    # Write data rows
    for row in rows:
        try:
            # Decrypt the content
            decrypted_content = fernet.decrypt(row["secret"])
            
            if row["is_file"]:
                # For files, don't include the actual file content in CSV for security/size reasons
                content = f"[FILE: {row['file_name']}]"
                file_name = row["file_name"] or ""
                file_type = row["file_type"] or ""
                file_size = round(row["file_size"] / 1024, 2) if row["file_size"] else ""
                entry_type = "File"
            else:
                # For passwords, include the actual password
                content = decrypted_content.decode('utf-8')
                file_name = ""
                file_type = ""
                file_size = ""
                entry_type = "Password"
            
            # Format dates
            created_date = row["created_at"] if row["created_at"] else ""
            updated_date = row["updated_at"] if row["updated_at"] else ""
            
            writer.writerow([
                row["label"],
                entry_type,
                content,
                file_name,
                file_type,
                file_size,
                created_date,
                updated_date
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
                row["created_at"] if row["created_at"] else "",
                row["updated_at"] if row["updated_at"] else ""
            ])
    
    # Create response
    csv_content = output.getvalue()
    output.close()
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"password_vault_export_{current_user.username}_{timestamp}.csv"
    
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    flash(f"Exported {len(rows)} entries to CSV", "success")
    return response

# Security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com code.jquery.com; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com; img-src 'self' data:;"
    return response

if __name__ == "__main__":
    app.run(debug=True) 