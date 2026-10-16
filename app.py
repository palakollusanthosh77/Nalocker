"""Na Locker - Personal Document Locker (Flask + SQLite)."""
import logging
import os
import secrets
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent

CATEGORIES = ["Certificates", "Resume", "Education", "Personal", "Other"]
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx", "xlsx", "pptx", "doc", "txt"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
EMAIL_MAX = 254

# Simple in-memory login throttle (per email+IP). Resets when the server restarts.
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
_login_attempts = {}


def create_app(test_config=None):
    app = Flask(__name__)
    production = os.environ.get("NALOCKER_PRODUCTION") == "1"

    app.config.update(
        DATABASE=os.environ.get("NALOCKER_DB", str(BASE_DIR / "database.db")),
        UPLOAD_FOLDER=os.environ.get("NALOCKER_UPLOADS", str(BASE_DIR / "uploads")),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 1024 * 64,  # small allowance for form overhead
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,  # requires HTTPS when NALOCKER_PRODUCTION=1
        PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    )
    if test_config:
        app.config.update(test_config)

    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or load_secret_key(production)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.INFO)
    init_db(app.config["DATABASE"])
    register_hooks(app)
    register_routes(app)
    return app


def load_secret_key(production):
    """Secret key from env var; in development, generate one and keep it in instance/."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    if production:
        raise RuntimeError("Set the SECRET_KEY environment variable in production.")
    instance = BASE_DIR / "instance"
    instance.mkdir(exist_ok=True)
    key_file = instance / "secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    return key


# --------------------------------------------------------------------------- DB
def init_db(db_path):
    """Create tables if missing and add any missing columns to existing tables
    so existing accounts and records are preserved."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT ''
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Other',
            file_type TEXT NOT NULL DEFAULT '',
            file_size INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")
        add_missing_columns(conn, "users", {
            "name": "TEXT NOT NULL DEFAULT ''",
            "created_at": "TEXT NOT NULL DEFAULT ''",
        })
        # Older versions may have called the column "password".
        user_cols = columns(conn, "users")
        if "password_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
            if "password" in user_cols:
                conn.execute("UPDATE users SET password_hash = password WHERE password_hash = ''")
        add_missing_columns(conn, "documents", {
            "display_name": "TEXT NOT NULL DEFAULT ''",
            "stored_name": "TEXT NOT NULL DEFAULT ''",
            "category": "TEXT NOT NULL DEFAULT 'Other'",
            "file_type": "TEXT NOT NULL DEFAULT ''",
            "file_size": "INTEGER NOT NULL DEFAULT 0",
            "uploaded_at": "TEXT NOT NULL DEFAULT ''",
        })
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(lower(email))")
        except sqlite3.IntegrityError:
            logging.warning("Duplicate emails exist; unique email index not created.")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id)")
        conn.commit()
    finally:
        conn.close()


def columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def add_missing_columns(conn, table, wanted):
    existing = columns(conn, table)
    for name, ddl in wanted.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def get_db():
    from flask import current_app
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


# ------------------------------------------------------------------ validation
def validate_file_content(path, ext):
    """Check that the file's real content matches its extension (magic bytes)."""
    with open(path, "rb") as f:
        head = f.read(16)
    if ext == "pdf":
        return head.startswith(b"%PDF-")
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "doc":
        return head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    if ext in ("docx", "xlsx", "pptx"):
        required = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}[ext]
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                return "[Content_Types].xml" in names and any(n.startswith(required) for n in names)
        except zipfile.BadZipFile:
            return False
    if ext == "txt":
        with open(path, "rb") as f:
            data = f.read(8192)
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            # may have cut a multi-byte character at the chunk boundary
            try:
                data[:-3].decode("utf-8")
            except UnicodeDecodeError:
                return False
        return True
    return False


def clean_display_name(text, fallback):
    text = (text or "").strip()
    text = "".join(ch for ch in text if ch.isprintable())
    text = text.replace("/", "_").replace("\\", "_")
    return (text or fallback)[:120]


def human_size(num):
    for unit in ("B", "KB", "MB"):
        if num < 1024 or unit == "MB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024


def like_escape(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def valid_email(email):
    if not email or len(email) > EMAIL_MAX or " " in email:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".") and "@" not in domain


def password_problem(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters long."
    if len(pw) > 128:
        return "Password must be 128 characters or fewer."
    if not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        return "Password must contain at least one letter and one number."
    return None


# ----------------------------------------------------------------------- hooks
def register_hooks(app):
    @app.before_request
    def csrf_protect():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session["csrf_token"]):
                flash("Your session expired or the form was invalid. Please try again.", "error")
                return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

    @app.context_processor
    def inject_globals():
        return {"csrf_token": session.get("csrf_token", ""), "categories": CATEGORIES,
                "current_year": datetime.now().year}

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'")
        if request.endpoint in ("dashboard", "download"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(413)
    def too_large(_e):
        flash("That file is too large. The maximum upload size is 10 MB.", "error")
        return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="We couldn't find that page."), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, message="Something went wrong on our side."), 500


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------- routes
def register_routes(app):
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if session.get("user_id") else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        form = {"name": "", "email": ""}
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            form = {"name": name, "email": email}

            error = None
            if not (2 <= len(name) <= 60):
                error = "Please enter your name (2-60 characters)."
            elif not valid_email(email):
                error = "Please enter a valid email address."
            elif password_problem(password):
                error = password_problem(password)
            elif password != confirm:
                error = "Passwords do not match."

            if error:
                flash(error, "error")
            else:
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (name, email, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
                    db.commit()
                    flash("Account created! Please log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("An account with that email already exists.", "error")
                except sqlite3.Error:
                    app.logger.exception("Database error during registration")
                    flash("We couldn't create your account right now. Please try again.", "error")
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        email = ""
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            key = (email, request.remote_addr)
            now = time.time()
            attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
            _login_attempts[key] = attempts
            if len(attempts) >= LOGIN_MAX_ATTEMPTS:
                flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
                return render_template("login.html", email=email), 429
            try:
                user = get_db().execute(
                    "SELECT id, name, email, password_hash FROM users WHERE lower(email) = ?", (email,)).fetchone()
            except sqlite3.Error:
                app.logger.exception("Database error during login")
                flash("We couldn't log you in right now. Please try again.", "error")
                return render_template("login.html", email=email)
            if user and check_password_hash(user["password_hash"], password):
                _login_attempts.pop(key, None)
                session.clear()  # prevents session fixation
                session["csrf_token"] = secrets.token_urlsafe(32)
                session["user_id"] = user["id"]
                session["user_name"] = user["name"] or user["email"].split("@")[0]
                session.permanent = True
                return redirect(url_for("dashboard"))
            _login_attempts[key].append(now)
            flash("Incorrect email or password.", "error")
        return render_template("login.html", email=email)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        q = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "")
        if category not in CATEGORIES:
            category = ""
        uid = session["user_id"]
        try:
            db = get_db()
            sql = "SELECT * FROM documents WHERE user_id = ?"
            params = [uid]
            if q:
                sql += " AND display_name LIKE ? ESCAPE '\\'"
                params.append(f"%{like_escape(q)}%")
            if category:
                sql += " AND category = ?"
                params.append(category)
            sql += " ORDER BY uploaded_at DESC, id DESC"
            docs = db.execute(sql, params).fetchall()
            total = db.execute("SELECT COUNT(*) FROM documents WHERE user_id = ?", (uid,)).fetchone()[0]
            size = db.execute("SELECT COALESCE(SUM(file_size),0) FROM documents WHERE user_id = ?", (uid,)).fetchone()[0]
        except sqlite3.Error:
            app.logger.exception("Database error loading dashboard")
            flash("We couldn't load your documents. Please try again.", "error")
            docs, total, size = [], 0, 0
        return render_template("dashboard.html", docs=docs, total=total, shown=len(docs),
                               storage=human_size(size), q=q, selected_category=category,
                               filtering=bool(q or category), max_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                               allowed=", ".join(sorted(e.upper() for e in ALLOWED_EXTENSIONS)))

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        file = request.files.get("document")
        category = request.form.get("category", "")
        if category not in CATEGORIES:
            flash("Please choose a valid category.", "error")
            return redirect(url_for("dashboard"))
        if not file or not file.filename:
            flash("Please choose a file to upload.", "error")
            return redirect(url_for("dashboard"))

        original = os.path.basename(file.filename.replace("\\", "/"))
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if ext not in ALLOWED_EXTENSIONS:
            flash("Unsupported file type. Allowed: " + ", ".join(sorted(e.upper() for e in ALLOWED_EXTENSIONS)) + ".", "error")
            return redirect(url_for("dashboard"))

        stored_name = f"{uuid.uuid4().hex}.{ext}"
        folder = Path(app.config["UPLOAD_FOLDER"])
        dest = folder / stored_name
        try:
            file.save(dest)
            size = dest.stat().st_size
            if size == 0:
                dest.unlink(missing_ok=True)
                flash("That file is empty.", "error")
                return redirect(url_for("dashboard"))
            if size > MAX_UPLOAD_BYTES:
                dest.unlink(missing_ok=True)
                flash("That file is too large. The maximum upload size is 10 MB.", "error")
                return redirect(url_for("dashboard"))
            if not validate_file_content(dest, ext):
                dest.unlink(missing_ok=True)
                flash("The file's contents do not match its extension, so it was rejected.", "error")
                return redirect(url_for("dashboard"))
            display = clean_display_name(request.form.get("display_name"), original)
            db = get_db()
            db.execute(
                "INSERT INTO documents (user_id, display_name, stored_name, category, file_type, file_size, uploaded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session["user_id"], display, stored_name, category, ext, size,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            db.commit()
        except (OSError, sqlite3.Error):
            app.logger.exception("Upload failed")
            (folder / stored_name).unlink(missing_ok=True)
            flash("The upload failed. Please try again.", "error")
            return redirect(url_for("dashboard"))
        flash("Document uploaded successfully.", "success")
        return redirect(url_for("dashboard"))

    def get_owned_document(doc_id):
        row = get_db().execute("SELECT * FROM documents WHERE id = ? AND user_id = ?",
                               (doc_id, session["user_id"])).fetchone()
        if row is None:
            abort(404)  # same response whether it doesn't exist or belongs to someone else
        return row

    @app.route("/download/<int:doc_id>")
    @login_required
    def download(doc_id):
        doc = get_owned_document(doc_id)
        stored = os.path.basename(doc["stored_name"])  # never trust the DB value as a path
        if not (Path(app.config["UPLOAD_FOLDER"]) / stored).is_file():
            flash("That file is missing from storage.", "error")
            return redirect(url_for("dashboard"))
        name = doc["display_name"]
        if doc["file_type"] and not name.lower().endswith("." + doc["file_type"]):
            name = f"{name}.{doc['file_type']}"
        return send_from_directory(app.config["UPLOAD_FOLDER"], stored, as_attachment=True, download_name=name)

    @app.route("/delete/<int:doc_id>", methods=["POST"])
    @login_required
    def delete(doc_id):
        doc = get_owned_document(doc_id)
        try:
            db = get_db()
            db.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc_id, session["user_id"]))
            db.commit()
            (Path(app.config["UPLOAD_FOLDER"]) / os.path.basename(doc["stored_name"])).unlink(missing_ok=True)
        except (OSError, sqlite3.Error):
            app.logger.exception("Delete failed")
            flash("We couldn't delete that document. Please try again.", "error")
            return redirect(url_for("dashboard"))
        flash("Document deleted.", "success")
        return redirect(url_for("dashboard"))


if __name__ == "__main__":
    # Debug is OFF by default. For local development only: set NALOCKER_DEBUG=1
    create_app().run(debug=os.environ.get("NALOCKER_DEBUG") == "1")
