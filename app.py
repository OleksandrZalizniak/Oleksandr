import os
import sqlite3
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import subprocess
import time
from datetime import datetime, timedelta
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import logging


app = Flask(__name__)
app.secret_key = "your_secret_key"  # For session and flash messages
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript from accessing cookies
    SESSION_COOKIE_SECURE=True,    # Ensure cookies are only sent over HTTPS
    SESSION_PERMANENT=False,        # Session expires on browser close
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5),  # Auto logout after 30 mins
    SESSION_COOKIE_SAMESITE = 'Strict',
)

app.config["SESSION_TYPE"] = "filesystem"  # Stores session on the server
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True  # Adds an extra layer of security
app.config["SESSION_KEY_PREFIX"] = "flask_session:"  # Avoid conflicts
Session(app)

csrf = CSRFProtect(app)

DATABASE = "users.db"
ENCRYPTION_KEY = b"1234567890abcdef1234567890abcdef"  # 32 bytes
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes (lockout duration)

MAX_LOGIN_ATTEMPTS = 3

limiter = Limiter(get_remote_address, app=app)

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            username TEXT,
            filename TEXT,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    """)
    conn.close()


# Encryption and decryption functions
def encrypt_file(file_data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

@app.before_request
def session_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

    if 'last_activity' in session:
        now = datetime.now()
        last_activity = session['last_activity']
        if (now - last_activity).seconds > 300:
            session.clear()
            flash("Session expired. Please log in again.", "info")
            return redirect(url_for("login"))
    session['last_activity'] = datetime.now()

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-XSS-Protection'] = "1; mode=block"
    return response

logging.basicConfig(filename="security.log", level=logging.INFO)

@app.before_request
def log_requests():
    if 'username' in session:
        logging.info(f"User {session['username']} accessed {request.path} at {datetime.now()}")

@app.before_request
def verify_session():
    if 'username' in session:
        if 'ip' not in session:
            session['ip'] = request.remote_addr
        if 'user_agent' not in session:
            session['user_agent'] = request.headers.get('User-Agent')

        if session['ip'] != request.remote_addr or session['user_agent'] != request.headers.get('User-Agent'):
            session.clear()
            flash("Session invalid. Please log in again.", "error")
            return redirect(url_for("login"))

# Routes
@app.route("/")
def home():
    return render_template("base.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password cannot be empty!", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DATABASE, timeout=5)
            conn.execute("INSERT INTO users (username, password) VALUES ('" + username + "', '" + hashed_password + "')")
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists!", "error")
            return redirect(url_for("register"))
        except sqlite3.OperationalError as e:
            flash(f"Database error: {e}", "error")
            return redirect(url_for("register"))
        finally:
            conn.close()

        flash("Registration successful!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Limit 5 login attempts per minute from the same IP
def login():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_failed_login'] = None

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")  # Ensure CSRF token is included
        if not csrf_token:
            flash("CSRF token is missing!", "error")
            return redirect(url_for("login"))

        username = request.form["username"]
        password = request.form["password"]

        # Check if the user is locked out
        if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            if session['last_failed_login']:
                # Make sure both datetimes are naive for the comparison
                last_failed_login_naive = session['last_failed_login'].replace(tzinfo=None)
                lockout_time = last_failed_login_naive + timedelta(seconds=LOCKOUT_TIME)

                if lockout_time > datetime.now():  # datetime.now() is naive by default
                    time_left = (lockout_time - datetime.now()).seconds
                    flash(f"Too many failed attempts. Please try again in {time_left} seconds.", "error")
                    return redirect(url_for("login"))
                else:
                    # Reset the lockout state after the lockout time has passed
                    session['login_attempts'] = 0
                    session['last_failed_login'] = None
            else:
                # If there's no failed login, reset the attempts count
                session['login_attempts'] = 0
                session['last_failed_login'] = None

        conn = sqlite3.connect(DATABASE)

        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # user[2] is the hashed password in the database
            session['login_attempts'] = 0  
            session['last_failed_login'] = None  
            session['username'] = username  # Store username in session after successful login
            flash("Login successful!", "success")
            return redirect(url_for("upload_file"))
        else:
            session['login_attempts'] += 1
            session['last_failed_login'] = datetime.now()  # Update the last failed login timestamp
            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                flash(f"Too many failed attempts. You are locked out for {LOCKOUT_TIME // 60} minutes.", "error")
            else:
                flash("Invalid credentials. Try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", csrf_token=generate_csrf())

@app.route("/logout")
def logout():
    session.clear()  # Clears the session and generates a new ID
    session['user'] = 'username'
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if 'username' not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = session['username']
        file = request.files["file"]
        file_data = file.read()
        filename = file.filename

        encrypted_data = encrypt_file(file_data, ENCRYPTION_KEY)

        os.makedirs("uploads", exist_ok=True)
        with open(f"uploads/{filename}.enc", "wb") as f:
            f.write(encrypted_data)

        conn = sqlite3.connect(DATABASE)
        conn.execute("INSERT INTO files (username, filename) VALUES (?, ?)", (username, filename))
        conn.commit()
        conn.close()

        flash(f"File '{filename}' uploaded and encrypted successfully!", "success")
        return redirect(url_for("home"))

    return render_template("upload.html")


@app.route("/download", methods=["GET", "POST"])
def download_file():
    if 'username' not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    username = session['username']

    if request.method == "POST":
        filename = request.form["filename"]
        action = request.form.get("action")

        file_path = f"uploads/{filename}.enc"

        try:
            if action in ["Download", "View Content"]:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = decrypt_file(encrypted_data, ENCRYPTION_KEY)

                if action == "Download":
                    return decrypted_data, 200, {"Content-Type": "application/octet-stream"}

                if action == "View Content":
                    try:
                        text_content = decrypted_data.decode("utf-8")
                    except UnicodeDecodeError:
                        flash("This file is not a readable text file!", "error")
                        return redirect(url_for("download_file"))

                    return render_template("view_content.html", username=username, filename=filename, text_content=text_content)

        except FileNotFoundError:
            flash("File not found!", "error")

    conn = sqlite3.connect(DATABASE)
    files = conn.execute("SELECT filename FROM files WHERE username = ?", (username,)).fetchall()
    conn.close()

    return render_template("download.html", username=username, files=[file[0] for file in files])


@app.route("/execute", methods=["GET", "POST"])
def execute_file():
    if 'username' not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    if request.method == "GET":
        # Fetch available .py files for execution
        files = [f for f in os.listdir("uploads") if f.endswith(".enc")]
        return render_template("execute.html", files=files)

    if request.method == "POST":
        filename = request.form["filename"]
        file_path = f"uploads/{filename}.enc"

        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_file(encrypted_data, ENCRYPTION_KEY)
            decrypted_file_path = f"uploads/{filename.replace('.enc', '')}"  # Remove .enc

            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)

            if decrypted_file_path.endswith('.py'):
                result = subprocess.run(["python", decrypted_file_path], capture_output=True, text=True)
                output = result.stdout + result.stderr
            else:
                flash("Unsupported file type for execution", "error")
                return redirect(url_for("execute_file"))

            return render_template("view_content.html", filename=filename, text_content=output)

        except FileNotFoundError:
            flash("File not found!", "error")

    return redirect(url_for("execute_file"))
if __name__ == "__main__":
    init_db() 
    app.run(debug=True)
