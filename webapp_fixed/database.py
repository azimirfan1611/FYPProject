"""SQLite database initializer for the HARDENED (fixed) demo application.

FIXED: passwords are stored as salted hashes (werkzeug), never in plaintext.
FIXED: added columns to support login-attempt lockout.
"""
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DB_PATH_FIXED", "/tmp/webapp_fixed.db")


def get_db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL UNIQUE,
            password_hash   TEXT NOT NULL,
            role            TEXT DEFAULT 'user',
            email           TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until    TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS comments (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            author  TEXT NOT NULL,
            body    TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Seed same demo accounts as the vulnerable app, but with hashed passwords.
    seed_users = [
        ("admin", "admin123", "admin", "admin@corp.local"),
        ("alice", "password1", "user", "alice@corp.local"),
        ("bob", "bob1234", "user", "bob@corp.local"),
        ("charlie", "charlie99", "user", "charlie@corp.local"),
    ]
    for username, password, role, email in seed_users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, email),
        )
    c.execute(
        "INSERT OR IGNORE INTO comments (author, body) VALUES (?, ?)", ("alice", "Hello everyone!")
    )
    c.execute(
        "INSERT OR IGNORE INTO comments (author, body) VALUES (?, ?)", ("bob", "Great site!")
    )
    conn.commit()
    conn.close()
