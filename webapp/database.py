"""SQLite database initializer with intentionally vulnerable seed data."""
import sqlite3, os

DB_PATH = os.environ.get("DB_PATH", "/tmp/webapp.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            email    TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            author  TEXT NOT NULL,
            body    TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        INSERT OR IGNORE INTO users (username, password, role, email) VALUES
            ('admin',   'admin123',  'admin', 'admin@corp.local'),
            ('alice',   'password1', 'user',  'alice@corp.local'),
            ('bob',     'bob1234',   'user',  'bob@corp.local'),
            ('charlie', 'charlie99', 'user',  'charlie@corp.local');
        INSERT OR IGNORE INTO comments (author, body) VALUES
            ('alice', 'Hello everyone!'),
            ('bob',   'Great site!');
    """)
    conn.commit()
    conn.close()
