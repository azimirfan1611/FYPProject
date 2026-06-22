import os
import subprocess

# Semgrep: OS injection vulnerability
def vulnerable_command_execution(user_input):
    os.system(f"echo {user_input}")  # VULNERABLE: OS injection

# Semgrep: Hardcoded credentials
DATABASE_PASSWORD = "admin123password"
API_KEY = "sk-12345abcde67890fghij"

# Semgrep: SQL injection
def vulnerable_query(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Semgrep: Path traversal
def read_file(filename):
    with open(f"/files/{filename}", "r") as f:
        return f.read()

# Semgrep: Weak cryptography
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: MD5

# Semgrep: Insecure deserialization
import pickle
def deserialize_user(data):
    return pickle.loads(data)  # VULNERABLE: Unsafe pickle
