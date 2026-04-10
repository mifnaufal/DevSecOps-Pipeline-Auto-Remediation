import hashlib
import sqlite3

# CWE-328: Using broken MD5 hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# CWE-328: Using broken SHA1
def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()

# CWE-89: SQL Injection
def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
