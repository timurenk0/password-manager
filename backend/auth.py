import sqlite3 as sq
import bcrypt

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

DB_NAME = "database.db"


def add_user(username, password):
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)
        """, (username, password_hash, public_pem))

        conn.commit()
    except sq.IntegrityError as e:
        print(f"Integrity Error: {str(e)} ( username: {username} )")
        conn.rollback()
        return None
    finally:
        conn.close()


    private_pem_str = private_pem.decode()
    if not (private_pem_str.startswith("-----BEGIN PRIVATE KEY-----") and
            private_pem_str.endswith("-----END PRIVATE KEY-----\n")):
        raise ValueError("Generated private key is not in valid PEM format")
    

    return private_pem_str


def login_user(username, password):
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result is None:
        return None
    
    user_id, stored_hash = result
    password_bytes = password.encode("utf-8")

    if bcrypt.checkpw(password_bytes, stored_hash):
        return user_id
    else:
        return None
    

def get_passwords_for_user(user_id):
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, password_name, password_text, created_at FROM passwords WHERE user_id = ?", (user_id,))
    passwords = cursor.fetchall()
    
    conn.close()

    if not passwords:
        return []
    

    return passwords


def save_password_for_user(user_id, password_name, encrypted_password):
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (user_id, password_name, password_text) VALUES (?, ?, ?)", (user_id, password_name, encrypted_password))

    conn.commit()
    conn.close()