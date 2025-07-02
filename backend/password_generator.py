from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

import sqlite3 as sq

DB_NAME = "database.db"


def decrypt_with_private_key(encrypted_password, private_key_pem):
    try:
        # Private key validation logic
        private_key_pem = private_key_pem.strip()
        if not (private_key_pem.startswith("-----BEGIN PRIVATE KEY-----") and
                private_key_pem.endswith("-----END PRIVATE KEY-----")):
            raise ValueError("Invalid PEM format: Missing BEGIN/END markers")
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )

        # Decrypt the password with PKCS1v15 padding
        decrypted_password = private_key.decrypt(
            encrypted_password,
            padding.PKCS1v15
        ).decode("utf-8")

        
        return decrypted_password
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
    

def encrypt_with_symmetric_key(user_id, plain_password):
    # Fetch the symmetric key for user
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT encrypted_symmetric_key FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()

    conn.close()

    if result is None:
        raise ValueError("Encrypted symmetric key not found for user")
    
    encrypted_symmetric_key = result[0]

    fernet = Fernet(encrypted_symmetric_key)
    encrypted_password = fernet.encrypt(plain_password.encode())

    return encrypted_password