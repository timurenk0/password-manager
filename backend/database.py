import sqlite3 as sq



def init_db():
    conn = sq.connect("database.db")
    cursor = conn.cursor()


    cursor.execute("""
            CREATE TABLE IF NOT EXISTS users
                (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
""")
    
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords
                 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    password_name TEXT NOT NULL,
                    password_text BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                 )
""")
    
    conn.commit()
    conn.close()


init_db()