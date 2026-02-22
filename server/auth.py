import bcrypt
from .database import get_connection

def register_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash.decode())
        )
        conn.commit()
        return True, "User registered successfully."
    except Exception as e:
        return False, "Username already exists."
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    conn.close()

    if result:
        stored_hash = result[0].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            return True
    return False