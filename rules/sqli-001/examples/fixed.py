"""Fixed example: SQL injection prevention via parameterized queries."""

def get_user_secure(user_id: str) -> dict:
    """This function uses parameterized queries to prevent SQL injection."""
    import sqlite3
    
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SECURE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    return result
