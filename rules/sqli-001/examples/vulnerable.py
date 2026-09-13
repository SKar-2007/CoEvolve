"""Vulnerable example: SQL injection via string formatting."""

def get_user_vulnerable(user_id: str) -> dict:
    """This function is vulnerable to SQL injection."""
    import sqlite3
    
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation with user input
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result
