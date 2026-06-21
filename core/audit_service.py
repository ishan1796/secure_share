import sqlite3
from core.db import get_db_connection

def log_event(user_id: int, event_type: str, file_id: int = None, details: str = None):
    """
    Log an event to the file_events table.
    event_type: 'SENT', 'RECEIVED', 'DOWNLOADED', 'REVOKED', 'FAILED_DECRYPT', 'EXPIRED'
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO file_events (file_id, user_id, event_type, details)
            VALUES (?, ?, ?, ?)
            """,
            (file_id, user_id, event_type, details)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging event: {e}")
    finally:
        conn.close()

def get_user_audit_logs(user_id: int):
    """
    Retrieve audit logs relevant to a given user.
    This includes events triggered by the user themselves, or events on files
    where the user is the sender or the recipient.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            fe.id, 
            fe.event_type, 
            fe.event_time, 
            fe.details, 
            f.original_filename,
            u.name as actor_name,
            u.secure_id as actor_secure_id
        FROM file_events fe
        LEFT JOIN files f ON fe.file_id = f.id
        JOIN users u ON fe.user_id = u.id
        WHERE fe.user_id = ? 
           OR f.sender_id = ? 
           OR f.recipient_id = ?
        ORDER BY fe.event_time DESC
    """
    
    cursor.execute(query, (user_id, user_id, user_id))
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            "id": row["id"],
            "event_type": row["event_type"],
            "event_time": row["event_time"],
            "details": row["details"],
            "original_filename": row["original_filename"] or "N/A",
            "actor_name": row["actor_name"],
            "actor_secure_id": row["actor_secure_id"]
        })
    return logs
