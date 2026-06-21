import os
import uuid
import datetime
import sqlite3
from core.db import get_db_connection
from core.key_manager import load_public_key
from core.crypto_service import encrypt_payload_hybrid

# Initialize paths relative to workspace
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(BASE_DIR, "storage", "encrypted_files")
TEMP_DIR = os.path.join(BASE_DIR, "storage", "temp")

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

def _check_and_update_expiry(conn, cursor, file_id: int, expires_at_str: str, status: str, ciphertext_path: str, recipient_id: int) -> str:
    """
    Utility function to check if a file has expired and update its status dynamically.
    If it is expired, the file payload is deleted from disk to ensure forward secrecy.
    """
    if expires_at_str and status == "ACTIVE":
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
        except ValueError:
            return status
            
        if datetime.datetime.now() > expires_at:
            # Update status in DB
            cursor.execute("UPDATE files SET status = 'EXPIRED' WHERE id = ?", (file_id,))
            conn.commit()
            
            # Log event
            from core.audit_service import log_event
            log_event(recipient_id, "EXPIRED", file_id=file_id, details=f"File expired dynamically on access check.")
            
            # Remove ciphertext payload from disk
            if os.path.exists(ciphertext_path):
                try:
                    os.remove(ciphertext_path)
                except Exception as e:
                    print(f"Error removing expired file at {ciphertext_path}: {e}")
            return "EXPIRED"
            
    return status

def get_user_by_secure_id(secure_id: str):
    """Retrieve user credentials and public key by their SecureShare ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, secure_id, name, email, public_key_pem FROM users WHERE secure_id = ?",
        (secure_id.strip().upper(),)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def send_file(sender_id: int, recipient_secure_id: str, original_filename: str, mime_type: str, file_bytes: bytes, notes: str = None, expiry_days: int = None, one_time_only: bool = False):
    """
    Performs the E2E E2E hybrid encryption file upload flow.
    Saves encrypted blob to disk, inserts DB metadata, and logs the SENT audit event.
    """
    # 1. Lookup recipient
    recipient = get_user_by_secure_id(recipient_secure_id)
    if not recipient:
        raise ValueError("Recipient SecureShare ID not found.")
        
    recipient_id = recipient["id"]
    if recipient_id == sender_id:
        raise ValueError("You cannot transfer files to yourself.")
        
    # 2. Hybrid Encrypt the file payload using recipient's public key
    try:
        recipient_public_key = load_public_key(recipient["public_key_pem"])
        crypto_payload = encrypt_payload_hybrid(file_bytes, recipient_public_key)
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")
        
    # 3. Save ciphertext to disk
    file_uid = str(uuid.uuid4())
    stored_filename = f"{file_uid}.encbin"
    ciphertext_path = os.path.join(STORAGE_DIR, stored_filename)
    
    try:
        with open(ciphertext_path, "wb") as f:
            f.write(crypto_payload["ciphertext"])
    except Exception as e:
        raise ValueError(f"Failed to write encrypted payload to disk: {str(e)}")
        
    # 4. Calculate Expiry
    expires_at = None
    if expiry_days is not None and expiry_days > 0:
        expires_at = (datetime.datetime.now() + datetime.timedelta(days=expiry_days)).isoformat()
        
    # 5. Insert DB metadata
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO files (file_uid, sender_id, recipient_id, original_filename, stored_filename, mime_type, size_bytes, ciphertext_path, encrypted_file_key, nonce, status, expires_at, one_time_only)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_uid,
                sender_id,
                recipient_id,
                original_filename,
                stored_filename,
                mime_type,
                len(file_bytes),
                ciphertext_path,
                crypto_payload["encrypted_aes_key"],
                crypto_payload["nonce"],
                "ACTIVE",
                expires_at,
                1 if one_time_only else 0
            )
        )
        file_id = cursor.lastrowid
        conn.commit()
        
        # Log event
        from core.audit_service import log_event
        details = f"File: {original_filename} | Expiry days: {expiry_days or 'None'} | One-time: {one_time_only}"
        if notes and notes.strip():
            details += f" | Notes: {notes.strip()}"
        log_event(sender_id, "SENT", file_id=file_id, details=details)
        
    except sqlite3.Error as e:
        if os.path.exists(ciphertext_path):
            os.remove(ciphertext_path)
        conn.close()
        raise ValueError(f"Failed to save metadata in database: {str(e)}")
        
    conn.close()
    return file_uid

def download_and_decrypt_file(file_uid: str, recipient_id: int, recipient_private_key) -> dict:
    """
    Downloads and decrypts a received file.
    Performs security policy validations (revoked, expired, one-time consumed).
    Deletes the encrypted file from storage if one-time download is active.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT f.id, f.file_uid, f.sender_id, f.recipient_id, f.original_filename, f.stored_filename,
               f.mime_type, f.size_bytes, f.ciphertext_path, f.encrypted_file_key, f.nonce,
               f.status, f.expires_at, f.one_time_only, f.downloaded_at
        FROM files f
        WHERE f.file_uid = ?
        """,
        (file_uid,)
    )
    file_row = cursor.fetchone()
    
    if not file_row:
        conn.close()
        raise ValueError("File entry not found in database.")
        
    file_id = file_row["id"]
    
    # 1. Access validation
    if file_row["recipient_id"] != recipient_id:
        from core.audit_service import log_event
        log_event(recipient_id, "FAILED_DECRYPT", file_id=file_id, details="Unauthorized file access attempt.")
        conn.close()
        raise ValueError("Access Denied: You are not authorized to download this file.")
        
    # 2. Expiry check
    status = _check_and_update_expiry(
        conn, cursor, file_id, file_row["expires_at"], file_row["status"],
        file_row["ciphertext_path"], recipient_id
    )
    
    if status == "EXPIRED":
        conn.close()
        raise ValueError("This file has expired and is no longer available.")
    if status == "REVOKED":
        conn.close()
        raise ValueError("This file has been revoked by the sender.")
    if status == "DOWNLOADED" and file_row["one_time_only"]:
        conn.close()
        raise ValueError("This file has already been downloaded (One-Time limit reached).")
        
    # 3. Read ciphertext from disk
    ciphertext_path = file_row["ciphertext_path"]
    if not os.path.exists(ciphertext_path):
        conn.close()
        raise ValueError("The encrypted file block does not exist on storage.")
        
    try:
        with open(ciphertext_path, "rb") as f:
            ciphertext = f.read()
    except Exception as e:
        conn.close()
        raise ValueError(f"Failed to read file from storage: {str(e)}")
        
    # 4. Decrypt file contents
    try:
        from core.crypto_service import decrypt_payload_hybrid
        plaintext = decrypt_payload_hybrid(
            ciphertext,
            file_row["encrypted_file_key"],
            file_row["nonce"],
            recipient_private_key
        )
    except Exception as e:
        from core.audit_service import log_event
        log_event(recipient_id, "FAILED_DECRYPT", file_id=file_id, details=f"Decryption error: {str(e)}")
        conn.close()
        raise ValueError(f"Decryption failed: {str(e)}")
        
    # 5. Policy enforcement: Update state & cleanup
    downloaded_at = datetime.datetime.now().isoformat()
    new_status = "DOWNLOADED" if file_row["one_time_only"] else "ACTIVE"
    
    cursor.execute(
        "UPDATE files SET downloaded_at = ?, status = ? WHERE id = ?",
        (downloaded_at, new_status, file_id)
    )
    conn.commit()
    
    # Log success
    from core.audit_service import log_event
    log_event(recipient_id, "DOWNLOADED", file_id=file_id, details="File decrypted and downloaded.")
    
    # For one-time only downloads, scrub the ciphertext from disk immediately
    if file_row["one_time_only"]:
        try:
            if os.path.exists(ciphertext_path):
                os.remove(ciphertext_path)
        except Exception as e:
            print(f"Scrubbing one-time file from storage failed: {e}")
            
    conn.close()
    
    return {
        "filename": file_row["original_filename"],
        "mime_type": file_row["mime_type"],
        "content": plaintext
    }

def revoke_file(file_uid: str, sender_id: int):
    """
    Revokes a sent file.
    Deletes the encrypted payload from disk and changes the database record status to REVOKED.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, sender_id, ciphertext_path, status FROM files WHERE file_uid = ?",
        (file_uid,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise ValueError("File not found.")
        
    if row["sender_id"] != sender_id:
        conn.close()
        raise ValueError("You are not authorized to revoke this file.")
        
    if row["status"] != "ACTIVE":
        conn.close()
        raise ValueError(f"Cannot revoke file with current status: {row['status']}")
        
    # Update status to REVOKED
    cursor.execute("UPDATE files SET status = 'REVOKED' WHERE id = ?", (row["id"],))
    conn.commit()
    
    # Log audit event
    from core.audit_service import log_event
    log_event(sender_id, "REVOKED", file_id=row["id"], details="File revoked by sender.")
    
    # Delete ciphertext from disk
    ciphertext_path = row["ciphertext_path"]
    if os.path.exists(ciphertext_path):
        try:
            os.remove(ciphertext_path)
        except Exception as e:
            print(f"Error removing revoked file {ciphertext_path}: {e}")
            
    conn.close()

def get_received_files(user_id: int) -> list:
    """Retrieve inbox files for the recipient, running dynamic expiry check on each."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT f.id, f.file_uid, f.sender_id, f.recipient_id, f.original_filename, f.mime_type, f.size_bytes,
               f.ciphertext_path, f.upload_time, f.status, f.expires_at, f.one_time_only, f.downloaded_at,
               u.name as sender_name, u.secure_id as sender_secure_id
        FROM files f
        JOIN users u ON f.sender_id = u.id
        WHERE f.recipient_id = ?
        ORDER BY f.upload_time DESC
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    
    files = []
    for row in rows:
        # Dynamic expiry verification
        status = _check_and_update_expiry(
            conn, cursor, row["id"], row["expires_at"], row["status"],
            row["ciphertext_path"], user_id
        )
        
        files.append({
            "id": row["id"],
            "file_uid": row["file_uid"],
            "sender_name": row["sender_name"],
            "sender_secure_id": row["sender_secure_id"],
            "original_filename": row["original_filename"],
            "mime_type": row["mime_type"],
            "size_bytes": row["size_bytes"],
            "upload_time": row["upload_time"],
            "status": status,
            "expires_at": row["expires_at"],
            "one_time_only": bool(row["one_time_only"]),
            "downloaded_at": row["downloaded_at"]
        })
        
    conn.close()
    return files

def get_sent_files(user_id: int) -> list:
    """Retrieve outbox files sent by the sender, running dynamic expiry check on each."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT f.id, f.file_uid, f.sender_id, f.recipient_id, f.original_filename, f.mime_type, f.size_bytes,
               f.ciphertext_path, f.upload_time, f.status, f.expires_at, f.one_time_only, f.downloaded_at,
               u.name as recipient_name, u.secure_id as recipient_secure_id
        FROM files f
        JOIN users u ON f.recipient_id = u.id
        WHERE f.sender_id = ?
        ORDER BY f.upload_time DESC
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    
    files = []
    for row in rows:
        # Dynamic expiry verification
        status = _check_and_update_expiry(
            conn, cursor, row["id"], row["expires_at"], row["status"],
            row["ciphertext_path"], row["recipient_id"]
        )
        
        files.append({
            "id": row["id"],
            "file_uid": row["file_uid"],
            "recipient_name": row["recipient_name"],
            "recipient_secure_id": row["recipient_secure_id"],
            "original_filename": row["original_filename"],
            "mime_type": row["mime_type"],
            "size_bytes": row["size_bytes"],
            "upload_time": row["upload_time"],
            "status": status,
            "expires_at": row["expires_at"],
            "one_time_only": bool(row["one_time_only"]),
            "downloaded_at": row["downloaded_at"]
        })
        
    conn.close()
    return files

def search_users(search_query: str) -> list:
    """Search for users by SecureShare ID or email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    q = f"%{search_query.strip().lower()}%"
    cursor.execute(
        """
        SELECT id, secure_id, name, email FROM users
        WHERE LOWER(secure_id) LIKE ? OR LOWER(email) LIKE ?
        """,
        (q, q)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def add_contact(user_id: int, contact_secure_id: str):
    """Add another user to the contacts list."""
    contact = get_user_by_secure_id(contact_secure_id)
    if not contact:
        raise ValueError("User not found.")
        
    if contact["id"] == user_id:
        raise ValueError("You cannot add yourself as a contact.")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO contacts (user_id, contact_user_id) VALUES (?, ?)",
            (user_id, contact["id"])
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError("This user is already in your contacts.")
    except sqlite3.Error as e:
        conn.close()
        raise ValueError(f"Database error: {str(e)}")
    finally:
        conn.close()

def get_contacts(user_id: int) -> list:
    """Retrieve all contacts saved by a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT u.id, u.secure_id, u.name, u.email
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ?
        ORDER BY u.name ASC
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def remove_contact(user_id: int, contact_id: int):
    """Remove a user from contacts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM contacts WHERE user_id = ? AND contact_user_id = ?",
        (user_id, contact_id)
    )
    conn.commit()
    conn.close()
