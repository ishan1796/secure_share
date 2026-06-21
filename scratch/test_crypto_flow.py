import sys
import os
import shutil

# Add parent directory to path so we can import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import init_db, get_db_connection
from core.auth import register_user, login_user
from core.file_service import send_file, download_and_decrypt_file, get_received_files, get_sent_files
from core.audit_service import get_user_audit_logs

def test_pipeline():
    print("=== STARTING SECURESHARE SYSTEM VERIFICATION ===")
    
    # 1. Reset database for clean test run
    db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database")
    db_path = os.path.join(db_dir, "secureshare.db")
    storage_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage", "encrypted_files")
    
    if os.path.exists(db_path):
        os.remove(db_path)
        print("[*] Cleared existing database.")
    if os.path.exists(storage_dir):
        shutil.rmtree(storage_dir)
        print("[*] Cleared existing storage folder.")
        
    os.makedirs(storage_dir, exist_ok=True)
    
    # Initialize DB
    init_db()
    print("[+] Database tables initialized.")

    # 2. Register two test users
    print("\n--- Testing User Registration ---")
    try:
        alice = register_user("Alice Smith", "alice@test.com", "AlicePassword123!", "AlicePassword123!")
        print(f"[+] Alice registered. Secure ID: {alice['secure_id']}")
    except Exception as e:
        print(f"[-] Alice registration failed: {e}")
        return False

    try:
        bob = register_user("Bob Jones", "bob@test.com", "BobPassword123!", "BobPassword123!")
        print(f"[+] Bob registered. Secure ID: {bob['secure_id']}")
    except Exception as e:
        print(f"[-] Bob registration failed: {e}")
        return False

    # 3. Log in users & retrieve decrypted private keys
    print("\n--- Testing User Login & Key Decryption ---")
    try:
        alice_session, alice_private_key = login_user("alice@test.com", "AlicePassword123!")
        print(f"[+] Alice logged in successfully. Private key decrypted in-memory.")
    except Exception as e:
        print(f"[-] Alice login failed: {e}")
        return False

    try:
        bob_session, bob_private_key = login_user("bob@test.com", "BobPassword123!")
        print(f"[+] Bob logged in successfully. Private key decrypted in-memory.")
    except Exception as e:
        print(f"[-] Bob login failed: {e}")
        return False

    # 4. Send encrypted file from Alice to Bob
    print("\n--- Testing Send File (Hybrid Encryption) ---")
    plaintext_data = b"CONFIDENTIAL: Project Apollo blueprint details. Do not share outside."
    original_filename = "apollo_blueprint.txt"
    mime_type = "text/plain"
    
    try:
        file_uid = send_file(
            sender_id=alice_session["id"],
            recipient_secure_id=bob_session["secure_id"],
            original_filename=original_filename,
            mime_type=mime_type,
            file_bytes=plaintext_data,
            notes="Please review immediately.",
            expiry_days=7,
            one_time_only=False
        )
        print(f"[+] File sent successfully! File UID: {file_uid}")
    except Exception as e:
        print(f"[-] Sending file failed: {e}")
        return False

    # Verify that the encrypted file blob was written to storage
    ciphertext_files = os.listdir(storage_dir)
    print(f"[+] Encrypted files in storage folder: {ciphertext_files}")
    if not ciphertext_files:
        print("[-] Encrypted file was not written to storage!")
        return False

    # 5. Retrieve inbox and decrypt file as Bob
    print("\n--- Testing Inbox Retrieval & Decryption ---")
    try:
        bob_inbox = get_received_files(bob_session["id"])
        print(f"[+] Bob's Inbox has {len(bob_inbox)} file(s).")
        if len(bob_inbox) != 1:
            print("[-] Bob should have received exactly 1 file.")
            return False
        
        file_to_download = bob_inbox[0]
        print(f"[+] Found file: {file_to_download['original_filename']} from {file_to_download['sender_name']}")
        
        # Download and decrypt
        downloaded = download_and_decrypt_file(
            file_to_download["file_uid"],
            bob_session["id"],
            bob_private_key
        )
        
        print(f"[+] File decrypted successfully.")
        print(f"[+] Decrypted content matches original: {downloaded['content'] == plaintext_data}")
        print(f"[+] Content: '{downloaded['content'].decode('utf-8')}'")
        
        if downloaded["content"] != plaintext_data:
            print("[-] Decrypted content does not match plaintext!")
            return False
            
    except Exception as e:
        print(f"[-] Inbox decryption failed: {e}")
        return False

    # 6. Verify audit logs
    print("\n--- Testing Audit Logs ---")
    try:
        alice_logs = get_user_audit_logs(alice_session["id"])
        print(f"[+] Alice's Audit Logs ({len(alice_logs)} items):")
        for log in alice_logs:
            print(f"    - [{log['event_time']}] {log['event_type']}: {log['details']}")
            
        bob_logs = get_user_audit_logs(bob_session["id"])
        print(f"[+] Bob's Audit Logs ({len(bob_logs)} items):")
        for log in bob_logs:
            print(f"    - [{log['event_time']}] {log['event_type']}: {log['details']}")
            
    except Exception as e:
        print(f"[-] Fetching audit logs failed: {e}")
        return False

    print("\n===========================================")
    print("[SUCCESS] ALL CRYPTOGRAPHIC AND FLOW TESTS PASSED [SUCCESS]")
    print("===========================================")
    return True

if __name__ == "__main__":
    success = test_pipeline()
    sys.exit(0 if success else 1)
