import bcrypt
import sqlite3
from core.db import get_db_connection
from core.utils import generate_secureshare_id, is_valid_email
from core.key_manager import generate_user_keys, decrypt_private_key

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify standard login password against hash using bcrypt."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def register_user(name: str, email: str, password: str, confirm_password: str):
    """
    Registers a new user.
    Generates a unique SecureShare ID and the RSA key pair.
    Saves encrypted private key and public key to SQLite.
    """
    # 1. Input Validations
    if not name or not name.strip():
        raise ValueError("Name cannot be empty.")
    if not email or not is_valid_email(email):
        raise ValueError("Invalid email format.")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if password != confirm_password:
        raise ValueError("Passwords do not match.")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if email exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (email.lower(),))
    if cursor.fetchone():
        conn.close()
        raise ValueError("A user with this email already exists.")
        
    # 2. Generate unique SecureShare ID
    secure_id = None
    max_attempts = 10
    for _ in range(max_attempts):
        candidate_id = generate_secureshare_id()
        cursor.execute("SELECT id FROM users WHERE secure_id = ?", (candidate_id,))
        if not cursor.fetchone():
            secure_id = candidate_id
            break
            
    if not secure_id:
        conn.close()
        raise ValueError("Could not generate a unique SecureShare ID. Please try again.")
        
    # 3. Generate RSA Key Pair
    try:
        public_key_pem, encrypted_private_key_pem, salt_b64 = generate_user_keys(password)
    except Exception as e:
        conn.close()
        raise ValueError(f"Failed during user key generation: {str(e)}")
        
    # 4. Hash standard login password
    password_hash = hash_password(password)
    
    # 5. Insert into Database
    try:
        cursor.execute(
            """
            INSERT INTO users (secure_id, name, email, password_hash, public_key_pem, encrypted_private_key_pem, private_key_salt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                secure_id,
                name.strip(),
                email.lower().strip(),
                password_hash,
                public_key_pem,
                encrypted_private_key_pem,
                salt_b64
            )
        )
        conn.commit()
    except sqlite3.Error as e:
        conn.close()
        raise ValueError(f"Database error during registration: {str(e)}")
        
    conn.close()
    return {
        "secure_id": secure_id,
        "name": name,
        "email": email
    }

def login_user(email: str, password: str):
    """
    Log in a user by validating their password, and decrypt their RSA private key.
    Returns:
        dict: User details dictionary.
        private_key_obj: Decrypted cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.
    """
    if not email or not password:
        raise ValueError("Email and password are required.")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT id, secure_id, name, email, password_hash, public_key_pem, encrypted_private_key_pem, private_key_salt
        FROM users WHERE email = ?
        """,
        (email.lower().strip(),)
    )
    user_row = cursor.fetchone()
    conn.close()
    
    if not user_row:
        raise ValueError("Invalid email or password.")
        
    # Validate hashed password
    if not verify_password(password, user_row["password_hash"]):
        raise ValueError("Invalid email or password.")
        
    # Attempt to decrypt their private key using the password (secondary authentication & decryption load)
    try:
        private_key = decrypt_private_key(
            user_row["encrypted_private_key_pem"],
            user_row["private_key_salt"],
            password
        )
    except ValueError as e:
        raise ValueError(f"Authentication failed: {str(e)}")
        
    return {
        "id": user_row["id"],
        "secure_id": user_row["secure_id"],
        "name": user_row["name"],
        "email": user_row["email"],
        "public_key_pem": user_row["public_key_pem"]
    }, private_key
