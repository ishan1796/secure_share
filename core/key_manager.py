import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITERATIONS = 100_000
KDF_KEY_LENGTH = 32 # 256 bits for AES-256

def generate_user_keys(password: str):
    """
    Generate a 2048-bit RSA key pair for a user.
    Encrypt the private key using an AES key derived from their password.
    Returns:
        public_key_pem (str): Plaintext public key in PEM format.
        encrypted_private_key_b64 (str): Base64 encoded (nonce + AES-GCM encrypted private key).
        salt_b64 (str): Base64 encoded KDF salt.
    """
    # 1. Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # 2. Serialize public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    # 3. Serialize private key to PEM (plaintext bytes in memory)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 4. Derive AES key from user password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KDF_KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS
    )
    derived_key = kdf.derive(password.encode())
    
    # 5. Encrypt private key PEM using AES-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, None)
    
    # Prepend nonce to ciphertext and encode to base64
    combined_payload = nonce + ciphertext
    encrypted_private_key_b64 = base64.b64encode(combined_payload).decode("utf-8")
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    
    return public_pem, encrypted_private_key_b64, salt_b64

def decrypt_private_key(encrypted_private_key_b64: str, salt_b64: str, password: str) -> rsa.RSAPrivateKey:
    """
    Decrypt and deserialize the RSA private key using the user's password.
    Returns:
        RSAPrivateKey: Cryptography RSA private key object.
    Raises:
        Exception: If decryption or key load fails (e.g. wrong password).
    """
    try:
        # Decode components
        combined_payload = base64.b64decode(encrypted_private_key_b64.encode("utf-8"))
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        
        # Extract nonce and ciphertext
        nonce = combined_payload[:12]
        ciphertext = combined_payload[12:]
        
        # Re-derive AES key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KDF_KEY_LENGTH,
            salt=salt,
            iterations=KDF_ITERATIONS
        )
        derived_key = kdf.derive(password.encode())
        
        # Decrypt ciphertext
        aesgcm = AESGCM(derived_key)
        private_pem = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Deserialize private key
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None
        )
        return private_key
    except Exception as e:
        raise ValueError("Failed to decrypt private key. Incorrect password or corrupted key data.") from e

def load_public_key(public_key_pem: str) -> rsa.RSAPublicKey:
    """Load an RSA public key object from its PEM string representation."""
    try:
        return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError("Failed to load public key PEM.") from e
