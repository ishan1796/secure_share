import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_payload_hybrid(plaintext_bytes: bytes, recipient_public_key: rsa.RSAPublicKey) -> dict:
    """
    Encrypt a plaintext payload using hybrid encryption (AES-256-GCM + RSA).
    Args:
        plaintext_bytes (bytes): The raw data to encrypt.
        recipient_public_key (RSAPublicKey): The recipient's RSA public key object.
    Returns:
        dict: Contains:
            - 'ciphertext' (bytes): Encrypted file content.
            - 'encrypted_aes_key' (str): Base64 encoded RSA-encrypted AES key.
            - 'nonce' (str): Base64 encoded AES-GCM IV.
    """
    # 1. Generate ephemeral 256-bit AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    
    # 2. Encrypt plaintext payload with AES-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    # 3. Encrypt/Wrap the AES key with recipient's RSA public key
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Return results (Base64 encoding key and nonce for database storage)
    return {
        "ciphertext": ciphertext,
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8")
    }

def decrypt_payload_hybrid(ciphertext_bytes: bytes, encrypted_aes_key_b64: str, nonce_b64: str, recipient_private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt a ciphertext payload using hybrid decryption (AES-256-GCM + RSA).
    Args:
        ciphertext_bytes (bytes): The encrypted file content.
        encrypted_aes_key_b64 (str): Base64 encoded RSA-encrypted AES key.
        nonce_b64 (str): Base64 encoded AES-GCM IV.
        recipient_private_key (RSAPrivateKey): The recipient's RSA private key object.
    Returns:
        bytes: Decrypted original payload bytes.
    Raises:
        ValueError: If decryption fails (corrupted data, wrong key, etc.).
    """
    try:
        # 1. Decode RSA-wrapped key and AES-GCM nonce
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64.encode("utf-8"))
        nonce = base64.b64decode(nonce_b64.encode("utf-8"))
        
        # 2. Decrypt/Unwrap the AES key using recipient's RSA private key
        aes_key = recipient_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Decrypt ciphertext payload using AES-GCM
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, None)
        
        return plaintext_bytes
    except Exception as e:
        raise ValueError("Hybrid decryption failed. The file may be corrupted, or the private key is incorrect.") from e
