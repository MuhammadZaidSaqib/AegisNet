import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib


def derive_key(shared_secret: bytes) -> bytes:
    """
    Derive AES-256 key from shared secret using SHA-256.
    """
    return hashlib.sha256(shared_secret).digest()


def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt message using AES-256-GCM.
    Returns: nonce + ciphertext
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext


def decrypt_message(key: bytes, encrypted_data: bytes) -> str:
    """
    Decrypt AES-256-GCM message.
    Expects: nonce + ciphertext
    """
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()