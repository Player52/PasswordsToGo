import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

# --- PBKDF2 Key Derivation ---
def derive_key(master_password, salt=None, iterations=200_000):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

# --- Per-Entry Encryption (with IV) ---
def encrypt_entry(data, key):
    f = Fernet(key)
    token = f.encrypt(data.encode())
    return token.decode()

def decrypt_entry(token, key):
    f = Fernet(key)
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return "<Decryption Failed>"

# --- Password Reveal Protection (re-authenticate before reveal) ---
def re_authenticate(master_password, stored_hash, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    try:
        kdf.verify(master_password.encode(), base64.urlsafe_b64decode(stored_hash))
        return True
    except Exception:
        return False

# --- In-Memory Encryption ---
class InMemoryVault:
    def __init__(self, key):
        self.fernet = Fernet(key)
        self._vault = None

    def load(self, encrypted_data):
        self._vault = self.fernet.decrypt(encrypted_data.encode())

    def get(self):
        return self._vault

    def save(self, data):
        self._vault = data
        return self.fernet.encrypt(data.encode()).decode()

# --- Tamper Detection (vault MAC/hash) ---
def compute_vault_hash(encrypted_vault):
    # SHA256 hash of vault file for integrity
    return hashlib.sha256(encrypted_vault.encode()).hexdigest()

def verify_vault_hash(encrypted_vault, stored_hash):
    return compute_vault_hash(encrypted_vault) == stored_hash

# --- Application Signing and Verification ---
def sign_release(file_path, private_key_path):
    # Simple signature: hash file and sign with private key (use cryptography's Ed25519 or RSA)
    # Placeholder only: Not implemented here
    pass

def verify_release(file_path, signature, public_key_path):
    # Placeholder only: Not implemented here
    pass

# --- Anti-Screenshot/Clipboard Hooks ---
def warn_screenshot():
    import platform
    if platform.system() == "Windows":
        import ctypes
        messagebox = ctypes.windll.user32.MessageBoxW
        messagebox(None, "Warning: Screenshots may expose sensitive data!", "Security Warning", 0)
    # On other platforms, print a warning
    else:
        print("Warning: Screenshots may expose sensitive data!")

def clear_clipboard():
    import pyperclip
    pyperclip.copy("")
