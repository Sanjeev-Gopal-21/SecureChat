"""
key_exchange.py  —  RSA-2048 key generation and session-key exchange.

Windows compatibility:
  - os.chmod() is a no-op on Windows for most permission bits; the call is
    wrapped in a platform check so it only runs on Linux/macOS.
  - All paths built with os.path.join() so separators are correct on every OS.
  - No POSIX-only APIs used anywhere in this file.
"""

import os
import sys
import platform
from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_OAEP
from Crypto.Random   import get_random_bytes


def _set_permissions(path: str, mode: int):
    """
    Apply Unix file-permission bits only on Linux/macOS.
    On Windows, os.chmod() is silently ignored for most bits, so we skip it
    entirely to avoid confusion and keep the code cross-platform.
    """
    if platform.system() != 'Windows':
        try:
            os.chmod(path, mode)
        except OSError:
            pass   # NFS / FAT32 / some network drives don't support chmod


class KeyExchange:
    """
    RSA-2048 key pair management and PKCS1-OAEP session-key exchange.

    Works on Windows, Linux and macOS.
    """

    KEY_SIZE = 2048

    def __init__(self, username: str, key_dir: str = "keys"):
        self.username   = username
        self.key_dir    = key_dir
        self.private_key = None
        self.public_key  = None

        os.makedirs(key_dir, exist_ok=True)
        _set_permissions(key_dir, 0o700)   # no-op on Windows

    # ── key generation ────────────────────────────────────────────────────────
    def generate_keypair(self):
        """Generate RSA-2048 key pair and save to disk."""
        print(f"[*] Generating RSA-2048 key pair for {self.username}...")
        key = RSA.generate(self.KEY_SIZE)
        self.private_key = key
        self.public_key  = key.publickey()

        priv_pem = key.export_key('PEM').decode('utf-8')
        pub_pem  = key.publickey().export_key('PEM').decode('utf-8')

        self._save_keys(priv_pem, pub_pem)

        print(f"[✓] RSA-2048 key pair generated and saved")
        print(f"    Private key fingerprint: {self._fingerprint(self.private_key)}")
        print(f"    Public  key fingerprint: {self._fingerprint(self.public_key)}")
        return pub_pem, priv_pem

    def _save_keys(self, priv_pem: str, pub_pem: str):
        """Write PEM files. Restrict private key permissions on Linux/macOS."""
        priv_path = os.path.join(self.key_dir, f"{self.username}_private.pem")
        pub_path  = os.path.join(self.key_dir, f"{self.username}_public.pem")

        with open(priv_path, 'w') as f:
            f.write(priv_pem)
        _set_permissions(priv_path, 0o600)   # owner read/write — no-op on Windows

        with open(pub_path, 'w') as f:
            f.write(pub_pem)
        _set_permissions(pub_path, 0o644)    # world-readable  — no-op on Windows

        print(f"[✓] Keys saved to {self.key_dir}{os.sep}")

    # ── load / validate ───────────────────────────────────────────────────────
    def load_keys(self) -> bool:
        """Load existing PEM files from disk. Returns True on success."""
        priv_path = os.path.join(self.key_dir, f"{self.username}_private.pem")
        pub_path  = os.path.join(self.key_dir, f"{self.username}_public.pem")

        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            return False
        try:
            with open(priv_path, 'r') as f:
                self.private_key = RSA.import_key(f.read())
            with open(pub_path, 'r') as f:
                self.public_key = RSA.import_key(f.read())
            print(f"[✓] Keys loaded for {self.username}")
            return True
        except Exception as e:
            print(f"[✗] Error loading keys: {e}")
            return False

    def validate_keys(self) -> bool:
        """Round-trip test: encrypt then decrypt a test value."""
        if self.private_key is None or self.public_key is None:
            return False
        try:
            test = b"key-validation-ping"
            enc  = PKCS1_OAEP.new(self.public_key).encrypt(test)
            dec  = PKCS1_OAEP.new(self.private_key).decrypt(enc)
            ok   = dec == test
            if ok:
                print(f"[✓] Keys validated successfully")
            else:
                print(f"[✗] Key validation mismatch")
            return ok
        except Exception as e:
            print(f"[✗] Key validation error: {e}")
            return False

    # ── public key export / import ────────────────────────────────────────────
    def get_public_key_pem(self) -> str:
        if self.public_key is None:
            raise ValueError("No public key — generate or load first")
        return self.public_key.export_key('PEM').decode('utf-8')

    def import_public_key(self, pem: str):
        """Import, validate and return a remote RSA public key object."""
        key = RSA.import_key(pem)
        if key.has_private():
            raise ValueError("Received a private key — expected a public key!")
        if key.size_in_bits() != self.KEY_SIZE:
            raise ValueError(f"Wrong key size: {key.size_in_bits()} (expected {self.KEY_SIZE})")
        print(f"[✓] Remote public key imported and validated")
        return key

    # ── session key operations ────────────────────────────────────────────────
    def encrypt_session_key(self, session_key: bytes, recipient_pub_pem: str) -> bytes:
        """
        Encrypt a 32-byte AES session key with the recipient's RSA public key.
        Uses PKCS1-OAEP (probabilistic, chosen-plaintext resistant).
        """
        recipient_key = RSA.import_key(recipient_pub_pem)
        encrypted     = PKCS1_OAEP.new(recipient_key).encrypt(session_key)
        print(f"[✓] Session key encrypted with RSA-OAEP  ({len(encrypted)} bytes)")
        return encrypted

    def decrypt_session_key(self, encrypted: bytes) -> bytes:
        """Decrypt an RSA-OAEP encrypted session key with our private key."""
        if self.private_key is None:
            raise ValueError("No private key available")
        key = PKCS1_OAEP.new(self.private_key).decrypt(encrypted)
        print(f"[✓] Session key decrypted  ({len(key)} bytes)")
        return key

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _fingerprint(key, length: int = 8) -> str:
        return key.export_key('DER')[-16:].hex()[:length].upper()


def generate_session_key(size: int = 32) -> bytes:
    """Return `size` cryptographically secure random bytes (default 256-bit)."""
    key = get_random_bytes(size)
    print(f"[✓] Generated random {size*8}-bit session key")
    return key
