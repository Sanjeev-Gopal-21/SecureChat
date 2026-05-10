"""
RSA Key Exchange Module
Handles RSA-2048 key pair generation and secure key exchange
"""

import os
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class KeyExchange:
    """
    Manages RSA-2048 key pairs and secure session key exchange.
    
    RSA is used for secure exchange of symmetric session keys.
    Private keys are never transmitted.
    """
    
    KEY_SIZE = 2048  # 2048-bit RSA keys
    
    def __init__(self, username, key_dir="keys"):
        """
        Initialize key exchange for a user.
        
        Args:
            username (str): Username for key storage
            key_dir (str): Directory to store keys
        """
        self.username = username
        self.key_dir = key_dir
        self.private_key = None
        self.public_key = None
        
        # Create key directory if it doesn't exist
        os.makedirs(key_dir, exist_ok=True)
        os.chmod(key_dir, 0o700)  # Restrict to owner only
    
    def generate_keypair(self):
        """
        Generate RSA-2048 key pair for the user.
        
        Returns:
            tuple: (public_key_pem, private_key_pem)
        """
        print(f"[*] Generating RSA-2048 key pair for {self.username}...")
        
        # Generate RSA key pair
        key = RSA.generate(self.KEY_SIZE)
        
        self.private_key = key
        self.public_key = key.publickey()
        
        # Export keys to PEM format
        private_key_pem = key.export_key('PEM').decode('utf-8')
        public_key_pem = key.publickey().export_key('PEM').decode('utf-8')
        
        # Save keys to disk
        self._save_keys(private_key_pem, public_key_pem)
        
        print(f"[✓] RSA-2048 key pair generated and saved")
        print(f"    Private key fingerprint: {self._get_key_fingerprint(self.private_key)}")
        print(f"    Public key fingerprint: {self._get_key_fingerprint(self.public_key)}")
        
        return public_key_pem, private_key_pem
    
    def _save_keys(self, private_pem, public_pem):
        """
        Save keys to disk with restricted permissions.
        
        Args:
            private_pem (str): Private key in PEM format
            public_pem (str): Public key in PEM format
        """
        # Save private key
        private_key_path = os.path.join(self.key_dir, f"{self.username}_private.pem")
        with open(private_key_path, 'w') as f:
            f.write(private_pem)
        os.chmod(private_key_path, 0o600)  # Read/write for owner only
        
        # Save public key
        public_key_path = os.path.join(self.key_dir, f"{self.username}_public.pem")
        with open(public_key_path, 'w') as f:
            f.write(public_pem)
        os.chmod(public_key_path, 0o644)  # Read for all, write for owner
        
        print(f"[✓] Keys saved to {self.key_dir}/")
    
    def load_keys(self):
        """
        Load existing keys from disk.
        
        Returns:
            bool: True if keys loaded successfully, False otherwise
        """
        private_key_path = os.path.join(self.key_dir, f"{self.username}_private.pem")
        public_key_path = os.path.join(self.key_dir, f"{self.username}_public.pem")
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            return False
        
        try:
            with open(private_key_path, 'r') as f:
                self.private_key = RSA.import_key(f.read())
            
            with open(public_key_path, 'r') as f:
                self.public_key = RSA.import_key(f.read())
            
            print(f"[✓] Keys loaded for {self.username}")
            return True
        except Exception as e:
            print(f"[✗] Error loading keys: {e}")
            return False
    
    def get_public_key_pem(self):
        """
        Get public key in PEM format for transmission.
        
        Returns:
            str: Public key in PEM format
        """
        if self.public_key is None:
            raise ValueError("No public key available. Generate or load keys first.")
        return self.public_key.export_key('PEM').decode('utf-8')
    
    def encrypt_session_key(self, session_key, recipient_public_key_pem):
        """
        Encrypt session key with recipient's public key.
        
        Uses RSA-OAEP (Optimal Asymmetric Encryption Padding) for security.
        
        Args:
            session_key (bytes): AES session key (32 bytes for AES-256)
            recipient_public_key_pem (str): Recipient's public key in PEM format
        
        Returns:
            bytes: Encrypted session key
        """
        try:
            # Import recipient's public key
            recipient_public_key = RSA.import_key(recipient_public_key_pem)
            
            # Create cipher
            cipher = PKCS1_OAEP.new(recipient_public_key)
            
            # Encrypt session key
            encrypted_key = cipher.encrypt(session_key)
            
            print(f"[✓] Session key encrypted with RSA-OAEP")
            print(f"    Plaintext size: {len(session_key)} bytes")
            print(f"    Ciphertext size: {len(encrypted_key)} bytes")
            
            return encrypted_key
        
        except Exception as e:
            print(f"[✗] Error encrypting session key: {e}")
            raise
    
    def decrypt_session_key(self, encrypted_session_key):
        """
        Decrypt session key using own private key.
        
        Args:
            encrypted_session_key (bytes): Encrypted session key
        
        Returns:
            bytes: Decrypted session key
        """
        if self.private_key is None:
            raise ValueError("No private key available")
        
        try:
            # Create cipher
            cipher = PKCS1_OAEP.new(self.private_key)
            
            # Decrypt session key
            session_key = cipher.decrypt(encrypted_session_key)
            
            print(f"[✓] Session key decrypted successfully")
            print(f"    Decrypted key size: {len(session_key)} bytes")
            
            return session_key
        
        except Exception as e:
            print(f"[✗] Error decrypting session key: {e}")
            raise
    
    def import_public_key(self, public_key_pem):
        """
        Import and validate a public key in PEM format.
        
        Args:
            public_key_pem (str): Public key in PEM format
        
        Returns:
            RSA.RsaKey: Imported public key object
        """
        try:
            public_key = RSA.import_key(public_key_pem)
            
            # Validate it's actually a public key
            if public_key.has_private():
                raise ValueError("Received a private key instead of public key!")
            
            # Validate key size
            if public_key.size_in_bits() != self.KEY_SIZE:
                raise ValueError(f"Key size mismatch. Expected {self.KEY_SIZE}, got {public_key.size_in_bits()}")
            
            print(f"[✓] Public key imported and validated")
            return public_key
        
        except Exception as e:
            print(f"[✗] Error importing public key: {e}")
            raise
    
    @staticmethod
    def _get_key_fingerprint(key, length=8):
        """
        Generate a fingerprint of a key for display purposes.
        
        Args:
            key: RSA key object
            length (int): Length of fingerprint to display
        
        Returns:
            str: Hex fingerprint
        """
        key_bytes = key.export_key('DER')
        fingerprint = key_bytes[-16:].hex()
        return fingerprint[:length].upper()
    
    def validate_keys(self):
        """
        Validate that keys are properly loaded and can perform operations.
        
        Returns:
            bool: True if validation successful
        """
        if self.private_key is None or self.public_key is None:
            print(f"[✗] Keys not loaded")
            return False
        
        try:
            # Test encryption/decryption
            test_message = b"Test message for key validation"
            
            cipher = PKCS1_OAEP.new(self.public_key)
            encrypted = cipher.encrypt(test_message)
            
            cipher = PKCS1_OAEP.new(self.private_key)
            decrypted = cipher.decrypt(encrypted)
            
            if decrypted != test_message:
                print(f"[✗] Key validation failed: encryption/decryption mismatch")
                return False
            
            print(f"[✓] Keys validated successfully")
            return True
        
        except Exception as e:
            print(f"[✗] Key validation error: {e}")
            return False


def generate_session_key(key_size=32):
    """
    Generate a random session key for AES encryption.
    
    Args:
        key_size (int): Size of the session key in bytes (32 = 256-bit for AES-256)
    
    Returns:
        bytes: Random session key
    """
    session_key = get_random_bytes(key_size)
    print(f"[✓] Generated random session key ({key_size*8}-bit)")
    return session_key
