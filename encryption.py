"""
AES Symmetric Encryption Module
Handles AES-256-CBC encryption and decryption of messages
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class SymmetricEncryption:
    """
    Manages AES-256-CBC encryption and decryption.
    
    Uses:
    - AES-256: 256-bit key for strong security
    - CBC Mode: Cipher Block Chaining for semantic security
    - Random IV: Different IV for each message prevents pattern recognition
    """
    
    ALGORITHM = "AES-256-CBC"
    KEY_SIZE = 32  # 256 bits / 8
    BLOCK_SIZE = 16  # AES block size is always 16 bytes
    IV_SIZE = 16  # AES IV size
    
    def __init__(self, session_key):
        """
        Initialize encryption handler with a session key.
        
        Args:
            session_key (bytes): 32-byte key for AES-256
        
        Raises:
            ValueError: If key size is incorrect
        """
        if len(session_key) != self.KEY_SIZE:
            raise ValueError(f"Invalid key size. Expected {self.KEY_SIZE} bytes, got {len(session_key)}")
        
        self.session_key = session_key
        print(f"[✓] Initialized {self.ALGORITHM} with {len(session_key)*8}-bit key")
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext message using AES-256-CBC.
        
        Process:
        1. Generate random IV
        2. Pad plaintext to block size
        3. Create cipher with IV
        4. Encrypt padded plaintext
        5. Return IV + ciphertext (IV needed for decryption)
        
        Args:
            plaintext (bytes): Message to encrypt
        
        Returns:
            tuple: (iv, ciphertext)
        """
        try:
            # Ensure plaintext is bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate random IV for this message
            iv = get_random_bytes(self.IV_SIZE)
            
            # Create cipher in CBC mode
            cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
            
            # Pad plaintext to block size (required for CBC mode)
            padded_plaintext = pad(plaintext, self.BLOCK_SIZE)
            
            # Encrypt
            ciphertext = cipher.encrypt(padded_plaintext)
            
            print(f"[✓] Message encrypted with {self.ALGORITHM}")
            print(f"    Plaintext size: {len(plaintext)} bytes")
            print(f"    IV size: {len(iv)} bytes")
            print(f"    Ciphertext size: {len(ciphertext)} bytes")
            
            return iv, ciphertext
        
        except Exception as e:
            print(f"[✗] Encryption error: {e}")
            raise
    
    def decrypt(self, iv, ciphertext):
        """
        Decrypt ciphertext message using AES-256-CBC.
        
        Process:
        1. Create cipher with provided IV
        2. Decrypt ciphertext
        3. Unpad plaintext
        4. Return plaintext
        
        Args:
            iv (bytes): Initialization vector (16 bytes)
            ciphertext (bytes): Encrypted message
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If decryption fails or padding is invalid
        """
        try:
            if len(iv) != self.IV_SIZE:
                raise ValueError(f"Invalid IV size. Expected {self.IV_SIZE} bytes, got {len(iv)}")
            
            # Create cipher with same IV
            cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
            
            # Decrypt
            padded_plaintext = cipher.decrypt(ciphertext)
            
            # Remove padding
            plaintext = unpad(padded_plaintext, self.BLOCK_SIZE)
            
            print(f"[✓] Message decrypted with {self.ALGORITHM}")
            print(f"    Ciphertext size: {len(ciphertext)} bytes")
            print(f"    Plaintext size: {len(plaintext)} bytes")
            
            return plaintext
        
        except ValueError as e:
            if "Unpadding error" in str(e):
                print(f"[✗] Padding validation failed - possible corruption or wrong key")
            else:
                print(f"[✗] Decryption error: {e}")
            raise
        
        except Exception as e:
            print(f"[✗] Unexpected error during decryption: {e}")
            raise
    
    def encrypt_message(self, plaintext):
        """
        Encrypt message and return combined IV+ciphertext.
        
        Args:
            plaintext (str or bytes): Message to encrypt
        
        Returns:
            bytes: IV concatenated with ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        iv, ciphertext = self.encrypt(plaintext)
        
        # Combine IV and ciphertext for transmission
        # IV is always 16 bytes, so receiver knows where to split
        combined = iv + ciphertext
        return combined
    
    def decrypt_message(self, combined_data):
        """
        Decrypt message from combined IV+ciphertext format.
        
        Args:
            combined_data (bytes): IV (16 bytes) + ciphertext
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If combined_data is too short
        """
        if len(combined_data) < self.IV_SIZE + self.BLOCK_SIZE:
            raise ValueError(f"Message too short. Minimum size is {self.IV_SIZE + self.BLOCK_SIZE} bytes")
        
        # Extract IV (first 16 bytes)
        iv = combined_data[:self.IV_SIZE]
        
        # Extract ciphertext (rest)
        ciphertext = combined_data[self.IV_SIZE:]
        
        # Decrypt
        plaintext = self.decrypt(iv, ciphertext)
        
        return plaintext
    
    def get_key_info(self):
        """
        Get information about the current session key.
        
        Returns:
            dict: Key information
        """
        return {
            'algorithm': self.ALGORITHM,
            'key_size_bits': len(self.session_key) * 8,
            'block_size': self.BLOCK_SIZE,
            'iv_size': self.IV_SIZE,
            'key_fingerprint': self.session_key[:8].hex().upper()
        }
    
    @staticmethod
    def validate_key(key):
        """
        Validate a key before using it for encryption.
        
        Args:
            key (bytes): Key to validate
        
        Returns:
            bool: True if valid
        
        Raises:
            ValueError: If key is invalid
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be bytes")
        
        if len(key) != SymmetricEncryption.KEY_SIZE:
            raise ValueError(f"Invalid key size. Expected {SymmetricEncryption.KEY_SIZE} bytes, got {len(key)}")
        
        return True


class StreamEncryption:
    """
    Helper class for streaming encryption of large messages.
    """
    
    def __init__(self, session_key):
        """Initialize with session key."""
        self.session_key = session_key
        SymmetricEncryption.validate_key(session_key)
    
    def encrypt_stream(self, data_chunks):
        """
        Encrypt data in chunks.
        
        Args:
            data_chunks (list): List of data chunks
        
        Returns:
            bytes: Combined encrypted data
        """
        enc = SymmetricEncryption(self.session_key)
        iv, ciphertext = enc.encrypt(b''.join(data_chunks))
        return iv + ciphertext
    
    def decrypt_stream(self, encrypted_data):
        """
        Decrypt data and return as chunks.
        
        Args:
            encrypted_data (bytes): Combined IV + ciphertext
        
        Returns:
            bytes: Decrypted data
        """
        enc = SymmetricEncryption(self.session_key)
        return enc.decrypt_message(encrypted_data)
