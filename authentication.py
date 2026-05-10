"""
Hashing and Authentication Module
Handles SHA-256 hashing for integrity and HMAC for authentication
"""

import hmac
import hashlib
from datetime import datetime


class Hashing:
    """
    Manages SHA-256 hashing for message integrity verification.
    
    SHA-256:
    - Output: 256 bits (32 bytes)
    - One-way function: cannot reverse
    - Collision resistant: infeasible to find two messages with same hash
    - Used to: detect message tampering
    """
    
    ALGORITHM = "SHA-256"
    HASH_SIZE = 32  # 256 bits / 8
    
    @staticmethod
    def compute_hash(message):
        """
        Compute SHA-256 hash of a message.
        
        Args:
            message (bytes or str): Message to hash
        
        Returns:
            bytes: 32-byte SHA-256 hash
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            hash_obj = hashlib.sha256(message)
            hash_value = hash_obj.digest()
            
            print(f"[✓] SHA-256 hash computed")
            print(f"    Message size: {len(message)} bytes")
            print(f"    Hash: {hash_value.hex()[:16].upper()}...")
            
            return hash_value
        
        except Exception as e:
            print(f"[✗] Error computing hash: {e}")
            raise
    
    @staticmethod
    def verify_hash(message, provided_hash):
        """
        Verify message integrity by comparing hashes.
        
        Args:
            message (bytes or str): Message to verify
            provided_hash (bytes): Hash to compare against
        
        Returns:
            bool: True if hashes match, False otherwise
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            computed_hash = Hashing.compute_hash(message)
            
            # Use constant-time comparison to prevent timing attacks
            result = hmac.compare_digest(computed_hash, provided_hash)
            
            if result:
                print(f"[✓] Hash verification PASSED")
            else:
                print(f"[✗] Hash verification FAILED - Message may have been tampered!")
            
            return result
        
        except Exception as e:
            print(f"[✗] Error verifying hash: {e}")
            return False
    
    @staticmethod
    def get_hash_info():
        """
        Get information about the hashing algorithm.
        
        Returns:
            dict: Algorithm information
        """
        return {
            'algorithm': Hashing.ALGORITHM,
            'hash_size_bits': Hashing.HASH_SIZE * 8,
            'hash_size_bytes': Hashing.HASH_SIZE
        }


class Authentication:
    """
    Manages HMAC-SHA256 for message authentication.
    
    HMAC (Hash-based Message Authentication Code):
    - Uses: Secret key + hash function
    - Output: 256 bits (32 bytes)
    - Proves: Message came from claimed sender (has the secret key)
    - Different from hash: Requires knowledge of secret key
    """
    
    ALGORITHM = "HMAC-SHA256"
    MAC_SIZE = 32  # 256 bits / 8
    
    @staticmethod
    def compute_hmac(message, session_key):
        """
        Compute HMAC-SHA256 of a message.
        
        Args:
            message (bytes or str): Message to authenticate
            session_key (bytes): Shared secret key (should be random & strong)
        
        Returns:
            bytes: 32-byte HMAC
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            if not isinstance(session_key, bytes):
                raise ValueError("Session key must be bytes")
            
            # Compute HMAC
            mac = hmac.new(session_key, message, hashlib.sha256)
            mac_value = mac.digest()
            
            print(f"[✓] HMAC-SHA256 computed")
            print(f"    Message size: {len(message)} bytes")
            print(f"    Key size: {len(session_key)} bytes")
            print(f"    HMAC: {mac_value.hex()[:16].upper()}...")
            
            return mac_value
        
        except Exception as e:
            print(f"[✗] Error computing HMAC: {e}")
            raise
    
    @staticmethod
    def verify_hmac(message, provided_hmac, session_key):
        """
        Verify message authentication using HMAC.
        
        Only someone with the session_key can compute matching HMAC.
        
        Args:
            message (bytes or str): Message to verify
            provided_hmac (bytes): HMAC to compare against
            session_key (bytes): Shared secret key
        
        Returns:
            bool: True if HMAC matches, False otherwise
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            if not isinstance(session_key, bytes):
                raise ValueError("Session key must be bytes")
            
            # Compute expected HMAC
            computed_hmac = Authentication.compute_hmac(message, session_key)
            
            # Use constant-time comparison to prevent timing attacks
            result = hmac.compare_digest(computed_hmac, provided_hmac)
            
            if result:
                print(f"[✓] HMAC verification PASSED")
            else:
                print(f"[✗] HMAC verification FAILED - Message not authentic!")
            
            return result
        
        except Exception as e:
            print(f"[✗] Error verifying HMAC: {e}")
            return False
    
    @staticmethod
    def compute_hmac_with_timestamp(message, session_key, timestamp=None):
        """
        Compute HMAC including timestamp to prevent replay attacks.
        
        Args:
            message (bytes or str): Message to authenticate
            session_key (bytes): Shared secret key
            timestamp (int): Unix timestamp (uses current time if None)
        
        Returns:
            tuple: (hmac_value, timestamp)
        """
        if timestamp is None:
            timestamp = int(datetime.now().timestamp())
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Include timestamp in HMAC computation
        message_with_timestamp = message + str(timestamp).encode('utf-8')
        
        mac = hmac.new(session_key, message_with_timestamp, hashlib.sha256)
        mac_value = mac.digest()
        
        return mac_value, timestamp
    
    @staticmethod
    def verify_hmac_with_timestamp(message, provided_hmac, session_key, timestamp, max_age_seconds=300):
        """
        Verify HMAC including timestamp.
        
        Args:
            message (bytes or str): Message to verify
            provided_hmac (bytes): HMAC to compare against
            session_key (bytes): Shared secret key
            timestamp (int): Unix timestamp from message
            max_age_seconds (int): Maximum age of message in seconds
        
        Returns:
            bool: True if HMAC matches and message is fresh
        """
        try:
            # Check message age
            current_time = int(datetime.now().timestamp())
            message_age = current_time - timestamp
            
            if message_age > max_age_seconds:
                print(f"[✗] Message too old: {message_age} seconds old (max {max_age_seconds}s)")
                return False
            
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Reconstruct message with timestamp
            message_with_timestamp = message + str(timestamp).encode('utf-8')
            
            # Compute expected HMAC
            mac = hmac.new(session_key, message_with_timestamp, hashlib.sha256)
            computed_hmac = mac.digest()
            
            # Constant-time comparison
            result = hmac.compare_digest(computed_hmac, provided_hmac)
            
            if result:
                print(f"[✓] HMAC verification PASSED (message age: {message_age}s)")
            else:
                print(f"[✗] HMAC verification FAILED")
            
            return result
        
        except Exception as e:
            print(f"[✗] Error verifying HMAC with timestamp: {e}")
            return False
    
    @staticmethod
    def get_hmac_info():
        """
        Get information about the HMAC algorithm.
        
        Returns:
            dict: Algorithm information
        """
        return {
            'algorithm': Authentication.ALGORITHM,
            'mac_size_bits': Authentication.MAC_SIZE * 8,
            'mac_size_bytes': Authentication.MAC_SIZE,
            'hash_function': 'SHA-256'
        }


class MessageIntegrity:
    """
    Combined integrity and authentication verification.
    
    Uses both SHA-256 (integrity) and HMAC (authentication) for complete protection.
    """
    
    @staticmethod
    def protect_message(plaintext, session_key):
        """
        Add integrity (hash) and authentication (HMAC) to a message.
        
        Args:
            plaintext (bytes or str): Message to protect
            session_key (bytes): Session key for HMAC
        
        Returns:
            dict: Contains hash, hmac, and timestamp
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Compute hash for integrity
        msg_hash = Hashing.compute_hash(plaintext)
        
        # Compute HMAC for authentication
        msg_hmac = Authentication.compute_hmac(plaintext, session_key)
        
        # Timestamp for replay attack prevention
        timestamp = int(datetime.now().timestamp())
        
        return {
            'hash': msg_hash,
            'hmac': msg_hmac,
            'timestamp': timestamp
        }
    
    @staticmethod
    def verify_message(plaintext, protection_data, session_key, max_age_seconds=300):
        """
        Verify both integrity and authentication of a message.
        
        Args:
            plaintext (bytes or str): Received plaintext message
            protection_data (dict): Hash, HMAC, and timestamp from sender
            session_key (bytes): Session key for HMAC
            max_age_seconds (int): Maximum message age
        
        Returns:
            bool: True if both integrity and authentication verified
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        print(f"\n[*] Verifying message integrity and authentication...")
        
        # Verify hash (integrity)
        hash_valid = Hashing.verify_hash(plaintext, protection_data['hash'])
        
        if not hash_valid:
            print(f"[✗] Message failed integrity check!")
            return False
        
        # Verify HMAC with timestamp (authentication + freshness)
        hmac_valid = Authentication.verify_hmac_with_timestamp(
            plaintext,
            protection_data['hmac'],
            session_key,
            protection_data['timestamp'],
            max_age_seconds
        )
        
        if not hmac_valid:
            print(f"[✗] Message failed authentication check!")
            return False
        
        print(f"[✓] Message integrity and authentication verified!")
        return True
