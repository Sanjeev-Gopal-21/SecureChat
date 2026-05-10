"""
Comprehensive Test Suite for Secure Chat Application
Tests encryption, key exchange, authentication, and integration
"""

import unittest
import os
import tempfile
from key_exchange import KeyExchange, generate_session_key
from encryption import SymmetricEncryption
from authentication import Hashing, Authentication, MessageIntegrity
from message_protocol import Message, MessageType, ChatMessage


class TestKeyExchange(unittest.TestCase):
    """Test RSA key exchange functionality."""
    
    def setUp(self):
        """Create temporary directory for test keys."""
        self.test_dir = tempfile.mkdtemp()
        self.key_exchange = KeyExchange("test_user", key_dir=self.test_dir)
    
    def tearDown(self):
        """Cleanup test keys."""
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_generate_keypair(self):
        """Test RSA key pair generation."""
        public_pem, private_pem = self.key_exchange.generate_keypair()
        
        # Verify keys are in PEM format
        self.assertIn("-----BEGIN PUBLIC KEY-----", public_pem)
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", private_pem)
        
        # Verify keys exist on disk
        self.assertTrue(os.path.exists(
            os.path.join(self.test_dir, "test_user_private.pem")
        ))
        self.assertTrue(os.path.exists(
            os.path.join(self.test_dir, "test_user_public.pem")
        ))
    
    def test_load_keys(self):
        """Test loading previously generated keys."""
        # Generate keys first
        self.key_exchange.generate_keypair()
        
        # Create new instance and load
        key_exchange2 = KeyExchange("test_user", key_dir=self.test_dir)
        result = key_exchange2.load_keys()
        
        self.assertTrue(result)
        self.assertIsNotNone(key_exchange2.private_key)
        self.assertIsNotNone(key_exchange2.public_key)
    
    def test_validate_keys(self):
        """Test key validation."""
        self.key_exchange.generate_keypair()
        result = self.key_exchange.validate_keys()
        self.assertTrue(result)
    
    def test_session_key_encryption_decryption(self):
        """Test encrypting and decrypting a session key."""
        # Setup two users
        alice = KeyExchange("alice", key_dir=self.test_dir)
        bob = KeyExchange("bob", key_dir=self.test_dir)
        
        alice.generate_keypair()
        bob.generate_keypair()
        
        # Generate session key
        session_key = generate_session_key()
        
        # Alice encrypts session key with Bob's public key
        encrypted = alice.encrypt_session_key(
            session_key,
            bob.get_public_key_pem()
        )
        
        # Bob decrypts with his private key
        decrypted = bob.decrypt_session_key(encrypted)
        
        # Verify they match
        self.assertEqual(session_key, decrypted)
    
    def test_session_key_cannot_decrypt_with_wrong_key(self):
        """Test that session key cannot be decrypted with wrong key."""
        alice = KeyExchange("alice", key_dir=self.test_dir)
        bob = KeyExchange("bob", key_dir=self.test_dir)
        charlie = KeyExchange("charlie", key_dir=self.test_dir)
        
        alice.generate_keypair()
        bob.generate_keypair()
        charlie.generate_keypair()
        
        # Alice encrypts with Bob's key
        session_key = generate_session_key()
        encrypted = alice.encrypt_session_key(
            session_key,
            bob.get_public_key_pem()
        )
        
        # Charlie tries to decrypt (should fail)
        with self.assertRaises(Exception):
            charlie.decrypt_session_key(encrypted)


class TestEncryption(unittest.TestCase):
    """Test AES-256-CBC encryption."""
    
    def setUp(self):
        """Setup test encryption."""
        self.session_key = generate_session_key()
        self.enc = SymmetricEncryption(self.session_key)
    
    def test_encrypt_decrypt(self):
        """Test encrypting and decrypting a message."""
        plaintext = b"Hello, secure world!"
        
        # Encrypt
        iv, ciphertext = self.enc.encrypt(plaintext)
        
        # Verify IV is random each time
        iv2, ciphertext2 = self.enc.encrypt(plaintext)
        self.assertNotEqual(iv, iv2)
        
        # Decrypt
        decrypted = self.enc.decrypt(iv, ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_string(self):
        """Test encrypting string plaintext."""
        plaintext = "Hello, secure world!"
        
        iv, ciphertext = self.enc.encrypt(plaintext)
        decrypted = self.enc.decrypt(iv, ciphertext)
        
        self.assertEqual(plaintext.encode('utf-8'), decrypted)
    
    def test_decrypt_with_wrong_key(self):
        """Test that decryption fails with wrong key."""
        plaintext = b"Secret message"
        
        # Encrypt with session_key
        iv, ciphertext = self.enc.encrypt(plaintext)
        
        # Try decrypt with different key
        wrong_key = generate_session_key()
        wrong_enc = SymmetricEncryption(wrong_key)
        
        with self.assertRaises(ValueError):
            wrong_enc.decrypt(iv, ciphertext)
    
    def test_encrypt_message_decrypt_message(self):
        """Test combined IV+ciphertext format."""
        plaintext = "Test message with IV+ciphertext"
        
        combined = self.enc.encrypt_message(plaintext)
        decrypted = self.enc.decrypt_message(combined)
        
        self.assertEqual(plaintext.encode('utf-8'), decrypted)
    
    def test_tampered_ciphertext_detection(self):
        """Test that tampered ciphertext is detected."""
        plaintext = b"Important message"
        
        iv, ciphertext = self.enc.encrypt(plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] = tampered[-1] ^ 0xFF  # Flip last byte
        
        # Decryption should fail
        with self.assertRaises(ValueError):
            self.enc.decrypt(iv, bytes(tampered))


class TestHashing(unittest.TestCase):
    """Test SHA-256 hashing."""
    
    def test_compute_hash(self):
        """Test SHA-256 hash computation."""
        message = b"Test message"
        hash_value = Hashing.compute_hash(message)
        
        # Verify hash size (SHA-256 = 32 bytes)
        self.assertEqual(len(hash_value), 32)
    
    def test_hash_consistency(self):
        """Test that same message produces same hash."""
        message = b"Consistent message"
        hash1 = Hashing.compute_hash(message)
        hash2 = Hashing.compute_hash(message)
        
        self.assertEqual(hash1, hash2)
    
    def test_hash_sensitivity(self):
        """Test that different messages produce different hashes."""
        hash1 = Hashing.compute_hash(b"Message A")
        hash2 = Hashing.compute_hash(b"Message B")
        
        self.assertNotEqual(hash1, hash2)
    
    def test_hash_string_input(self):
        """Test hashing string input."""
        message = "String message"
        hash_value = Hashing.compute_hash(message)
        
        self.assertEqual(len(hash_value), 32)
    
    def test_verify_hash(self):
        """Test hash verification."""
        message = b"Verify this message"
        hash_value = Hashing.compute_hash(message)
        
        # Should verify successfully
        result = Hashing.verify_hash(message, hash_value)
        self.assertTrue(result)
    
    def test_verify_tampered_hash(self):
        """Test that tampered hash fails verification."""
        message = b"Check integrity"
        correct_hash = Hashing.compute_hash(message)
        
        # Tamper with hash
        tampered_hash = bytearray(correct_hash)
        tampered_hash[0] = tampered_hash[0] ^ 0xFF
        
        # Verification should fail
        result = Hashing.verify_hash(message, bytes(tampered_hash))
        self.assertFalse(result)


class TestAuthentication(unittest.TestCase):
    """Test HMAC-SHA256 authentication."""
    
    def setUp(self):
        """Setup test HMAC."""
        self.session_key = generate_session_key()
    
    def test_compute_hmac(self):
        """Test HMAC computation."""
        message = b"Authenticate this"
        hmac_value = Authentication.compute_hmac(message, self.session_key)
        
        # Verify HMAC size (256 bits = 32 bytes)
        self.assertEqual(len(hmac_value), 32)
    
    def test_hmac_consistency(self):
        """Test HMAC consistency."""
        message = b"Same message"
        hmac1 = Authentication.compute_hmac(message, self.session_key)
        hmac2 = Authentication.compute_hmac(message, self.session_key)
        
        self.assertEqual(hmac1, hmac2)
    
    def test_verify_hmac(self):
        """Test HMAC verification."""
        message = b"Verify authenticity"
        hmac_value = Authentication.compute_hmac(message, self.session_key)
        
        result = Authentication.verify_hmac(message, hmac_value, self.session_key)
        self.assertTrue(result)
    
    def test_verify_hmac_wrong_key(self):
        """Test HMAC verification with wrong key."""
        message = b"Wrong key test"
        hmac_value = Authentication.compute_hmac(message, self.session_key)
        
        # Compute HMAC with different key
        wrong_key = generate_session_key()
        result = Authentication.verify_hmac(message, hmac_value, wrong_key)
        
        self.assertFalse(result)
    
    def test_verify_tampered_message(self):
        """Test HMAC fails for tampered message."""
        message = b"Original message"
        hmac_value = Authentication.compute_hmac(message, self.session_key)
        
        # Tamper with message
        tampered = b"Tampered message"
        result = Authentication.verify_hmac(tampered, hmac_value, self.session_key)
        
        self.assertFalse(result)


class TestMessageIntegrity(unittest.TestCase):
    """Test combined integrity and authentication."""
    
    def setUp(self):
        """Setup test data."""
        self.session_key = generate_session_key()
    
    def test_protect_and_verify_message(self):
        """Test protecting and verifying a message."""
        plaintext = b"Protected message"
        
        # Protect
        protection = MessageIntegrity.protect_message(plaintext, self.session_key)
        
        # Verify
        result = MessageIntegrity.verify_message(
            plaintext,
            protection,
            self.session_key
        )
        
        self.assertTrue(result)
    
    def test_verify_fails_tampered_message(self):
        """Test verification fails for tampered message."""
        plaintext = b"Original"
        protection = MessageIntegrity.protect_message(plaintext, self.session_key)
        
        # Tamper message
        tampered = b"Tampered"
        result = MessageIntegrity.verify_message(
            tampered,
            protection,
            self.session_key
        )
        
        self.assertFalse(result)


class TestMessageProtocol(unittest.TestCase):
    """Test message serialization/deserialization."""
    
    def test_message_serialize_deserialize(self):
        """Test message serialization and deserialization."""
        msg = Message(
            msg_type=MessageType.MESSAGE,
            payload=b"Test payload"
        )
        
        # Serialize
        serialized = msg.serialize()
        
        # Deserialize
        deserialized = Message.deserialize(serialized)
        
        # Verify
        self.assertEqual(msg.msg_type, deserialized.msg_type)
        self.assertEqual(msg.payload, deserialized.payload)
    
    def test_message_with_security_data(self):
        """Test message with hash, HMAC, IV."""
        payload = b"Secure payload"
        msg_hash = b"A" * 32
        hmac_value = b"B" * 32
        iv = b"C" * 16
        
        msg = Message(
            msg_type=MessageType.MESSAGE,
            payload=payload,
            msg_hash=msg_hash,
            hmac_value=hmac_value,
            iv=iv
        )
        
        # Serialize and deserialize
        serialized = msg.serialize()
        deserialized = Message.deserialize(serialized)
        
        # Verify all fields
        self.assertEqual(msg_hash, deserialized.msg_hash)
        self.assertEqual(hmac_value, deserialized.hmac_value)
        self.assertEqual(iv, deserialized.iv)
    
    def test_message_checksum_validation(self):
        """Test message checksum validation."""
        msg = Message(
            msg_type=MessageType.MESSAGE,
            payload=b"Checksum test"
        )
        
        serialized = msg.serialize()
        
        # Tamper with data (but not checksum)
        tampered = bytearray(serialized)
        tampered[20] = tampered[20] ^ 0xFF  # Flip a bit in payload
        
        # Deserialization should detect tampering
        with self.assertRaises(ValueError):
            Message.deserialize(bytes(tampered))


class TestIntegration(unittest.TestCase):
    """Integration tests for full message flow."""
    
    def setUp(self):
        """Setup for integration tests."""
        self.test_dir = tempfile.mkdtemp()
        
        # Setup two users
        self.alice = KeyExchange("alice", key_dir=self.test_dir)
        self.bob = KeyExchange("bob", key_dir=self.test_dir)
        
        self.alice.generate_keypair()
        self.bob.generate_keypair()
        
        # Exchange and establish session key
        self.session_key = generate_session_key()
        encrypted_for_bob = self.alice.encrypt_session_key(
            self.session_key,
            self.bob.get_public_key_pem()
        )
        decrypted_key = self.bob.decrypt_session_key(encrypted_for_bob)
        
        # Both should have same session key
        self.assertEqual(self.session_key, decrypted_key)
        
        # Setup encryption with session key
        self.enc_alice = SymmetricEncryption(self.session_key)
        self.enc_bob = SymmetricEncryption(decrypted_key)
    
    def tearDown(self):
        """Cleanup."""
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_full_message_flow(self):
        """Test complete message flow with encryption and authentication."""
        # Alice's side: create and encrypt message
        plaintext = "Hello Bob, this is secret!"
        
        # Add integrity protection
        protection = MessageIntegrity.protect_message(
            plaintext.encode('utf-8'),
            self.session_key
        )
        
        # Encrypt
        iv, ciphertext = self.enc_alice.encrypt(plaintext)
        
        # Create message
        chat_msg = ChatMessage.create(
            iv + ciphertext,
            protection['hash'],
            protection['hmac'],
            iv
        )
        
        serialized = chat_msg.serialize()
        
        # Transmit (simulated)
        received_data = serialized
        
        # Bob's side: receive and decrypt
        deserialized = Message.deserialize(received_data)
        content = ChatMessage.extract_content(deserialized)
        
        # Extract IV and ciphertext
        iv_received = content['iv']
        ciphertext_received = content['encrypted_content'][len(content['iv']):]
        
        # Decrypt
        decrypted = self.enc_bob.decrypt(iv_received, ciphertext_received)
        
        # Verify
        is_valid = MessageIntegrity.verify_message(
            decrypted,
            {
                'hash': content['hash'],
                'hmac': content['hmac'],
                'timestamp': content['timestamp']
            },
            self.session_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(plaintext.encode('utf-8'), decrypted)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == '__main__':
    run_tests()
