"""
Message Protocol Module
Defines message structure and serialization/deserialization
"""

import struct
import json
from datetime import datetime


class MessageType:
    """Message type constants."""
    KEY_EXCHANGE = 1
    SESSION_KEY = 2
    MESSAGE = 3
    ACK = 4
    DISCONNECT = 5


class Message:
    """
    Represents a secure message with encryption, integrity, and authentication.
    
    Message Structure (Binary):
    [1 byte]   Message Type
    [4 bytes]  Payload Length (little-endian)
    [4 bytes]  Timestamp (unix timestamp)
    [32 bytes] SHA-256 Hash
    [32 bytes] HMAC
    [16 bytes] IV (AES initialization vector)
    [N bytes]  Encrypted Payload
    [4 bytes]  Checksum (CRC32)
    """
    
    HEADER_SIZE = 1 + 4 + 4  # Type (1) + Length (4) + Timestamp (4)
    HASH_SIZE = 32  # SHA-256
    HMAC_SIZE = 32  # HMAC-SHA256
    IV_SIZE = 16   # AES IV
    CHECKSUM_SIZE = 4  # CRC32
    
    MIN_MESSAGE_SIZE = HEADER_SIZE + HASH_SIZE + HMAC_SIZE + IV_SIZE + CHECKSUM_SIZE
    
    def __init__(self, msg_type, payload, timestamp=None, msg_hash=None, hmac_value=None, iv=None, checksum=None):
        """
        Initialize a message.
        
        Args:
            msg_type (int): Message type constant
            payload (bytes): Message payload (encrypted)
            timestamp (int): Unix timestamp (auto-generated if None)
            msg_hash (bytes): SHA-256 hash of original message
            hmac_value (bytes): HMAC of original message
            iv (bytes): AES initialization vector
            checksum (int): CRC32 checksum of entire message
        """
        self.msg_type = msg_type
        self.payload = payload if isinstance(payload, bytes) else payload.encode('utf-8')
        self.timestamp = timestamp or int(datetime.now().timestamp())
        self.msg_hash = msg_hash or b'\x00' * self.HASH_SIZE
        self.hmac_value = hmac_value or b'\x00' * self.HMAC_SIZE
        self.iv = iv or b'\x00' * self.IV_SIZE
        self.checksum = checksum or 0
    
    def serialize(self):
        """
        Serialize message to binary format.
        
        Returns:
            bytes: Serialized message
        """
        try:
            payload_length = len(self.payload)
            
            # Build message
            message = b''
            
            # Header: Type + Length + Timestamp
            message += struct.pack('<B', self.msg_type)  # 1 byte
            message += struct.pack('<I', payload_length)  # 4 bytes, little-endian
            message += struct.pack('<I', self.timestamp)  # 4 bytes, little-endian
            
            # Security info
            message += self.msg_hash  # 32 bytes
            message += self.hmac_value  # 32 bytes
            message += self.iv  # 16 bytes
            
            # Payload
            message += self.payload  # N bytes
            
            # Checksum (calculated on entire message so far)
            checksum = self._calculate_checksum(message)
            message += struct.pack('<I', checksum)  # 4 bytes, little-endian
            
            print(f"[✓] Message serialized")
            print(f"    Type: {self.msg_type}")
            print(f"    Payload size: {payload_length} bytes")
            print(f"    Total size: {len(message)} bytes")
            
            return message
        
        except Exception as e:
            print(f"[✗] Error serializing message: {e}")
            raise
    
    @staticmethod
    def deserialize(data):
        """
        Deserialize binary message back to Message object.
        
        Args:
            data (bytes): Serialized message
        
        Returns:
            Message: Deserialized message object
        
        Raises:
            ValueError: If message format is invalid
        """
        try:
            if len(data) < Message.MIN_MESSAGE_SIZE:
                raise ValueError(f"Message too short. Minimum {Message.MIN_MESSAGE_SIZE} bytes, got {len(data)}")
            
            offset = 0
            
            # Parse header
            msg_type = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            
            payload_length = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            timestamp = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse security info
            msg_hash = data[offset:offset+Message.HASH_SIZE]
            offset += Message.HASH_SIZE
            
            hmac_value = data[offset:offset+Message.HMAC_SIZE]
            offset += Message.HMAC_SIZE
            
            iv = data[offset:offset+Message.IV_SIZE]
            offset += Message.IV_SIZE
            
            # Parse payload
            if len(data) < offset + payload_length + Message.CHECKSUM_SIZE:
                raise ValueError(f"Incomplete message data")
            
            payload = data[offset:offset+payload_length]
            offset += payload_length
            
            # Parse checksum
            provided_checksum = struct.unpack('<I', data[offset:offset+Message.CHECKSUM_SIZE])[0]
            
            # Verify checksum
            message_data = data[:offset]
            calculated_checksum = Message._calculate_checksum(message_data)
            
            if calculated_checksum != provided_checksum:
                raise ValueError(f"Checksum mismatch! Expected {calculated_checksum}, got {provided_checksum}")
            
            print(f"[✓] Message deserialized")
            print(f"    Type: {msg_type}")
            print(f"    Payload size: {payload_length} bytes")
            print(f"    Total size: {len(data)} bytes")
            
            return Message(msg_type, payload, timestamp, msg_hash, hmac_value, iv, provided_checksum)
        
        except Exception as e:
            print(f"[✗] Error deserializing message: {e}")
            raise
    
    @staticmethod
    def _calculate_checksum(data):
        """
        Calculate CRC32 checksum of data.
        
        Args:
            data (bytes): Data to checksum
        
        Returns:
            int: CRC32 checksum
        """
        import zlib
        return zlib.crc32(data) & 0xffffffff
    
    def get_type_name(self):
        """Get human-readable message type name."""
        type_names = {
            MessageType.KEY_EXCHANGE: "KEY_EXCHANGE",
            MessageType.SESSION_KEY: "SESSION_KEY",
            MessageType.MESSAGE: "MESSAGE",
            MessageType.ACK: "ACK",
            MessageType.DISCONNECT: "DISCONNECT"
        }
        return type_names.get(self.msg_type, f"UNKNOWN({self.msg_type})")
    
    def __repr__(self):
        """String representation of message."""
        return (f"Message(type={self.get_type_name()}, "
                f"payload_size={len(self.payload)}, "
                f"timestamp={self.timestamp})")


class KeyExchangeMessage:
    """Message for key exchange phase."""
    
    @staticmethod
    def create(public_key_pem):
        """
        Create a key exchange message.
        
        Args:
            public_key_pem (str): Public key in PEM format
        
        Returns:
            Message: Key exchange message
        """
        payload = public_key_pem.encode('utf-8')
        return Message(MessageType.KEY_EXCHANGE, payload)
    
    @staticmethod
    def extract_public_key(message):
        """
        Extract public key from key exchange message.
        
        Args:
            message (Message): Key exchange message
        
        Returns:
            str: Public key in PEM format
        """
        return message.payload.decode('utf-8')


class SessionKeyMessage:
    """Message for encrypted session key transmission."""
    
    @staticmethod
    def create(encrypted_session_key, iv_used_in_message=None):
        """
        Create a session key message.
        
        Args:
            encrypted_session_key (bytes): RSA-encrypted session key
            iv_used_in_message (bytes): Optional IV hint
        
        Returns:
            Message: Session key message
        """
        return Message(MessageType.SESSION_KEY, encrypted_session_key)
    
    @staticmethod
    def extract_encrypted_key(message):
        """
        Extract encrypted session key from message.
        
        Args:
            message (Message): Session key message
        
        Returns:
            bytes: Encrypted session key
        """
        return message.payload


class ChatMessage:
    """Message for actual chat content."""
    
    @staticmethod
    def create(encrypted_content, msg_hash, hmac_value, iv):
        """
        Create a chat message.
        
        Args:
            encrypted_content (bytes): Encrypted message
            msg_hash (bytes): SHA-256 hash of original message
            hmac_value (bytes): HMAC of original message
            iv (bytes): AES IV used for encryption
        
        Returns:
            Message: Chat message
        """
        msg = Message(MessageType.MESSAGE, encrypted_content)
        msg.msg_hash = msg_hash
        msg.hmac_value = hmac_value
        msg.iv = iv
        return msg
    
    @staticmethod
    def extract_content(message):
        """
        Extract encrypted content from chat message.
        
        Args:
            message (Message): Chat message
        
        Returns:
            dict: Contains encrypted_content, hash, hmac, iv
        """
        return {
            'encrypted_content': message.payload,
            'hash': message.msg_hash,
            'hmac': message.hmac_value,
            'iv': message.iv,
            'timestamp': message.timestamp
        }


class ControlMessage:
    """Message for connection control."""
    
    @staticmethod
    def create_ack(message_id):
        """Create an acknowledgement message."""
        payload = f"ACK:{message_id}".encode('utf-8')
        return Message(MessageType.ACK, payload)
    
    @staticmethod
    def create_disconnect():
        """Create a disconnect message."""
        return Message(MessageType.DISCONNECT, b"Goodbye")
    
    @staticmethod
    def extract_ack_id(message):
        """Extract message ID from ACK."""
        return message.payload.decode('utf-8').split(':')[1]


class MessageBuilder:
    """Builder class for creating complex messages."""
    
    def __init__(self, msg_type):
        """Initialize builder with message type."""
        self.msg_type = msg_type
        self.payload = b''
        self.msg_hash = None
        self.hmac_value = None
        self.iv = None
        self.timestamp = None
    
    def with_payload(self, payload):
        """Set message payload."""
        if isinstance(payload, str):
            self.payload = payload.encode('utf-8')
        else:
            self.payload = payload
        return self
    
    def with_hash(self, msg_hash):
        """Set message hash."""
        self.msg_hash = msg_hash
        return self
    
    def with_hmac(self, hmac_value):
        """Set message HMAC."""
        self.hmac_value = hmac_value
        return self
    
    def with_iv(self, iv):
        """Set initialization vector."""
        self.iv = iv
        return self
    
    def with_timestamp(self, timestamp):
        """Set timestamp."""
        self.timestamp = timestamp
        return self
    
    def build(self):
        """Build the message."""
        return Message(
            self.msg_type,
            self.payload,
            self.timestamp,
            self.msg_hash,
            self.hmac_value,
            self.iv
        )
