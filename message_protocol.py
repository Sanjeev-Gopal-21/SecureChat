"""
Message Protocol Module
All payloads are JSON so the server can read routing (from/to) without
needing any cryptographic material.
"""

import struct
import json
import zlib
import base64
from datetime import datetime


class MessageType:
    KEY_EXCHANGE = 1
    SESSION_KEY  = 2
    MESSAGE      = 3
    ACK          = 4
    DISCONNECT   = 5


class Message:
    """
    Binary framing:
      [1B] type | [4B] payload_len | [4B] timestamp |
      [32B] hash_field | [32B] hmac_field | [16B] iv_field |
      [NB] payload | [4B] CRC32
    Total fixed overhead = 93 bytes  (MIN_MESSAGE_SIZE)
    """

    HEADER_SIZE    = 1 + 4 + 4
    HASH_SIZE      = 32
    HMAC_SIZE      = 32
    IV_SIZE        = 16
    CHECKSUM_SIZE  = 4
    MIN_MESSAGE_SIZE = HEADER_SIZE + HASH_SIZE + HMAC_SIZE + IV_SIZE + CHECKSUM_SIZE  # 93

    def __init__(self, msg_type, payload,
                 timestamp=None, msg_hash=None, hmac_value=None, iv=None):
        self.msg_type   = msg_type
        self.payload    = payload if isinstance(payload, bytes) else payload.encode('utf-8')
        self.timestamp  = timestamp or int(datetime.now().timestamp())
        self.msg_hash   = msg_hash   or b'\x00' * self.HASH_SIZE
        self.hmac_value = hmac_value or b'\x00' * self.HMAC_SIZE
        self.iv         = iv         or b'\x00' * self.IV_SIZE

    def serialize(self):
        buf  = struct.pack('<B', self.msg_type)
        buf += struct.pack('<I', len(self.payload))
        buf += struct.pack('<I', self.timestamp)
        buf += self.msg_hash
        buf += self.hmac_value
        buf += self.iv
        buf += self.payload
        buf += struct.pack('<I', zlib.crc32(buf) & 0xFFFFFFFF)
        return buf

    @staticmethod
    def deserialize(data):
        if len(data) < Message.MIN_MESSAGE_SIZE:
            raise ValueError(
                f"Message too short: need {Message.MIN_MESSAGE_SIZE}B, got {len(data)}B")

        offset = 0
        msg_type    = struct.unpack('<B', data[offset:offset+1])[0];  offset += 1
        payload_len = struct.unpack('<I', data[offset:offset+4])[0];  offset += 4
        timestamp   = struct.unpack('<I', data[offset:offset+4])[0];  offset += 4
        msg_hash    = data[offset:offset+Message.HASH_SIZE];          offset += Message.HASH_SIZE
        hmac_value  = data[offset:offset+Message.HMAC_SIZE];          offset += Message.HMAC_SIZE
        iv          = data[offset:offset+Message.IV_SIZE];             offset += Message.IV_SIZE

        if len(data) < offset + payload_len + Message.CHECKSUM_SIZE:
            raise ValueError("Incomplete message data")

        payload      = data[offset:offset+payload_len]; offset += payload_len
        recv_crc     = struct.unpack('<I', data[offset:offset+4])[0]
        calc_crc     = zlib.crc32(data[:offset]) & 0xFFFFFFFF

        if recv_crc != calc_crc:
            raise ValueError(f"Checksum mismatch! Expected {calc_crc}, got {recv_crc}")

        return Message(msg_type, payload, timestamp, msg_hash, hmac_value, iv)

    def json_payload(self):
        """Parse payload as JSON (used for all message types in this project)."""
        return json.loads(self.payload.decode('utf-8'))

    def __repr__(self):
        types = {1:'KEY_EXCHANGE',2:'SESSION_KEY',3:'MESSAGE',4:'ACK',5:'DISCONNECT'}
        return f"Message(type={types.get(self.msg_type,self.msg_type)}, payload={len(self.payload)}B)"


# ─── helper factories ─────────────────────────────────────────────────────────

class KeyExchangeMessage:
    """
    Payload JSON: {"from": str, "to": str, "public_key": str(PEM)}
    """
    @staticmethod
    def create(sender, target, public_key_pem):
        payload = json.dumps({
            "from":       sender,
            "to":         target,
            "public_key": public_key_pem,
        }).encode('utf-8')
        return Message(MessageType.KEY_EXCHANGE, payload)

    @staticmethod
    def parse(msg):
        return msg.json_payload()   # keys: from, to, public_key


class SessionKeyMessage:
    """
    Payload JSON: {"from": str, "to": str, "encrypted_key": base64str}
    """
    @staticmethod
    def create(sender, target, encrypted_key_bytes):
        payload = json.dumps({
            "from":          sender,
            "to":            target,
            "encrypted_key": base64.b64encode(encrypted_key_bytes).decode(),
        }).encode('utf-8')
        return Message(MessageType.SESSION_KEY, payload)

    @staticmethod
    def parse(msg):
        d = msg.json_payload()
        d['encrypted_key'] = base64.b64decode(d['encrypted_key'])
        return d   # keys: from, to, encrypted_key(bytes)


class ChatMessage:
    """
    Payload JSON: {
      "from": str, "to": str,
      "iv": b64, "ciphertext": b64,
      "hash": b64, "hmac": b64,
      "timestamp": int
    }
    """
    @staticmethod
    def create(sender, target, iv, ciphertext, msg_hash, hmac_val, timestamp):
        payload = json.dumps({
            "from":       sender,
            "to":         target,
            "iv":         base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "hash":       base64.b64encode(msg_hash).decode(),
            "hmac":       base64.b64encode(hmac_val).decode(),
            "timestamp":  timestamp,
        }).encode('utf-8')
        msg = Message(MessageType.MESSAGE, payload)
        msg.msg_hash   = msg_hash
        msg.hmac_value = hmac_val
        msg.iv         = iv
        return msg

    @staticmethod
    def parse(msg):
        d = msg.json_payload()
        d['iv']         = base64.b64decode(d['iv'])
        d['ciphertext'] = base64.b64decode(d['ciphertext'])
        d['hash']       = base64.b64decode(d['hash'])
        d['hmac']       = base64.b64decode(d['hmac'])
        return d   # keys: from, to, iv, ciphertext, hash, hmac, timestamp


class ControlMessage:
    @staticmethod
    def create_ack(recipient_id):
        payload = json.dumps({"ack_for": recipient_id}).encode('utf-8')
        return Message(MessageType.ACK, payload)

    @staticmethod
    def create_disconnect(sender):
        payload = json.dumps({"from": sender}).encode('utf-8')
        return Message(MessageType.DISCONNECT, payload)
