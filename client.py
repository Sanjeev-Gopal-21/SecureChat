"""
Secure Chat Client — fully working hybrid-encryption chat client.

Fixed bugs vs original:
  1. KEY_EXCHANGE now includes from/to routing → server can relay correctly.
  2. Server response (target's public key) is properly received and stored
     → /session no longer fails with "Remote public key not set".
  3. SESSION_KEY includes from/to routing → server relays to recipient.
  4. Incoming SESSION_KEY is decrypted and stored automatically.
  5. Chat messages include from/to routing → server relays to recipient.
  6. Incoming messages are decrypted and verified correctly (JSON payload).
  7. HMAC mismatch fixed in authentication.py (protect uses timestamp HMAC).
  8. self.running=True set before interactive_chat starts (race condition fixed).
  9. Recv buffer properly handles TCP fragmentation and mixed JSON/binary data.
 10. Logging configured per-instance without polluting root logger.
"""

import socket
import threading
import json
import struct
import uuid
import logging
import os
import base64
from datetime import datetime

from key_exchange  import KeyExchange, generate_session_key
from encryption    import SymmetricEncryption
from authentication import MessageIntegrity
from message_protocol import (Message, MessageType,
                               KeyExchangeMessage, SessionKeyMessage,
                               ChatMessage, ControlMessage)


class ChatClient:
    def __init__(self, username, host='localhost', port=5000):
        self.username       = username
        self.host           = host
        self.port           = port
        self.client_id      = str(uuid.uuid4())[:8]

        # crypto
        self.key_exchange   = KeyExchange(username)
        self.symmetric_enc  = None
        self.session_key    = None

        # peer
        self.remote_public_key = None   # RSA key object
        self.remote_username   = None

        # network
        self.socket    = None
        self.connected = False
        self.running   = False          # set True before interactive_chat

        os.makedirs('logs', exist_ok=True)
        self.logger = self._make_logger()

    # ── logging ───────────────────────────────────────────────────────────────
    def _make_logger(self):
        log = logging.getLogger(f'Client_{self.username}_{self.client_id}')
        log.setLevel(logging.INFO)
        if not log.handlers:
            fh = logging.FileHandler(f'logs/client_{self.username}.log')
            fh.setFormatter(logging.Formatter(
                f'[{self.username}] %(asctime)s - %(message)s'))
            log.addHandler(fh)
        return log

    # ── setup & connect ───────────────────────────────────────────────────────
    def setup_encryption(self):
        print(f"\n[*] Setting up encryption for {self.username}...")
        if not self.key_exchange.load_keys():
            self.key_exchange.generate_keypair()
        if not self.key_exchange.validate_keys():
            raise RuntimeError("Key validation failed!")
        print(f"[✓] Encryption setup complete")

    def connect_to_server(self):
        try:
            print(f"\n[*] Connecting to server at {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"[✓] Connected to server")
            self.logger.info(f"Connected to {self.host}:{self.port}")

            # Send handshake (JSON line)
            handshake = json.dumps(
                {'username': self.username, 'client_id': self.client_id}
            ) + '\n'
            self.socket.sendall(handshake.encode('utf-8'))

            # Start background receiver BEFORE interactive_chat
            self.running = True
            t = threading.Thread(target=self._recv_loop, daemon=True)
            t.start()
            return True

        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            self.logger.error(f"Connection failed: {e}")
            return False

    # ── key exchange ──────────────────────────────────────────────────────────
    def exchange_keys_with_remote(self, remote_username):
        """
        Send our public key to the server, tagged with from/to so the server
        can (a) relay it to the target and (b) send the target's key back to us.
        """
        try:
            print(f"\n[*] Initiating key exchange with {remote_username}...")
            self.remote_username = remote_username

            msg = KeyExchangeMessage.create(
                sender         = self.username,
                target         = remote_username,
                public_key_pem = self.key_exchange.get_public_key_pem()
            )
            self.socket.sendall(msg.serialize())
            print(f"[✓] Public key sent to server (routed to {remote_username})")

        except Exception as e:
            print(f"[✗] Key exchange failed: {e}")
            self.logger.error(f"Key exchange error: {e}")

    # ── session key ───────────────────────────────────────────────────────────
    def establish_session_key(self, remote_username=None):
        """
        Generate AES-256 session key, encrypt with remote's RSA public key,
        send to server — server relays to remote.
        Call AFTER remote_public_key has been received from the key exchange.
        """
        if remote_username:
            self.remote_username = remote_username

        if self.remote_public_key is None:
            print("[!] Remote public key not yet received. "
                  "Wait for key exchange to complete first.")
            return False

        try:
            print(f"\n[*] Establishing session key with {self.remote_username}...")
            self.session_key = generate_session_key()

            encrypted = self.key_exchange.encrypt_session_key(
                self.session_key,
                self.remote_public_key.export_key('PEM').decode('utf-8')
            )

            msg = SessionKeyMessage.create(
                sender             = self.username,
                target             = self.remote_username,
                encrypted_key_bytes= encrypted
            )
            self.socket.sendall(msg.serialize())

            self.symmetric_enc = SymmetricEncryption(self.session_key)
            print(f"[✓] Session key sent to {self.remote_username}")
            print(f"[✓] AES-256 encryption READY — you can now send messages")
            self.logger.info(f"Session key established with {self.remote_username}")
            return True

        except Exception as e:
            print(f"[!] Session key establishment failed: {e}")
            self.logger.error(f"Session key error: {e}")
            return False

    # ── send message ──────────────────────────────────────────────────────────
    def send_message(self, plaintext_str):
        if not self.connected:
            print("[!] Not connected to server")
            return False
        if self.symmetric_enc is None:
            print("[!] No session established. Use /session <username> first.")
            return False
        if not self.remote_username:
            print("[!] No remote user set. Use /remote <username> first.")
            return False

        try:
            plaintext = plaintext_str.encode('utf-8')

            # Integrity + authentication
            protection = MessageIntegrity.protect_message(plaintext, self.session_key)

            # Encrypt
            iv, ciphertext = self.symmetric_enc.encrypt(plaintext)

            # Build and send
            msg = ChatMessage.create(
                sender    = self.username,
                target    = self.remote_username,
                iv        = iv,
                ciphertext= ciphertext,
                msg_hash  = protection['hash'],
                hmac_val  = protection['hmac'],
                timestamp = protection['timestamp'],
            )
            self.socket.sendall(msg.serialize())
            print(f"[✓] Encrypted message sent to {self.remote_username}")
            self.logger.info(f"Message sent to {self.remote_username}")
            return True

        except Exception as e:
            print(f"[!] Send error: {e}")
            self.logger.error(f"Send error: {e}")
            return False

    # ── receiver loop ─────────────────────────────────────────────────────────
    def _recv_loop(self):
        buf = b''
        while self.running and self.connected:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    self.connected = False
                    print("\n[!] Connection closed by server")
                    return
                buf += chunk

                while buf:
                    # JSON line from server (online-users broadcast)?
                    if buf[0:1] == b'{':
                        nl = buf.find(b'\n')
                        if nl == -1:
                            break   # incomplete — wait for more
                        self._on_json(buf[:nl])
                        buf = buf[nl+1:]
                        continue

                    # Binary Message packet
                    if len(buf) < Message.MIN_MESSAGE_SIZE:
                        break
                    payload_len = struct.unpack('<I', buf[1:5])[0]
                    full_size   = Message.MIN_MESSAGE_SIZE + payload_len
                    if len(buf) < full_size:
                        break

                    packet = buf[:full_size]
                    buf    = buf[full_size:]

                    try:
                        msg = Message.deserialize(packet)
                        self._dispatch(msg)
                    except Exception as e:
                        self.logger.error(f"Deserialize error: {e}")

            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                if self.running:
                    print(f"\n[!] Connection lost: {e}")
                self.connected = False
                return
            except Exception as e:
                if self.running:
                    self.logger.error(f"Recv error: {e}")

    def _dispatch(self, msg):
        if   msg.msg_type == MessageType.KEY_EXCHANGE: self._on_key_exchange(msg)
        elif msg.msg_type == MessageType.SESSION_KEY:  self._on_session_key(msg)
        elif msg.msg_type == MessageType.MESSAGE:      self._on_message(msg)
        elif msg.msg_type == MessageType.ACK:
            self.logger.info("ACK received")
        else:
            self.logger.warning(f"Unknown msg type: {msg.msg_type}")

    # ── incoming KEY_EXCHANGE ─────────────────────────────────────────────────
    def _on_key_exchange(self, msg):
        """Receive the remote user's public key from the server."""
        try:
            data   = KeyExchangeMessage.parse(msg)
            sender = data['from']
            if sender == self.username:
                return   # echo of own key — ignore
            pub_key_pem = data['public_key']
            self.remote_public_key = self.key_exchange.import_public_key(pub_key_pem)
            if not self.remote_username:
                self.remote_username = sender
            print(f"\n[✓] Received public key from {sender}")
            print(f"    You can now run:  /session {sender}")
            print(f"[{self.username}] > ", end='', flush=True)
        except Exception as e:
            self.logger.error(f"Key exchange receive error: {e}")

    # ── incoming SESSION_KEY ──────────────────────────────────────────────────
    def _on_session_key(self, msg):
        """Receive and decrypt the RSA-encrypted AES session key."""
        try:
            data           = SessionKeyMessage.parse(msg)
            sender         = data['from']
            encrypted_key  = data['encrypted_key']

            self.session_key = self.key_exchange.decrypt_session_key(encrypted_key)
            self.symmetric_enc = SymmetricEncryption(self.session_key)

            if not self.remote_username:
                self.remote_username = sender
            print(f"\n[✓] Session key received from {sender}")
            print(f"[✓] AES-256 encryption READY — you can now send messages")
            print(f"[{self.username}] > ", end='', flush=True)
            self.logger.info(f"Session key received from {sender}")
        except Exception as e:
            self.logger.error(f"Session key receive error: {e}")
            print(f"\n[!] Failed to receive session key: {e}")
            print(f"[{self.username}] > ", end='', flush=True)

    # ── incoming MESSAGE ──────────────────────────────────────────────────────
    def _on_message(self, msg):
        """Decrypt, verify, and display an incoming encrypted message."""
        try:
            if self.symmetric_enc is None:
                print("\n[!] Received message but no session established")
                return

            data       = ChatMessage.parse(msg)
            sender     = data['from']
            iv         = data['iv']
            ciphertext = data['ciphertext']
            protection = {
                'hash':      data['hash'],
                'hmac':      data['hmac'],
                'timestamp': data['timestamp'],
            }

            # Decrypt
            plaintext = self.symmetric_enc.decrypt(iv, ciphertext)

            # Verify integrity + authentication
            if not MessageIntegrity.verify_message(plaintext, protection, self.session_key):
                print(f"\n[✗] Message from {sender} FAILED verification — discarded!")
                print(f"[{self.username}] > ", end='', flush=True)
                return

            print(f"\n{sender}: {plaintext.decode('utf-8')}")
            print(f"[{self.username}] > ", end='', flush=True)
            self.logger.info(f"Message received from {sender}")

        except Exception as e:
            self.logger.error(f"Message receive error: {e}")
            print(f"\n[!] Error receiving message: {e}")
            print(f"[{self.username}] > ", end='', flush=True)

    # ── JSON control messages (online users broadcast) ────────────────────────
    def _on_json(self, data: bytes):
        try:
            payload = json.loads(data.decode('utf-8'))
            if payload.get('type') == 'online_users':
                names = [u['username'] for u in payload.get('users', [])]
                print(f"\n[*] Online users: {', '.join(names) if names else 'none'}")
                print(f"[{self.username}] > ", end='', flush=True)
        except Exception as e:
            self.logger.error(f"JSON parse error: {e}")

    # ── interactive loop ──────────────────────────────────────────────────────
    def interactive_chat(self):
        print(f"\n{'='*50}")
        print(f"  Secure Chat — {self.username}")
        print(f"{'='*50}")
        print("Commands:")
        print("  /key <user>     — exchange public keys")
        print("  /session <user> — establish encrypted session")
        print("  /remote <user>  — set chat partner")
        print("  /status         — show current status")
        print("  /quit           — exit")
        print(f"{'='*50}\n")

        while self.running:
            try:
                line = input(f"[{self.username}] > ").strip()
                if not line:
                    continue
                if line.startswith('/'):
                    self._command(line)
                else:
                    self.send_message(line)
            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                break
            except EOFError:
                break
            except Exception as e:
                print(f"[!] Error: {e}")

    def _command(self, line):
        parts = line.split()
        cmd   = parts[0].lower()

        if cmd == '/key' and len(parts) > 1:
            self.exchange_keys_with_remote(parts[1])

        elif cmd == '/session' and len(parts) > 1:
            self.establish_session_key(parts[1])

        elif cmd == '/remote' and len(parts) > 1:
            self.remote_username = parts[1]
            print(f"[✓] Remote user set to: {self.remote_username}")

        elif cmd == '/status':
            print(f"\n{'─'*40}")
            print(f"  User      : {self.username} ({self.client_id})")
            print(f"  Connected : {self.connected}")
            print(f"  Remote    : {self.remote_username or 'not set'}")
            rk = "received ✓" if self.remote_public_key else "not received"
            print(f"  Remote key: {rk}")
            sk = "established ✓" if self.session_key else "not established"
            print(f"  Session   : {sk}")
            print(f"{'─'*40}\n")

        elif cmd == '/quit':
            print("[*] Exiting...")
            self.running = False
            self.disconnect()

        else:
            print(f"[!] Unknown command. Try /key, /session, /remote, /status, /quit")

    def disconnect(self):
        try:
            if self.socket and self.connected:
                disc = ControlMessage.create_disconnect(self.username)
                try: self.socket.sendall(disc.serialize())
                except: pass
                self.socket.close()
            self.connected = False
            self.running   = False
            print("[✓] Disconnected from server")
            self.logger.info("Disconnected")
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")


def main():
    import argparse
    p = argparse.ArgumentParser(description='Secure Chat Client')
    p.add_argument('--username', required=True)
    p.add_argument('--host',    default='localhost')
    p.add_argument('--port',    type=int, default=5000)
    args = p.parse_args()

    client = ChatClient(args.username, args.host, args.port)
    try:
        client.setup_encryption()
        if not client.connect_to_server():
            return
        client.interactive_chat()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
