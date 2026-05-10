"""
Secure Chat Client
Handles encryption, decryption, and secure communication with server
"""

import socket
import threading
import json
import uuid
import logging
import time
from datetime import datetime

from key_exchange import KeyExchange, generate_session_key
from encryption import SymmetricEncryption
from authentication import Hashing, Authentication, MessageIntegrity
from message_protocol import Message, MessageType, KeyExchangeMessage, SessionKeyMessage, ChatMessage


class ChatClient:
    """
    Secure chat client with hybrid encryption.
    
    Protocol flow:
    1. Connect to server
    2. Generate RSA-2048 key pair
    3. Exchange public keys with other clients
    4. Generate and exchange AES-256 session key
    5. Exchange encrypted messages
    """
    
    def __init__(self, username, host='localhost', port=5000):
        """
        Initialize chat client.
        
        Args:
            username (str): Username for this client
            host (str): Server host
            port (int): Server port
        """
        self.username = username
        self.host = host
        self.port = port
        self.client_id = str(uuid.uuid4())[:8]
        
        # Cryptography components
        self.key_exchange = KeyExchange(username)
        self.symmetric_enc = None
        self.session_key = None
        
        # Remote user information
        self.remote_public_key = None
        self.remote_username = None
        
        # Connection
        self.socket = None
        self.connected = False
        self.running = False
        
        # Setup logging
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging for client."""
        logging.basicConfig(
            level=logging.INFO,
            format=f'[{self.username}] %(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(f'client_{self.username}.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(f'ChatClient_{self.username}')
    
    def setup_encryption(self):
        """
        Setup cryptography for this client.
        
        Generates RSA key pair if not exists.
        """
        print(f"\n[*] Setting up encryption for {self.username}...")
        
        # Try to load existing keys
        if not self.key_exchange.load_keys():
            # Generate new keys
            self.key_exchange.generate_keypair()
        
        # Validate keys
        if not self.key_exchange.validate_keys():
            raise Exception("Key validation failed!")
        
        print(f"[✓] Encryption setup complete")
    
    def connect_to_server(self):
        """
        Connect to the chat server.
        
        Returns:
            bool: True if connection successful
        """
        try:
            print(f"\n[*] Connecting to server at {self.host}:{self.port}...")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            print(f"[✓] Connected to server")
            self.logger.info(f"Connected to server at {self.host}:{self.port}")
            
            # Send client info to server
            client_info = {
                'username': self.username,
                'client_id': self.client_id
            }
            self.socket.sendall(json.dumps(client_info).encode('utf-8'))
            
            # Start message receiver thread
            receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
            receiver_thread.start()
            
            return True
        
        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def exchange_keys_with_remote(self, remote_username):
        """
        Exchange public keys with a remote user.
        
        Args:
            remote_username (str): Username of remote user
        
        Returns:
            bool: True if key exchange successful
        """
        try:
            print(f"\n[*] Initiating key exchange with {remote_username}...")
            
            # Send own public key to server
            public_key_pem = self.key_exchange.get_public_key_pem()
            key_msg = KeyExchangeMessage.create(public_key_pem)
            
            self.socket.sendall(key_msg.serialize())
            print(f"[✓] Public key sent to server")
            
            # For this demo, we'll manually handle receiving remote's key
            # In production, server would relay this
            self.remote_username = remote_username
            
            return True
        
        except Exception as e:
            print(f"[✗] Key exchange failed: {e}")
            self.logger.error(f"Key exchange error: {e}")
            return False
    
    def set_remote_public_key(self, remote_public_key_pem):
        """
        Set the remote user's public key.
        
        Args:
            remote_public_key_pem (str): Remote public key in PEM format
        """
        try:
            self.remote_public_key = self.key_exchange.import_public_key(remote_public_key_pem)
            print(f"[✓] Remote public key received and validated")
        except Exception as e:
            print(f"[✗] Error setting remote public key: {e}")
            raise
    
    def establish_session_key(self):
        """
        Establish AES-256 session key with remote user.
        
        Process:
        1. Generate random session key
        2. Encrypt with remote's public key
        3. Send to server
        4. Server relays to remote
        """
        if self.remote_public_key is None:
            raise ValueError("Remote public key not set. Exchange keys first.")
        
        try:
            print(f"\n[*] Establishing session key with {self.remote_username}...")
            
            # Generate random session key
            self.session_key = generate_session_key()
            
            # Encrypt with remote's public key
            encrypted_key = self.key_exchange.encrypt_session_key(
                self.session_key,
                self.remote_public_key.export_key('PEM').decode('utf-8')
            )
            
            # Create and send session key message
            session_msg = SessionKeyMessage.create(encrypted_key)
            self.socket.sendall(session_msg.serialize())
            
            # Setup symmetric encryption
            self.symmetric_enc = SymmetricEncryption(self.session_key)
            
            print(f"[✓] Session key established and ready for encrypted messaging")
            self.logger.info(f"Session key established with {self.remote_username}")
            
        except Exception as e:
            print(f"[✗] Session key establishment failed: {e}")
            self.logger.error(f"Session key error: {e}")
            raise
    
    def receive_session_key(self, encrypted_session_key):
        """
        Receive and decrypt session key from remote user.
        
        Args:
            encrypted_session_key (bytes): RSA-encrypted session key
        """
        try:
            print(f"\n[*] Receiving session key from {self.remote_username}...")
            
            # Decrypt with own private key
            self.session_key = self.key_exchange.decrypt_session_key(encrypted_session_key)
            
            # Setup symmetric encryption
            self.symmetric_enc = SymmetricEncryption(self.session_key)
            
            print(f"[✓] Session key received and decrypted")
            self.logger.info(f"Session key received from {self.remote_username}")
        
        except Exception as e:
            print(f"[✗] Session key reception failed: {e}")
            self.logger.error(f"Session key reception error: {e}")
            raise
    
    def send_message(self, plaintext):
        """
        Send an encrypted, authenticated message.
        
        Process:
        1. Compute SHA-256 hash (integrity)
        2. Compute HMAC-SHA256 (authentication)
        3. Encrypt with AES-256-CBC
        4. Create message packet
        5. Send to server
        
        Args:
            plaintext (str): Message to send
        
        Returns:
            bool: True if send successful
        """
        if self.symmetric_enc is None:
            print(f"[✗] Session not established. Establish session key first.")
            return False
        
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            print(f"\n[*] Encrypting and sending message...")
            
            # Compute integrity and authentication
            protection = MessageIntegrity.protect_message(plaintext, self.session_key)
            
            # Encrypt message
            iv, ciphertext = self.symmetric_enc.encrypt(plaintext)
            
            # Create chat message
            chat_msg = ChatMessage.create(
                iv + ciphertext,  # Combined IV + ciphertext
                protection['hash'],
                protection['hmac'],
                iv
            )
            
            # Serialize and send
            serialized = chat_msg.serialize()
            self.socket.sendall(serialized)
            
            print(f"[✓] Message sent ({len(serialized)} bytes)")
            self.logger.info(f"Message sent to {self.remote_username} ({len(serialized)} bytes)")
            
            return True
        
        except Exception as e:
            print(f"[✗] Error sending message: {e}")
            self.logger.error(f"Send error: {e}")
            return False
    
    def _receive_messages(self):
        """
        Background thread for receiving messages from server.
        """
        self.running = True
        
        while self.running and self.connected:
            try:
                # Receive message header first (at least 100 bytes)
                data = b''
                while len(data) < Message.MIN_MESSAGE_SIZE:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        self.connected = False
                        print(f"\n[!] Connection closed by server")
                        return
                    data += chunk
                
                # Deserialize
                msg = Message.deserialize(data)
                
                # Handle based on type
                if msg.msg_type == MessageType.MESSAGE:
                    self._handle_received_message(msg)
                elif msg.msg_type == MessageType.KEY_EXCHANGE:
                    self._handle_key_exchange_message(msg)
                elif msg.msg_type == MessageType.SESSION_KEY:
                    self._handle_session_key_message(msg)
                elif msg.msg_type == MessageType.ACK:
                    print(f"[✓] Acknowledgement received")
            
            except Exception as e:
                if self.running:
                    self.logger.error(f"Receive error: {e}")
                    # Don't print error for normal disconnection
                    if "Connection" not in str(e):
                        print(f"[!] Error receiving: {e}")
    
    def _handle_received_message(self, msg):
        """Handle received chat message."""
        try:
            if self.symmetric_enc is None:
                print(f"[!] Received message but session not established")
                return
            
            content = ChatMessage.extract_content(msg)
            
            print(f"\n[*] Decrypting received message...")
            
            # Decrypt
            plaintext = self.symmetric_enc.decrypt(
                content['iv'],
                content['encrypted_content'][len(content['iv']):]
            )
            
            # Verify integrity and authentication
            if not MessageIntegrity.verify_message(plaintext, content, self.session_key):
                print(f"[✗] Message verification failed - ignoring message!")
                return
            
            # Display message
            print(f"\n{self.remote_username}: {plaintext.decode('utf-8')}")
            print(f"[{self.username}] > ", end='', flush=True)
        
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
            print(f"[!] Error handling received message: {e}")
    
    def _handle_key_exchange_message(self, msg):
        """Handle key exchange message."""
        try:
            remote_key_pem = KeyExchangeMessage.extract_public_key(msg)
            self.set_remote_public_key(remote_key_pem)
            print(f"\n[✓] Remote public key received")
        except Exception as e:
            self.logger.error(f"Key exchange message error: {e}")
    
    def _handle_session_key_message(self, msg):
        """Handle session key message."""
        try:
            encrypted_key = SessionKeyMessage.extract_encrypted_key(msg)
            self.receive_session_key(encrypted_key)
        except Exception as e:
            self.logger.error(f"Session key message error: {e}")
    
    def interactive_chat(self):
        """
        Interactive chat loop for user input.
        """
        print(f"\n{'='*50}")
        print(f"  Secure Chat - {self.username}")
        print(f"{'='*50}")
        print(f"Commands:")
        print(f"  /key <username>     - Exchange keys")
        print(f"  /session <username> - Establish session (after key exchange)")
        print(f"  /remote <username>  - Set remote user")
        print(f"  /status             - Show status")
        print(f"  /quit               - Exit")
        print(f"{'='*50}\n")
        
        while self.running:
            try:
                user_input = input(f"[{self.username}] > ").strip()
                
                if not user_input:
                    continue
                
                if user_input.startswith('/'):
                    self._handle_command(user_input)
                else:
                    # Send message
                    self.send_message(user_input)
            
            except KeyboardInterrupt:
                print(f"\n[*] Chat interrupted")
                break
            except EOFError:
                break
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def _handle_command(self, command):
        """Handle user commands."""
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == '/key' and len(parts) > 1:
            remote_user = parts[1]
            self.exchange_keys_with_remote(remote_user)
        
        elif cmd == '/session' and len(parts) > 1:
            remote_user = parts[1]
            self.remote_username = remote_user
            try:
                self.establish_session_key()
            except Exception as e:
                print(f"[!] Session establishment failed: {e}")
        
        elif cmd == '/remote' and len(parts) > 1:
            self.remote_username = parts[1]
            print(f"[✓] Remote user set to: {self.remote_username}")
        
        elif cmd == '/status':
            self._show_status()
        
        elif cmd == '/quit':
            print(f"[*] Exiting...")
            self.running = False
            self.disconnect()
        
        else:
            print(f"[!] Unknown command: {cmd}")
    
    def _show_status(self):
        """Show client status."""
        print(f"\n{'─'*40}")
        print(f"Status: {self.username} ({self.client_id})")
        print(f"Connected: {self.connected}")
        print(f"Remote User: {self.remote_username or 'Not set'}")
        print(f"Session Established: {self.session_key is not None}")
        if self.session_key:
            print(f"Session Key: {self.session_key[:8].hex().upper()}...")
        print(f"{'─'*40}\n")
    
    def disconnect(self):
        """Disconnect from server."""
        try:
            if self.socket:
                self.socket.close()
            self.connected = False
            self.running = False
            print(f"[✓] Disconnected from server")
            self.logger.info("Disconnected from server")
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")


def main():
    """Main client entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Chat Client')
    parser.add_argument('--username', required=True, help='Your username')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    
    args = parser.parse_args()
    
    # Create client
    client = ChatClient(args.username, args.host, args.port)
    
    try:
        # Setup encryption
        client.setup_encryption()
        
        # Connect to server
        if not client.connect_to_server():
            return
        
        # Start interactive chat
        client.interactive_chat()
    
    except KeyboardInterrupt:
        print(f"\n[!] Client interrupted")
    except Exception as e:
        print(f"[✗] Error: {e}")
    
    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
