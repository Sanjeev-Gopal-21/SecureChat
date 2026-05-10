"""
Secure Chat Server
Manages client connections and relays encrypted messages between clients
"""

import socket
import threading
import json
import logging
from datetime import datetime
from collections import defaultdict

from message_protocol import Message, MessageType, KeyExchangeMessage, SessionKeyMessage, ChatMessage, ControlMessage


class ChatServer:
    """
    Secure chat server that manages connections and relays encrypted messages.
    
    Server responsibilities:
    - Accept client connections
    - Manage client registry
    - Relay public keys for key exchange
    - Relay encrypted messages
    - Handle disconnections
    """
    
    def __init__(self, host='0.0.0.0', port=5000, max_clients=10):
        """
        Initialize chat server.
        
        Args:
            host (str): Server host address
            port (int): Server port
            max_clients (int): Maximum concurrent clients
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.server_socket = None
        self.clients = {}  # {client_id: {'socket': socket, 'username': str, 'public_key': str}}
        self.client_sessions = {}  # {(client_a, client_b): session_key}
        self.clients_lock = threading.Lock()
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Server running flag
        self.running = False
    
    def _setup_logging(self):
        """Setup logging for server."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('server.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def start(self):
        """
        Start the chat server.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_clients)
            
            self.running = True
            
            print("\n" + "="*50)
            print("  SECURE CHAT SERVER STARTED")
            print("="*50)
            print(f"[✓] Server listening on {self.host}:{self.port}")
            print(f"[✓] Max clients: {self.max_clients}")
            print(f"[*] Waiting for connections...\n")
            
            self.logger.info(f"Server started on {self.host}:{self.port}")
            
            # Accept connections in a loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
        
        except Exception as e:
            print(f"[✗] Server error: {e}")
            self.logger.error(f"Server error: {e}")
        
        finally:
            self.stop()
    
    def _handle_client(self, client_socket, client_address):
        """
        Handle a connected client.
        
        Args:
            client_socket: Client socket
            client_address: Client address tuple
        """
        client_id = None
        username = None
        
        try:
            # Get initial client info
            data = client_socket.recv(1024).decode('utf-8')
            client_info = json.loads(data)
            
            username = client_info.get('username', f'User_{client_address[1]}')
            client_id = client_info.get('client_id')
            
            # Register client
            with self.clients_lock:
                self.clients[client_id] = {
                    'socket': client_socket,
                    'username': username,
                    'address': client_address,
                    'connected_at': datetime.now(),
                    'public_key': None
                }
            
            print(f"[+] Client Connected: {username} ({client_id}) from {client_address}")
            self.logger.info(f"Client {username} ({client_id}) connected from {client_address}")
            
            # Send list of online users
            self._broadcast_online_users()
            
            # Handle client messages
            while self.running:
                try:
                    # Receive message
                    data = client_socket.recv(4096)
                    
                    if not data:
                        break
                    
                    # Parse message based on first byte (message type)
                    msg_type = data[0]
                    
                    if msg_type == MessageType.KEY_EXCHANGE:
                        self._handle_key_exchange(client_id, data)
                    
                    elif msg_type == MessageType.SESSION_KEY:
                        self._handle_session_key(client_id, data)
                    
                    elif msg_type == MessageType.MESSAGE:
                        self._handle_message(client_id, data)
                    
                    elif msg_type == MessageType.DISCONNECT:
                        print(f"[*] {username} requested disconnect")
                        break
                
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Error handling client {username}: {e}")
                    self.logger.error(f"Error handling {username}: {e}")
                    break
        
        except Exception as e:
            print(f"[!] Error in client handler: {e}")
            self.logger.error(f"Client handler error: {e}")
        
        finally:
            # Cleanup
            if client_id in self.clients:
                with self.clients_lock:
                    del self.clients[client_id]
            
            try:
                client_socket.close()
            except:
                pass
            
            if username:
                print(f"[-] Client Disconnected: {username}")
                self.logger.info(f"Client {username} disconnected")
                self._broadcast_online_users()
    
    def _handle_key_exchange(self, sender_id, data):
        """
        Handle public key exchange.
        
        Args:
            sender_id: Sender client ID
            data: Raw message data
        """
        try:
            msg = Message.deserialize(data)
            public_key_pem = KeyExchangeMessage.extract_public_key(msg)
            
            # Store public key
            with self.clients_lock:
                if sender_id in self.clients:
                    self.clients[sender_id]['public_key'] = public_key_pem
            
            username = self.clients[sender_id]['username']
            print(f"[*] Public key received from {username}")
            self.logger.info(f"Public key stored for {username}")
            
            # Send ACK
            ack_msg = ControlMessage.create_ack(sender_id)
            self.clients[sender_id]['socket'].sendall(ack_msg.serialize())
        
        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")
    
    def _handle_session_key(self, sender_id, data):
        """
        Handle encrypted session key relay.
        
        Args:
            sender_id: Sender client ID
            data: Raw message data
        """
        try:
            msg = Message.deserialize(data)
            
            # In real implementation, this would include recipient info
            # For now, just log it
            self.logger.info(f"Session key exchange initiated by {self.clients[sender_id]['username']}")
            
            # Send ACK
            ack_msg = ControlMessage.create_ack(sender_id)
            self.clients[sender_id]['socket'].sendall(ack_msg.serialize())
        
        except Exception as e:
            self.logger.error(f"Session key error: {e}")
    
    def _handle_message(self, sender_id, data):
        """
        Handle and relay encrypted message.
        
        Args:
            sender_id: Sender client ID
            data: Raw message data
        """
        try:
            msg = Message.deserialize(data)
            
            sender_username = self.clients[sender_id]['username']
            print(f"[→] Relaying message from {sender_username} ({len(data)} bytes)")
            self.logger.info(f"Message received from {sender_username} ({len(data)} bytes)")
            
            # In a real implementation, message would include recipient info
            # For now, we just acknowledge receipt
            ack_msg = ControlMessage.create_ack(sender_id)
            self.clients[sender_id]['socket'].sendall(ack_msg.serialize())
        
        except Exception as e:
            self.logger.error(f"Message handling error: {e}")
    
    def _broadcast_online_users(self):
        """
        Broadcast list of online users to all connected clients.
        """
        try:
            with self.clients_lock:
                online_users = [
                    {
                        'id': client_id,
                        'username': client_info['username'],
                        'connected_at': str(client_info['connected_at'])
                    }
                    for client_id, client_info in self.clients.items()
                ]
            
            users_json = json.dumps({
                'type': 'online_users',
                'users': online_users,
                'count': len(online_users)
            })
            
            # Send to all connected clients
            with self.clients_lock:
                for client_id, client_info in self.clients.items():
                    try:
                        client_info['socket'].sendall(users_json.encode('utf-8') + b'\n')
                    except:
                        pass
        
        except Exception as e:
            self.logger.error(f"Broadcast error: {e}")
    
    def get_client_public_key(self, username):
        """
        Get public key of a client by username.
        
        Args:
            username (str): Username to look up
        
        Returns:
            str: Public key in PEM format or None
        """
        with self.clients_lock:
            for client_info in self.clients.values():
                if client_info['username'] == username:
                    return client_info['public_key']
        return None
    
    def stop(self):
        """Stop the server gracefully."""
        print("\n[*] Shutting down server...")
        self.running = False
        
        with self.clients_lock:
            for client_id, client_info in list(self.clients.items()):
                try:
                    client_info['socket'].close()
                except:
                    pass
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[✓] Server stopped")
        self.logger.info("Server stopped")


def main():
    """Main server entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Chat Server')
    parser.add_argument('--host', default='0.0.0.0', help='Server host')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--max-clients', type=int, default=10, help='Max concurrent clients')
    
    args = parser.parse_args()
    
    server = ChatServer(host=args.host, port=args.port, max_clients=args.max_clients)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server interrupted by user")
        server.stop()


if __name__ == '__main__':
    main()
