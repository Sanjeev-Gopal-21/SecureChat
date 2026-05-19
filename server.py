"""
Secure Chat Server
Properly relays: public keys, encrypted session keys, and encrypted messages.
"""

import socket
import threading
import json
import struct
import logging
import os
from datetime import datetime

from message_protocol import Message, MessageType, KeyExchangeMessage, \
    SessionKeyMessage, ChatMessage, ControlMessage


class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000, max_clients=10):
        self.host        = host
        self.port        = port
        self.max_clients = max_clients
        self.clients     = {}   # {client_id: {socket, username, public_key, connected_at}}
        self.lock        = threading.Lock()
        self.running     = False
        self.server_sock = None
        os.makedirs('logs', exist_ok=True)
        self.logger      = self._make_logger()

    # ── logging ───────────────────────────────────────────────────────────────
    def _make_logger(self):
        log = logging.getLogger('ChatServer')
        log.setLevel(logging.INFO)
        if not log.handlers:
            fh = logging.FileHandler('logs/server.log')
            fh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
            log.addHandler(fh)
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
            log.addHandler(sh)
        return log

    # ── helpers ───────────────────────────────────────────────────────────────
    def _client_by_username(self, username):
        """Return (client_id, client_info) for the given username, or (None, None)."""
        with self.lock:
            for cid, info in self.clients.items():
                if info['username'] == username:
                    return cid, info
        return None, None

    def _send_to(self, client_id, data):
        """Thread-safe send; silently ignore if client gone."""
        try:
            with self.lock:
                sock = self.clients[client_id]['socket']
            sock.sendall(data)
        except Exception as e:
            self.logger.warning(f"Send to {client_id} failed: {e}")

    # ── server lifecycle ──────────────────────────────────────────────────────
    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(self.max_clients)
        self.running = True

        print('\n' + '='*50)
        print('  SECURE CHAT SERVER STARTED')
        print('='*50)
        print(f"[✓] Listening on {self.host}:{self.port}")
        print(f"[*] Waiting for connections...\n")
        self.logger.info(f"Server started on {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    client_sock, addr = self.server_sock.accept()
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True)
                    t.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
        finally:
            self.stop()

    def stop(self):
        print("\n[*] Shutting down server...")
        self.running = False
        with self.lock:
            for info in list(self.clients.values()):
                try: info['socket'].close()
                except: pass
        try: self.server_sock.close()
        except: pass
        print("[✓] Server stopped")

    # ── per-client handler ────────────────────────────────────────────────────
    def _handle_client(self, client_sock, addr):
        client_id = None
        username  = None
        try:
            # ── handshake: receive JSON line with username + client_id ─────
            raw = b''
            while b'\n' not in raw and len(raw) < 2048:
                chunk = client_sock.recv(1024)
                if not chunk:
                    return
                raw += chunk
            info      = json.loads(raw.split(b'\n')[0].decode('utf-8'))
            username  = info.get('username',  f'User_{addr[1]}')
            client_id = info.get('client_id', str(addr[1]))

            with self.lock:
                self.clients[client_id] = {
                    'socket':       client_sock,
                    'username':     username,
                    'address':      addr,
                    'connected_at': datetime.now(),
                    'public_key':   None,
                }

            print(f"[+] Connected: {username} ({client_id}) from {addr}")
            self.logger.info(f"{username} connected from {addr}")
            self._broadcast_online_users()

            # ── buffered receive loop ─────────────────────────────────────
            buf = b''
            while self.running:
                try:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk

                    while buf:
                        if len(buf) < Message.MIN_MESSAGE_SIZE:
                            break
                        payload_len = struct.unpack('<I', buf[1:5])[0]
                        full_size   = Message.MIN_MESSAGE_SIZE + payload_len
                        if len(buf) < full_size:
                            break
                        packet = buf[:full_size]
                        buf    = buf[full_size:]
                        self._dispatch(client_id, packet)

                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    break
                except Exception as e:
                    self.logger.error(f"Error from {username}: {e}")
                    break

        except Exception as e:
            self.logger.error(f"Client handler error: {e}")
        finally:
            if client_id and client_id in self.clients:
                with self.lock:
                    del self.clients[client_id]
            try: client_sock.close()
            except: pass
            if username:
                print(f"[-] Disconnected: {username}")
                self.logger.info(f"{username} disconnected")
                self._broadcast_online_users()

    # ── dispatch incoming packets ─────────────────────────────────────────────
    def _dispatch(self, sender_id, raw_packet):
        try:
            msg      = Message.deserialize(raw_packet)
            msg_type = msg.msg_type

            if   msg_type == MessageType.KEY_EXCHANGE: self._on_key_exchange(sender_id, msg, raw_packet)
            elif msg_type == MessageType.SESSION_KEY:  self._on_session_key(sender_id, msg, raw_packet)
            elif msg_type == MessageType.MESSAGE:      self._on_message(sender_id, msg, raw_packet)
            elif msg_type == MessageType.DISCONNECT:   pass   # _handle_client loop exits on empty recv
            elif msg_type == MessageType.ACK:          pass
            else:
                self.logger.warning(f"Unknown type {msg_type} from {sender_id}")
        except Exception as e:
            self.logger.error(f"Dispatch error from {sender_id}: {e}")

    # ── KEY_EXCHANGE ──────────────────────────────────────────────────────────
    def _on_key_exchange(self, sender_id, msg, raw_packet):
        """
        1. Store sender's public key.
        2. Forward sender's public key to the target (if connected).
        3. Send target's public key back to sender (if target already registered theirs).
        """
        try:
            data            = KeyExchangeMessage.parse(msg)
            sender_username = data['from']
            target_username = data['to']
            sender_pub_key  = data['public_key']

            # Store sender's key
            with self.lock:
                if sender_id in self.clients:
                    self.clients[sender_id]['public_key'] = sender_pub_key

            self.logger.info(f"Public key stored for {sender_username}")
            print(f"[KEY] {sender_username} → {target_username}: public key stored")

            # ACK to sender
            ack = ControlMessage.create_ack(sender_id)
            self._send_to(sender_id, ack.serialize())

            # ── relay sender's key to target ──────────────────────────────
            target_id, target_info = self._client_by_username(target_username)
            if target_id:
                self._send_to(target_id, raw_packet)
                print(f"[KEY] Relayed {sender_username}'s key → {target_username}")
            else:
                print(f"[KEY] {target_username} not connected — key not relayed yet")

            # ── send target's existing key back to sender ─────────────────
            if target_id and target_info.get('public_key'):
                reply = KeyExchangeMessage.create(
                    sender   = target_username,
                    target   = sender_username,
                    public_key_pem = target_info['public_key']
                )
                self._send_to(sender_id, reply.serialize())
                print(f"[KEY] Sent {target_username}'s key back → {sender_username}")

        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")

    # ── SESSION_KEY ───────────────────────────────────────────────────────────
    def _on_session_key(self, sender_id, msg, raw_packet):
        """Relay the RSA-encrypted session key to the intended recipient."""
        try:
            data            = msg.json_payload()
            sender_username = data['from']
            target_username = data['to']

            target_id, _ = self._client_by_username(target_username)
            if target_id:
                self._send_to(target_id, raw_packet)
                print(f"[SES] Session key relayed: {sender_username} → {target_username}")
            else:
                print(f"[SES] {target_username} not connected — session key dropped")

            # ACK to sender
            ack = ControlMessage.create_ack(sender_id)
            self._send_to(sender_id, ack.serialize())

        except Exception as e:
            self.logger.error(f"Session key relay error: {e}")

    # ── MESSAGE ───────────────────────────────────────────────────────────────
    def _on_message(self, sender_id, msg, raw_packet):
        """Relay encrypted chat message to the intended recipient."""
        try:
            data            = msg.json_payload()
            sender_username = data['from']
            target_username = data['to']

            target_id, _ = self._client_by_username(target_username)
            if target_id:
                self._send_to(target_id, raw_packet)
                self.logger.info(
                    f"Message relayed: {sender_username} → {target_username} "
                    f"({len(raw_packet)} bytes)")
                print(f"[MSG] {sender_username} → {target_username} ({len(raw_packet)}B)")
            else:
                print(f"[MSG] {target_username} not connected — message dropped")

            # ACK to sender
            ack = ControlMessage.create_ack(sender_id)
            self._send_to(sender_id, ack.serialize())

        except Exception as e:
            self.logger.error(f"Message relay error: {e}")

    # ── broadcast online users (JSON line) ────────────────────────────────────
    def _broadcast_online_users(self):
        try:
            with self.lock:
                users = [
                    {'id': cid, 'username': info['username'],
                     'connected_at': str(info['connected_at'])}
                    for cid, info in self.clients.items()
                ]
            line = (json.dumps({'type': 'online_users', 'users': users,
                                'count': len(users)}) + '\n').encode('utf-8')
            with self.lock:
                sockets = [(cid, info['socket'])
                           for cid, info in self.clients.items()]
            for cid, sock in sockets:
                try:
                    sock.sendall(line)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Broadcast error: {e}")


def main():
    import argparse
    p = argparse.ArgumentParser(description='Secure Chat Server')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=5000)
    args = p.parse_args()

    server = ChatServer(host=args.host, port=args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == '__main__':
    main()
