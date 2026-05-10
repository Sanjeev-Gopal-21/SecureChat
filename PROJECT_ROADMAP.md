# SECURE CHAT APPLICATION WITH HYBRID CRYPTOGRAPHY
## Complete Implementation Roadmap

---

## PROJECT OVERVIEW

### What We're Building
A secure peer-to-peer chat application that uses hybrid cryptography to protect communications. Users can exchange messages safely using a combination of RSA (asymmetric) encryption for key exchange and AES (symmetric) encryption for actual messages.

### Why Hybrid Cryptography?
- **RSA**: Securely exchanges the session key between parties
- **AES**: Fast encryption of actual messages (much faster than RSA for large data)
- **SHA-256**: Verifies message integrity
- **HMAC**: Authenticates messages (proving they came from who they claim)

---

## PHASE 1: PROJECT SETUP & ARCHITECTURE

### 1.1 Project Structure
```
SecureChatApp/
├── src/
│   ├── crypto/
│   │   ├── encryption.py       # AES encryption/decryption
│   │   ├── key_exchange.py     # RSA key generation & exchange
│   │   ├── hashing.py          # SHA-256 hashing
│   │   └── authentication.py   # HMAC/Digital Signatures
│   ├── network/
│   │   ├── client.py           # Client implementation
│   │   ├── server.py           # Server implementation
│   │   └── message_protocol.py # Message format & serialization
│   ├── utils/
│   │   ├── key_manager.py      # Key storage & management
│   │   └── logger.py           # Logging & error handling
│   └── main.py                 # Entry point
├── tests/
│   ├── test_encryption.py
│   ├── test_key_exchange.py
│   └── test_integration.py
├── keys/                        # Directory for storing keys (gitignore)
├── logs/                        # Directory for logs
├── README.md
└── requirements.txt
```

### 1.2 System Architecture Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                    SECURE CHAT SYSTEM                       │
├──────────────────────────┬──────────────────────────────────┤
│       CLIENT A           │         CLIENT B                 │
├──────────────────────────┼──────────────────────────────────┤
│                          │                                  │
│  1. Generate RSA         │  1. Generate RSA                 │
│     Key Pair             │     Key Pair                     │
│  2. Exchange Public      │  2. Exchange Public              │
│     Keys via Socket      │     Keys via Socket              │
│                          │                                  │
│    ┌──────────────────┐  │  ┌──────────────────┐           │
│    │ KEY EXCHANGE     │  │  │ KEY EXCHANGE     │           │
│    │ (RSA-2048)       │◄─┼─►│ (RSA-2048)       │           │
│    │                  │  │  │                  │           │
│    │ Establish Secure │  │  │ Establish Secure │           │
│    │ Session Key (AES)│  │  │ Session Key (AES)│           │
│    └──────────────────┘  │  └──────────────────┘           │
│           │              │           │                     │
│           ▼              │           ▼                     │
│    ┌──────────────────┐  │  ┌──────────────────┐           │
│    │ MESSAGE ENCRYPT  │  │  │ MESSAGE ENCRYPT  │           │
│    │ & AUTHENTICATE   │  │  │ & AUTHENTICATE   │           │
│    │                  │  │  │                  │           │
│    │ • AES-256-CBC    │  │  │ • AES-256-CBC    │           │
│    │ • SHA-256 Hash   │  │  │ • SHA-256 Hash   │           │
│    │ • HMAC Auth      │  │  │ • HMAC Auth      │           │
│    └──────────────────┘  │  └──────────────────┘           │
│           │              │           │                     │
│           └──────────────┼───────────┘                     │
│                  │       │       │                         │
│            [Encrypted Message + MAC + Hash]               │
│                          │                                 │
│    Secure Socket Connection (TLS-like Protection)         │
│                                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## PHASE 2: CRYPTOGRAPHIC COMPONENTS IMPLEMENTATION

### 2.1 Key Exchange (RSA)
**File: `src/crypto/key_exchange.py`**

**What it does:**
- Generates RSA-2048 key pairs for each client
- Securely exchanges public keys
- Derives a shared session key using the other party's public key

**Implementation Steps:**
1. Generate RSA key pair using PyCryptodome
2. Export public key in PEM format
3. Send public key to other party
4. Receive other party's public key
5. Generate a random session key
6. Encrypt the session key with other party's public key
7. Send encrypted session key

**Key Functions:**
```python
def generate_rsa_keypair(key_size=2048)
    ↓
def export_public_key(public_key)
    ↓
def import_public_key(key_data)
    ↓
def encrypt_session_key(session_key, public_key)
    ↓
def decrypt_session_key(encrypted_key, private_key)
```

### 2.2 Symmetric Encryption (AES)
**File: `src/crypto/encryption.py`**

**What it does:**
- Uses AES-256 in CBC mode for fast message encryption
- Generates random IV for each message
- Encrypts/decrypts actual chat messages

**Implementation Steps:**
1. Accept session key from key exchange
2. Generate random IV for each message
3. Encrypt plaintext message using AES-256-CBC
4. Prepend IV to ciphertext
5. Send to recipient
6. Recipient extracts IV and decrypts

**Key Functions:**
```python
def encrypt_message(plaintext, session_key)
    ↓ Returns: IV + Ciphertext
def decrypt_message(ciphertext_with_iv, session_key)
    ↓ Returns: Plaintext
```

### 2.3 Integrity Verification (SHA-256)
**File: `src/crypto/hashing.py`**

**What it does:**
- Creates SHA-256 hash of messages
- Recipient hashes received message and compares
- Ensures message hasn't been tampered with

**Implementation Steps:**
1. Compute SHA-256 hash of plaintext message
2. Include hash in transmission
3. Recipient computes hash of received plaintext
4. Compare hashes - if different, message was tampered

**Key Functions:**
```python
def compute_hash(message)
    ↓ Returns: SHA-256 hash
def verify_hash(message, provided_hash)
    ↓ Returns: True/False
```

### 2.4 Authentication (HMAC)
**File: `src/crypto/authentication.py`**

**What it does:**
- Uses HMAC-SHA256 to authenticate messages
- Proves message came from claimed sender
- Both parties use shared session key to compute MAC

**Implementation Steps:**
1. Use HMAC-SHA256 with session key
2. Compute MAC of entire message (plaintext + timestamp)
3. Include MAC in transmission
4. Recipient computes MAC and compares
5. If MAC matches, message is authentic

**Key Functions:**
```python
def compute_hmac(message, session_key)
    ↓ Returns: HMAC signature
def verify_hmac(message, provided_hmac, session_key)
    ↓ Returns: True/False
```

---

## PHASE 3: NETWORK IMPLEMENTATION

### 3.1 Message Protocol Design
**File: `src/network/message_protocol.py`**

**Message Structure:**
```
┌─────────────────────────────────────────┐
│  MESSAGE STRUCTURE (Binary Format)      │
├─────────────────────────────────────────┤
│ [1 byte]   Message Type (1=Chat, 2=Key)│
│ [4 bytes]  Payload Length (Little-Endian)
│ [4 bytes]  Timestamp                    │
│ [32 bytes] SHA-256 Hash                 │
│ [32 bytes] HMAC                         │
│ [16 bytes] IV (for AES)                 │
│ [N bytes]  Encrypted Payload            │
│ [4 bytes]  Checksum                     │
└─────────────────────────────────────────┘
Total: Variable (typically 108+ bytes)
```

**Implementation:**
```python
class Message:
    - msg_type: int
    - timestamp: int
    - hash: bytes
    - hmac: bytes
    - iv: bytes
    - ciphertext: bytes
    - checksum: int
    
    serialize() → bytes
    deserialize(data) → Message
```

### 3.2 Server Implementation
**File: `src/network/server.py`**

**Server Responsibilities:**
- Listen for incoming client connections (port 5000)
- Handle client registration
- Relay encrypted messages between clients
- Maintain client list
- Handle client disconnection

**Key Functions:**
```python
class ChatServer:
    def start_server(host, port)
    def accept_connections()
    def handle_client(client_socket, client_address)
    def relay_message(sender_id, recipient_id, message)
    def disconnect_client(client_id)
    def broadcast_online_users()
```

**Server Flow:**
```
Server Start
    ↓
Listen on 0.0.0.0:5000
    ↓
Accept Client A → Ask for username → Store & send online users
    ↓
Accept Client B → Ask for username → Store & send online users
    ↓
Client A wants to chat with B:
    ├─ Client A: "Let's establish secure channel with B"
    ├─ Server: Provides B's public key to A
    ├─ Client A: Sends encrypted session key to B
    ├─ Client B: Accepts & decrypts session key
    ├─ Server: "Channel established"
    └─ Now A & B can exchange encrypted messages via server
```

### 3.3 Client Implementation
**File: `src/network/client.py`**

**Client Responsibilities:**
- Connect to server
- Generate and manage own RSA key pair
- Perform key exchange with other clients
- Encrypt messages before sending
- Decrypt received messages
- Display UI/interface for user

**Key Functions:**
```python
class ChatClient:
    def connect_to_server(host, port)
    def setup_encryption()
    def request_public_key(recipient_username)
    def establish_session_key(recipient_public_key)
    def send_message(recipient_username, plaintext)
    def receive_message()
    def verify_message_integrity(received_message)
    def verify_message_authentication(received_message)
    def display_chat_interface()
```

**Client Flow:**
```
Client Start
    ↓
Generate RSA-2048 key pair
    ↓
Connect to Server:5000
    ↓
Get online users list
    ↓
User enters: "Send message to Bob"
    ↓
Request Bob's public key from server
    ↓
Generate random session key (AES-256)
    ↓
Encrypt session key with Bob's public key
    ↓
Send to server: "Session initiation request"
    ↓
Server relays to Bob
    ↓
Bob decrypts session key → Both now share secret
    ↓
User types: "Hello Bob!"
    ↓
    ├─ Compute SHA-256 hash of message
    ├─ Compute HMAC-SHA256 with session key
    ├─ Encrypt message with AES-256-CBC
    ├─ Generate random IV
    ├─ Package: [Type][Length][Hash][HMAC][IV][Ciphertext][Checksum]
    ├─ Send to server
    │
    ↓ (Server relays to Bob)
    │
Bob receives:
    ├─ Extract all fields
    ├─ Verify checksum
    ├─ Decrypt with session key
    ├─ Verify SHA-256 hash
    ├─ Verify HMAC authentication
    ├─ Display to Bob: "Alice: Hello Bob!"
    └─ Send ACK back
```

---

## PHASE 4: ERROR HANDLING & SECURITY

### 4.1 Error Handling
**File: `src/utils/error_handler.py`**

**Errors to Handle:**
1. **Invalid Keys**
   - Corrupted RSA keys
   - Wrong key format
   - Missing key files
   
2. **Corrupted Ciphertext**
   - Checksum mismatch
   - MAC verification failure
   - Hash mismatch
   - IV extraction failure
   
3. **Connection Failures**
   - Server unreachable
   - Client disconnect
   - Socket timeout
   - Incomplete message receive

**Error Handling Strategy:**
```python
try:
    perform_operation()
except InvalidKeyError:
    Log error & notify user
    Attempt key regeneration
except CiphertextCorruptionError:
    Log error & notify user
    Request message retransmission
except ConnectionError:
    Log error & notify user
    Attempt reconnection
except Exception as e:
    Log unexpected error
    Graceful shutdown
```

### 4.2 Security Best Practices
**File: `src/utils/security.py`**

1. **Key Management**
   - Never print private keys
   - Store keys with restricted permissions (chmod 600)
   - Clear keys from memory after use

2. **Memory Safety**
   - Use `secrets` module for random generation
   - Overwrite sensitive data before deallocation
   - No hardcoded secrets in code

3. **Session Management**
   - Use random session IDs
   - Implement session timeout (30 minutes)
   - Invalidate sessions on logout

4. **Logging**
   - Log all security events (key generation, decryption failures)
   - Never log plaintext messages or keys
   - Use secure logging with limited access

---

## PHASE 5: TESTING STRATEGY

### 5.1 Unit Tests
**File: `tests/test_encryption.py`**

```python
test_aes_encryption_decryption()
    - Encrypt plaintext
    - Decrypt ciphertext
    - Verify plaintext == original
    
test_aes_different_keys_cannot_decrypt()
    - Encrypt with key A
    - Try decrypt with key B
    - Verify failure

test_hash_verification()
    - Compute hash
    - Verify hash matches
    - Tamper with message
    - Verify hash fails

test_hmac_authentication()
    - Compute HMAC with key A
    - Verify with key A (success)
    - Verify with key B (fail)
```

### 5.2 Integration Tests
**File: `tests/test_integration.py`**

```python
test_client_server_key_exchange()
    - Start server
    - Connect client A
    - Connect client B
    - Exchange keys
    - Verify shared session key

test_encrypted_message_transmission()
    - Client A sends message
    - Client B receives
    - Verify decryption correct
    - Verify hash matches
    - Verify HMAC valid

test_message_tampering_detection()
    - Intercept message
    - Modify byte
    - Try to decrypt
    - Verify failure detected
```

---

## PHASE 6: DELIVERABLES PREPARATION

### 6.1 Required Documents

**README.md**
- Installation instructions
- How to run server and clients
- Example usage
- Configuration options
- Troubleshooting

**Security Analysis Report**
- Which algorithms used & why
- Key size justification (RSA-2048, AES-256)
- Security assumptions
- Known limitations
- Future improvements

**System Architecture Diagram**
- Message flow
- Component interactions
- Data flow

### 6.2 Screenshots to Capture
1. Server startup
2. Client A connects
3. Client B connects
4. Key exchange process
5. Message encryption happening
6. Message transmission
7. Message decryption & display
8. Hash verification success
9. HMAC verification success
10. Connection termination

### 6.3 Demo Video Checklist
- [x] Start server
- [x] Connect 2 clients
- [x] Show keys are different (not transmitted)
- [x] Send message from A to B
- [x] Show encryption happening
- [x] Show decryption on B's side
- [x] Demonstrate hash verification
- [x] Attempt tampering & show detection
- [x] Graceful disconnect
- [x] Error handling (invalid input, etc.)

---

## IMPLEMENTATION TIMELINE

### Week 1: Foundation (Days 1-3)
- [ ] Setup project structure
- [ ] Install dependencies
- [ ] Implement RSA key generation
- [ ] Implement AES encryption/decryption
- [ ] Write unit tests

### Week 1-2: Core Crypto (Days 4-7)
- [ ] Implement SHA-256 hashing
- [ ] Implement HMAC authentication
- [ ] Design message protocol
- [ ] Implement message serialization

### Week 2: Networking (Days 8-11)
- [ ] Implement server socket handling
- [ ] Implement client socket handling
- [ ] Implement message relay
- [ ] Test basic connectivity

### Week 2-3: Integration (Days 12-15)
- [ ] Integrate crypto with networking
- [ ] Implement key exchange flow
- [ ] Implement encrypted message transmission
- [ ] Write integration tests

### Week 3: Refinement (Days 16-18)
- [ ] Error handling & validation
- [ ] Security audit
- [ ] Code cleanup & documentation
- [ ] Performance optimization

### Week 3-4: Documentation & Demo (Days 19-21)
- [ ] Write comprehensive README
- [ ] Create architecture diagrams
- [ ] Capture screenshots
- [ ] Record demo video
- [ ] Final testing

---

## MARKING RUBRIC ALIGNMENT

| Requirement | Implementation Strategy | Marks |
|------------|----------------------|-------|
| **Algorithm Correctness** | Unit tests for each crypto function | 6 |
| **Hybrid Crypto Integration** | RSA for key exchange + AES for messages | 5 |
| **Network Simulation** | Full client-server with socket communication | 4 |
| **Security Features** | SHA-256 integrity + HMAC authentication | 4 |
| **Code Quality** | Modular design, docstrings, comments | 3 |
| **Innovation** | Digital signatures option, logging, monitoring | 3 |

---

## KEY FEATURES CHECKLIST

### Mandatory Requirements
- [x] RSA-2048 for key exchange
- [x] AES-256-CBC for encryption
- [x] SHA-256 for integrity
- [x] HMAC for authentication
- [x] Client-server architecture
- [x] Secure key management
- [x] Error handling
- [x] Secure termination

### Extra Features (for full marks)
- [x] Detailed logging system
- [x] Multiple clients support
- [x] Session timeout
- [x] User authentication
- [x] Message timestamps
- [x] Online user list
- [x] Connection retry logic
- [x] Comprehensive test suite

---

## INSTALLATION & QUICK START

```bash
# Clone/extract project
cd SecureChatApp

# Install dependencies
pip install -r requirements.txt

# Terminal 1: Start server
python src/main.py --mode server --port 5000

# Terminal 2: Start client A
python src/main.py --mode client --username Alice --host localhost --port 5000

# Terminal 3: Start client B
python src/main.py --mode client --username Bob --host localhost --port 5000

# In Client A terminal:
> Alice: chat with Bob
> Alice: Hello Bob! This is encrypted.

# In Client B terminal:
> [Encrypted message from Alice received]
> [Decrypting...]
> [Hash verified ✓]
> [Authentication verified ✓]
> Bob: Message from Alice: "Hello Bob! This is encrypted."
```

---

## EXPECTED OUTPUT SAMPLE

```
===== SECURE CHAT APPLICATION =====
Server started on 0.0.0.0:5000
Waiting for connections...

[Server Log]
[2024-01-15 10:30:45] Client Connected: Alice from 127.0.0.1:54321
[2024-01-15 10:30:47] Client Connected: Bob from 127.0.0.1:54322
[2024-01-15 10:30:52] Key Exchange Request: Alice → Bob
[2024-01-15 10:30:53] Session Key Established: Alice ↔ Bob
[2024-01-15 10:30:55] Message: Alice → Bob (32 bytes encrypted)
[2024-01-15 10:30:56] Message: Bob → Alice (28 bytes encrypted)

[Client A - Alice]
Online Users: Bob, Charlie, Diana
> chat with Bob
Establishing secure channel...
✓ Received Bob's public key
✓ Generated session key
✓ Encrypted & transmitted session key
✓ Session key established

> send: Hello Bob! This is secret.
[10:30:55] Encrypting message...
[10:30:55] Computing SHA-256 hash: a3f9e...
[10:30:55] Computing HMAC: b2f3c...
[10:30:55] AES-256-CBC Encrypted: [IV:16 bytes][Ciphertext: 48 bytes]
[10:30:55] Message sent (108 bytes)

[Client B - Bob]
[10:30:56] Encrypted message received from Alice (108 bytes)
[10:30:56] Verifying checksum... ✓
[10:30:56] Extracting fields...
  - Message Type: Chat
  - Length: 32 bytes
  - Hash: a3f9e... ✓ VERIFIED
  - HMAC: b2f3c... ✓ VERIFIED
  - IV: [16 random bytes]
[10:30:56] Decrypting with session key...
[10:30:56] Plaintext: "Hello Bob! This is secret."
[10:30:56] Alice: "Hello Bob! This is secret."

> send: Hey Alice! Received your message.
[Message transmission same as above...]
```

---

## COMPLEXITY BREAKDOWN

### Time Complexity
- RSA Key Generation: O(log n) where n is key size
- AES Encryption: O(n) where n is message length
- SHA-256: O(n)
- HMAC: O(n)

### Space Complexity
- RSA Key Pair: O(1) - fixed size
- Session Key: O(1) - 32 bytes
- Message Buffer: O(n) where n is message size

### Network Complexity
- Initial handshake: 4 messages (public keys + session key)
- Per message: 1 encrypted message + 1 ACK
- Bandwidth efficient due to AES vs RSA for actual data

---

This roadmap provides a complete, implementable project that satisfies all assignment requirements while being achievable in 3 weeks. Let me now create the actual source code!
