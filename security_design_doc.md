# ATM Security Protocol Design Document

## System Overview

This document describes the security protocol for an ATM/Bank communication system. The system consists of three main components that communicate over an untrusted UDP network:

### Architecture

```
[ATM Client] ←→ [Router] ←→ [Bank Server]
    :32004         :32000       :32001
```

- **ATM**: Client program where users perform banking operations
- **Bank**: Server that manages accounts and processes transactions  
- **Router**: Network intermediary that forwards packets between ATM and Bank

### Core Components

**Initialization**: The `init` program generates shared cryptographic keys stored in `.atm` and `.bank` files.

**Authentication**: Users possess card files (`.card`) containing encrypted authentication keys that require their PIN to decrypt.

**Communication**: All ATM↔Bank messages are encrypted and authenticated using AES-256-CBC and HMAC-SHA256.

### Protocol Design

**File Formats**:
- Initialization files contain 64 bytes: K_enc (32) + K_mac (32)
- Card files contain 64 bytes: salt (16) + IV (16) + encrypted_user_key (32)

**Message Format**:
```
Wire: IV (16 bytes) + Ciphertext (variable) + MAC (32 bytes)
Plaintext: Timestamp (8) + Command (1) + Data (variable)
```

**Cryptographic Primitives**:
- **AES-256-CBC**: Message and card file encryption with random IVs
- **HMAC-SHA256**: Message authentication and integrity
- **PBKDF2**: PIN-based key derivation (10,000 iterations + salt)

**Session Management**: 
- Single active session per user enforced by Bank
- Automatic timeouts: 60s inactivity (ATM), 5min total (Bank)
- Session IDs track active connections

**Security Properties**:
- **Confidentiality**: AES encryption protects all sensitive data
- **Integrity**: HMAC prevents message tampering
- **Authentication**: Two-factor (card + PIN) user verification
- **Freshness**: Timestamp validation with 60-second window
- **Replay Protection**: Message cache prevents duplicate processing

### Protocol Flows

**Authentication Flow**:
1. User provides username and PIN
2. ATM reads card file, extracts salt and encrypted user key
3. ATM derives decryption key using PBKDF2(PIN, salt, 10000)
4. ATM decrypts user key and sends to Bank in encrypted message
5. Bank verifies user key matches stored value and creates session

**Transaction Flow**:
1. ATM encrypts transaction request (withdraw/balance/end-session)
2. Bank verifies MAC, decrypts, validates timestamp and session
3. Bank processes transaction and sends encrypted response
4. ATM verifies response and displays result

**Network Security**:
- All messages use Encrypt-then-MAC composition
- Random IVs ensure semantic security
- Separate keys (K_enc, K_mac) for encryption and authentication
- Replay cache prevents duplicate message processing

---

## Vulnerabilities

### Vulnerability #1: Authentication Bypass
**Description**: An attacker could attempt to access user accounts without proper credentials, either by possessing only a card file OR only knowing a PIN, or through brute force attacks on authentication.

**Mitigation**: To protect against authentication bypass, we implement cryptographic two-factor authentication where both the card file and correct PIN are required to derive the user's authentication key.

**Current Implementation**: 
- Card files store user keys encrypted with PIN-derived keys using PBKDF2(PIN, salt, 10000 iterations)
- ATM derives decryption key from entered PIN: `derive_key_from_pin(pin, salt, 16, pin_key)`
- Only correct PIN produces valid user key that Bank can verify
- PBKDF2 with 10,000 iterations makes brute force computationally expensive
- Random salt prevents rainbow table attacks

### Vulnerability #2: Message Tampering
**Description**: A network attacker controlling the router could intercept and modify messages, changing transaction amounts, usernames, or commands to steal money or access unauthorized accounts.

**Mitigation**: To protect against message tampering, we use authenticated encryption with the Encrypt-then-MAC composition and separate keys for encryption and authentication.

**Current Implementation**:
- All messages protected by HMAC-SHA256: `mac = hmac_sha256(K_mac, iv || ciphertext)`
- MAC verification before decryption: `if (constant_time_compare(received_mac, expected_mac) != 0) reject_message()`
- Separate K_enc and K_mac keys prevent cryptographic vulnerabilities
- MAC covers both IV and ciphertext to prevent any tampering

### Vulnerability #3: Replay Attacks  
**Description**: An attacker could record valid messages and retransmit them later to repeat transactions, potentially withdrawing money multiple times or replaying authentication messages.

**Mitigation**: To protect against replay attacks, we implement timestamp-based freshness validation combined with a message cache for duplicate detection.

**Current Implementation**:
- Timestamp validation with 60-second window: `if (packet_age > 60 || packet_age < -5) reject_message()`
- Message hash cache: `message_hash = sha256(timestamp || command || data)`
- Duplicate detection: `if (hash_table_find(recent_messages, message_hash)) reject_message()`
- Automatic cache cleanup prevents memory exhaustion

### Vulnerability #4: Race Conditions in Transactions
**Description**: Concurrent transactions for the same user could cause Time-of-Check-to-Time-of-Use (TOCTOU) vulnerabilities, where multiple withdrawals see the same balance and all succeed, leading to account overdrafts.

**Mitigation**: To protect against race conditions, we enforce single active session per user, ensuring all transactions for a user are serialized.

**Current Implementation**:
- Bank maintains active sessions table: `HashTable *active_sessions` mapping username to session info
- Session verification before transactions: `if (hash_table_find(active_sessions, username) == NULL) reject_transaction()`
- Concurrent session prevention: `if (existing_session) reject_new_session("Session already active")`
- Only one authentication allowed per user at any time

### Vulnerability #5: Session Hijacking
**Description**: An attacker could gain access to an active session after a legitimate user walks away from the ATM without properly logging out, allowing unauthorized transactions.

**Mitigation**: To protect against session hijacking, we implement automatic session termination based on user inactivity timeouts.

**Current Implementation**:
- ATM-side inactivity tracking: `if ((current_time - last_activity_time) > 60) timeout_session()`
- Automatic session cleanup: `send_end_session_to_bank(); session_active = 0;`
- Activity updates on commands: `last_activity_time = time(NULL)`
- Defense in depth with Bank's 5-minute total session timeout

### Vulnerability #6: Buffer Overflow Attacks
**Description**: An attacker could send malformed input with excessively long strings to overflow buffers, potentially leading to code execution or system crashes.

**Mitigation**: To protect against buffer overflows, we use safe string functions and implement comprehensive bounds checking throughout the codebase.

**Current Implementation**:
- Safe string functions: `snprintf(buffer, sizeof(buffer), ...)` instead of `sprintf`
- Bounds checking: `strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\0';`
- Input validation: `if (username_len > 250) reject_input("Username too long")`
- Length verification before processing user input


