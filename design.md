# SSH Implementation Design

## Core Pipeline

```
Message <---> SshPacket <---> Bytes <---> TcpStream <---> Network
```

## Data Flow

### Outgoing

```
Message ---> SshPacket ---> Bytes ---> TcpStream
to_packet()   encode()     write()       send()
```

### Incoming

```
TcpStream ---> Bytes ---> SshPacket ---> Message
receive()      read()     decode()    from_packet()
```

## Protocol State Machine

```
Initial ---> SendVersion ---> VersionExchanged
                                |
                                | SendKexInit
                                V
KexInitSent <---------------> KexInitReceived
     |                             |
SendDhInit                   ReceiveDhInit
     |                             |
     V                             V
DhInitSent                   DhInitReceived
     |                             |
ReceiveDhReply               SendDhReply
     |                             |
     V                             V
DhReplyReceived               DhReplySent
     |                             |
SendNewKeys                  SendNewKeys
     |                             |
     V                             V
NewKeysSent                  NewKeysSent
     |                             |
ReceiveNewKeys               ReceiveNewKeys
     |                             |
     V                             V
NewKeysReceived              NewKeysReceived
     |                             |
RequestAuth                  ReceiveAuthRequest
     |                             |
     V                             V
AuthRequested                AuthRequested
     |                             |
SendAuthMethod               SendAuthAccept
     |                             |
     V                             V
AuthMethodNegotiated         AuthAccepted
     |                             |
Auth Verified                ReceiveUsernamePassword
     |                             |
     V                             V
OpenChannel                  ReceivedUsernamePassword
     |                             |
     V                             V
ChannelOpen  <---------------> ChannelOpen
     |                             |
StartSession                 SendChannelOpenConfirmation
     |                             |
     V                             V
SessionStarted <-------------> SessionStarted
     |                             |
     |                      ReceiveCommand (loop)
     |                             |
     V                             V
Disconnect                   Disconnect
     |                             |
     V                             V
Closed                       Closed
```

## Message Types

```
Message
  |
  |--> Disconnect
  |
  |--> Unimplemented
  |
  |--> KexInit
  |
  |--> KexDhInit
  |
  |--> KexDhReply
  |
  |--> NewKeys
  |
  |--> ServiceRequest
  |
  |--> ServiceAccept
  |
  |--> UsernamePassword
  |
  |--> AuthVerified
  |
  |--> OpenChannel
  |
  |--> ChannelOpenConfirmation
  |
  |--> ExecuteCommand
  |
  |--> CommandResult
```

## Transport Layer

```
TcpStream <--- reads/writes ---> SshPackets
    ^                                ^
    |                                |
    | manages                    contains
    |                                |
Transport <--------------------> BytesMut
```

## State Machine Implementation

The SSH protocol is implemented as a state machine in `SshStateMachine` that transitions between states based on events:

```
SshEvent ---> SshStateMachine ---> State Transition
```

Events are processed by corresponding handler methods that perform the necessary protocol operations.

## Encryption and Authentication Flow

### Key Exchange

```
1. Version Exchange
   Client <--SSH-2.0-RRH_X.Y--> Server

2. Algorithm Negotiation (KEX_INIT)
   Client <--Algorithm Lists--> Server

3. Diffie-Hellman Exchange
   Client --KEXDH_INIT--> Server
   Client <--KEXDH_REPLY-- Server

4. New Keys Activation
   Client --NEWKEYS--> Server
   Client <--NEWKEYS-- Server
```

### Authentication

```
1. Service Request
   Client --SSH_MSG_SERVICE_REQUEST--> Server
   Client <--SSH_MSG_SERVICE_ACCEPT-- Server

2. Username/Password Authentication
   Client --USERNAME_PASSWORD--> Server
   Client <--AUTH_VERIFIED-- Server
```

### Session Establishment

```
1. Channel Opening
   Client --SSH_MSG_CHANNEL_OPEN--> Server
   Client <--SSH_MSG_CHANNEL_OPEN_CONFIRMATION-- Server

2. Command Execution
   Client --EXECUTE_COMMAND--> Server
   Client <--COMMAND_RESULT-- Server (repeats)
```

## Encryption Implementation

### Shared Secret Generation
```
1. Client generates: (secret_c, public_c)
2. Server generates: (secret_s, public_s)
3. Client and Server compute the same:
   shared_secret = DH(secret_c, public_s) = DH(secret_s, public_c)
```

### Key Derivation
```
K = shared_secret
H = exchange_hash
session_id = First H in the connection

Derived Keys:
IV_c2s = HASH(K || H || "A" || session_id)
IV_s2c = HASH(K || H || "B" || session_id)
key_c2s = HASH(K || H || "C" || session_id)
key_s2c = HASH(K || H || "D" || session_id)
mac_c2s = HASH(K || H || "E" || session_id)
mac_s2c = HASH(K || H || "F" || session_id)
```

### Encryption/Decryption Process
```
Encryption:
1. Create packet (length, padding_length, payload, padding)
2. Encrypt with AES-128-CTR using appropriate key and IV
3. Compute HMAC-SHA1 over (seq_num || packet) using appropriate MAC key
4. Transmit (packet_length || encrypted_data || mac)

Decryption:
1. Read packet_length
2. Read encrypted_data + MAC
3. Verify MAC using appropriate MAC key
4. Decrypt data using appropriate key and IV
5. Process decrypted packet
```

## Session Management

The `Session` struct holds all session-specific data:
- Cryptographic keys and parameters
- Connection state
- Authentication information
- Channel information

## Modular Architecture

```
+-----------------+
|    SshClient    |      Client implementation
+-----------------+
        |
+------------------+
| SshStateMachine  |      State transitions and event handling
+------------------+
        |
+------------------+
|     Transport    |      Packet encoding/decoding, encryption
+------------------+
        |
+------------------+
|     Message      |      SSH protocol messages
+------------------+
        |
+------------------+
|    SshPacket     |      Binary packet format
+------------------+
```

## Security Features

- Host key verification
- SHA1 for exchange hash calculation 
- AES-128-CTR for encryption
- HMAC-SHA1 for message authentication
- X25519 Diffie-Hellman for key exchange
- ED25519 for server host key signing

## Command Execution

Client:
1. Presents shell prompt to user
2. Captures user input
3. Sends EXECUTE_COMMAND message
4. Receives and displays COMMAND_RESULT

Server:
1. Receives EXECUTE_COMMAND
2. Executes command via shell
3. Captures stdout/stderr
4. Returns results via COMMAND_RESULT

