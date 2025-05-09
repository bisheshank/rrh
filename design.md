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
     V                             V
```

NOTE: Need to add new keys and channel open after here

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

