# TCP Signaling Wire Format — Evidence

**Evidence for: FF-0001, FF-0006**

---

## Frame Structure

```
Byte 0:     Protocol Type
Byte 1-4:   Payload Length (big-endian int32)
Byte 5-N:   Payload (AES-CBC encrypted protobuf, except HEARTBEAT)
```

## Protocol Types

| Type | Value | Encrypted | Purpose |
|------|-------|-----------|---------|
| INIT | 1 | Yes | Session initialization, token exchange |
| HEARTBEAT | 2 | No | Keep-alive (single byte 0x02) |
| ACCOUNT | 11 | Yes | Account binding |
| SIGNALING | 40 | Yes | Voice channel signaling |

## Message Protobuf (after decryption)

```protobuf
message ProtoReq {
    required int32 cmd = 1;
    optional bytes data = 2;
}
```

**Note:** No nonce, timestamp, or sequence number field — supports FF-0006 (no replay protection).

## Encryption

- Algorithm: AES-128-CBC
- Key: `N!Qvw2!ePbfNF2lu` (static, all sessions)
- IV: `K*hKRuiSXZv!9enI` (static, all messages)
- Padding: PKCS5Padding
- MAC: None

---

*Evidence version: 2.0 · Last updated: July 2026*
