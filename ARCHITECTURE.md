# Application Architecture

**Free Fire OB54 â€” Architecture Analysis**

---

## High-Level Architecture

```mermaid
graph TB
    subgraph Client["Android Client"]
        UI["Unity Game Engine"]
        Vodka["Vodka Voice SDK"]
        BT["BeeTalk SDK"]
        VK["VK ID SDK"]
        DD["DataDome SDK"]
        NS["Network Stack"]
        KS["Keystore/Cache"]
    end

    subgraph Network["Network Layer"]
        HTTP["HTTP/HTTPS APIs"]
        TCP["Raw TCP Socket"]
        RTP["RTP Media"]
    end

    subgraph Backend["Garena Backend"]
        AUTH["Auth Server<br/>202.81.106.160:39001"]
        VOICE["Voice Signaling Server"]
        GAME["Game Server"]
        API["API Gateway<br/>ffmconnect.live.gop.garenanow.com"]
    end

    subgraph ThirdParty["Third Party"]
        FIREBASE["Firebase"]
        VKAPI["VK API"]
    end

    UI --> HTTP
    UI --> TCP
    Vodka --> TCP
    Vodka --> RTP
    BT --> HTTP
    VK --> HTTP
    NS --> HTTP
    NS --> TCP

    HTTP --> API
    HTTP --> AUTH
    TCP --> VOICE
    RTP --> VOICE
    HTTP --> GAME

    HTTP -.-> FIREBASE
    HTTP -.-> VKAPI
```

---

## Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant OAuth as OAuth Server<br/>ffmconnect.live.gop.garenanow.com
    participant Auth as Auth Server<br/>202.81.106.160:39001
    participant Voice as Voice Server

    C->>OAuth: POST /oauth/guest/token/grant<br/>(client_id, client_secret)
    OAuth-->>C: {access_token, refresh_token, expires_in}

    C->>Auth: HTTP POST /MajorLogin<br/>(account_id, access_token, device_info)
    Auth-->>C: {account_id, token, voice_service_address, ...}

    C->>Voice: TCP CONNECT to voice_service_address
    C->>Voice: INIT frame (session token, encrypted with static AES key)
    Voice-->>C: INIT response

    loop Every 5s
        C->>Voice: HEARTBEAT frame (0x02)
        Voice-->>C: HEARTBEAT response
    end

    C->>Voice: SIGNALING frame (JOIN_CHANNEL, SDP offer)
    Voice-->>C: SIGNALING frame (SDP answer, ICE candidates)
```

---

## Voice Signaling Protocol Stack

```mermaid
graph TB
    subgraph Application["Application Layer"]
        MSG["Message Types:<br/>INIT(1), HEARTBEAT(2),<br/>ACCOUNT(11), SIGNALING(40)"]
    end

    subgraph Encryption["Encryption Layer"]
        AES["AES-128-CBC<br/>Key: N!Qvw2!ePbfNF2lu<br/>IV: K*hKRuiSXZv!9enI"]
    end

    subgraph Framing["Framing Layer"]
        FRM["Wire Format:<br/>[1B type][4B length][NB payload]"]
    end

    subgraph Transport["Transport Layer"]
        TCP["Raw TCP Socket<br/>No TLS"]
    end

    MSG --> AES
    AES --> FRM
    FRM --> TCP
```

---

## Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Requested: App Launch
    Requested --> Active: OAuth Grant<br/>access_token received
    Active --> Refreshed: Near Expiry<br/>refresh_token used
    Refreshed --> Active: New access_token
    Active --> Expired: TTL exceeded<br/>no refresh
    Expired --> Requested: Re-authentication
    Active --> Revoked: Server-side revocation
    Revoked --> Requested: Re-authentication
```

---

## Trust Boundaries

```mermaid
graph LR
    subgraph TB1["Trust Boundary 1: Device"]
        A[Unity Engine] --> B[Vodka SDK]
        A --> C[BeeTalk SDK]
        A --> D[VK ID SDK]
    end

    subgraph TB2["Trust Boundary 2: Network"]
        E[HTTP/TCP]
    end

    subgraph TB3["Trust Boundary 3: Backend"]
        F[Auth Server]
        G[Voice Server]
        H[Game Server]
    end

    subgraph TB4["Trust Boundary 4: Third Party"]
        I[Firebase]
        J[VK API]
    end

    B -->|TLS?| E
    C -->|HTTP| E
    D -->|HTTPS| E
    E -->|TLS?| F
    E -->|No TLS| G
    E -->|HTTPS| H
    E -.-> I
    E -.-> J
```

---

## Component Interaction Map

| Component | Connects To | Protocol | TLS | Auth Method |
|-----------|-------------|----------|-----|-------------|
| Vodka SDK | Voice Server | TCP | No | Static AES + token |
| BeeTalk SDK | API Gateway | HTTP | Configurable | Password in params |
| VK ID SDK | VK API | HTTPS | Yes | OAuth 2.0 |
| Game Client | Auth Server | HTTP | Cleartext permitted | MajorLogin |
| Game Client | Game Server | HTTPS | Yes | Session token |
| Firebase SDK | Firebase | HTTPS | Yes | API Key |
| DataDome SDK | DataDome | HTTPS | Yes | Client key |

---

## Key Architectural Weaknesses

1. **Split-brain encryption**: Voice signaling uses custom AES-CBC on raw TCP while HTTP APIs use TLS. This inconsistency creates two entirely different security postures.

2. **Static key management**: The Vodka SDK uses hardcoded keys for all encryption, while the HTTP stack uses proper TLS. This suggests the voice subsystem was developed independently with lower security standards.

3. **Trust boundary gaps**: The TCP connection crosses from device to network without TLS, meaning the trust boundary between device and backend is unprotected at the transport layer.

4. **No server authentication**: The client does not verify server identity for TCP connections, allowing rogue server impersonation.

---

*Architecture version: 2.0 Â· Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) · Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 · Classification: Confidential — Internal Use Only*
