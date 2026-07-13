# Authentication Flow — Call Graph Evidence

**Evidence for: FF-0005, FF-0008, FF-0012**

---

## Complete Authentication Flow

```
App Launch
  ↓
OAuthGuestTokenRequest
  ↓
POST https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant
  Parameters: client_id, client_secret
  ↓
Response: {access_token, refresh_token, expires_in}
  ↓
MajorLoginRequest (CSMajorLoginReq protobuf)
  Fields: account_id, access_token, device fingerprint (REGION, SYSTEM_VERSION, CPU_ARC, etc.)
  ↓
POST http://202.81.106.160:39001/MajorLogin  ← HTTP, not HTTPS
  ↓
Response: {account_id, token, voice_service_address, ...}
  ↓
TCP Connect to voice_service_address
  ↓
INIT frame (token, encrypted with static AES key FF-0002)
  ↓
Session established
```

---

## Classes Involved

| Class | Role | Source File |
|-------|------|-------------|
| `C8198a` | Token JSON parsing | `sources/p345j1/C8198a.java` |
| `AbstractC3508k` | Token storage (SharedPreferences) | `sources/com/beetalk/sdk/cache/AbstractC3508k.java` |
| `C3619j` | HTTP request with password | `sources/com/beetalk/sdk/networking/service/C3619j.java` |
| `C0583m` | TCP signaling client | `sources/p102L2/C0583m.java` |
| `VodkaConst` | Credentials and constants | `sources/com/garena/android/vodka/model/VodkaConst.java` |

---

## Key Observations

1. MajorLogin uses HTTP (not HTTPS) — FF-0009
2. Device fingerprint is entirely client-provided — FF-0016
3. Token is stored in plaintext SharedPreferences — FF-0010
4. TCP INIT uses static AES key — FF-0002
5. No server identity verification — FF-0008

---

*Evidence version: 2.0 · Last updated: July 2026*
