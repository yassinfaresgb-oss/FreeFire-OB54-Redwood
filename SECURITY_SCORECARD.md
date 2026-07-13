# Security Scorecard

**Free Fire OB54 — Maturity Ratings by Security Domain**

---

## Scoring Methodology

Each domain is rated on a 0–10 scale:

| Score | Level | Definition |
|-------|-------|------------|
| 0–2 | Critical Gaps | Fundamental security controls absent or bypassed |
| 3–4 | Weak | Basic controls present but significantly flawed |
| 5–6 | Adequate | Industry-standard controls with notable gaps |
| 7–8 | Strong | Well-implemented controls with minor improvements needed |
| 9–10 | Excellent | Best-in-class implementation |

---

## Scores

### Authentication — 4/10

**Rationale:** OAuth guest token flow follows standard patterns, but hardcoded `app_key`/`app_secret` (FF-0005) in the APK undermine the credential model. Long-lived tokens with refresh (FF-0012) extend exposure windows. One-way authentication in TCP signaling (FF-0008) means the client cannot verify server identity.

**Strengths:**
- OAuth 2.0 guest token grant for initial authentication
- Separate token for game server vs. voice server

**Weaknesses:**
- Hardcoded credentials extractable from APK
- No mutual authentication for voice server
- Long token lifetime

---

### Authorization — 5/10

**Rationale:** Authorization is primarily server-side and cannot be fully assessed from client-side analysis alone. The client sends account identifiers and tokens, but authorization decisions appear to be made server-side. However, the ability to forge messages with the static AES key (FF-0002) could bypass client-side authorization checks.

**Strengths:**
- Server-side authorization decisions
- Account-based access control model

**Weaknesses:**
- Client-side token can be forged due to static encryption key
- No visible role-based access control in client code

---

### Transport Security — 2/10

**Rationale:** This is the weakest domain. The voice signaling protocol uses raw TCP without TLS (FF-0001). The hardcoded fallback address uses HTTP (FF-0001). NetworkSecurityConfig permits cleartext traffic (FF-0009). The SSL certificate validation bypass (FF-0003) undermines HTTPS protections where they do exist.

**Strengths:**
- HTTPS used for some API endpoints
- NetworkSecurityConfig present (though misconfigured)

**Weaknesses:**
- Raw TCP for voice signaling
- Cleartext HTTP permitted
- Custom TrustManager bypasses certificate validation
- No certificate pinning on sensitive endpoints

---

### Cryptography — 2/10

**Rationale:** The primary encryption mechanism uses a static AES-128-CBC key and IV (FF-0002) without HMAC (FF-0007). No key exchange, no forward secrecy, no per-message IVs. MD5 and SHA-1 usage (FF-0017) for hashing. AES/ECB within CMAC/EAX constructions is actually correct (FF-0021 is a low-confidence finding).

**Strengths:**
- AES-CBC provides basic confidentiality
- BouncyCastle implementations for CMAC/EAX are standard

**Weaknesses:**
- Static key/IV for all sessions
- No MAC on CBC ciphertext
- No key derivation function
- No forward secrecy
- MD5/SHA-1 usage

---

### Key Management — 1/10

**Rationale:** This is the most critical gap. All cryptographic keys are hardcoded in the APK (FF-0002, FF-0005). No key exchange protocol. No key rotation. No key derivation. No hardware-backed key storage for the voice subsystem.

**Strengths:**
- None identified for the voice subsystem

**Weaknesses:**
- Static AES key in APK source
- Hardcoded app credentials in APK source
- No ECDH or similar key exchange
- No key rotation mechanism
- No HKDF or KDF usage

---

### Session Management — 4/10

**Rationale:** Tokens are issued with refresh capability (FF-0012), which is a standard pattern. However, the signaling session uses a static key rather than per-session keys, meaning all sessions share the same cryptographic material. Reconnection is unlimited (FF-0014), and heartbeats are unauthenticated (FF-0022).

**Strengths:**
- Token refresh mechanism exists
- Session tokens provided by MajorLogin

**Weaknesses:**
- Static encryption key shared across all sessions
- No session-bound keys
- Unlimited reconnection attempts
- Unauthenticated heartbeat protocol

---

### Storage — 5/10

**Rationale:** The app uses a mix of encrypted and unencrypted storage. VK ID SDK correctly uses EncryptedSharedPreferences, but the BeeTalk SDK stores sensitive data in plaintext SharedPreferences (FF-0010). FileProvider paths are overly broad (FF-0011). allowBackup is disabled in the manifest.

**Strengths:**
- EncryptedSharedPreferences used by VK ID SDK
- allowBackup=false in manifest
- Android Keystore integration for VK tokens

**Weaknesses:**
- BeeTalk SDK uses unencrypted SharedPreferences
- Overly broad FileProvider paths
- Tokens stored in META-INF (FF-0024)

---

### Privacy — 6/10

**Rationale:** The app collects device information for the MajorLogin fingerprint (FF-0016), which is standard for game analytics. Firebase is integrated for analytics. However, the VK token in META-INF (FF-0024) and device fingerprint spoofability (FF-0016) present privacy concerns.

**Strengths:**
- DataDome SDK present for bot protection (though unconfigured)
- No obvious PII leakage in decompiled code

**Weaknesses:**
- VK token exposed in META-INF
- Device fingerprint is spoofable
- Firebase credentials exposed

---

### Network Security — 3/10

**Rationale:** The network security configuration permits cleartext traffic (FF-0009). No certificate pinning is implemented. The custom TrustManager (FF-0003) actively undermines network security. Remote native library downloads (FF-0004) without integrity checking create supply chain risks.

**Strengths:**
- NetworkSecurityConfig present
- Some HTTPS usage for API endpoints

**Weaknesses:**
- Cleartext traffic permitted
- No certificate pinning
- SSL validation bypass
- Remote native library download without integrity

---

### Platform Security — 5/10

**Rationale:** The manifest properly sets debuggable=false and allowBackup=false. However, exported components without adequate protection (FF-0013), overly broad FileProvider paths (FF-0011), and WebView JS bridge exposure (FF-0020) present platform-level risks.

**Strengths:**
- debuggable=false
- allowBackup=false
- Target SDK 35 (latest)

**Weaknesses:**
- Exported components without signature permissions
- WebView JS bridge exposure
- Overly broad FileProvider paths

---

### Native Code — 4/10

**Rationale:** 56 native libraries are present, compiled for multiple architectures. The JNI reflection proxy (FF-0023) obscures native call analysis. Remote native library download (FF-0004) without integrity verification is the primary concern.

**Strengths:**
- Native libraries compiled for standard architectures
- IL2CPP compilation provides some obfuscation

**Weaknesses:**
- Remote .so download without integrity check
- JNI reflection proxy obscures analysis
- MD5 used for native library integrity (FF-0017)

---

## Overall Score

| Domain | Score | Weight | Weighted |
|--------|-------|--------|----------|
| Authentication | 4 | 15% | 0.60 |
| Authorization | 5 | 10% | 0.50 |
| Transport Security | 2 | 20% | 0.40 |
| Cryptography | 2 | 15% | 0.30 |
| Key Management | 1 | 15% | 0.15 |
| Session Management | 4 | 5% | 0.20 |
| Storage | 5 | 5% | 0.25 |
| Privacy | 6 | 5% | 0.30 |
| Network Security | 3 | 5% | 0.15 |
| Platform Security | 5 | 5% | 0.25 |
| Native Code | 4 | 5% | 0.20 |
| **Overall** | | **100%** | **3.30 / 10** |

---

**Overall Security Maturity: 3.3 / 10 — Weak**

The application has fundamental cryptographic and transport security weaknesses in the voice signaling subsystem. While the HTTP API stack uses standard TLS protections, the voice subsystem operates with custom encryption using static keys on raw TCP, creating a significant security gap. Key management is the weakest domain (1/10) with all keys hardcoded in the APK.

---

*Scorecard version: 2.0 · Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) � Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 � Classification: Confidential � Internal Use Only*
