# Security Hardening Checklist

**Free Fire OB54 — Phased Remediation Checklist**

---

## Phase 1: Immediate (0–7 days)

### Transport Security
- [ ] Implement TLS 1.3 for TCP signaling connections — **FF-0001**
- [ ] Remove hardcoded HTTP fallback address (`http://202.81.106.160:39001`) — **FF-0001**
- [ ] Remove custom TrustManager bypass — **FF-0003**
- [ ] Set `cleartextTrafficPermitted="false"` in NetworkSecurityConfig — **FF-0009**

### Cryptography
- [ ] Implement ECDH key exchange for TCP sessions — **FF-0002**
- [ ] Replace static AES key/IV with per-session ephemeral keys — **FF-0002**
- [ ] Remove hardcoded `DEFAULT_KEY` and `TEST_KEY` from VodkaConst — **FF-0002**
- [ ] Implement AES-GCM instead of AES-CBC — **FF-0007**

### Credentials
- [ ] Rotate and move `app_key`/`app_secret` to server-side OAuth — **FF-0005**
- [ ] Implement code signing for remotely downloaded native libraries — **FF-0004**

---

## Phase 2: Short-Term (1–4 weeks)

### Protocol Security
- [ ] Add nonces/timestamps to all signaling messages — **FF-0006**
- [ ] Add sequence numbers to protocol messages — **FF-0006**
- [ ] Implement server authentication for TCP connections — **FF-0008**
- [ ] Implement certificate pinning for sensitive endpoints — **FF-0003**

### Token Management
- [ ] Implement short-lived access tokens (15–30 minutes) — **FF-0012**
- [ ] Implement server-side refresh token rotation — **FF-0012**
- [ ] Implement token revocation mechanism — **FF-0012**

### Android Platform
- [ ] Set `exported="false"` for non-essential components — **FF-0013**
- [ ] Restrict FileProvider paths to minimum necessary directories — **FF-0011**
- [ ] Audit and restrict WebView JavaScript interfaces — **FF-0020**

---

## Phase 3: Medium-Term (1–3 months)

### Anti-Cheat
- [ ] Integrate Play Integrity API for client attestation — **FF-0015, FF-0016**
- [ ] Implement server-side rate limiting per IP/account — **FF-0014**
- [ ] Add behavioral analysis for bot detection — **FF-0015**

### Storage
- [ ] Migrate BeeTalk SDK to EncryptedSharedPreferences — **FF-0010**
- [ ] Remove VK token from META-INF — **FF-0024**
- [ ] Configure Firebase Security Rules — **FF-0019**
- [ ] Implement Firebase App Check — **FF-0019**

### Cryptography
- [ ] Replace MD5 with SHA-256 — **FF-0017**
- [ ] Replace SHA-1 with SHA-256 where possible — **FF-0017**
- [ ] Use RSA/ECDSA signatures for native library integrity — **FF-0004**

### Networking
- [ ] Migrate BeeTalk SDK to OAuth 2.0 — **FF-0018**
- [ ] Remove password-as-HTTP-parameter pattern — **FF-0018**

---

## Phase 4: Long-Term (3–6 months)

### Protocol Hardening
- [ ] Authenticate heartbeat messages with HMAC — **FF-0022**
- [ ] Include session-bound nonces in heartbeats — **FF-0022**
- [ ] Audit JNI bridge for security implications — **FF-0023**

### Configuration
- [ ] Configure DataDome bot protection — **FF-0025**
- [ ] Document crypto architecture and guard rails — **FF-0021**
- [ ] Implement key rotation infrastructure — **FF-0002, FF-0005**

---

## Verification

After implementing fixes:
1. Re-run static analysis to verify code changes
2. Capture network traffic to verify TLS implementation
3. Test MITM resistance with proxy tools
4. Verify token expiration and revocation
5. Test FileProvider path restrictions
6. Verify no hardcoded secrets remain in APK
7. Run automated security scanning (MobSF, QARK)

---

*Checklist version: 2.0 · Last updated: July 2026*
