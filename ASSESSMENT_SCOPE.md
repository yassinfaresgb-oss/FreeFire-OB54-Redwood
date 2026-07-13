# Assessment Scope

**Free Fire OB54 â€” In-Scope and Out-of-Scope Targets**

---

## In-Scope Targets

### Primary Target

| Property | Value |
|----------|-------|
| Application | Garena Free Fire |
| Package | `com.dts.freefireadv` |
| Version | 68.54.0 (OB54) |
| Version Code | 2019112752 |
| APK File | `Free.Fire.Advance.Server.theffadvancedserver.com.apk` |
| Framework | Unity + IL2CPP |

### Components Under Assessment

| Component | Scope | Depth |
|-----------|-------|-------|
| Vodka Voice Signaling SDK | Full | Protocol analysis, crypto review, authentication flow |
| TCP Signaling Protocol | Full | Wire format, message types, encryption, reconnection |
| HTTP API Authentication | Full | OAuth flow, MajorLogin, token lifecycle |
| Cryptographic Implementations | Full | AES, MD5, SHA-1, key management, certificate validation |
| Android Platform Configuration | Full | Manifest, exported components, FileProvider, WebView |
| Network Security Configuration | Full | TLS policy, cleartext permissions, certificate pinning |
| Native Library Loading | Full | Remote download, integrity verification, JNI bridge |
| Token Management | Full | Storage, lifecycle, refresh mechanism |
| Third-Party SDKs | Partial | BeeTalk SDK, VK ID SDK, DataDome |

### Files Analyzed

| Category | Count | Key Files |
|----------|-------|-----------|
| Decompiled Java Sources | ~13,000+ | Full JADX output across 3 DEX files |
| AndroidManifest.xml | 1 | 884 lines, 20+ exported components |
| Network Security Config | 1 | cleartextTrafficPermitted="true" |
| Protobuf Definitions | 4 | signalingservice.proto, common.proto, account.proto, http.proto |
| Native Libraries | 56 | .so files for multiple architectures |
| Google Services Config | 1 | google-services.json with Firebase credentials |
| FileProvider Config | 1 | filepaths.xml with broad path mappings |

---

## Out-of-Scope Targets

| Target | Reason |
|--------|--------|
| iOS Application | Not assessed (Android only) |
| Server-Side Infrastructure | No production access; all server observations are client-side derived |
| Game Engine (Unity IL2CPP) | Business logic obfuscation not in scope |
| Game Anti-Cheat (GameSafe) | Separate assessment scope |
| Dynamic Runtime Behavior | No instrumentation, no packet capture, no Frida |
| Third-Party API Client (FreeFire-Api-main) | Unauthorized public tool; analyzed separately for context only |
| Backend Databases | No access |
| CDN/Infrastructure | No access |
| Employee Systems | Not in scope |

---

## Assessment Boundaries

### What Was Done

- Full JADX decompilation of the APK
- Manual code review of all critical paths
- Pattern-based grep analysis for hardcoded secrets, weak crypto, and insecure configurations
- Protobuf definition analysis
- AndroidManifest.xml analysis
- Cryptographic implementation review
- Network protocol analysis
- Trust boundary identification

### What Was NOT Done

- Dynamic analysis or runtime instrumentation
- Network traffic capture or packet manipulation
- Fuzzing of protocol endpoints
- Server-side vulnerability assessment
- Social engineering testing
- Physical device testing
- Privilege escalation testing on rooted devices
- Automated scanning tools (MobSF, QARK, etc.)

---

## Confidence Boundaries

> **This observation is derived from client-side reverse engineering and requires server-side validation before exploitability can be confirmed.**

Findings marked with this note depend on server-side behavior that cannot be verified from the decompiled APK alone. The server may implement additional protections not visible in the client code.

---

*Assessment Scope version: 2.0 Â· Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) · Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 · Classification: Confidential — Internal Use Only*
