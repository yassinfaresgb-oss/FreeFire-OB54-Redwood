# Evidence Index

**Free Fire OB54 â€” Supporting Evidence Reference**

---

## Evidence Organization

Evidence files are organized by category and cross-referenced to findings.

### evidence/jadx/

| File | Description | Findings |
|------|-------------|----------|
| `jadx-decompilation-notes.md` | JADX decompilation setup and configuration | All |
| `obfuscation-mapping.md` | Known obfuscated class name mappings | All |

### evidence/classes/

| File | Description | Findings |
|------|-------------|----------|
| `dex-file-structure.md` | DEX file sizes, class counts, package distribution | All |
| `critical-class-list.md` | All classes referenced in findings | All |

### evidence/callgraph/

| File | Description | Findings |
|------|-------------|----------|
| `authentication-flow.md` | Complete authentication call chain | FF-0005, FF-0008, FF-0012 |
| `signaling-call-chain.md` | TCP signaling client call chain | FF-0001, FF-0002, FF-0006, FF-0007 |
| `crypto-call-chain.md` | Cryptographic operation call chain | FF-0002, FF-0007, FF-0017, FF-0021 |

### evidence/protobuf/

| File | Description | Findings |
|------|-------------|----------|
| `signalingservice.proto` | TCP signaling protocol definitions (17 message types) | FF-0001, FF-0006, FF-0015 |
| `common.proto` | Common protobuf definitions (CSMajorLoginReq) | FF-0016 |
| `account.proto` | Account protobuf definitions | FF-0005, FF-0008 |
| `http.proto` | HTTP API protobuf definitions | FF-0018 |

### evidence/manifest/

| File | Description | Findings |
|------|-------------|----------|
| `androidmanifest-analysis.md` | Complete manifest analysis (884 lines) | FF-0009, FF-0013 |
| `exported-components.md` | All exported components with protection levels | FF-0013 |
| `permissions-list.md` | All 39 declared permissions | FF-0013 |

### evidence/resources/

| File | Description | Findings |
|------|-------------|----------|
| `network-security-config.md` | Network security configuration analysis | FF-0009 |
| `filepaths-analysis.md` | FileProvider path analysis | FF-0011 |
| `google-services-analysis.md` | Firebase configuration analysis | FF-0019 |

### evidence/crypto/

| File | Description | Findings |
|------|-------------|----------|
| `aes-implementation.md` | AES-CBC implementation analysis | FF-0002, FF-0007 |
| `key-management.md` | Key storage and rotation analysis | FF-0002, FF-0005 |
| `hash-implementations.md` | MD5/SHA-1 usage locations | FF-0017 |
| `trust-manager-analysis.md` | Custom TrustManager bypass analysis | FF-0003 |
| `cmac-eax-analysis.md` | AES/ECB in CMAC/EAX (false positive analysis) | FF-0021 |

### evidence/network/

| File | Description | Findings |
|------|-------------|----------|
| `tcp-wire-format.md` | TCP protocol wire format documentation | FF-0001, FF-0006 |
| `http-endpoints.md` | Known HTTP API endpoints | FF-0009, FF-0018 |
| `server-addresses.md` | All discovered server addresses | FF-0001, FF-0005 |

### evidence/native/

| File | Description | Findings |
|------|-------------|----------|
| `native-libraries-list.md` | All 56 native libraries with architectures | FF-0004 |
| `jni-bridge-analysis.md` | JNIBridge reflection proxy analysis | FF-0023 |

### evidence/architecture/

| File | Description | Findings |
|------|-------------|----------|
| `component-diagram.md` | Application component interaction diagram | All |
| `trust-boundary-map.md` | Trust boundary identification | FF-0001, FF-0003, FF-0008 |
| `data-flow-diagrams.md` | Data flow for critical paths | All |

---

*Evidence Index version: 2.0 Â· Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) · Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 · Classification: Confidential — Internal Use Only*
