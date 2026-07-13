# Trust Manager Analysis — Evidence

**Evidence for: FF-0003**

---

## Files

| File | Role |
|------|------|
| `sources/p215X7/C1771d.java` | InsecureTrustManager — skips validation for listed hosts |
| `sources/p215X7/C1768a.java` | Reflection-based delegation to default TrustManager |
| `sources/p215X7/C1773f.java` | TrustManagerFactory — creates the insecure TrustManager |

## Bypass Mechanism

```
C1773f.a()
  ↓
Creates X509TrustManager wrapping C1771d
  ↓
C1771d.checkServerTrusted(chain, authType)
  ↓
insecureHosts.contains(currentHost)?
  ├─ YES → Skip validation (return without checking)
  └─ NO  → C1768a.a() → Method.invoke(defaultTrustManager, ...)
```

## Key Observations

1. The bypass is hostname-based — specific hosts have no certificate validation
2. Reflection is used to avoid compile-time references to the default TrustManager
3. The `insecureHosts` list is maintained as a runtime configuration
4. No certificate pinning is implemented

---

*Evidence version: 2.0 · Last updated: July 2026*
