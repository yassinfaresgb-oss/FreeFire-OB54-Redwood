# Native Libraries â€” Evidence

**Evidence for: FF-0004, FF-0023**

---

## Library Count

56 native `.so` files across multiple architectures (arm64-v8a, armeabi-v7a, x86, x86_64).

## Key Libraries

| Library | Purpose | Security Relevance |
|---------|---------|-------------------|
| `libvvvoiceengine.so` | Voice engine | Downloaded at runtime (FF-0004) |
| `libgnative.so` | Game native code | Core game logic |
| `libunity.so` | Unity engine | IL2CPP compiled |
| Various `libsoda*.so` | SDK libraries | Third-party SDK native code |

## Remote Download (FF-0004)

- Source: `FFVoiceManager.java`
- Download URL: Remote (HTTP/HTTPS)
- Integrity: MD5 hash check only (client-side)
- No cryptographic signature verification

## JNI Bridge (FF-0023)

- Source: `bitter.jnibridge.JNIBridge.java`
- All Java interface methods routed through single native `invoke()` method
- Uses `java.lang.reflect.Proxy.newProxyInstance()`
- Uses `MethodHandles.Lookup.setAccessible(true)` for default methods

---

*Evidence version: 2.0 Â· Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) · Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 · Classification: Confidential — Internal Use Only*
