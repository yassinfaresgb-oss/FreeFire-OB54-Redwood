# AndroidManifest Analysis — Evidence

**Evidence for: FF-0009, FF-0013**

---

## Overview

| Property | Value |
|----------|-------|
| File | `resources/AndroidManifest.xml` |
| Lines | 884 |
| Package | `com.dts.freefireadv` |
| Target SDK | 35 |
| Min SDK | 21 |
| debuggable | false |
| allowBackup | false |
| permissions | 39 declared |

## Network Security

- `android:networkSecurityConfig` referenced
- `network_security_config.xml` contains `cleartextTrafficPermitted="true"` — FF-0009
- No certificate pinning configured

## Exported Components (FF-0013)

| Type | Count | Examples |
|------|-------|----------|
| Activities | 8+ | Deep link handlers, auth callbacks |
| Services | 4+ | Background services |
| Receivers | 5+ | Broadcast receivers |
| Providers | 3+ | Content providers (including FileProvider) |

## FileProvider (FF-0011)

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.dts.freefireadv.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/filepaths" />
</provider>
```

Filepaths.xml contains broad path mappings (root-path, external-path).

---

*Evidence version: 2.0 · Last updated: July 2026*
