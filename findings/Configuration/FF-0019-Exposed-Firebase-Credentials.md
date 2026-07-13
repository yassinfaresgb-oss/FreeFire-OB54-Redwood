# FF-0019 — Exposed Firebase API Keys and OAuth Credentials

## 1. Finding Header

| Field | Details |
|-------|---------|
| **Severity** | Medium |
| **CVSS** | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| **Vector** | Network |
| **Category** | Configuration |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **OWASP MASVS** | M7 — Client Code Quality |
| **OWASP MASTG** | MSTG-CONFIG-2 |
| **Component** | google-services.json |
| **Confidence** | ★★★★★ · 90% |
| **Validation Status** | Verified from Code |

> **NOTE:** Firebase API keys bundled in `google-services.json` are considered **by design** — Google explicitly documents this pattern. The actual security risk depends entirely on the **Firebase Security Rules** configured on the server side.

---

## 2. Code References

### Application
| Field | Value |
|-------|-------|
| **Application** | Free Fire Advance (FF-SECURITY-ASSESSMENT-OB54) |
| **Component** | google-services.json |
| **Package** | N/A (resource config) |
| **DEX** | N/A (resource file) |
| **Source File** | `resources/assets/google-services.json` |
| **Class** | N/A (JSON configuration) |
| **Inner Class** | N/A |
| **Method** | N/A |
| **Signature** | N/A |
| **Return Type** | N/A |
| **Parameters** | N/A |
| **Line Numbers** | 1–433 (full file) |

### Additional Source Files

| Source File | Lines | Description |
|-------------|-------|-------------|
| `META-INF/` | N/A | VK service token (see FF-0024) |

---

## 3. Security Context

### Purpose
Firebase service configuration providing API keys, project metadata, OAuth client IDs, and AdMob identifiers for Firebase SDK initialization.

### Responsibility
This configuration enables Firebase Authentication, Firestore, Realtime Database, Cloud Messaging, and AdMob services within the application.

### Interaction with Modules

| Module | Interaction |
|--------|-------------|
| Firebase SDK | Initialization via `FirebaseApp.initializeApp()` |
| VK SDK | Social platform integration via VK token |
| AdMob SDK | Advertising service configuration |
| OAuth 2.0 Flow | Client IDs for Google sign-in |

### Assets Handled

| Asset | Type | Sensitivity |
|-------|------|-------------|
| Firebase API Key | `AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4` | Medium — by design, but enables API access |
| Firebase Project ID | `free-fire-8cd39` | Low — public project identifier |
| Firebase Project Number | `180947006533` | Low — numeric identifier |
| OAuth Client IDs | 9 distinct client identifiers | Medium — OAuth flow identifiers |
| Certificate SHA-1 Hashes | Multiple registered fingerprints | Low — public cert metadata |
| AdMob Application ID | Embedded advertising configuration | Low — ad network identifier |
| VK Service Token | `Y7RKESKMDBH6BFTDGS2ZPH7K7I` | Medium — long-lived service credential |

### Security Relevance
The bundled credentials enable API calls to Firebase services and VK social platform integration. The VK token is a long-lived service credential that persists beyond the app session. Security posture depends on server-side Firebase Security Rules and App Check enforcement.

---

## 4. Decompiled Evidence

```java
// resources/assets/google-services.json (lines 1–433)
// Full file contents — key excerpts:

// Line ~5–12: Project configuration
{
  "project_info": {
    "project_number": "180947006533",
    "firebase_url": "https://free-fire-8cd39.firebaseio.com",
    "project_id": "free-fire-8cd39",
    "storage_bucket": "free-fire-8cd39.appspot.com"
  },

// Line ~13–70: Client configuration with API key
  "client": [
    {
      "client_info": {
        "mobilesdk_app_id": "1:180947006533:android:...",
        "api_key": [
          {
            "current_key": "AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4"
          }
        ],

// Line ~45–68: OAuth client entries (9 total)
        "oauth_client": [
          {
            "client_id": "180947006533-...apps.googleusercontent.com",
            "client_type": 1,
            "android_info": {
              "package_name": "com.dts.freefireadv",
              "certificate_hash": "<SHA-1 fingerprint>"
            }
          }
        ]
      }
    }
  ],

// Line ~300–320: AdMob configuration
  "admob": {
    "admob_app_id": "<AdMob application ID>"
  }
}
```

```java
// META-INF/ — VK service token (related to FF-0024)
// Y7RKESKMDBH6BFTDGS2ZPH7K7I
// Embedded in VK SDK configuration files
```

### Line-by-Line Analysis

| Line(s) | Code | Observation |
|---------|------|-------------|
| 5–12 | `"project_info"` block | Reveals Firebase project identifier and storage bucket |
| 13–70 | `"client"` array with `"api_key"` | Contains the Firebase API key in cleartext |
| 45–68 | `"oauth_client"` array (9 entries) | Exposes OAuth client IDs and certificate hashes |
| 300–320 | `"admob"` block | AdMob application ID for advertising |

### Why This Line Matters

| Line(s) | Why This Matters |
|---------|------------------|
| 13–70 | API key `AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4` is the primary credential for Firebase service access |
| 45–68 | 9 OAuth client IDs increase attack surface; unused clients may have weaker restrictions |
| 300–320 | AdMob ID can be used for ad fraud if extracted |

---

## 5. Cross References

### Called By
- Firebase SDK initialization (`FirebaseApp.initializeApp()`)

### Calls
- Firebase Authentication API
- Cloud Firestore API
- Realtime Database API
- Firebase Cloud Messaging API
- Google AdMob SDK
- VK API (via VK token)

### Interfaces
- Firebase SDK configuration interfaces
- Google OAuth 2.0 endpoints

### Inheritance
- N/A (configuration file)

### Related Classes
- Firebase SDK initialization classes
- VK SDK integration modules
- AdMob SDK bootstrap classes

### Related Protobuf
- N/A

### Native Bindings
- None

### JNI
- None

### Manifest Entries
- Firebase permissions
- VK permissions
- Internet access permission

---

## 6. Data Flow

```
[OBSERVATION] google-services.json (APK asset, 433 lines)
    ↓
[OBSERVATION] FirebaseApp.initializeApp(context)
    ↓
[OBSERVATION] Parse JSON → extract API keys, project config, OAuth clients
    ↓
[OBSERVATION] Firebase Auth / Firestore / RTDB / FCM / AdMob SDKs
    ↓
[TRUST BOUNDARY] — Local app process → Remote Firebase Backend
    ↓
[OBSERVATION] API calls with embedded API key: AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4
    ↓
[OBSERVATION] Firebase Backend (free-fire-8cd39) — security depends on Security Rules
```

---

## 7. Trust Boundary

```mermaid
graph LR
    A[APK: com.dts.freefireadv] -->|"API key in cleartext"| B[Firebase Backend]
    A -->|"VK token in META-INF"| C[VK API Backend]
    A -->|"AdMob ID"| D[Google AdMob]

    style A fill:#ff6b6b,color:#fff
    style B fill:#4ecdc4,color:#fff
    style C fill:#4ecdc4,color:#fff
```

### Trust Boundary Analysis

| Boundary | From | To | Trust Level | Rationale |
|----------|------|----|-------------|-----------|
| Client → Firebase | APK (client) | Firebase Backend | Low | API key is public client-side; server must enforce Security Rules |
| Client → VK | APK (client) | VK API Backend | Low | Token is embedded in cleartext; no client-side protection |
| Client → AdMob | APK (client) | Google AdMob | Low | AdMob ID is a public identifier |

The API keys are embedded in the client binary, which is publicly distributed. The trust boundary depends entirely on Firebase Security Rules — if rules are permissive, there is effectively no boundary between the API key and unrestricted data access.

---

## 8. Why This Line Matters

| Code Fragment | Location | Why It Matters |
|---------------|----------|----------------|
| `"current_key": "AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4"` | google-services.json:74-77 | Primary Firebase API key — enables authenticated API calls to Firebase services |
| `"oauth_client"` array (9 entries) | google-services.json:81-91 | 9 OAuth client IDs shipped; over-provisioning increases attack surface |
| `"admob_app_id"` | google-services.json:300-320 | AdMob ID for advertising; can be used in ad fraud if extracted |
| `Y7RKESKMDBH6BFTDGS2ZPH7K7I` | META-INF/ | Long-lived VK service token with no visible expiry |

---

## 9. Impact

| Impact Vector | Description | Worst Case |
|---------------|-------------|------------|
| Firebase data exfiltration | If Security Rules are permissive, any actor with the API key can read/write Firestore or Realtime Database | Full database dump of user data |
| VK account impersonation | The VK service token can be extracted and reused to make API calls on behalf of the VK app integration | Unauthorized VK actions on behalf of users |
| Ad fraud | AdMob application ID can be used to generate fraudulent ad requests | Revenue fraud via fake ad impressions |
| Reconnaissance | OAuth client IDs and certificate hashes reveal authentication infrastructure for targeted attacks | Targeted phishing against VK/Firebase auth flows |

> **Required Server Validation:** The backend may implement Firebase Security Rules that restrict data access, rate limiting on API key usage, or Firebase App Check attestation that limits the impact of extracted credentials. These server-side controls are not verifiable from client-side analysis.

---

## 10. Attack Flow

```mermaid
flowchart TD
    A[Attacker extracts APK] --> B[Decompile with jadx/apktool]
    B --> C[Read google-services.json]
    C --> D{Extracts credentials}
    D --> E[Firebase API Key]
    D --> F[VK Service Token]
    D --> G[OAuth Client IDs]
    E --> H{Firebase Security Rules permissive?}
    H -->|Yes| I[Direct Firestore/RTDB access]
    I --> J[Read/write game data]
    H -->|No| K[Key usable only for allowed operations]
    F --> L[VK API calls with stolen token]
    L --> M[Impersonate VK integration]
    G --> N[Recon for targeted OAuth phishing]
    style H fill:#f96,stroke:#333
    style I fill:#f66,stroke:#333
    style L fill:#f66,stroke:#333
```

---

## 11. False Positive Analysis

### Alternative Explanation
Firebase API keys in `google-services.json` are documented by Google as non-secret identifiers. Their security is designed to be enforced by Security Rules, API restrictions, and App Check — not by key secrecy. The VK token may be a public integration token with limited scope.

### False Positive Conditions
- If Firebase Security Rules enforce authenticated access with per-user authorization
- If Firebase App Check is enabled and attests all API requests
- If the VK token only grants read-only access to public profile data
- If API key restrictions in Google Cloud Console limit usage to specific apps/bundles

### Additional Evidence Needed
- Firebase Security Rules configuration (server-side)
- Firebase App Check enablement status
- VK token scope and permission set
- Google Cloud Console API key restrictions (application restrictions, API restrictions)

### Confidence Rationale
The credentials are clearly hardcoded in the APK — that fact is 100% verified. The 90% confidence reflects that the **impact** depends on server-side Firebase Security Rules, which cannot be verified from client-side analysis alone. If rules are permissive, this becomes a high-impact finding.

### Evidence Source

| Evidence | Source | Method |
|----------|--------|--------|
| Firebase API Key | google-services.json:74-77 | Direct extraction from APK asset |
| Project Metadata | google-services.json:5-12 | Direct extraction from APK asset |
| OAuth Client IDs | google-services.json:81-91 | Direct extraction from APK asset |
| VK Service Token | META-INF/ | Direct extraction from APK metadata |
| AdMob ID | google-services.json:300-320 | Direct extraction from APK asset |

---

## 12. Affected Component Map

```
google-services.json (APK asset)
  ↓
Firebase SDK Initialization
  ↓
  ├── Firebase Auth (OAuth client IDs)
  ├── Firestore (API key → data access)
  ├── Realtime Database (API key → data access)
  ├── Cloud Messaging (project number)
  └── AdMob (admob_app_id)

META-INF/ — VK Token
  ↓
VK SDK Integration
  ↓
VK API Backend (token-based auth)
```

---

## 13. Developer Verification Checklist

### Preconditions
- [ ] Decompiled APK via JADX or apktool
- [ ] Access to `resources/assets/google-services.json`
- [ ] Access to META-INF/ for VK token

### Relevant Files
- `resources/assets/google-services.json` — Full Firebase configuration (433 lines)
- `META-INF/` — VK service token

### Expected Behavior
- [ ] Firebase Security Rules enforce authenticated access
- [ ] API keys restricted by bundle signature and API restrictions
- [ ] VK tokens are short-lived and refresh server-side
- [ ] App Check enabled for all Firebase services

### Observed Behavior
- [ ] Firebase API key `AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4` in plaintext
- [ ] VK token `Y7RKESKMDBH6BFTDGS2ZPH7K7I` with no visible expiry
- [ ] 9 OAuth client IDs shipped (potential over-provisioning)
- [ ] No evidence of App Check in decompiled code

### Required Server Review
- [ ] Verify Firebase Firestore Security Rules require authentication
- [ ] Verify Firebase Realtime Database rules enforce per-user access
- [ ] Verify API key restrictions in Google Cloud Console
- [ ] Verify VK token scope and expiry mechanism
- [ ] Verify Firebase App Check is enabled in production

### Recommended Validation Steps
1. Query Firebase Security Rules via `firebase-cli`: `firebase deploy --only rules --dry-run`
2. Test API key access without authentication: `curl -H "Authorization: Bearer invalid" https://firestore.googleapis.com/v1/projects/free-fire-8cd39/databases/(default)/documents/`
3. Verify VK token expiry: Check VK API docs for token lifetime

---

## 14. Remediation

### 1. Configure Firebase Security Rules

```text
// Firestore rules — enforce authenticated access
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null
                         && request.auth.uid == resource.data.ownerUid;
    }
  }
}
```

### 2. Enable Firebase App Check

```java
// FirebaseAppCheck.install() — attestation for all API calls
FirebaseApp.initializeApp(context);
FirebaseAppCheck.install(
    provider = PlayIntegrityProvider(),
    debugProvider = DebugProvider(debugToken)
);
// All subsequent Firebase API calls are attested
```

### 3. Rotate VK Token and Implement Refresh

```java
// Replace static VK token with server-side refresh flow
public class VKTokenManager {
    private static final long MAX_TOKEN_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

    public String getValidToken() {
        String token = secureStore.load("vk_token");
        long tokenAge = System.currentTimeMillis() - secureStore.getCreationTime("vk_token");

        if (token == null || tokenAge > MAX_TOKEN_AGE_MS) {
            token = refreshVKTokenServerSide();
            secureStore.save("vk_token", token);
        }
        return token;
    }
}
```

### 4. Restrict API Key in Google Cloud Console

```text
// Google Cloud Console → APIs & Services → Credentials
// Application restrictions:
//   - Android apps: com.dts.freefireadv
//   - SHA-1 certificate fingerprint: <production signing key>
// API restrictions:
//   - Restrict to: Firebase Authentication, Firestore, FCM
//   - Remove unused APIs
```

### Recommended Actions
1. **Audit Firebase Security Rules** — Verify Firestore and Realtime Database rules require authentication and enforce least-privilege access
2. **Rotate VK token** — Invalidate the embedded VK token and implement server-side token refresh with short-lived access tokens
3. **Enable Firebase App Check** — Attach attestation to all Firebase API calls to prevent abuse from non-genuine app instances
4. **Prune unused OAuth clients** — Remove any OAuth client IDs that are not actively used in production
5. **Restrict API key in Google Cloud Console** — Add application restrictions (bundle signature) and API restrictions (limit to used services)

---

## 15. References

| Source | Reference |
|--------|-----------|
| CWE-200 | https://cwe.mitre.org/data/definitions/200.html |
| OWASP MASVS M7 | https://mas.owasp.org/MASVS/activities/M7-Client-Code-Quality/ |
| OWASP MASTG MSTG-CONFIG-2 | https://mas.owasp.org/MASTG/General/0x05a-Platform-Interaction/ |
| Firebase Security Rules | https://firebase.google.com/docs/rules |
| Firebase App Check | https://firebase.google.com/docs/app-check |
| Google — Protect Firebase API Keys | https://support.google.com/firebase/answer/9268042 |

---

## 16. Related Findings

| Finding | Relationship |
|---------|-------------|
| FF-0024 | Direct — VK token `Y7RKESKMDBH6BFTDGS2ZPH7K7I` also exposed in META-INF |
| FF-0025 | Sibling — empty DataDome configuration indicates incomplete security integration |
| FF-0005 | Pattern — hardcoded credentials in VodkaConst (same architectural weakness) |

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) � Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 � Classification: Confidential � Internal Use Only*
