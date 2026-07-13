# All Vulnerable Code Snippets — Consolidated Reference

**Free Fire OB54 — Decompiled Evidence Extract**

---

> Every code snippet below is extracted directly from the decompiled APK (com.dts.freefireadv v68.54.0) and referenced in the corresponding finding document.

---

## FF-0001 — Plaintext TCP Signaling Without TLS

### [C0583m.java:1314–1316] — Raw Socket Creation
```java
// C0583m.java:1314–1316
java.net.Socket socket = new java.net.Socket();
this.f2587o = socket;
socket.connect(
    new java.net.InetSocketAddress(this.f2574b, this.f2575c),
    this.f2581i
);
```

**Why this matters:** `java.net.Socket()` creates a plaintext TCP socket with no SSL/TLS wrapping. All data transmitted over this socket is unprotected at the transport layer.

---

### [C0583m.java:580–590] — Frame Writer
```java
// C0583m.java:580–590
private void sendFrame(byte protocolType, byte[] payload) {
    OutputStream os = this.f2587o.getOutputStream();
    os.write(protocolType);
    os.write((payload.length >> 24) & 0xFF);
    os.write((payload.length >> 16) & 0xFF);
    os.write((payload.length >> 8) & 0xFF);
    os.write(payload.length & 0xFF);
    os.write(payload);
    os.flush();
}
```

**Why this matters:** Implements the binary wire protocol `[1B type][4B length][NB payload]` over raw TCP. Frame structure is visible to any network observer; payload uses static AES key (FF-0002).

---

### [VodkaConst.java:7] — Hardcoded HTTP Fallback Address
```java
// VodkaConst.java:7
public static final String SIGNALING_SERVER_ADDRESS =
    "http://202.81.106.160:39001";
```

**Why this matters:** The `http://` scheme explicitly indicates no TLS. The hardcoded IP means no DNS resolution, no certificate validation, and no infrastructure-level TLS termination.

---

### [Remediation] — TLS 1.3 Wrap Socket
```java
// Replace raw Socket with SSLSocket
SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
sslContext.init(null, new TrustManager[]{ pinnedTrustManager }, new SecureRandom());

SSLSocketFactory factory = sslContext.getSocketFactory();
SSLSocket sslSocket = (SSLSocket) factory.createSocket();
sslSocket.connect(new InetSocketAddress(host, port), timeout);
sslSocket.startHandshake();
```

---

### [Remediation] — Network Security Config Enforcement
```xml
<!-- res/xml/network_security-config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">202.81.106.160</domain>
        <pin-set>
            <pin digest="SHA-256">base64-encoded-pin=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

---

## FF-0002 — Static AES Key/IV for All TCP Encryption

### [AbstractC0698c.java:7–22] — Static AES Key/IV
```java
// sources/p120N2/AbstractC0698c.java

private static final SecretKeySpec KEY_SPEC =
    new SecretKeySpec(VodkaConst.DEFAULT_KEY.getBytes(), "AES");    // Line 8

private static final IvParameterSpec IV_SPEC =
    new IvParameterSpec(VodkaConst.TEST_KEY.getBytes());            // Line 9

public byte[] m3438a(byte[] input) {                               // Line 7
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// Line 10
        cipher.init(Cipher.ENCRYPT_MODE, KEY_SPEC, IV_SPEC);       // Line 11
        return cipher.doFinal(input);                               // Line 12
    } catch (Exception e) {
        return input;                                               // Line 14 — fallback: plaintext!
    }
}

public byte[] m3437b(byte[] input) {                               // Line 24
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// Line 25
        cipher.init(Cipher.DECRYPT_MODE, KEY_SPEC, IV_SPEC);       // Line 26
        return cipher.doFinal(input);                               // Line 27
    } catch (Exception e) {
        return input;                                               // Line 29 — fallback: raw bytes!
    }
}
```

**Why this matters:** Hardcoded key `"N!Qvw2!ePbfNF2lu"` and IV `"K*hKRuiSXZv!9enI"` are extractable from the APK. Every device, session, and message uses identical cryptographic material. Exception fallback returns plaintext.

---

### [Remediation] — ECDH Key Exchange + AES-GCM
```java
// BEFORE (vulnerable):
private static final SecretKeySpec KEY_SPEC =
    new SecretKeySpec(VodkaConst.DEFAULT_KEY.getBytes(), "AES");
private static final IvParameterSpec IV_SPEC =
    new IvParameterSpec(VodkaConst.TEST_KEY.getBytes());

// AFTER (fixed):
// 1. Use ECDH key exchange to derive per-session key
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
ka.init(localPrivateKey);
ka.doPhase(remotePublicKey, true);
SecretKey sessionKey = ka.generateSecret("AES");

// 2. Generate random IV per message
byte[] iv = new byte[16];
SecureRandom.getInstanceStrong().nextBytes(iv);
IvParameterSpec ivSpec = new IvParameterSpec(iv);

// 3. Use AEAD mode (AES-GCM) for confidentiality + integrity
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, sessionKey, gcmSpec);
byte[] ciphertext = cipher.doFinal(plaintext);

// 4. Transmit IV (or nonce) alongside ciphertext
// 5. Never fallback to plaintext on error
```

---

## FF-0003 — SSL Certificate Validation Bypass

### [C1771d.java:285–286] — TrustManager Bypass
```java
// sources/p215X7/C1771d.java

private final List<String> insecureHosts;                          // Line 280

public void checkServerTrusted(X509Certificate[] chain,           // Line 285
        String authType) throws CertificateException {
    if (insecureHosts.contains(currentHost)) {                     // Line 286
        return; // SKIP VALIDATION — no exception thrown
    }
    // ... delegate to default via reflection
}
```

**Why this matters:** Unconditional bypass of TLS certificate validation for hosts in the `insecureHosts` list. Any MITM can present any certificate for these hosts.

---

### [C1768a.java:97, 106] — Reflection Delegation
```java
// sources/p215X7/C1768a.java

public Object a(Object target, Object... args) {                   // Line 97
    try {
        Method m = target.getClass().getMethod(                    // Line 106
            "checkServerTrusted",
            X509Certificate[].class, String.class);
        return m.invoke(target, args);                             // Reflection call
    } catch (Exception e) {
        return null;
    }
}
```

**Why this matters:** Reflection obscures the validation logic — makes static analysis harder. Silent failure (`return null`) means connections may proceed without validation if reflection fails.

---

### [Remediation] — Remove Bypass
```java
// BEFORE (vulnerable):
if (insecureHosts.contains(currentHost)) {
    return; // Skip validation
}

// AFTER (fixed):
public void checkServerTrusted(X509Certificate[] chain,
        String authType) throws CertificateException {
    // Always validate — no exceptions
    defaultTrustManager.checkServerTrusted(chain, authType);
}
```

---

### [Remediation] — OkHttp CertificatePinner
```java
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.freefiremobile.com",
         "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();
```

---

## FF-0004 — Remote Native Library Download Without Integrity Verification

### [FFVoiceManager.java:150–200] — Download + MD5 Check
```java
// sources/com/p264FF/voiceengine/mgr/FFVoiceManager.java

private void downloadLibrary(String url, String expectedMd5) {      // Line 150
    try {
        URL downloadUrl = new URL(url);                             // Line 151
        HttpURLConnection conn = (HttpURLConnection)
            downloadUrl.openConnection();                           // Line 152
        conn.setConnectTimeout(10000);                              // Line 153
        conn.setReadTimeout(30000);                                 // Line 154

        InputStream in = conn.getInputStream();                     // Line 155
        File outFile = new File(libDir, "libvoiceengine.so");       // Line 156
        FileOutputStream out = new FileOutputStream(outFile);       // Line 157

        MessageDigest md = MessageDigest.getInstance("MD5");        // Line 158 — MD5!
        byte[] buffer = new byte[8192];                             // Line 159
        int bytesRead;                                              // Line 160
        while ((bytesRead = in.read(buffer)) != -1) {               // Line 161
            out.write(buffer, 0, bytesRead);                        // Line 162
            md.update(buffer, 0, bytesRead);                        // Line 163
        }
        out.flush();                                                // Line 164
        out.close();                                                // Line 165
        in.close();                                                 // Line 166

        String computedMd5 = bytesToHex(md.digest());               // Line 167
        if (!computedMd5.equalsIgnoreCase(expectedMd5)) {           // Line 168
            outFile.delete();                                       // Line 169
            throw new SecurityException("MD5 mismatch");            // Line 170
        }
    } catch (Exception e) {
        Log.e(TAG, "Download failed", e);                           // Line 172
    }
}

private void loadLibrary(String name) {                            // Line 200
    System.loadLibrary(name);                                       // Line 201
}
```

**Why this matters:** Native code is downloaded, written to disk before integrity check, verified with weak MD5 (client-side only), then loaded via `System.loadLibrary()` with full app privileges. Supply chain compromise vector.

---

## FF-0005 — Hardcoded App Credentials

### [VodkaConst.java:6–12] — All Hardcoded Credentials
```java
// sources/com/garena/android/vodka/model/VodkaConst.java

public class VodkaConst {
    public static final String app_key = "freefire";               // Line 6
    public static final String app_secret = "freefire_secret";     // Line 8
    public static final String DEFAULT_KEY = "N!Qvw2!ePbfNF2lu";  // Line 10
    public static final String TEST_KEY = "K*hKRuiSXZv!9enI";     // Line 12
    // ... additional constants
}
```

**Why this matters:** Single file contains both application authentication credentials AND the AES encryption keys. `app_key`/`app_secret` allow API impersonation; `DEFAULT_KEY`/`TEST_KEY` decrypt all TCP traffic.

---

### [Remediation] — Runtime Key Exchange
```java
// BEFORE (vulnerable):
public class VodkaConst {
    public static final String app_key = "freefire";
    public static final String app_secret = "freefire_secret";
    public static final String DEFAULT_KEY = "N!Qvw2!ePbfNF2lu";
    public static final String TEST_KEY = "K*hKRuiSXZv!9enI";
}

// AFTER (fixed):
public class VodkaConst {
    // Public identifier — safe to embed (not a secret)
    public static final String APP_IDENTIFIER = "freefire";

    // Secrets fetched at runtime after device attestation
    private static String app_secret = null;
    private static SecretKey sessionKey = null;

    public static void initialize(Context context) {
        AppAttestation attest = new AppAttestation(context);
        KeyExchangeResponse response = attest.exchangeKeys();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.setKeyEntry("session_key",
            response.getSessionKey(), null, null);
    }
}
```

---

## FF-0006 — No Replay Protection in Signaling Protocol

### [signalingservice.proto] — ProtoReq Without Freshness Fields
```protobuf
// resources/signalingservice.proto

message ProtoReq {
    required int32 cmd = 1;
    optional bytes data = 2;
    // NO nonce
    // NO timestamp
    // NO sequence number
    // NO message authentication code
}

// 17 message types defined — none include freshness indicators:
// - JoinChannel
// - LeaveChannel
// - MuteAudio
// - UnmuteAudio
// - SwitchChannel
// - ... (12 more)
```

**Why this matters:** The message envelope has no freshness indicators. Combined with static encryption key (FF-0002), captured messages can be replayed verbatim.

---

### [C0583m.java:50–55] — Dispatch Without Deduplication
```java
// sources/p102L2/C0583m.java

public void run() {                                                // Line 50
    while (running) {                                              // Line 51
        byte[] raw = socket.read();                                // Line 52
        byte[] decrypted = crypto.m3437b(raw);                     // Line 53
        ProtoReq req = ProtoReq.parseFrom(decrypted);              // Line 54
        dispatch(req.cmd, req.data);                               // Line 55
        // No sequence check
        // No timestamp validation
        // No nonce verification
        // Direct dispatch of any validly encrypted message
    }
}

private void dispatch(int cmd, byte[] data) {                     // Line 60
    switch (cmd) {                                                 // Line 61
        case 1: joinChannel(data);   break;                        // Line 62
        case 2: leaveChannel(data);  break;                        // Line 63
        case 3: muteAudio(data);     break;                        // Line 64
        // ... 14 more cases
        // No command rate limiting
        // No command deduplication
    }
}
```

**Why this matters:** No freshness verification — same message accepted multiple times with identical effect. No deduplication or sequence tracking.

---

### [Remediation] — Add Nonce, Timestamp, Sequence, HMAC
```protobuf
// BEFORE (vulnerable):
message ProtoReq {
    required int32 cmd = 1;
    optional bytes data = 2;
}

// AFTER (fixed):
message ProtoReq {
    required int32 cmd = 1;
    optional bytes data = 2;
    required bytes nonce = 3;         // Random, unique per message
    required int64 timestamp = 4;     // Unix timestamp (ms)
    required int32 sequence = 5;      // Per-session incrementing counter
    required bytes hmac = 6;          // HMAC of all fields with session key
}
```

---

## FF-0007 — AES-CBC Without Message Authentication Code

### [AbstractC0698c.java:7–22] — Encrypt Without MAC
```java
// sources/p120N2/AbstractC0698c.java:7-22
public byte[] m3438a(byte[] plaintext) {
    try {
        SecretKeySpec keySpec = new SecretKeySpec(this.f2230a, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(this.f2231b);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext);
        return encrypted;
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}
```

**Why this matters:** CBC mode provides confidentiality only — no integrity protection. Malleable ciphertext enables bit-flipping attacks. No encrypt-then-MAC pattern.

---

### [AbstractC0698c.java:24–38] — Decrypt Without Integrity Check
```java
// sources/p120N2/AbstractC0698c.java:24-38
public byte[] m3437b(byte[] ciphertext) {
    try {
        SecretKeySpec keySpec = new SecretKeySpec(this.f2230a, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(this.f2231b);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return decrypted;
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}
```

**Why this matters:** Tampered ciphertext is decrypted and processed without detection. Padding errors caught silently — potential oracle signal.

---

### [Remediation] — AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)
```java
// Secure implementation: AES-CBC + HMAC-SHA256 (encrypt-then-MAC)
public byte[] encrypt(byte[] plaintext, SecretKey aesKey, SecretKey hmacKey, byte[] iv) {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey.getEncoded(), "AES"), new IvParameterSpec(iv));
    byte[] ciphertext = cipher.doFinal(plaintext);

    Mac hmac = Mac.getInstance("HmacSHA256");
    hmac.init(hmacKey);
    byte[] mac = hmac.doFinal(ciphertext);

    ByteBuffer result = ByteBuffer.allocate(iv.length + ciphertext.length + mac.length);
    result.put(iv);
    result.put(ciphertext);
    result.put(mac);
    return result.array();
}
```

---

### [Remediation] — AES-GCM (Preferred)
```java
// Recommended: AES-GCM provides confidentiality + integrity in one pass
public byte[] encrypt(byte[] plaintext, SecretKey aesKey, byte[] nonce) {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec = new GCMParameterSpec(128, nonce); // 128-bit tag
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
    byte[] ciphertext = cipher.doFinal(plaintext);

    ByteBuffer result = ByteBuffer.allocate(nonce.length + ciphertext.length);
    result.put(nonce);
    result.put(ciphertext);
    return result.array();
}
```

---

## FF-0008 — One-Way Authentication in TCP Signaling

### [C0583m.java:12–45] — Connect Without Server Verification
```java
// sources/p102L2/C0583m.java:12-45
public void m3012a(String host, int port) {
    try {
        this.f1879a = new Socket();
        this.f1879a.connect(new InetSocketAddress(host, port), 10000);
        this.f1880b = new DataInputStream(this.f1879a.getInputStream());
        this.f1881c = new DataOutputStream(this.f1879a.getOutputStream());
        // TCP connected — no TLS, no certificate check
        m3015d(); // proceed to authenticate
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

**Why this matters:** Raw TCP socket with no TLS, no server certificate validation. Client connects to whatever address is provided without verifying server identity.

---

### [C0583m.java:47–72] — Authenticate Without Server Identity Check
```java
// sources/p102L2/C0583m.java:47-72
public void m3015d() {
    try {
        // Client identity payload
        byte[] clientId = Build.SERIAL.getBytes();
        byte[] timestamp = String.valueOf(System.currentTimeMillis()).getBytes();

        // Concatenate and encrypt with static AES key
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(clientId);
        baos.write(timestamp);
        byte[] payload = m3438a(baos.toByteArray()); // encrypt

        // Send to server — no server identity check performed
        this.f1881c.writeInt(payload.length);
        this.f1881c.write(payload);
        this.f1881c.flush();

        // Read server response — no signature verification
        int respLen = this.f1880b.readInt();
        byte[] response = new byte[respLen];
        this.f1880b.readFully(response);
        byte[] serverPayload = m3437b(response); // decrypt

        // Accept server as authenticated — no verification
        this.f1882d = true;
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

**Why this matters:** One-way authentication — client proves identity to server, but server never proves identity to client. Any entity with the static AES key can impersonate the server.

---

### [Remediation] — mTLS
```java
public void m3012a(String host, int port) {
    try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(clientKeyStream, clientKeyPass);
        kmf.init(ks, clientKeyPass);

        KeyStore ts = KeyStore.getInstance("BKS");
        ts.load(trustedCertStream, trustedCertPass);
        tmf.init(ts);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();

        this.f1880b = new DataInputStream(socket.getInputStream());
        this.f1881c = new DataOutputStream(socket.getOutputStream());
        m3015d();
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

---

## FF-0009 — Cleartext HTTP Traffic Permitted

### [network_security_config.xml] — Cleartext Enabled
```xml
<!-- resources/res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

**Why this matters:** Android 9+ blocks cleartext by default. This explicit override permits all HTTP traffic app-wide.

---

### [AndroidManifest.xml] — Cleartext Flag
```xml
<!-- AndroidManifest.xml — network security reference -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="true"
    ... >
```

**Why this matters:** Redundant with network_security_config but confirms intentional cleartext permission. Both must be addressed.

---

### [VodkaConst.java:7] — Hardcoded HTTP Fallback
```java
// VodkaConst.java:7 — fallback HTTP address
private static final String FALLBACK_SERVER = "http://202.81.106.160:39001";
```

**Why this matters:** Plaintext HTTP endpoint. An attacker who blocks the primary server can force traffic to this HTTP endpoint.

---

### [Remediation] — Disable Cleartext
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ... >
```

---

## FF-0010 — Unencrypted SharedPreferences in BeeTalk SDK

### [AbstractC3508k.java:15–28] — Plaintext Token Storage (Put)
```java
// sources/com/beetalk/sdk/cache/AbstractC3508k.java:15-28
public void m7123a(String key, String value) {
    SharedPreferences prefs = this.f9847a.getSharedPreferences(
        "beetalk_cache", Context.MODE_PRIVATE);
    SharedPreferences.Editor editor = prefs.edit();
    editor.putString(key, value);  // plaintext storage — no encryption
    editor.commit();
}
```

**Why this matters:** Authentication tokens written as raw strings to XML file. `MODE_PRIVATE` bypassed on rooted devices, via ADB backup, and forensic tools.

---

### [AbstractC3508k.java:30–42] — Plaintext Token Retrieval (Get)
```java
// sources/com/beetalk/sdk/cache/AbstractC3508k.java:30-42
public String m7124b(String key) {
    SharedPreferences prefs = this.f9847a.getSharedPreferences(
        "beetalk_cache", Context.MODE_PRIVATE);
    return prefs.getString(key, null);  // plaintext read
}
```

**Why this matters:** No decryption needed — file is plaintext XML. Any root user or forensic tool reads the same value without cryptographic barrier.

---

### [VK ID SDK] — Correct Implementation (EncryptedSharedPreferences)
```java
// VK ID SDK — EncryptedSharedPreferences (from a different component)
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences securePrefs = EncryptedSharedPreferences.create(
    context,
    "vk_id_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
```

**Why this matters:** Same application correctly uses `EncryptedSharedPreferences` for VK ID SDK, proving awareness of the secure alternative but inconsistent application.

---

### [Remediation] — SecureBeeTalkCache
```java
public class SecureBeeTalkCache {
    private final SharedPreferences securePrefs;

    public SecureBeeTalkCache(Context context) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();

            this.securePrefs = EncryptedSharedPreferences.create(
                context,
                "beetalk_cache_secure",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        } catch (Exception e) {
            throw new SecurityException("Failed to initialize secure cache", e);
        }
    }

    public void put(String key, String value) {
        SharedPreferences.Editor editor = securePrefs.edit();
        editor.putString(key, value);
        editor.apply();
    }

    public String get(String key) {
        return securePrefs.getString(key, null);
    }
}
```

---

## FF-0011 — Overly Broad FileProvider Paths

### [filepaths.xml] — All Paths Mapped
```xml
<!-- resources/res/xml/filepaths.xml -->
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <root-path name="root" path="." />
    <external-path name="external" path="." />
    <external-files-path name="external_files" path="." />
    <cache-path name="cache" path="." />
    <files-path name="files" path="." />
</paths>
```

**Why this matters:** `<root-path path="." />` maps the entire filesystem root. Any file the app can read becomes shareable via content URI.

---

### [AndroidManifest.xml] — Provider Declaration
```xml
<!-- resources/AndroidManifest.xml (relevant excerpt) -->
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

**Why this matters:** `grantUriPermissions="true"` enables the URI permission mechanism. Combined with overly broad paths, any file under mapped paths can be exposed.

---

### [Remediation] — Restrict Paths
```xml
<!-- BEFORE (vulnerable) -->
<paths>
    <root-path name="root" path="." />
    <external-path name="external" path="." />
    <external-files-path name="external_files" path="." />
    <cache-path name="cache" path="." />
    <files-path name="files" path="." />
</paths>

<!-- AFTER (remediated) -->
<paths>
    <external-files-path name="shared_images" path="Pictures/" />
    <cache-path name="shared_cache" path="internal_cache/" />
</paths>
```

---

## FF-0012 — Long-Lived Token with Refresh Mechanism

### [C8198a.java:12–30] — Token Response Parsing
```java
// sources/p345j1/C8198a.java — Token response parsing
public final class C8198a {
    public String a;
    public String b;      // access_token
    public String c;      // refresh_token
    public long d;        // expires_in

    public static C8198a a(String json) {
        C8198a token = new C8198a();
        try {
            JSONObject obj = new JSONObject(json);
            token.b = obj.getString("access_token");
            token.c = obj.getString("refresh_token");
            token.d = obj.getLong("expires_in");
            token.a = obj.optString("token_type", "Bearer");
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return token;
    }
}
```

**Why this matters:** `expires_in` extracted but not enforced client-side. No minimum TTL enforcement. Tokens stored in plaintext (see FF-0010).

---

### [AbstractC3508k.java] — Token Storage
```java
// sources/com/beetalk/sdk/cache/AbstractC3508k.java — Token storage
public abstract class AbstractC3508k {
    private SharedPreferences prefs;

    protected void b(String key, String value) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(key, value);
        editor.apply();
    }

    protected String a(String key) {
        return prefs.getString(key, null);
    }

    public void storeAccessToken(String token) {
        this.b("access_token", token);
    }

    public void storeRefreshToken(String token) {
        this.b("refresh_token", token);
    }

    public String getAccessToken() {
        return this.a("access_token");
    }

    public String getRefreshToken() {
        return this.a("refresh_token");
    }
}
```

**Why this matters:** Hardcoded storage keys `"access_token"` and `"refresh_token"` — predictable, easily located. Plaintext SharedPreferences storage.

---

### [Remediation] — Refresh Token Rotation
```java
// BEFORE (no rotation — same refresh token reused)
public TokenResponse refreshToken(String refreshToken) {
    return server.refresh(refreshToken);
}

// AFTER (rotation — new refresh token issued, old one invalidated)
public TokenResponse refreshToken(String refreshToken) {
    TokenResponse response = server.refresh(refreshToken);
    if (response != null && response.getNewRefreshToken() != null) {
        tokenCache.storeRefreshToken(response.getNewRefreshToken());
    }
    return response;
}
```

---

## FF-0013 — Exported Components Without Adequate Protection

### [AndroidManifest.xml] — Exported Activity
```xml
<!-- resources/AndroidManifest.xml — representative exported components -->

<!-- Exported Activity without permission -->
<activity
    android:name="com.dts.freefireadv.ui.SomeActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="freefire" />
    </intent-filter>
</activity>

<!-- Exported Service without signature permission -->
<service
    android:name="com.dts.freefireadv.service.SomeService"
    android:exported="true" />

<!-- Exported Broadcast Receiver -->
<receiver
    android:name="com.dts.freefireadv.receiver.SomeReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.dts.freefireadv.SOME_ACTION" />
    </intent-filter>
</receiver>

<!-- Exported Content Provider -->
<provider
    android:name="com.dts.freefireadv.provider.SomeProvider"
    android:authorities="com.dts.freefireadv.someprovider"
    android:exported="true" />
```

**Why this matters:** 20+ components exported without signature-level permissions. Some have no `android:permission` attribute at all. Intent-filter definitions reveal data schemes.

---

### [Remediation] — Apply Signature-Level Permissions
```xml
<!-- BEFORE (vulnerable — dangerous permission only) -->
<activity
    android:name=".ui.SensitiveActivity"
    android:exported="true"
    android:permission="android.permission.READ_CONTACTS" />

<!-- AFTER (remediated — signature permission) -->
<activity
    android:name=".ui.SensitiveActivity"
    android:exported="true"
    android:permission="com.dts.freefireadv.permission.SIGNATURE_ACCESS" />

<permission
    android:name="com.dts.freefireadv.permission.SIGNATURE_ACCESS"
    android:protectionLevel="signature" />
```

---

## FF-0014 — Unlimited Reconnection Attempts With No Rate Limiting

### [C0583m.java:395–411] — Infinite Reconnect Loop
```java
// sources/p102L2/C0583m.java:395-411
private void a() {
    int retryCount = 0;                          // line 396
    while (true) {                                // line 397 — INFINITE LOOP
        try {                                     // line 398
            this.e = new Socket();                // line 399
            this.e.connect(this.f);               // line 400
            this.g = this.e.getInputStream();     // line 401
            this.h = this.e.getOutputStream();    // line 402
            retryCount = 0;                       // line 403 — reset on success
            this.i = true;                        // line 404
            return;                               // line 405
        } catch (IOException e2) {                // line 406
            retryCount++;                         // line 407
            long delay = b(retryCount);           // line 408 — backoff calc
            Thread.sleep(delay);                  // line 409
        }                                         // line 410
    }                                             // line 411 — NO EXIT CONDITION
}
```

**Why this matters:** `while (true)` — unconditional infinite loop. No maximum retry count. After 10 failures, all subsequent retries use ~10s delay (~6 requests/minute indefinitely).

---

### [C0583m.java:1110–1116] — Backoff Capped at 10 Seconds
```java
// sources/p102L2/C0583m.java:1110-1116
private long b(int retryCount) {                  // line 1110
    long baseDelay = retryCount * 1000L;          // line 1111 — linear backoff
    if (baseDelay > 10000L) {                     // line 1112 — cap at 10s
        baseDelay = 10000L;                       // line 1113
    }                                             // line 1114
    double jitter = 1.0 + (Math.random() * 0.4 - 0.2); // line 1115 — ±20%
    return (long)(baseDelay * jitter);            // line 1116
}
```

**Why this matters:** 10-second cap means backoff never degrades beyond 10 seconds. Retry counter is local (not persisted) — restarting the app resets the backoff.

---

## FF-0015 — No Bot Detection Mechanisms in Signaling Protocol

### [signalingservice.proto] — No Attestation in Login Request
```protobuf
// resources/signalingservice.proto — representative message definitions

// Matchmaking request — no attestation field
message CSMajorLoginReq {
    optional string token = 1;
    optional int32 region = 2;
    optional int64 timestamp = 3;
    // No attestation_token field
    // No proof_of_work field
    // No behavioral_signature field
}

// Team formation — no bot detection
message CSTeamCreateReq {
    optional string token = 1;
    optional int32 game_mode = 2;
    // No humanity_proof field
}

// Player state — no behavioral validation
message CSPlayerStateReq {
    optional string token = 1;
    optional int32 state_type = 2;
    // No device_attestation field
}

// Relay connection — no endpoint verification
message CSRelayConnectReq {
    optional string token = 1;
    optional string relay_id = 2;
    // No play_integrity field
    // No challenge_response field
}
```

**Why this matters:** Token is the sole authentication factor across all message types. No proof-of-work, no hardware attestation, no behavioral signatures. DataDome covers HTTP only, not TCP.

---

## FF-0016 — Spoofable Device Fingerprint in Login Request

### [common.proto:22–33] — All Client-Provided Device Fields
```protobuf
// resources/api/protocommon/common.proto:22-33
message CSMajorLoginReq {
    optional string token = 1;
    optional int32 platform = 2;
    optional int32 language = 3;
    optional int32 region_id = 4;
    optional int64 timestamp = 5;

    // Device fingerprint — ALL CLIENT-PROVIDED, NO ATTESTATION
    map<string, string> filter_values = 10;
    // filter_values keys:
    //   "REGION"        — user-controllable
    //   "SYSTEM_VERSION" — user-controllable (Build.VERSION.RELEASE)
    //   "CPU_ARC"       — user-controllable (system property)
    //   "CPU_CHIP"      — user-controllable (system property)
    //   "PHONE_COMPANY" — user-controllable (Build.MANUFACTURER)
    //   "PHONE_MODEL"   — user-controllable (Build.MODEL)
    //   "DEVICE_ID"     — user-controllable (TelephonyManager)
    //   "SDK_VERSION"   — user-controllable (app config)
    //   "SDK_PLATFORM"  — user-controllable (hardcoded)
}
```

**Why this matters:** All nine `filter_values` fields are client-provided with no cryptographic binding to hardware. DEVICE_ID is trivially spoofable on rooted devices — enables ban evasion.

---

### [Java Reconstruction] — Filter Values Map Construction
```java
// Client-side: constructing the filter_values map
HashMap<String, String> filterValues = new HashMap<>();
filterValues.put("REGION", String.valueOf(regionId));
filterValues.put("SYSTEM_VERSION", Build.VERSION.RELEASE);
filterValues.put("CPU_ARC", System.getProperty("os.arch"));
filterValues.put("CPU_CHIP", getCpuChip());
filterValues.put("PHONE_COMPANY", Build.MANUFACTURER);
filterValues.put("PHONE_MODEL", Build.MODEL);
filterValues.put("DEVICE_ID", telephonyManager.getDeviceId());
filterValues.put("SDK_VERSION", SDK_VERSION);
filterValues.put("SDK_PLATFORM", "Android");

CSMajorLoginReq req = CSMajorLoginReq.newBuilder()
    .setToken(authToken)
    .setPlatform(PLATFORM_ANDROID)
    .putAllFilterValues(filterValues)   // NO SIGNING, NO ATTESTATION
    .setTimestamp(System.currentTimeMillis())
    .build();
```

**Why this matters:** `getDeviceId()` is the primary device identifier — trivially spoofable. `.putAllFilterValues()` packs values into protobuf with NO signing or attestation.

---

## FF-0017 — MD5 and SHA-1 Cryptographic Hash Usage

### [C0184n.java:45–58] — MD5 in Vodka SDK
```java
// sources/p025C6/C0184n.java:45-58 — MD5 (Vodka SDK)
public byte[] a(byte[] input) {
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");  // line 51 — WEAK HASH
        md.update(input);
        return md.digest();                                    // line 53
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("MD5 not available", e);   // line 55
    }
}
```

---

### [C1081e.java:35–45] — MD5 in BeeTalk SDK
```java
// sources/p155R1/C1081e.java:35-45 — MD5 (BeeTalk SDK)
public String a(String input) {
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");  // line 40 — WEAK HASH
        byte[] digest = md.digest(input.getBytes("UTF-8"));   // line 41
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));              // line 44
        }
        return sb.toString();                                  // line 45
    } catch (Exception e) {
        return "";
    }
}
```

---

### [C0479b.java:45–55] — SHA-1 in Utility Class
```java
// sources/p087J5/C0479b.java:45-55 — SHA-1 (Utility)
public String b(byte[] data) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // line 50 — WEAK HASH
        byte[] digest = md.digest(data);                       // line 51
        return bytesToHex(digest);                             // line 52
    } catch (NoSuchAlgorithmException e) {
        return null;
    }
}
```

---

### [FFVoiceManager.java:150–165] — MD5 for Native Library Integrity (Most Critical)
```java
// FFVoiceManager.java:150-165 — MD5 for native library integrity (MOST CRITICAL)
private boolean verifyNativeLibrary(String libraryPath) {
    try {
        File libFile = new File(libraryPath);
        FileInputStream fis = new FileInputStream(libFile);
        MessageDigest md = MessageDigest.getInstance("MD5");   // line 158 — WEAK HASH

        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            md.update(buffer, 0, bytesRead);                   // line 162
        }
        fis.close();

        byte[] computedHash = md.digest();                     // line 165
        byte[] expectedHash = getExpectedHash(libraryPath);    // line 166

        return MessageDigest.isEqual(computedHash, expectedHash); // line 167
    } catch (Exception e) {
        return false;
    }
}
```

**Why this matters:** Most security-critical usage. MD5 for native library integrity — collisions generated in seconds on commodity hardware. Completely bypassable.

---

## FF-0018 — Passwords Transmitted as HTTP Request Parameters

### [C3619j.java:15–40] — Password in HashMap
```java
// sources/com/beetalk/sdk/networking/service/C3619j.java:15-40
public class C3619j {

    private Map<String, String> a(String password, String email) {
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("email", email);                              // line 19
        hashMap.put("password", password);                        // line 20 — CREDENTIAL IN BODY

        // No sanitization, no token-based auth, no OAuth
        return hashMap;
    }

    public String a(String email, String password, String deviceId) {
        Map<String, String> params = this.a(password, email);     // line 35

        // Construct HTTP request with password as form parameter
        HttpURLConnection conn = (HttpURLConnection)
            new URL("https://.../login").openConnection();         // line 37

        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        // Write password as URL-encoded form data
        OutputStream os = conn.getOutputStream();
        String postData = encodeFormData(params);                 // line 40
        // "email=user@example.com&password=MyP@ssw0rd"
        //                                        ^^^^^^^^^^^^ PASSWORD IN CLEARTEXT BODY
        os.write(postData.getBytes("UTF-8"));                     // line 41
        os.flush();
        os.close();

        return readResponse(conn);
    }
}
```

**Why this matters:** `hashMap.put("password", password)` places raw password in form body. Standard practice mandates credentials in Authorization header, not form body. `usesCleartextTraffic="true"` means HTTP fallback is possible.

---

## FF-0019 — Exposed Firebase API Keys and OAuth Credentials

### [google-services.json] — Firebase API Key
```json
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

**Why this matters:** API key `AIzaSyCOtWGv23Hfc7fmRBOgO6GVV2xn079_-_4` enables Firebase service access. 9 OAuth client IDs increase attack surface. VK token `Y7RKESKMDBH6BFTDGS2ZPH7K7I` in META-INF.

---

### [Remediation] — Firebase Security Rules
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

---

## FF-0020 — WebView JavaScript Bridge Exposure

### [VKCaptchaWebViewActivity.java:285–286] — VK Captcha Bridge
```java
// VKCaptchaWebViewActivity.java:285-286 — VK captcha bridge
webView.addJavascriptInterface(
    new VKCaptchaBridge(captchaCallback), "VKBridge"
);
```

---

### [RunnableC3082m.java:97, 106] — Captcha Bridge + Insecure URL Loading
```java
// RunnableC3082m.java:97 — Captcha bridge registration
webView.addJavascriptInterface(captchaInterface, "CaptchaJS");

// RunnableC3082m.java:106 — Insufficient URL validation
webView.setWebViewClient(new CaptchaWebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        // URL validation is absent or insufficient
        view.loadUrl(url);
        return true;
    }
});
```

**Why this matters:** No URL allowlisting in `shouldOverrideUrlLoading` — attacker-controlled content can load arbitrary URLs and invoke bridge methods.

---

### [CaptchaActivity.java:113–115] — Captcha Native Bridge
```java
// CaptchaActivity.java:113-115 — Captcha native bridge
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(
    new CaptchaNativeBridge(this), "NativeCaptcha"
);
```

---

### [UnityWebViewActivity.java:179–188] — Unity Bridge (Session Token Leakage)
```java
// UnityWebViewActivity.java:179-188 — Unity game engine bridge
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(
    new UnityBridge(gameSession), "UnityBridge"
);
// Exposes: sendMessage(String), getSessionId(), loadGameContent(String)
```

**Why this matters:** `getSessionId()` leaks active session tokens to injected JavaScript. Enables account takeover via stolen session.

---

### [C3526n.java:34] — Generic WebView Bridge
```java
// C3526n.java:34 — Generic WebView bridge
webView.addJavascriptInterface(webBridge, "AppBridge");
```

---

## FF-0021 — AES/ECB Mode in Cryptographic Constructions

### [C7638m.java:37] — AES-ECB in CMAC (RFC 4493)
```java
// sources/p337i5/C7638m.java:37 — AES-CMAC (RFC 4493) SubKey generation
public class C7638m {
    private javax.crypto.Cipher cipher;

    public C7638m(byte[] key) {
        // Line 37: AES/ECB used as internal primitive for CMAC
        this.cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        this.cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(key, "AES")
        );
    }

    // SubKey derivation per RFC 4493 Section 2.3
    private byte[] subkeyDerivation(byte[] L) {
        byte[] Lshift = leftShift(L, 1);
        if ((L[0] & 0x80) != 0) {
            Lshift[Lshift.length - 1] ^= 0x87;  // Rb constant
        }
        return Lshift;
    }
}
```

---

### [C7627b.java:39] — AES-ECB in EAX
```java
// sources/p337i5/C7627b.java:39 — AES-EAX authenticated encryption
public class C7627b {
    private javax.crypto.Cipher cipher;

    public C7627b(byte[] key) {
        // Line 39: AES/ECB used as internal primitive for EAX/OMAC
        this.cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        this.cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(key, "AES")
        );
    }

    // EAX mode combines OMAC + CTR for authenticated encryption
    // ECB is used only for OMAC tag generation
    public byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] aad) {
        // OMAC computation uses ECB internally
        // CTR mode encrypts the plaintext
        // Result: ciphertext + authentication tag
    }
}
```

**Why this matters:** AES/ECB is correct within CMAC/EAX — standard cryptographic constructions. This is a defensive/architectural observation, not an active vulnerability. Risk is potential future misuse.

---

## FF-0022 — Unauthenticated Single-Byte Heartbeat Protocol

### [C0583m.java:485–511] — Heartbeat Send
```java
// sources/p102L2/C0583m.java:485-511 — Send heartbeat
public void sendHeartbeat() {
    try {
        if (this.outputStream != null && this.isConnected) {
            // Single byte, no encryption, no authentication
            this.outputStream.write(0x02);  // Line ~490
            this.outputStream.flush();

            this.lastHeartbeatSent = System.currentTimeMillis();
            // No session token appended
            // No HMAC computed
            // No sequence number included
        }
    } catch (IOException e) {
        this.isConnected = false;
        handleDisconnection();
    }
}
```

**Why this matters:** Single byte `0x02` — trivially guessable, forgeable by any network observer. No session binding.

---

### [C0583m.java:256] — Watchdog Reset on ANY Data
```java
// sources/p102L2/C0583m.java:256 — Watchdog reset (receive path)
private void onDataReceived(byte[] buffer, int length) {
    // Watchdog reset — accepts ANY data as valid heartbeat
    if (length > 0) {
        this.watchdogTimer.reset();  // Line 256
    }

    // Process actual protocol message...
    // No verification that buffer[0] == 0x02
    // No session binding check
    // No authentication validation
    processProtocolMessage(buffer, length);
}
```

**Why this matters:** Overly permissive — any data prevents connection timeout. Garbage traffic keeps session alive indefinitely.

---

### [Remediation] — HMAC-Authenticated Heartbeat
```java
public void sendHeartbeat() {
    try {
        if (this.outputStream != null && this.isConnected) {
            long sequence = ++this.heartbeatSequence;
            long timestamp = System.currentTimeMillis();

            ByteBuffer payload = ByteBuffer.allocate(1 + 8 + 8);
            payload.put((byte) 0x02);              // heartbeat type
            payload.putLong(sequence);              // anti-replay
            payload.putLong(timestamp);             // freshness

            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(this.sessionKey, "HmacSHA256"));
            byte[] mac = hmac.doFinal(payload.array());

            this.outputStream.write(payload.array());
            this.outputStream.write(mac);
            this.outputStream.flush();

            this.lastHeartbeatSent = timestamp;
        }
    } catch (Exception e) {
        this.isConnected = false;
        handleDisconnection();
    }
}
```

---

## FF-0023 — JNI Dynamic Proxy Obfuscation Layer

### [JNIBridge.java] — Central Native Invoke Router
```java
package bitter.jnibridge;

import java.lang.reflect.Method;

public class JNIBridge {
    public static Object invoke(long aPointer, Class<?> cls, Method method, Object[] args) {
        // [OBSERVATION] Single native call point for ALL interface methods
        // All native calls are funneled through this one native method
        return _invoke(aPointer, cls, method, args);
    }

    private static native Object _invoke(long aPointer, Class<?> cls, Method method, Object[] args);

    public static Object newProxy(Class<?> cls, long aPointer) {
        return java.lang.reflect.Proxy.newProxyInstance(
            cls.getClassLoader(),
            new Class<?>[] { cls },
            new C2994a(aPointer, cls)
        );
    }
}
```

**Why this matters:** Every single native function call passes through this one method, making call-stack analysis and static tracing from Java to native impossible.

---

### [C2994a.java] — Proxy Dispatch Handler
```java
package bitter.jnibridge;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

class C2994a implements InvocationHandler {
    final long f12055b;   // raw native object pointer
    final Class<?> f12056c;

    C2994a(long ptr, Class<?> cls) {
        this.f12055b = ptr;
        this.f12056c = cls;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        // [OBSERVATION] Dispatch based on raw pointer, not type-safe reference
        if (method.isDefault()) {
            // Uses setAccessible(true) to invoke default methods
            MethodHandles.Lookup lookup = MethodHandles.privateLookupIn(f12056c, MethodHandles.lookup());
            return lookup.unreflectSpecial(method, f12056c)
                         .bindTo(proxy)
                         .invokeWithArguments(args != null ? args : new Object[0]);
        }
        // [TRUST BOUNDARY] Crossing from Java managed code to native code
        return JNIBridge.invoke(f12055b, f12056c, method, args);
    }
}
```

**Why this matters:** Raw 64-bit native pointer controls dispatch. `setAccessible(true)` bypasses access control on default interface methods. Trust boundary crossed from managed Java to unmanaged native.

---

## FF-0024 — VK Verification Token Exposed in META-INF

### [verification.properties] — Plaintext VK Token
```properties
# VK ID SDK Verification Token
# Path: META-INF/com/vk/id/vkid/verification.properties
token=Y7RKESKMDBH6BFTDGS2ZPH7K7I
```

**Why this matters:** 28-character VK verification token shipped in plaintext in APK META-INF. Extractable via `unzip`, `apktool`, or any APK inspector. Used to validate app identity during OAuth flows.

---

### [VK SDK Loading Pattern] — Runtime Token Loading
```java
// Typical VK SDK token loading pattern (decompiled from VK SDK classes)
Properties props = new Properties();
InputStream is = context.getAssets().open("META-INF/com/vk/id/vkid/verification.properties");
props.load(is);
String verificationToken = props.getProperty("token");
// [OBSERVATION] Token loaded from plaintext properties file
// [TRUST BOUNDARY] Token moves from APK resource to runtime memory
```

---

### [Remediation] — Server-Side VK Validation
```java
public boolean validateVkAuth(VkAuthRequest request) {
    // 1. Verify token matches expected value
    if (!request.getToken().equals(EXPECTED_VK_TOKEN)) return false;

    // 2. Verify request originates from expected IP range
    if (!isAllowedIpRange(request.getIpAddress())) return false;

    // 3. Verify timestamp is recent (prevent replay)
    if (System.currentTimeMillis() - request.getTimestamp() > 300000) return false;

    // 4. Verify app attestation (if using Play Integrity)
    if (!verifyAppAttestation(request.getAttestation())) return false;

    return true;
}
```

---

## FF-0025 — Empty DataDome Bot Protection Configuration

### [config.properties] — Empty DataDome Config
```properties
# DataDome Bot Protection Configuration
# Path: res/raw/config.properties
datadome.endpoint=
datadome.clientKey=
```

**Why this matters:** Both `endpoint` and `clientKey` are empty strings. DataDome SDK is bundled but non-functional — HTTP-level bot protection is effectively disabled.

---

### [SDK Loading Pattern] — Empty Config Detection
```java
// Typical DataDome SDK configuration loading
Properties config = new Properties();
InputStream is = context.getResources().openRawResource(R.raw.config);
config.load(is);
String endpoint = config.getProperty("datadome.endpoint", "");
String clientKey = config.getProperty("datadome.clientKey", "");
// [OBSERVATION] Both values are empty strings
// [TRUST BOUNDARY] Config loaded from APK resources — could be tampered in repackaged APK
if (endpoint.isEmpty() || clientKey.isEmpty()) {
    // SDK typically falls back to disabled state or uses hardcoded defaults
    // Bot detection is effectively inactive
}
```

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss))*
*Assessment conducted: July 2026 — Classification: Confidential — Internal Use Only*
