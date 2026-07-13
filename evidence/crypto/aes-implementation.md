# AES Implementation â€” Evidence

**Evidence for: FF-0002, FF-0007**

---

## Encryption (AbstractC0698c.m3438a)

```java
public static byte[] m3438a(byte[] data) throws Exception {
    SecretKeySpec key = new SecretKeySpec(
        VodkaConst.DEFAULT_KEY.getBytes("UTF-8"), "AES"
    );
    IvParameterSpec iv = new IvParameterSpec(
        VodkaConst.TEST_KEY.getBytes("UTF-8")
    );
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return cipher.doFinal(data);
}
```

## Decryption (AbstractC0698c.m3437b)

```java
public static byte[] m3437b(byte[] encrypted) throws Exception {
    SecretKeySpec key = new SecretKeySpec(
        VodkaConst.DEFAULT_KEY.getBytes("UTF-8"), "AES"
    );
    IvParameterSpec iv = new IvParameterSpec(
        VodkaConst.TEST_KEY.getBytes("UTF-8")
    );
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    return cipher.doFinal(encrypted);
}
```

## Key Constants (VodkaConst.java)

```java
public static String DEFAULT_KEY = "N!Qvw2!ePbfNF2lu";  // 16 bytes
public static String TEST_KEY    = "K*hKRuiSXZv!9enI";   // 16 bytes
```

## Analysis

| Property | Value | Security Implication |
|----------|-------|---------------------|
| Algorithm | AES-128 | Adequate key size |
| Mode | CBC | No integrity protection (FF-0007) |
| Padding | PKCS5 | Vulnerable to padding oracle (FF-0007) |
| Key | Static string | No forward secrecy (FF-0002) |
| IV | Static string | Identical plaintexts â†’ identical ciphertexts |
| MAC | None | Ciphertext malleable (FF-0007) |
| KDF | None | Raw string bytes used directly |

---

*Evidence version: 2.0 Â· Last updated: July 2026*

---

*Author: swift.dev ([@yassinfaresgb-oss](https://github.com/yassinfaresgb-oss)) · Repository: [FreeFire-OB54-Redwood](https://github.com/yassinfaresgb-oss/FreeFire-OB54-Redwood)*
*Assessment conducted: July 2026 · Classification: Confidential — Internal Use Only*
