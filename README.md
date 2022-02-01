# SO_Java_BouncyCastleReadPkcs8PrivateKey_70786275

Reproduces problem described in https://stackoverflow.com/q/70786275/1082681.

See also https://github.com/bcgit/bc-java/issues/1099.

The current version solves the problem by not just adding BouncyCastle (BC) to the global list of security providers,
but by also explicitly setting same security provider when constructing an input decryptor provider later: 

```java
BouncyCastleProvider securityProvider = new BouncyCastleProvider();
Security.addProvider(securityProvider);
// (...)
InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder()
  // Explicitly setting security provider helps to avoid ambiguities which otherwise can cause problems,
  // e.g. on OpenJ9 JVMs. See https://github.com/bcgit/bc-java/issues/1099#issuecomment-1025253004.
  .setProvider(securityProvider)
  .build(passphrase.toCharArray());
```

If you wish to reproduce the original problem, simply comment out `.setProvider(securityProvider)`, then run the main
class on both OpenJ9 and another JVM such as Oracle Hotspot. The output will differ like this:

**Oracle JVM:**

```text
[SUN version 17, SunRsaSign version 17, SunEC version 17, SunJSSE version 17, SunJCE version 17, SunJGSS version 17, SunSASL version 17, XMLDSig version 17, SunPCSC version 17, JdkLDAP version 17, JdkSASL version 17, SunMSCAPI version 17, SunPKCS11 version 17, BC version 1.7]
------------------------------------------------------------
1232
1329
1.2.840.113549.1.5.13
------------------------------------------------------------
1232
Cipher.2.16.840.1.101.3.4.1.42, mode: decryption, algorithm from: BC
1218
------------------------------------------------------------
Private key algorithm: 1.2.840.113549.1.1.1
Has public key: false
```

**OpenJ9 JVM:**

```text
[SUN version 17, SunRsaSign version 17, SunEC version 17, SunJSSE version 17, SunJCE version 17, SunJGSS version 17, SunSASL version 17, XMLDSig version 17, SunPCSC version 17, JdkLDAP version 17, JdkSASL version 17, SunMSCAPI version 17, SunPKCS11 version 17, BC version 1.7]
------------------------------------------------------------
1232
1329
1.2.840.113549.1.5.13
------------------------------------------------------------
1232
Cipher.2.16.840.1.101.3.4.1.42, mode: decryption, algorithm from: SunJCE
1232
------------------------------------------------------------
Exception in thread "main" org.bouncycastle.pkcs.PKCSException: unable to read encrypted data: failed to construct sequence from byte[]: Extra data detected in stream
  at org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(Unknown Source)
  at de.scrum_master.stackoverflow.q70786275.Application.main(Application.java:70)
Caused by: java.lang.IllegalArgumentException: failed to construct sequence from byte[]: Extra data detected in stream
  at org.bouncycastle.asn1.ASN1Sequence.getInstance(ASN1Sequence.java:101)
  at org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(PrivateKeyInfo.java:82)
  ... 2 more
```

Please note the differences on the last two output lines before the exception. 
