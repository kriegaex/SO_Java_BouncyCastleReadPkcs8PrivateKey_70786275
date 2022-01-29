package de.scrum_master.stackoverflow.q70786275;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class Application {
  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    InputStream privateKeyInputStream = new FileInputStream("src/main/resources/key.k8");
    PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyInputStream, StandardCharsets.UTF_8));
    Object pemObject = pemParser.readObject();
    if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
      PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemObject;
      String passphrase = "123456";
      InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());
      PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(pkcs8Prov); // Fails here on OpenJ9
      System.out.println("Private key algorithm: " + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
      System.out.println("Has public key: " + privateKeyInfo.hasPublicKey());
    }
  }
}
