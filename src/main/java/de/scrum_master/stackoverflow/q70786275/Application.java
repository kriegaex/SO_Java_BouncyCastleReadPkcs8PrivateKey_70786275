package de.scrum_master.stackoverflow.q70786275;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
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

      // These are all the same on OpenJ9 and other JVM types
      System.out.println(encryptedPrivateKeyInfo.getEncryptedData().length);
      System.out.println(encryptedPrivateKeyInfo.getEncoded().length);
      System.out.println(encryptedPrivateKeyInfo.getEncryptionAlgorithm().getAlgorithm());
      System.out.println("------------------------------------------------------------");

      String passphrase = "123456";
      InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());

      // Gather and print some data, mimicking what happens in PKCS8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo
      // These are all the same on OpenJ9 and other JVM types
      InputDecryptor decryptor = pkcs8Prov.get(encryptedPrivateKeyInfo.getEncryptionAlgorithm());
      System.out.println(decryptor.getClass());
      ByteArrayInputStream encIn = new ByteArrayInputStream(encryptedPrivateKeyInfo.getEncryptedData());
      System.out.println(encIn.available());
      InputStream decrytorInputStream = decryptor.getInputStream(encIn);
      System.out.println(decrytorInputStream.getClass());
      // Here OpenJ9 yields a byte[1232], while other JVM types yield byte[1218]
      byte[] readAll = Streams.readAll(decrytorInputStream);
      System.out.println(readAll.length);
      System.out.println("------------------------------------------------------------");

      PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(pkcs8Prov); // Fails here on OpenJ9
      System.out.println("Private key algorithm: " + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
      System.out.println("Has public key: " + privateKeyInfo.hasPublicKey());
    }
  }
}
