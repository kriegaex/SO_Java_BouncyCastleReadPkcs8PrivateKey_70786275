package de.scrum_master.stackoverflow.q70786275;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;

public class Application {
  public static void main(String[] args) throws IOException, PKCSException, OperatorCreationException {
    new Application().decryptPrivateKey();
  }

  public Application() {
    Security.addProvider(new BouncyCastleProvider());
  }

  public void decryptPrivateKey() throws IOException, PKCSException, OperatorCreationException {
    InputStream privateKeyInputStream = getPrivateKeyInputStream(); // reads the key file from classpath and share as DataStream
    System.out.println("InputStreamExists --> " + privateKeyInputStream.available());
    PEMParser pemParser = new PEMParser(new InputStreamReader(privateKeyInputStream));
    Object pemObject = pemParser.readObject();
    if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
      // Handle the case where the private key is encrypted.
      PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemObject;
      String passphrase = "123456";
      InputDecryptorProvider pkcs8Prov =
        new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());
      PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(pkcs8Prov); // fails here
      System.out.println("Private key algorithm: " + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
      System.out.println("Has public key: " + privateKeyInfo.hasPublicKey());
    }
  }

  private InputStream getPrivateKeyInputStream() {
    InputStream resourceAsStream = null;
    String privateKeyMode = "x";
    String privateKeyPath = "src/main/resources/key.k8";
    if ("local".equals(privateKeyMode)) {
      resourceAsStream = this.getClass().getResourceAsStream(privateKeyPath);
    }
    else {
      File keyFile = new File(privateKeyPath);
      System.out.printf("Key file found in %s mode. FileName : %s, Exists : %s%n", privateKeyMode, keyFile.getName(), keyFile.exists());
      try {
        resourceAsStream = new FileInputStream(keyFile);
      }
      catch (FileNotFoundException e) {
        e.printStackTrace();
      }
    }
    return resourceAsStream;
  }
}
