import java.io.*;
import java.net.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.spec.SecretKeySpec;
public class Test{

  	public static String encryptRSA(byte[] plainText, PublicKey publicKey) throws Exception {
  		 Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
  		 encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

  		 byte[] cipherText = encryptCipher.doFinal(plainText);

  		 return Base64.getEncoder().encodeToString(cipherText);
   }

   public static String decryptRSA(String cipherText, PrivateKey privateKey) throws Exception {
  			 byte[] bytes = Base64.getDecoder().decode(cipherText);

  			 Cipher decriptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
  			 decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

  			 return new String(decriptCipher.doFinal(bytes));
  	 }

  public static void main(String args[]){
    try{
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(1024);
      KeyPair kp;
      kp = kpg.generateKeyPair();
      PublicKey pub;
      PrivateKey pvt;
      kp = kpg.generateKeyPair();
      pub = kp.getPublic();
      pvt = kp.getPrivate();
      String str = "[B@27ada7f2";
      String cipher = encryptRSA(str.getBytes(), pub);
      System.out.println(cipher);
      String plain = decryptRSA(cipher, pvt);
      System.out.println(plain);
      plain = "C4F0kVdr9Im1237V+wcUyw==";
      SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
      // get base64 encoded version of the key
      String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
      System.out.println("new key = "+encodedKey);

      byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
      // rebuild key using SecretKeySpec
      SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
      //PrivateKey aes_key = KeyFactory.getInstance("AES").generatePrivate(new X509EncodedKeySpec(plain.getBytes()));
      //key_pub = encoder.encodeToString(pub.getEncoded());
      //key_priv = encoder.encodeToString(pvt.getEncoded());
    }catch(Exception e){e.printStackTrace();}
  }
}
