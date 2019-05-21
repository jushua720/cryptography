package cryptography;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ecdsa {
  
  private static final String base58Table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  private static final BigInteger base = BigInteger.valueOf(58);
  private static final String curveName = "P-256";
  
  
  // @check: Names
  
  public static PrivateKey getPrivateKey(String key) throws Exception {
    
    BigInteger bintKey = new BigInteger(key, 16);
    
    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName); 
    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(bintKey, parameterSpec); 
    
    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");       
    PrivateKey pKey = keyFactory.generatePrivate(keySpec);
    
    return pKey;
  }
  
  public static PublicKey getPublicKeyFromPrivate(PrivateKey pkey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName); 
    
    ECPoint Q = parameterSpec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) pkey).getD());
    ECPublicKeySpec keySpec = new ECPublicKeySpec(Q, parameterSpec);
    
    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
    PublicKey pubKey = keyFactory.generatePublic(keySpec);
    
    return pubKey;
  } 
  
  
  public static String[] getXYUsingPrivateKey(String privKey) throws Exception {
    String pointXY[] = new String[2];
    
    PublicKey pubKeyGo = getPublicKeyFromPrivate(getPrivateKey(privKey));
    
    ECPublicKey pubKey = (ECPublicKey)pubKeyGo;
    
    pointXY[0] = pubKey.getW().getAffineX().toString(10);
    pointXY[1] = pubKey.getW().getAffineY().toString(10);
    
    return pointXY;
    
  }
  
  public PublicKey getPublicKeyFromXY(String pointX, String pointY) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    BigInteger x = new BigInteger(pointX);
    BigInteger y = new BigInteger(pointY);
    
    java.security.spec.ECPoint pointXY = new java.security.spec.ECPoint(x, y);
    ECNamedCurveParameterSpec curveParamSpec = ECNamedCurveTable.getParameterSpec(curveName);
    KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
    ECCurve curveEC = curveParamSpec.getCurve();
    
    java.security.spec.EllipticCurve curveElliptic = EC5Util.convertCurve(curveEC, curveParamSpec.getSeed());
    java.security.spec.ECParameterSpec ecParamSpec = EC5Util.convertSpec(curveElliptic, curveParamSpec);
    
    java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(pointXY, ecParamSpec);
    
    return (ECPublicKey) fact.generatePublic(keySpec);
  }
  
  
  public static byte[] signMessage(PrivateKey privKey, String msg) throws Exception {
    
    Signature signature = Signature.getInstance("SHA1withECDSA");    
    signature.initSign(privKey);
    
    byte[] byteMsg = msg.getBytes("UTF-8");
    signature.update(byteMsg);
    
    byte[] signedMsg = signature.sign();
    
    System.out.println("Signature: " + new BigInteger(1, signedMsg).toString(16));
    
    return signedMsg;
  }
  
  // @note: combine R S functions into one 
  public static BigInteger getRFromSignature(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
  }
  
  public static BigInteger getSFromSignature(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    int startS = startR + 2 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }
  
  
  public static String hashString(String s) throws NoSuchAlgorithmException { 
    MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
    byte[] hash = msgDigest.digest(s.getBytes(StandardCharsets.UTF_8));
    
    // @note: clean / leave
    
    /*
     for (int i = 0; i < hash.length; i++) {
     System.out.print(hash[i]);
     System.out.println("sha256"); 
     }  
     */
    
    String strHash = b58encode(hash);
    
    return strHash;
  }
  
  public static String[] generateKeys() throws Exception {
    String keyPair[] = new String[2];
    
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    
    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    keyGenerator.initialize(parameterSpec);
    KeyPair keys = keyGenerator.generateKeyPair();
    
    
    String privKey = pKeyToString(keys.getPrivate());
    String pubKey = pubKeyToString(keys.getPublic());
    
    keyPair[0] = privKey;
    keyPair[1] = pubKey;
    
    return keyPair;  
  }
  
  
  // @note: optimize key to string into 1 function for priv and public
  public static String pubKeyToString(PublicKey pubKey) throws Exception  {
    
    byte[] byteKey = pubKey.getEncoded(); 
    String strKey = b58encode(byteKey); 
    
    return strKey;
  }
  public static String pKeyToString(PrivateKey privKey) throws GeneralSecurityException {
    
    KeyFactory factory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec keySpec = factory.getKeySpec(privKey, PKCS8EncodedKeySpec.class);
    
    byte[] byteKey = keySpec.getEncoded();
    String strKey = b58encode(byteKey);
    
    return strKey;
  }
  
  
  public static String b58encode(byte[] s) {
    BigInteger bint = new BigInteger(1, s);
    StringBuffer buffer = new StringBuffer();
    
    while (bint.compareTo(base) >= 0) {
      
      BigInteger mod = bint.mod(base);
      buffer.insert(0, base58Table.charAt(mod.intValue()));
      bint = bint.subtract(mod).divide(base);
      
    }
    
    buffer.insert(0, base58Table.charAt(bint.intValue()));
    
    for (byte inputString : s) {
      if (inputString == 0)
        buffer.insert(0, base58Table.charAt(0));
      else
        break;
    }
    return buffer.toString();
  }
  
  
  public static byte[] b58decode(String str) {
    
    int leadingZeros = 0;
    byte[] byteInt = decodeToBigInteger(str).toByteArray();
    boolean stripSignByte = byteInt.length > 1 && byteInt[0] == 0 && byteInt[1] < 0;
    
    for (int i = 0; str.charAt(i) == base58Table.charAt(0); i++) {
      leadingZeros++;
    }
    
    byte[] decodedStr = new byte[byteInt.length - (stripSignByte ? 1 : 0) + leadingZeros];
    System.arraycopy(byteInt, stripSignByte ? 1 : 0, decodedStr, leadingZeros, decodedStr.length - leadingZeros);
    
    return decodedStr;
  }
  
  
  public static BigInteger decodeToBigInteger(String str) {
    
    BigInteger bInt = BigInteger.valueOf(0);
    
    for (int i=0; i <= str.length()-1 ; i++) {
      
      int index = base58Table.indexOf(str.charAt(i));
      if (index == -1) {
        throw new RuntimeException("Bad character " + str.charAt(i) + " at " + i);
      }
      bInt = bInt.add(BigInteger.valueOf(index).multiply(base.pow(str.length() - 1 - i)));
    }
    
    return bInt;
  }
  
  
  public static String signMessage(String privKey, String msg) throws Exception {
    
    byte[] encodedPriv = b58decode(privKey);
    
    EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPriv);
    
    // @ note: or change factory to kf everywhere
    KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
    PrivateKey priv = factory.generatePrivate(keySpec);
    
    Signature ecdsa = Signature.getInstance("SHA1withECDSA");    
    
    ecdsa.initSign(priv);
    
    byte[] byteMsg = msg.getBytes("UTF-8");
    ecdsa.update(byteMsg);
    
    byte[] signedMsg = ecdsa.sign();
    
    return b58encode(signedMsg);
    
  }
  
  public static boolean verifySignature(String pubKey, String signature, String msg) throws Exception {
    
    byte[] byteSignature = b58decode(signature);
    
    byte[] encodedPub = b58decode(pubKey);
    
    Signature ecdsa = Signature.getInstance("SHA1withECDSA");    
    
    EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPub);
    KeyFactory factory = KeyFactory.getInstance("ECDSA");
    
    ecdsa.initVerify(factory.generatePublic(keySpec));   
    ecdsa.update(msg.getBytes("UTF-8"));
    
    return ecdsa.verify(byteSignature);
  }
  
  public static String encryptMessage(String pubKey, String msg) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
    
    byte[] byteMsg = msg.getBytes("UTF-8");
    byte[] encryptedMsg;
    
    byte[] encodedKey = b58decode(pubKey);
    
    EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
    KeyFactory factory = KeyFactory.getInstance("ECDSA");
    
    Cipher cipher = Cipher.getInstance("ECIES", "BC");
    cipher.init(Cipher.ENCRYPT_MODE, factory.generatePublic(keySpec));
    
    encryptedMsg = new byte[cipher.getOutputSize(byteMsg.length)];
    
    //@check: nuzni li jeti strocki
    int encLength = cipher.update(byteMsg, 0, byteMsg.length, encryptedMsg, 0);
    encLength += cipher.doFinal(encryptedMsg, encLength);
    
    return b58encode(encryptedMsg); 
    
  }
  
  public static String decryptMessage(String privKey, String msg) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
    
    byte[] decodedKey = b58decode(privKey);
    
    EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
    KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
    PrivateKey pKey = kf.generatePrivate(keySpec);
    
    byte[] byteMsg = b58decode(msg);
    
    byte[] decryptedMsg;
    
    Cipher cipher = Cipher.getInstance("ECIES", "BC");
    cipher.init(Cipher.DECRYPT_MODE, pKey);
    
    
    decryptedMsg = new byte[cipher.getOutputSize(byteMsg.length)];
    int decryptLength = cipher.update(byteMsg, 0, byteMsg.length, decryptedMsg, 0);
    decryptLength += cipher.doFinal(decryptedMsg, decryptLength);  
    
    return new String(decryptedMsg, "UTF-8");
    
  } 
  
  
  
  public static void main(String[] args) throws Exception {
    String[] keys = new String[2];
    keys = generateKeys();
    
    String plainTxt = "plain text message";
    
    String encryptedMsg = encryptMessage(keys[1], plainTxt);
    String decryptedMsg = decryptMessage(keys[0], encryptedMsg);
    
    // @note: signature is byte but use String and check empty string => arg to verifySignature function
    
    String signedMsg = signMessage(keys[0], plainTxt); 
    Boolean isVerified = verifySignature(keys[1], signedMsg, plainTxt); 
    
    System.out.println("Generated Keys");
    System.out.println("Public Key        : " + keys[1]);
    System.out.println("Private Key       : " + keys[0]);
    
    System.out.println("\nEncryption / Decryption");
    System.out.println("Encrypted Message : " + encryptedMsg);
    System.out.println("Decrypted Message : " + decryptedMsg);
    
    System.out.println("\nSignature               ");
    System.out.println("Signed Message    : " + signedMsg);
    System.out.println("Verification      : " + isVerified);
    System.out.println();
    
    // @notice: GoLang generated private key
    String privKey = "e2673adf00cfa383040845b295a37cc3a627bda7ff7a74a148b9528f5c65a557";
    String hash = hashString("message");
    
    PrivateKey privateKey = getPrivateKey(privKey);
    byte[] signedMsgGo = signMessage(privateKey, hash);
    
    
    
    BigInteger R = getRFromSignature(signedMsgGo);
    BigInteger S = getSFromSignature(signedMsgGo);
    
    String pointXY[] = new String[2];
    pointXY = getXYUsingPrivateKey(privKey);
    
    System.out.println("Signed Message: " + new BigInteger(1, signedMsgGo).toString(16));
    
    System.out.println("\nGoLang Generated Private Key");
    System.out.println("R                 : " + R.toString());
    System.out.println("S                 : " + S.toString());
    System.out.println();
    System.out.println("X                 : " + pointXY[0]);
    System.out.println("Y                 : " + pointXY[1]);
    
  }
  
}
