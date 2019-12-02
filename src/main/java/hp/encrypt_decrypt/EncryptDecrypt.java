package hp.encrypt_decrypt;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

//import org.apache.log4j.Logger;
//import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
//import org.springframework.beans.factory.annotation.Autowired;


import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class EncryptDecrypt 
{

//	private static Logger logger = Logger.getLogger("util.CRMWorkerThread");
//	private static String algorithm = "DESede";
//	private static String algorithm = "PBEWithMD5AndDES";
//	private static String algorithm = "DESede/ECB/PKCS5Padding";
	private static String algorithm = "PBEWithMD5AndDES/CBC/PKCS5Padding";
//	private static String algorithm = "PBEWithMD5AndDES/ECB/PKCS5Padding";
	
    private static Key key = null;
    private static Cipher cipher = null;
    private static BASE64Encoder base64encoder = new BASE64Encoder();
    private static BASE64Decoder base64decoder = new BASE64Decoder();
    private static SecretKeySpec skeySpec = null;
	
	private static EncryptDecrypt theInstance = new EncryptDecrypt();
	
//	public static final String STRING_TO_DECRYPT = "EnUfeZcH9xFFf4KEXMu3Jg==";
//	public static final String STRING_TO_DECRYPT = "tbQcqwFRaZLih5YtoMCEV/5rlv2FjRdw";
	public static final String STRING_TO_DECRYPT = "YySYCRCDlwxTufv+S7Ghb8Rh8jFcvEY60gsI6ux9u7E=";
//	public static final String STRING_TO_DECRYPT = "3AhD7DEMb7uTPM0N6no7HRoBBb2LvqOA";
//	public static final String STRING_TO_DECRYPT = "Rkrl/ZTTdRxtiincyC8veSrQLKikrX8I";
//	public static final String STRING_TO_ENCRYPT = "Dev@aEtL@$123";
//	public static final String STRING_TO_ENCRYPT = "Administrator";
	public static final String STRING_TO_ENCRYPT = "Cc2861@29051983";
	public static final String STRING_KEY = "Rkrl/ZTTdRxtiincyC8veSrQLKikrX8I";
	
	
	public static EncryptDecrypt getInstance()  {
		return theInstance;
	}
	
//	@Autowired
	static StandardPBEStringEncryptor encryptor;

	
	public EncryptDecrypt() {
	    
	    try {
            setUp();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
	
	public void setEncryptor(StandardPBEStringEncryptor encryptor) {
		EncryptDecrypt.encryptor = encryptor;
	}

	public StandardPBEStringEncryptor getEncryptor() {
		return EncryptDecrypt.encryptor;
	}

    private static void setUp() throws Exception {
   	 	//key = KeyGenerator.getInstance(algorithm).generateKey();
   	 	//String keyString = base64encoder.encode(key.getEncoded());
   	 	//System.out.println("keyString : " + keyString);

    	String keyString = "Rkrl/ZTTdRxtiincyC8veSrQLKikrX8I";
    	byte[] keyB = base64decoder.decodeBuffer(keyString);
//    	key = new SecretKeySpec(keyB, "DESede");
//    	key = new SecretKeySpec(keyB, EncryptDecrypt.algorithm);
    	key = new SecretKeySpec(keyB, EncryptDecrypt.getInstance().algorithm);

    	
    	//skeySpec = new SecretKeySpec(key, algorithm);
   	 	//String keyString = "Rkrl/ZTTdRxtiincyC8veSrQLKikrX8I";
   	 	//key = base64decoder.decodeBuffer(keyString);

    	
//        cipher = Cipher.getInstance("DESede");
//        cipher = Cipher.getInstance(EncryptDecrypt.algorithm);
        cipher = Cipher.getInstance(EncryptDecrypt.getInstance().algorithm);
        
    	
        //cipher = Cipher.getInstance(algorithm);
    }
    
    public static String encrypt2(String value) {
        return encryptor.encrypt(value);
    }
    
    public static String decrypt2(String value) {
        return encryptor.decrypt(value);
    }
    
    public static String encrypt(String input) throws InvalidKeyException, 
           BadPaddingException,
           IllegalBlockSizeException {
    	cipher.init(Cipher.ENCRYPT_MODE, key);
    	byte[] inputBytes = input.getBytes();
    	byte[] encryptionBytes = cipher.doFinal(inputBytes);
    	String encodedString = base64encoder.encode(encryptionBytes);
    	
    	return encodedString;
    }

    @SuppressWarnings("restriction")
	public static String decrypt(String encryptedString) throws InvalidKeyException, 
           BadPaddingException,
           IllegalBlockSizeException, IOException, NullPointerException {
    	
//    	logger.debug("EncryptionDecryption : Beginning decrypt()");    	
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	
//    	logger.debug("EncryptionDecryption : Inside decrypt() --> Beginning decodeBuffer()");   
    	byte[] encryptedBytes = base64decoder.decodeBuffer(encryptedString);
    	
//    	logger.debug("Encrypted string: " +encryptedString);
//    	logger.debug("Decoded encrypted Bytes: " + encryptedBytes);
    	
//    	logger.debug("EncryptionDecryption : Inside decrypt() --> Beginning doFinal()");
    	byte[] recoveredBytes = cipher.doFinal(encryptedBytes);
    	
//    	logger.debug("EncryptionDecryption : Inside decrypt() --> Setting recovered string");
    	String recovered = new String(recoveredBytes);
    	
    	/*System.out.println("Original decrypt: " + recovered);
        String newDec = encrypt2(recovered);
        System.out.println("Encrypted with NEW encryptor: " + newDec);
        String plainText = encryptor.decrypt(newDec);
        System.out.println("Decrypted : " + plainText);
        */
        
  //  	logger.debug("EncryptionDecryption : Ending decrypt() and returning String");   
    	return recovered;
    }
    
    public static void main ( String []  args )
    {
    	EncryptDecrypt encryptionDecryption;
    	StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
//        encryptor.setAlgorithm("DESede");
//        encryptor.setAlgorithm("PBEWithMD5AndDES");
//        encryptor.setAlgorithm("DESede/ECB/PKCS5Padding");
//        encryptor.setAlgorithm("PBEWithMD5AndDES/CBC/PKCS5Padding");
//        encryptor.setAlgorithm("PBEWithMD5AndDES/ECB/PKCS5Padding");

        
        // Set the password to what was in the EncryptionDecrclass
        encryptor.setPassword(STRING_KEY);
		System.out.println("Public Key : " + STRING_KEY);
		
        EncryptDecrypt.getInstance().setEncryptor(encryptor);
		encryptionDecryption = EncryptDecrypt.getInstance();

		System.out.println("String to encrypt : " + STRING_TO_ENCRYPT);
		String encrypted = EncryptDecrypt.encrypt2(STRING_TO_ENCRYPT);
		System.out.println("String encrypted : " + encrypted);
		
//		String decrypt = EncryptDecrypt.decrypt2("o2+bTqvf5SGI4YdIeQrEfwVHmZJ+pE9Z");
//		String decrypt = EncryptDecrypt.decrypt2("A80G604FUTM973zpG9nz3WiFCyGVHW5N");
		System.out.println("String to decrypt : " + STRING_TO_DECRYPT);
		String decrypt = EncryptDecrypt.decrypt2(STRING_TO_DECRYPT);
		System.out.println("String decrypted : " + decrypt);
		
		try 
		{
			encrypted = encryptionDecryption.decrypt2(encrypted);
		}
		catch (NullPointerException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 		
    }
		
}
