package hp.encrypt_decrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Encriptacion2 {
	
	//public Cifrado() {
	// super();
	// }
	
	public static void main(String[] args) throws Exception {
		String encript=encripta("ayuda");
		System.out.println("Encriptado "+encript);
		String decrypt=desencripta(encript);
		System.out.println("Yasta "+decrypt);
	}
	
	public static String encripta(String s){
		Cipher ecipher;
		try {
			SecretKey key = KeyGenerator.getInstance("DES").generateKey();
			ecipher = Cipher.getInstance("DES");
			ecipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] utf8 = s.getBytes("UTF8");
			byte[] enc = ecipher.doFinal(utf8);
			return new sun.misc.BASE64Encoder().encode(enc);
		}catch (javax.crypto.BadPaddingException e) { }
		catch (IllegalBlockSizeException e) { }
		catch (UnsupportedEncodingException e) { }
		catch (java.io.IOException e) { }
		catch(NoSuchPaddingException l){l.printStackTrace();}
		catch(NoSuchAlgorithmException i){i.printStackTrace();}
		catch(InvalidKeyException p){p.printStackTrace();}
		return "";
	}
	
	public static String desencripta(String s){
		Cipher ecipher;
		System.out.println("Valor pasado "+s);
		try {
			ecipher = Cipher.getInstance("DES");
			SecretKey key = KeyGenerator.getInstance("DES").generateKey();
			ecipher.init(Cipher.DECRYPT_MODE, key);
			byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(s);
			byte[] utf8 = ecipher.doFinal(dec);
			return new String(utf8, "UTF8");
		} catch (javax.crypto.BadPaddingException e) {e.printStackTrace(); }
		catch (IllegalBlockSizeException e) {e.printStackTrace(); }
		catch (UnsupportedEncodingException e) {e.printStackTrace(); }
		catch (java.io.IOException e) { e.printStackTrace();}
		catch(NoSuchPaddingException l){l.printStackTrace();}
		catch(NoSuchAlgorithmException i){i.printStackTrace();}
		catch(InvalidKeyException p){p.printStackTrace();}
		return null;
	}
	
}