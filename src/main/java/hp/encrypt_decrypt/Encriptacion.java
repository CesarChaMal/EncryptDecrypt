package hp.encrypt_decrypt;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

public class Encriptacion {
    public Encriptacion() {
        super();
    }

    public static String encrypt(String pass, String ruta, String file) {
        Cipher ecipher;
        try {
            SecretKey key = KeyGenerator.getInstance("DES").generateKey();
            guardaKey(key, ruta, file);
            ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] utf8 = pass.getBytes("UTF8");
			byte[] enc = ecipher.doFinal(utf8);
			return new sun.misc.BASE64Encoder().encode(enc);
		} catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String ruta, String file, String s) {
        Cipher ecipher;
        SecretKey key = readKey(ruta, file);
        if (key == null) return null;
        try {
            ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.DECRYPT_MODE, key);
            byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(s);
            byte[] utf8 = ecipher.doFinal(dec);
            return new String(utf8, "UTF8");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        SecretKey secretKey = keyGen.generateKey();
        String file = "usuario";
//		String ruta="/root/Oracle/Middleware/GenKey";
        String ruta = "c:/temp/";
        //guardaKey(secretKey,file, ruta);
        //readKey(ruta, file);
//		String pass="Mi password";
        String pass = "$Almldapint001";
        String encrStr = encrypt(pass, ruta, file);
        System.out.println("Encriptado: " + encrStr);
        String decrStr = decrypt(ruta, file, encrStr);
        System.out.println("Desencriptado: " + decrStr);
		/*
		Cipher cifrador= Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
		String mensaje = "Este el texto que se va a cifrar";
		byte[] mensajeCifrado = cifrador.doFinal(mensaje.getBytes(), 0, mensaje.getBytes().length);
		 */
    }

    public static void imprimeKey(SecretKey key) {
        System.out.println("**** Impresion **");
        System.out.println("Algoritmo " + key.getAlgorithm());
        System.out.println("To String " + key.toString());
    }

    public static void guardaKey(SecretKey key, String ruta, String fileName) {
        imprimeKey(key);
        String fl = ruta + "/" + fileName + ".key";
        System.out.println("Ruta hasta el archivo " + fl);
        try {
            FileOutputStream fos = new FileOutputStream(fl);
            byte[] kb = key.getEncoded();
            fos.write(kb);
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey readKey(String ruta, String fileName) {
        String fl = ruta + "/" + fileName + ".key";
        KeySpec ks = null;
        SecretKey ky = null;
        SecretKeyFactory kf = null;
        try {
            FileInputStream fis = new FileInputStream(fl);
            int kl = fis.available();
            byte[] kb = new byte[kl];
            fis.read(kb);
            fis.close();
            ks = new DESKeySpec(kb);
            kf = SecretKeyFactory.getInstance("DES");
            ky = kf.generateSecret(ks);
            imprimeKey(ky);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (java.security.spec.InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return ky;
    }

}