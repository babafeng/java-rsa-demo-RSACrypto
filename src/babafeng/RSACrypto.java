package babafeng;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
* @author babafeng
* @date : 2016年12月28日 上午11:05:06
*/

public class RSACrypto {
	public static HashMap<String, Object> generateKeys() throws NoSuchAlgorithmException {
		HashMap<String, Object> map = new HashMap<String, Object>();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey pubkey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey prikey = (RSAPrivateKey) keyPair.getPrivate();
		map.put("PubKey", pubkey);
		map.put("PriKey", prikey);
		return map;
	}

	public static HashMap<String, Object> generateKeys(int nbits) throws NoSuchAlgorithmException {
		HashMap<String, Object> map = new HashMap<String, Object>();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(nbits);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey pubkey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey prikey = (RSAPrivateKey) keyPair.getPrivate();
		map.put("PubKey", pubkey);
		map.put("PriKey", prikey);
		return map;
	}

	public static RSAPublicKey getPublicKey(String modulus, String exponent)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		BigInteger mod = new BigInteger(modulus);
		BigInteger exp = new BigInteger(exponent);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		return (RSAPublicKey) keyFactory.generatePublic(keySpec);

	}

	public static RSAPrivateKey getPrivateKey(String modulus, String exponent)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		BigInteger mod = new BigInteger(modulus);
		BigInteger exp = new BigInteger(exponent);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
		return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

	}

	public static String[] splitString(String string, int len) {
		int integer = string.length() / len;
		int mod = string.length() % len;
		int tmp = 0;
		if (mod != 0) {
			tmp = 1;
		}
		String[] strings = new String[integer + tmp];
		String str = "";
		for (int i = 0; i < integer + tmp; i++) {
			if (i == integer + tmp - 1 && mod != 0) {
				str = string.substring(i * len, i * len + mod);
			} else {
				str = string.substring(i * len, i * len + len);
			}
			strings[i] = str;
		}
		return strings;
	}

	public static byte[][] splitArray(byte[] data, int len) {
		int integer = data.length / len;
		int mod = data.length % len;
		int tmp = 0;
		if (mod != 0) {
			tmp = 1;
		}
		byte[][] arrays = new byte[integer + tmp][];
		byte[] arr;
		for (int i = 0; i < integer + tmp; i++) {
			arr = new byte[len];
			if (i == integer + tmp - 1 && mod != 0) {
				System.arraycopy(data, i * len, arr, 0, mod);
			} else {
				System.arraycopy(data, i * len, arr, 0, len);
			}
			arrays[i] = arr;
		}
		return arrays;
	}

	public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {
		byte[] bcd = new byte[asc_len / 2];
		int j = 0;
		for (int i = 0; i < (asc_len + 1) / 2; i++) {
			bcd[i] = asc_to_bcd(ascii[j++]);
			bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));
		}
		return bcd;
	}

	public static byte asc_to_bcd(byte asc) {
		byte bcd;

		if ((asc >= '0') && (asc <= '9'))
			bcd = (byte) (asc - '0');
		else if ((asc >= 'A') && (asc <= 'F'))
			bcd = (byte) (asc - 'A' + 10);
		else if ((asc >= 'a') && (asc <= 'f'))
			bcd = (byte) (asc - 'a' + 10);
		else
			bcd = (byte) (asc - 48);
		return bcd;
	}

	public static String bcd2Str(byte[] bytes) {
		char temp[] = new char[bytes.length * 2], val;

		for (int i = 0; i < bytes.length; i++) {
			val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
			temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

			val = (char) (bytes[i] & 0x0f);
			temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
		}
		return new String(temp);
	}

	public static String encrypt(RSAPublicKey pubkey, String message) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubkey);

		int key_len = pubkey.getModulus().bitLength() / 8;

		String[] messages = splitString(message, key_len);
		String encodes = "";

		for (String s : messages) {
			encodes += bcd2Str(cipher.doFinal(s.getBytes()));
		}
		return encodes;
	}

	public static String encrypt(RSAPrivateKey pubkey, String message) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubkey);

		int key_len = pubkey.getModulus().bitLength() / 8;

		String[] messages = splitString(message, key_len);
		String encodes = "";

		for (String s : messages) {
			encodes += bcd2Str(cipher.doFinal(s.getBytes()));
		}
		return encodes;
	}

	public static String decrypt(RSAPrivateKey prikey, String encode) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, prikey);

		int key_len = prikey.getModulus().bitLength() / 8;
		byte[] bytes = encode.getBytes();
		byte[] bcd = ASCII_To_BCD(bytes, bytes.length);

		String decodes = "";
		byte[][] arrays = splitArray(bcd, key_len);
		for (byte[] arr : arrays) {
			decodes += new String(cipher.doFinal(arr));
		}
		return decodes;
	}

	public static String decrypt(RSAPublicKey prikey, String encode) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, prikey);

		int key_len = prikey.getModulus().bitLength() / 8;
		byte[] bytes = encode.getBytes();
		byte[] bcd = ASCII_To_BCD(bytes, bytes.length);

		String decodes = "";
		byte[][] arrays = splitArray(bcd, key_len);
		for (byte[] arr : arrays) {
			decodes += new String(cipher.doFinal(arr));
		}
		return decodes;
	}

	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		// 初始化RSA公钥和私钥
		HashMap<String, Object> keys = generateKeys(512);

		// 获得公钥和私钥
		RSAPublicKey publicKey = (RSAPublicKey) keys.get("PubKey");
		RSAPrivateKey privateKey = (RSAPrivateKey) keys.get("PriKey");

		// 使用公钥加密
		System.out.println(encrypt(publicKey, "123456789"));

		// 使用私钥解密
		System.out.println(decrypt(privateKey, encrypt(publicKey, "123456789")));

		// 使用私钥加密
		System.out.println(encrypt(privateKey, "123456789"));

		// 使用公钥解密
		System.out.println(decrypt(publicKey, encrypt(privateKey, "123456789")));

	}
}