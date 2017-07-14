package com.lq.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

public class RSASecurityUtil {
	private static final String KEY_ALGORITHM = "RSA";
	private static final int KEY_SIZE = 4096;
	private static final int ENCRYPT_BlOCK_SIZE = KEY_SIZE / 8 - 11;
	private static final int DECRYPT_BLOCK_SIZE = KEY_SIZE / 8;

	public static KeyPair getKeyPair() throws Exception {
		KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		kpGenerator.initialize(KEY_SIZE);
		KeyPair keyPair = kpGenerator.generateKeyPair();
		return keyPair;
	}

	/**
	 * 加密
	 * 
	 * @param encryptStr
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String encryptStr, String publicKey) throws Exception {
		byte[] publicKeyBytes = Base64.decodeBase64(publicKey);
		byte[] encryptBytes = encryptStr.getBytes("UTF-8");

		if (encryptBytes.length <= ENCRYPT_BlOCK_SIZE) {
			return Base64.encodeBase64String(encrypt(encryptBytes, publicKeyBytes));
		} else {
			byte[] buffer = null;
			byte[] blockBytes = new byte[ENCRYPT_BlOCK_SIZE];

			int index = ((encryptBytes.length - 1) / ENCRYPT_BlOCK_SIZE) + 1;

			for (int i = 0; i < index; i++) {
				if (i == (index - 1)) {
					blockBytes = new byte[ENCRYPT_BlOCK_SIZE];
				}
				int startIndex = i * ENCRYPT_BlOCK_SIZE;
				int endIndex = startIndex + ENCRYPT_BlOCK_SIZE;
				blockBytes = ArrayUtils.subarray(encryptBytes, startIndex, endIndex);
				if (buffer == null) {
					buffer = encrypt(blockBytes, publicKeyBytes);
				} else {
					buffer = ArrayUtils.addAll(buffer, encrypt(blockBytes, publicKeyBytes));
				}

			}
			return Base64.encodeBase64String(buffer);
		}
	}

	/**
	 * 解密
	 * 
	 * @param decryptStr
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String decryptStr, String privateKey) throws Exception {
		byte[] privateKeyBytes = Base64.decodeBase64(privateKey);

		byte[] decryptBytes = Base64.decodeBase64(decryptStr);

		if (decryptBytes.length <= DECRYPT_BLOCK_SIZE) {
			return new String(decrypt(decryptBytes, privateKeyBytes), "UTF-8");
		} else {
			byte[] buffer = null;

			int index = ((decryptBytes.length - 1) / DECRYPT_BLOCK_SIZE) + 1;
			byte[] blockBytes = new byte[DECRYPT_BLOCK_SIZE];
			for (int i = 0; i < index; i++) {
				if (i == index - 1) {
					blockBytes = new byte[DECRYPT_BLOCK_SIZE];
				}
				int startIndex = i * DECRYPT_BLOCK_SIZE;
				int endIndex = startIndex + DECRYPT_BLOCK_SIZE;
				blockBytes = ArrayUtils.subarray(decryptBytes, startIndex,
						endIndex > decryptBytes.length ? decryptBytes.length : endIndex);
				if (buffer == null) {
					buffer = decrypt(blockBytes, privateKeyBytes);
				} else {
					buffer = ArrayUtils.addAll(buffer, decrypt(blockBytes, privateKeyBytes));
				}
			}
			return new String(buffer, "UTF-8");
		}
	}

	/**
	 * 加密
	 * 
	 * @param encryptStr
	 * @param publicKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] encryptBytes, byte[] publicKeyBytes) throws Exception {
		PublicKey publicKey = RSASecurityUtil.codeToPublicKey(publicKeyBytes);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] enBytes = cipher.doFinal(encryptBytes);
		return enBytes;
	}

	/**
	 * 解密
	 * 
	 * @param decryptStr
	 * @param privateKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] decrypt, byte[] privateKeyBytes) throws Exception {
		PrivateKey privateKey = RSASecurityUtil.codeToPrivateKey(privateKeyBytes);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] resultBytes = cipher.doFinal(decrypt);
		return resultBytes;
	}

	/**
	 * 解密
	 * 
	 * @param dncrypteStr
	 * @param privateKeyBytes
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String decryptStr, byte[] privateKeyBytes) throws Exception {
		PrivateKey privateKey = RSASecurityUtil.codeToPrivateKey(privateKeyBytes);
		// 加密/解密算法/工作模式/填充方式
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptBytes = Base64.decodeBase64(decryptStr);
		byte[] resultBytes = cipher.doFinal(decryptBytes);
		return new String(resultBytes, "UTF-8");
	}

	public static String privateKeyToXml(PrivateKey key) {
		if (!RSAPrivateCrtKey.class.isInstance(key)) {
			return null;
		}
		RSAPrivateCrtKey priKey = (RSAPrivateCrtKey) key;

		StringBuilder sb = new StringBuilder();
		sb.append("<RSAKeyValue>");
		sb.append("<Modulus>").append(Base64.encodeBase64String(removeMSZero(priKey.getModulus().toByteArray())))
				.append("</Modulus>");
		sb.append("<Exponent>")
				.append(Base64.encodeBase64String(removeMSZero(priKey.getPublicExponent().toByteArray())))
				.append("</Exponent>");
		sb.append("<P>").append(Base64.encodeBase64String(removeMSZero(priKey.getPrimeP().toByteArray())))
				.append("</P>");
		sb.append("<Q>").append(Base64.encodeBase64String(removeMSZero(priKey.getPrimeQ().toByteArray())))
				.append("</Q>");
		sb.append("<DP>").append(Base64.encodeBase64String(removeMSZero(priKey.getPrimeExponentP().toByteArray())))
				.append("</DP>");
		sb.append("<DQ>").append(Base64.encodeBase64String(removeMSZero(priKey.getPrimeExponentQ().toByteArray())))
				.append("</DQ>");
		sb.append("<InverseQ>")
				.append(Base64.encodeBase64String(removeMSZero(priKey.getCrtCoefficient().toByteArray())))
				.append("</InverseQ>");
		sb.append("<D>").append(Base64.encodeBase64String(removeMSZero(priKey.getPrivateExponent().toByteArray())))
				.append("</D>");
		sb.append("</RSAKeyValue>");
		return sb.toString();
	}

	public static String publicKeyToXml(PublicKey key) {
		if (!RSAPublicKey.class.isInstance(key)) {
			return null;
		}
		RSAPublicKey pubKey = (RSAPublicKey) key;
		StringBuilder sb = new StringBuilder();

		sb.append("<RSAKeyValue>");
		sb.append("<Modulus>").append(Base64.encodeBase64String(removeMSZero(pubKey.getModulus().toByteArray())))
				.append("</Modulus>");
		sb.append("<Exponent>")
				.append(Base64.encodeBase64String(removeMSZero(pubKey.getPublicExponent().toByteArray())))
				.append("</Exponent>");
		sb.append("</RSAKeyValue>");
		return sb.toString();
	}

	public static PublicKey codeToPublicKey(String publicKeyStr) throws Exception {
		byte[] publicKeyBytes = Base64.decodeBase64(publicKeyStr);
		// x.509,是x500那套网络协议（好像是目录协议吧）的一个子集，专门定义了在目录访问中需要身份认证的证书的格式。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		return keyFactory.generatePublic(keySpec);
	}

	public static PrivateKey codeToPrivateKey(String privateKeyStr) throws Exception {
		byte[] privateKeyBytes = Base64.decodeBase64(privateKeyStr);
		// PKCS#8：描述私有密钥信息格式，该信息包括公开密钥算法的私有密钥以及可选的属性集等。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey keyPrivate = keyFactory.generatePrivate(keySpec);
		return keyPrivate;
	}

	public static PublicKey codeToPublicKey(byte[] publicKey) throws Exception {
		// x.509,是x500那套网络协议（好像是目录协议吧）的一个子集，专门定义了在目录访问中需要身份认证的证书的格式。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		return keyFactory.generatePublic(keySpec);
	}

	public static PrivateKey codeToPrivateKey(byte[] privateKey) throws Exception {
		// PKCS#8：描述私有密钥信息格式，该信息包括公开密钥算法的私有密钥以及可选的属性集等。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey keyPrivate = keyFactory.generatePrivate(keySpec);
		return keyPrivate;
	}

	private static byte[] removeMSZero(byte[] data) {
		byte[] data1;
		int len = data.length;
		if (data[0] == 0) {
			data1 = new byte[data.length - 1];
			System.arraycopy(data, 1, data1, 0, len - 1);
		} else
			data1 = data;

		return data1;
	}

	public static void main(String[] args) throws Exception {
		KeyPair keyPair = RSASecurityUtil.getKeyPair();
		System.out.println("公钥：" + Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
		System.out.println("私钥：" + Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
		// System.out.println("XML公钥：" +
		// RSASecurityUtil.publicKeyToXml(keyPair.getPublic()));
		// System.out.println("XML私钥：" +
		// RSASecurityUtil.privateKeyToXml(keyPair.getPrivate()));

		// String yw = "测试数据333“";
		// String mw =
		// RSASecurityUtil.encrypt(yw,keyPair.getPublic().getEncoded());
		// String hw =
		// RSASecurityUtil.dncrypte(mw,keyPair.getPrivate().getEncoded());

		// System.out.println("原文：" + yw);
		// System.out.println("密文：" + mw);
		// System.out.println("明文：" + hw);
		String wenjian = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + "<mainData>\n" + "<config>\n"
				+ "     <operate>1</operate>                  <!--0:删除，1:新增，2:修改-->\n" + "</config>\n"
				+ "<dataList type=\"personnel\">\n" + "     <data id=\"员工主数据主键\">            <!--默认主数据代码-->\n"
				+ "       <code></code>                       <!--代码-->\n"
				+ "       <name></name>                       <!--姓名-->\n"
				+ "       <sex></sex>                         <!--性别-->\n"
				+ "       <birthday></birthday>               <!--出生日期-->\n"
				+ "       <education></education>             <!--文化程度-->\n"
				+ "       <idNumber></idNumber>               <!--身份证号码-->\n"
				+ "       <entryDate></entryDate>             <!--入职日期-->\n"
				+ "       <departureDate></departureDate>     <!--离职日期-->\n"
				+ "       <address></address>                 <!--住址-->\n"
				+ "       <phoneNumber></phoneNumber>         <!--电话-->\n"
				+ "       <mobilePhoneNumber></mobilePhoneNumber><!--移动电话-->\n"
				+ "       <email></email>                     <!--电子邮件-->\n"
				+ "       <position></position>               <!--职务-->\n"
				+ "       <maritalStatus></maritalStatus>     <!--婚姻状况-->\n"
				+ "       <partyAffiliation></partyAffiliation><!--政治面貌-->\n"
				+ "       <username></username>               <!--用户名-->\n"
				+ "       <sortNo></sortNo>                   <!--排序号-->\n"
				+ "       <status></status>                   <!--状态-->\n"
				+ "       <department></department>           <!--所属部门-->\n"
				+ "       <company></company>                 <!--所属公司-->\n" + "    </data>\n" + "</dataList>\n"
				+ "</mainData>";
		// Thread
		String mw = RSASecurityUtil.encrypt(wenjian, Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
		String wm = RSASecurityUtil.decrypt(mw, Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
		System.out.println("加密后：" + mw);
		System.out.println("解密后：" + wm);

	}
}