package encLogin.utils;


import encLogin.dao.JDBCInMemory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

@Component
public class GenerateKeys {


	private KeyPairGenerator keyGen;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private static final String PUBLICKEY_PREFIX    = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLICKEY_POSTFIX   = "-----END PUBLIC KEY-----";
	private static final String PRIVATEKEY_PREFIX   = "-----BEGIN RSA PRIVATE KEY-----";
	private static final String PRIVATEKEY_POSTFIX  = "-----END RSA PRIVATE KEY-----";


	public GenerateKeys() throws NoSuchAlgorithmException, NoSuchProviderException {

		generateSecureKeys();
	}
	private void generateSecureKeys()  {
		try {
			this.keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		this.keyGen.initialize(1024);
		createKeys();
	}

	private void createKeys() {
		KeyPair pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	private PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	private PublicKey getPublicKey() {
		return this.publicKey;
	}


	public String getGeneratedPublicKey() {
		String publicKeyPEM = null;
		String privateKeyPEM;
		System.out.println("main method of generator");
		try {
			this.generateSecureKeys();
			this.createKeys();

			// THIS IS PEM:
	        publicKeyPEM = DatatypeConverter.printBase64Binary(this.getPublicKey().getEncoded());
	        privateKeyPEM = DatatypeConverter.printBase64Binary(this.getPrivateKey().getEncoded());
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		return publicKeyPEM;
	}
	public PrivateKey readPrivateKey(String appId)
			throws IOException, GeneralSecurityException {
		PrivateKey key;

		byte[] keyBytes = DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(this.getPrivateKey().getEncoded()));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		key = kf.generatePrivate(spec);
		return key;
	}

}
