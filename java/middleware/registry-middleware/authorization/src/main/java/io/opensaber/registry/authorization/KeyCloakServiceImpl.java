package io.opensaber.registry.authorization;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.RSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;


public class KeyCloakServiceImpl {



	private static Logger logger = LoggerFactory.getLogger(KeyCloakServiceImpl.class);

	private String ssoUrl = "http://13.234.251.56:8080/auth/";
	private String ssoRealm = "Arghyam";
	private PublicKey publicKey = toPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgq9mNJRAYGq4bW6HbOY3u7K1a875Ul7/kECKff/fNKqLjIKGia2A1+gjE7n95q7oeiwq/BDbtvg93vID4vOzTf+VH+QbL31unJdLEMhdkWFiwe/pfgsHlOe0m0N2QZn9A31KEOVNoHMewUspLSBs+tS3SC1ow4f61/YYxFmCa+ADtnyS3km4C7PA+H4jhZ3o5UCBmd+UjnipHdtCUfhIM+I+3w7Q0uXVU2iF4x7vyJiarf0lltP+k7w8cnpqPHdpmEKXgtq33Mno3CYON1ZZjPqUHqe6ai0hGKZd/371ZxCU4vFwhnkSzpHToWt4cLG7wzWS+W3dzy5qTof8s9S+hQIDAQAB");

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * This method verifies input JWT access token using RSATokenVerifier of Sunbird
	 * keycloak server
	 *
	 * @param accessToken
	 * @throws VerificationException
	 * @throws Exception
	 */
	public String verifyToken(String accessToken) throws VerificationException, Exception {
		ObjectMapper objectMapper = new ObjectMapper();
		logger.info("*********************"+objectMapper.writeValueAsString(ssoUrl));
		AccessToken token = RSATokenVerifier.verifyToken(accessToken, publicKey, ssoUrl + "realms/" + ssoRealm, true,
				true);
		String userId = token.getSubject();
		logger.debug("Authentication token \n TokenId: {} \t isActive: {} \t isExpired: {} \t", token.getId(),
				token.isActive(), token.isExpired());
		return userId;
	}

	/**
	 * This method transforms public key from String to encoded format
	 *
	 * @param publicKeyString
	 * @throws VerificationException
	 * @throws Exception
	 */
	public PublicKey toPublicKey(String publicKeyString) {
		try {
			byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			return null;
		}
	}
}
