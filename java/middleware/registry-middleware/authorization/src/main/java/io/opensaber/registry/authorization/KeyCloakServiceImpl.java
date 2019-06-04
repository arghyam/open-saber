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
	private PublicKey publicKey = toPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAggxlcrHCDN9edhkgMxSfwwM8mozxYQOV/v6WA3JCSWKe3F/79UC9hl6gYvyUqJbPuJNADjjVRwYvTKhOvkdxVFHV6w7r1lnALoRhdRk3lpu6TlKl/Ehm0o3yhPbbiCNRrqZjBPv1xmNdT++T4r0pdogrol/eBxn7OjPb2Tn5zklsZgrKjnzGVovAvgq3JcjyaxiYxhPMDmCNSTFF6sPywfumzZSuj4M/xC1/1HnVjJ226wIfGH/y8Mu7qRrYiL99044Q9lsOgbmmpWhXH9kYSITGkHdVodo5SnDp4ojA5MB+XSwfMSW+ezrnOMi0zNTAOA7BH9o13rejROLEI0xfDQIDAQAB");

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
		logger.info("*********************"+objectMapper.writeValueAsString(System.getenv("sso_url")));
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
