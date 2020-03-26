package net.jmb.module.security.model;

import org.springframework.util.StringUtils;

public enum IdentityProvider {
	
	KEYCLOAK,
	PROSANTE,
	GOOGLE;
	
	public static IdentityProvider get(String idpKey) {
		if (StringUtils.hasText(idpKey)) {
			try {
				return valueOf(idpKey.trim().toUpperCase());
			} catch (Exception e) {}
		}
		return null;
	}
}
