package net.jmb.module.security.model;

import org.springframework.util.StringUtils;

public enum IdentityProviders {
	
	KEYCLOAK,
	PROSANTE,
	GOOGLE;
	
	public static IdentityProviders get(String idpKey) {
		if (StringUtils.hasText(idpKey)) {
			try {
				return valueOf(idpKey.trim().toUpperCase());
			} catch (Exception e) {}
		}
		return null;
	}
}
