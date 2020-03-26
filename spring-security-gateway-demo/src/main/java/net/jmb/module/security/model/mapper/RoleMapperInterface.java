package net.jmb.module.security.model.mapper;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.StringUtils;

import net.jmb.module.security.model.Role;

public interface RoleMapperInterface {

	default public List<Role> mapRoles(OidcIdToken oidcIdToken) {
		return Arrays.asList(Role.ANONYMOUS);
	}

	default public Role getRole(String role) {
		
		Role result = null;
		if (StringUtils.hasText(role)) {
			try {
				result = Role.valueOf(role.trim().toUpperCase());
			} catch (Exception e) {
				result = null;
			}
		}
		return result;
	}

}
