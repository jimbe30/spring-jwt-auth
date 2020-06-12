package net.jmb.module.security.model.mapper;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.StringUtils;

import net.jmb.module.security.model.Role;

public class RoleMapperKeycloak implements RoleMapperInterface {

	@Override
	public List<Role> mapRoles(OidcIdToken oidcIdToken) {

		List<Role> result = null;

		List<String> roles = oidcIdToken.getClaimAsStringList("roles");
		if (roles != null) {
			result = roles
				.stream()
				.map(role -> getRole(role))
				.filter(role -> role != null)
				.collect(Collectors.toList());
		}
		
		if (result == null) {
			result = new ArrayList<>();
		}
		
		String profile = oidcIdToken.getProfile();
		if (StringUtils.hasText(profile)) {
			Role role = getRole(profile);
			if (role != null && !result.contains(role)) {
				result.add(role);
			}
		}
		
		if (result.isEmpty()) {
			result.add(Role.ANONYMOUS);
		}

		return result;
	}

}
