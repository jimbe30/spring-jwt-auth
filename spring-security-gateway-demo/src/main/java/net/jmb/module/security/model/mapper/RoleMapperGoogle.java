package net.jmb.module.security.model.mapper;

import java.util.List;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import net.jmb.module.security.model.Role;

public class RoleMapperGoogle extends RoleMapperDefault implements RoleMapperInterface {

	@Override
	public List<Role> mapRoles(OidcIdToken oidcIdToken) {
		return super.mapRoles(oidcIdToken);
	}

}
