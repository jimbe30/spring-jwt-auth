package net.jmb.module.security.model.mapper;

import net.jmb.module.security.model.IdentityProvider;

public class RoleMapperFactory {
	
	public RoleMapperInterface get(String providerId)  {
		
		IdentityProvider idp = IdentityProvider.get(providerId);
		if (idp != null) {
			switch (idp) {
			case GOOGLE:
				return new RoleMapperGoogle();
			case KEYCLOAK:
				return new RoleMapperKeycloak();
			case PROSANTE:
				return new RoleMapperProSante();
			default:
				return new RoleMapperDefault();
			}
		}
		return new RoleMapperDefault();
	}
	

	


	
}
