package net.jmb.module.security.model.mapper;

import net.jmb.module.security.model.IdentityProviders;

public class RoleMapperFactory {
	
	public RoleMapperInterface get(String providerId)  {
		
		IdentityProviders idp = IdentityProviders.get(providerId);
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
