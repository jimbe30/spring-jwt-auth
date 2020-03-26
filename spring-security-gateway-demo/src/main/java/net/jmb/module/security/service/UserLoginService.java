package net.jmb.module.security.service;

import java.io.IOException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import net.jmb.module.security.config.CacheConfig;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class UserLoginService {
	

	@Autowired 	protected UserLoginService self;	
	@Autowired 	protected IdentityProviderService identityProviderService;	
	@Autowired 	protected TokenService tokenService;
	@Autowired	protected  UserDetailsManager oidcUserDetailsService;
	@Autowired	protected  PasswordEncoder passwordEncoder;	

	public Map<String, IdentityProviderRegistration> loginInfos() throws IOException {
		
		return identityProviderService.findIdentityProviders();
	}	

	public Object idpLoginUrl(String idp) throws IOException {
		Map<String, IdentityProviderRegistration> infos = self.loginInfos();
		IdentityProviderRegistration idpInfos = infos.get(idp);
		String url = idpInfos.getAuthorizationURL();
		return url;
	}

	public UserDetails register(String accessToken) throws IOException {
			
		OidcUserDetails user = tokenService.buildOidcUserDetails(accessToken);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		oidcUserDetailsService.deleteUser(user.getUsername());
		oidcUserDetailsService.createUser(user);
		return user;
	}


}
