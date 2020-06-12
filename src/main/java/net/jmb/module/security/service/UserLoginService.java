package net.jmb.module.security.service;

import java.io.IOException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.JwtException;
import net.jmb.module.security.config.CacheConfig;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.oidc.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class UserLoginService {

	@Autowired
	protected String securityBaseURL;
	@Autowired
	protected UserLoginService self;
	@Autowired
	protected IdentityProviderService identityProviderService;
	@Autowired
	protected TokenService tokenService;
	@Autowired
	protected UserDetailsManager oidcUserDetailsService;
	@Autowired
	protected PasswordEncoder passwordEncoder;

	public Map<String, IdentityProviderRegistration> loginInfos() throws IOException {

		return identityProviderService.findIdentityProviders();
	}

	public Object idpLoginUrl(String idp) throws IOException {
		Map<String, IdentityProviderRegistration> infos = self.loginInfos();
		IdentityProviderRegistration idpInfos = infos.get(idp);
		String url = securityBaseURL + idpInfos.getAuthorizationPath();
		return url;
	}

	public UserDetails register(String accessToken) throws IOException {

		/**
		 * TODO vérifier la validité du jeton auprès du serveur d'authentification
		 */
		try {
			OidcUserDetails user = tokenService.buildOidcUserDetails(accessToken, true);
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			oidcUserDetailsService.deleteUser(user.getUsername());
			oidcUserDetailsService.createUser(user);
			return user;
		} catch (JwtException | AuthenticationException e) {
			throw e;
		}
	}

}
