package net.jmb.module.security.service;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.StringTokenizer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import net.jmb.module.security.config.CacheConfig;
import net.jmb.module.security.config.WebSecurityConfig;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.module.security.model.Role;
import net.jmb.module.security.model.mapper.RoleMapperFactory;
import net.jmb.module.security.model.mapper.RoleMapperInterface;
import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class TokenService {
	
	final long expirationDelay = WebSecurityConfig.EXPIRATION_DELAY_SECONDS_TOLERANCE;
	
	@Autowired	private IdentityProviderService identityProviderService;
	@Autowired	private RoleMapperFactory roleMapperFactory;
	

	public OidcIdToken resolveToken(String accessToken) throws JwtException {
		
		OidcIdToken result = null;

		if (accessToken != null) {
			StringTokenizer stringTokenizer = new StringTokenizer(accessToken, ".", true);
			StringBuffer buffer = new StringBuffer();
			for (int nbPoints = 0; stringTokenizer.hasMoreTokens();) {
				String tokenElement = stringTokenizer.nextToken();
				if (tokenElement.equals(".")) {
					nbPoints++;
				}
				if (nbPoints < 2 || stringTokenizer.hasMoreTokens()) {
					buffer.append(tokenElement);
				}
			}
			String unsignedToken = buffer.toString();
			@SuppressWarnings("rawtypes")
			io.jsonwebtoken.Jwt<Header, Claims> decodedJwt = 
				Jwts.parser()
					.setAllowedClockSkewSeconds(expirationDelay)
					.parseClaimsJwt(unsignedToken);
			
			Claims claims = decodedJwt.getBody();
			
			Instant issuedAt = Instant.ofEpochMilli(claims.getIssuedAt().getTime());
			Instant expireAt = Instant.ofEpochMilli(claims.getExpiration().getTime());

			result = new OidcIdToken(accessToken, issuedAt, expireAt, claims);

		}

		return result;
	}
	
	public OidcUserDetails buildOidcUserDetails(String accessToken) throws IOException {

		OidcUserDetails result = null;

		if (accessToken != null) {
			
			OidcIdToken oidcIdToken = resolveToken(accessToken);
			String id = oidcIdToken.getSubject();
			String issuer = oidcIdToken.getIssuer().toString()
					.replace("//", "").replace("/", ".");
			id += "@".concat(issuer);
			
			IdentityProviderRegistration identityProvider = 
					identityProviderService.resolveIdentityProvider(oidcIdToken);
			RoleMapperInterface roleMapper = roleMapperFactory.get(identityProvider.getRegistrationId());
			List<Role> roles = roleMapper.mapRoles(oidcIdToken);
			
			result = new OidcUserDetails(
						accessToken, 
						oidcIdToken.getIssuedAt(), 
						oidcIdToken.getExpiresAt(), 
						oidcIdToken.getClaims())
					.setId(id)
					.setUsername(id)
					.setPassword(accessToken)
					.setRoles(roles);
		}
		return result;
	}	
	

}
