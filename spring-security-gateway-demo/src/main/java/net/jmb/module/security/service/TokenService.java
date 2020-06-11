package net.jmb.module.security.service;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import net.jmb.module.security.config.CacheConfig;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.module.security.model.Role;
import net.jmb.module.security.model.mapper.RoleMapperFactory;
import net.jmb.module.security.model.mapper.RoleMapperInterface;
import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class TokenService {
	
	@Autowired
	Integer expirationJwtTolerance;
	
	@Autowired	private IdentityProviderService identityProviderService;
	@Autowired	private RoleMapperFactory roleMapperFactory;
	

	public OidcIdToken resolveToken(String accessToken, boolean checkExpiration) throws JwtException {

		OidcIdToken result = null;

		if (accessToken != null) {
			
			long expirationDelay = checkExpiration ? expirationJwtTolerance * 60 : 24 * 3600;			
			try {
				String unsignedToken = getUnsignedPart(accessToken);
				@SuppressWarnings("rawtypes")
				io.jsonwebtoken.Jwt<Header, Claims> decodedJwt = Jwts.parser()
						.setAllowedClockSkewSeconds(expirationDelay).parseClaimsJwt(unsignedToken);

				Claims claims = decodedJwt.getBody();
				Instant issuedAt = Instant.ofEpochMilli(claims.getIssuedAt().getTime());
				Instant expireAt = Instant.ofEpochMilli(claims.getExpiration().getTime());

				result = new OidcIdToken(accessToken, issuedAt, expireAt, claims);
			} catch (Exception e) {
				throw new JwtException(e.getMessage());
			}
		}
		return result;
	}
	
	public String getUnsignedPart(String accessToken) {
		String[] parts = getParts(accessToken);
		if (parts != null && parts.length >= 2) {
			return parts[0].concat(".").concat(parts[1]).concat(".");
		}
		return null;
	}
	
	public String getSignedPart(String accessToken) {
		String[] parts = getParts(accessToken);
		if (parts != null && parts.length == 3) {
			return parts[2];
		}
		return null;
	}
	
	public String[] getParts(String accessToken) {
		if (accessToken != null) {			
			return accessToken.split("\\.");
		}
		return null;
	}
	
	public OidcUserDetails buildOidcUserDetails(String accessToken, boolean checkExpiration) throws IOException {

		OidcUserDetails result = null;
		if (accessToken != null) {
			try {
				OidcIdToken oidcIdToken = resolveToken(accessToken, checkExpiration);
				String issuer = oidcIdToken.getIssuer().toString();
				String id = oidcIdToken.getSubject().concat("@").concat(issuer);

				IdentityProviderRegistration identityProvider = identityProviderService
						.resolveIdentityProvider(oidcIdToken);
				RoleMapperInterface roleMapper = roleMapperFactory.get(identityProvider.getRegistrationId());
				List<Role> roles = roleMapper.mapRoles(oidcIdToken);

				result = new OidcUserDetails("-- no token stored --", oidcIdToken.getIssuedAt(), oidcIdToken.getExpiresAt(),
						oidcIdToken.getClaims()).setUsername(id).setPassword(String.valueOf(accessToken.hashCode()))
								.setRoles(roles);
			} catch (Exception e) {
				throw new JwtException(e.getMessage());
			}
		}
		return result;
	}	
	

}
