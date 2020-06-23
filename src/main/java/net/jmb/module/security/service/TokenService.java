package net.jmb.module.security.service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import net.jmb.module.security.config.CacheConfig;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.module.security.model.Role;
import net.jmb.module.security.model.mapper.RoleMapperFactory;
import net.jmb.module.security.model.mapper.RoleMapperInterface;
import net.jmb.oidc.model.IdentityProviderRegistration;

@Service
@org.springframework.cache.annotation.CacheConfig(cacheNames = CacheConfig.IDP_INFOS_CACHE)
public class TokenService {
	
	@Autowired
	Integer expirationJwtTolerance;
	@Autowired	
	String securityBaseURL;
	@Autowired
	UserDetailsManager oidcUserDetailsService;
	@Autowired
	PasswordEncoder passwordEncoder;
	
	
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

				result = new OidcUserDetails("-- no token stored --", oidcIdToken.getIssuedAt(), 
						oidcIdToken.getExpiresAt(),	oidcIdToken.getClaims())
							.setUsername(id)
							.setPassword(String.valueOf(accessToken.hashCode()))
							.setIdpRegistration(identityProvider)
							.setRoles(roles);
			} catch (Exception e) {
				throw new JwtException(e.getMessage());
			}
		}
		return result;
	}	
	
	public ResponseEntity<Object> validateToken(String accessToken) throws IOException, URISyntaxException {
		
		RequestEntity<Void> request = RequestEntity.get(new URI(securityBaseURL + "/token/validate?id_token=" + accessToken)).build();
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<Object> response ;
		try {
			response = restTemplate.exchange(request, Object.class);
		} catch (HttpClientErrorException.Unauthorized e) {
			response = new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
		}		
		if (Arrays.asList(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN).contains(response.getStatusCode())) {
			throw new BadCredentialsException("Accès non autorisé : le jeton est invalide") ;
		}
		
		return response;
	}
	
	public UserDetails registerUser(String accessToken) throws IOException {

		ResponseEntity<Object> tokenDetails = null;
		try {
			tokenDetails = validateToken(accessToken);			
		} catch (IOException | URISyntaxException e1) {
			throw new JwtException(e1.getMessage());
		}
		
		if (tokenDetails == null || Arrays.asList(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN)
				.contains(tokenDetails.getStatusCode())) {
			throw new JwtException("Le jeton est invalide : accès interdit");
		}
		
		try {			
			OidcUserDetails user = buildOidcUserDetails(accessToken, true);
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			oidcUserDetailsService.deleteUser(user.getUsername());
			oidcUserDetailsService.createUser(user);
			return user;
		} catch (JwtException | AuthenticationException e) {
			throw e;
		}
	}
	

}
