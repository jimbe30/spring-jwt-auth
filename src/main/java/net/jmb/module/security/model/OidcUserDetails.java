package net.jmb.module.security.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import com.fasterxml.jackson.annotation.JsonIgnore;

import net.jmb.oidc.model.IdentityProviderRegistration;

public class OidcUserDetails extends OidcIdToken implements UserDetails {	

	private static final long serialVersionUID = 1L;
	
	private String username;
	private String password;
	private List<Role> roles;
	private long lastAccessTime;
	private long sessionExpirationDelay;
	private IdentityProviderRegistration idpRegistration;
	
	public OidcUserDetails(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt, claims);
		updateLastAccessTime();
	}
	
	@Override
	@JsonIgnore
	public Map<String, Object> getClaims() {
		return super.getClaims();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles;
	}

	@Override
	@JsonIgnore
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	public List<Role> getRoles() {
		return roles;
	}

	public OidcUserDetails setRoles(List<Role> roles) {
		this.roles = roles;
		return this;
	}
	
	public OidcUserDetails setRoles(Role... roles) {
		this.roles = Arrays.asList(roles);
		return this;
	}

	public OidcUserDetails setUsername(String username) {
		this.username = username;
		return this;
	}

	public OidcUserDetails setPassword(String password) {
		this.password = password;
		return this;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		long expirationTime = getExpiresAt().toEpochMilli();
		long now = new Date().getTime();
		if (now > expirationTime && now > lastAccessTime + sessionExpirationDelay) {
			return false;
		}	
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public long getLastAccessTime() {
		return lastAccessTime;
	}

	public void updateLastAccessTime() {
		this.lastAccessTime = new Date().getTime();
	}

	public long getSessionExpirationDelay() {
		return sessionExpirationDelay;
	}

	public void setSessionExpirationDelay(long sessionExpirationDelay) {
		this.sessionExpirationDelay = sessionExpirationDelay;
	}

	public IdentityProviderRegistration getIdpRegistration() {
		return idpRegistration;
	}

	public OidcUserDetails setIdpRegistration(IdentityProviderRegistration idpRegistration) {
		this.idpRegistration = idpRegistration;
		return this;
	}

}
