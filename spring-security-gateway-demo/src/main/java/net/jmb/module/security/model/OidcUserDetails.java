package net.jmb.module.security.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

public class OidcUserDetails extends OidcIdToken implements UserDetails {	

	private static final long serialVersionUID = 1L;

	private String id;
	private String username;
	private String password;
	private List<Role> roles;	
	
	public OidcUserDetails(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt, claims);
	}

	public String getId() {
		return id;
	}
	
	public OidcUserDetails setId(String id) {
		this.id = id;
		return this;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
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
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
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

}
