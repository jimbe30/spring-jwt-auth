package net.jmb.module.security.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
	ADMIN, CLIENT, USER, ANONYMOUS, MEDECIN, ETABLISSEMENT;

	public String getAuthority() {
		return "ROLE_" + name();
	}

	public String getRole() {
		return name();
	}

}
