package net.jmb.module.security.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
  ROLE_ADMIN, ROLE_CLIENT, ROLE_USER;

  public String getAuthority() {
    return name();
  }

}
