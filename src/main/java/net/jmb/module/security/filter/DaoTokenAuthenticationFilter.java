package net.jmb.module.security.filter;

import java.io.IOException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.jsonwebtoken.JwtException;
import net.jmb.module.security.exception.InvalidOidcTokenException;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.module.security.service.TokenService;


public class DaoTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	@Autowired
	TokenService tokenService;
	
	@Autowired
	UserDetailsManager oidcUserDetailsService;


	public DaoTokenAuthenticationFilter(AuthenticationManager authenticationManager, RequestMatcher requestMatcher) {
		super(requestMatcher);
		setAuthenticationManager(authenticationManager);
		
		setAuthenticationSuccessHandler(
			(request, response, authentication) -> {
				String path = new URL(request.getRequestURL().toString()).getPath();
				request.getRequestDispatcher(path).forward(request, response);
			} 
		);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException {
		
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			bearerToken = bearerToken.substring(7);
			OidcUserDetails user = null;
			try {
				user = tokenService.buildOidcUserDetails(bearerToken, false);
			} catch (JwtException e) {
				throw new InvalidOidcTokenException(e.getMessage());
			}
			if (user != null) {

				UserDetails registeredUser = null;

				try {
					registeredUser = oidcUserDetailsService.loadUserByUsername(user.getUsername());
				} catch (UsernameNotFoundException e) {
					registeredUser = tokenService.registerUser(bearerToken);
					Authentication authentication = new UsernamePasswordAuthenticationToken(registeredUser, null,
							registeredUser.getAuthorities());
					return authentication;
				}

				UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
						user.getUsername(), user.getPassword());

				Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
				if (authentication != null && authentication.isAuthenticated()) {
					return authentication;
				}

			} else {
				throw new UsernameNotFoundException("Impossible d'identifier l'utilisateur à partir du header Authorization");
			}
		}
		return null;
	}

	
}
