package net.jmb.module.security.filter;

import java.io.IOException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.JwtException;
import net.jmb.module.security.exception.InvalidOidcTokenException;
import net.jmb.module.security.model.OidcUserDetails;
import net.jmb.module.security.service.TokenService;


public class DaoTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	@Autowired
	TokenService tokenService;


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
				user = tokenService.buildOidcUserDetails(bearerToken);
			} catch (JwtException e) {
				throw new InvalidOidcTokenException(e.getMessage());
			}
			if (user != null) {
				UsernamePasswordAuthenticationToken authRequest = 
						new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
				try {
					Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
					if (authentication != null && authentication.isAuthenticated()) {						
						return authentication;
					}
				} catch (AuthenticationException e) {
					e.printStackTrace();
				}
			}
		}
		return null;		
	}
	
//	@Override
//	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
//			throws IOException, ServletException {
//		
//		super.doFilter(req, res, chain);		
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		if (requiresAuthentication((HttpServletRequest) req, (HttpServletResponse) res) && authentication == null) {
//			chain.doFilter(req, res);
//		}		
//	}
	

	
}
