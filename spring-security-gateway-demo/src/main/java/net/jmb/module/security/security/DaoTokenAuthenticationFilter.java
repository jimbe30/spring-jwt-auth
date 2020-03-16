package net.jmb.module.security.security;

import java.io.IOException;
import java.util.StringTokenizer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class DaoTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	public static long EXPIRATION_DELAY_SECONDS_TOLERANCE = 3600;

	public DaoTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(request -> {
				String bearerToken = request.getHeader("Authorization");
			    return (bearerToken != null && bearerToken.startsWith("Bearer "));
			}
		);
		setAuthenticationManager(authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		
		String username = null;
		String password = null;
		
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			bearerToken = bearerToken.substring(7);
			StringTokenizer stringTokenizer = new StringTokenizer(bearerToken, ".", true);
			StringBuffer buffer = new StringBuffer();
			while (stringTokenizer.hasMoreTokens()) {
				String tokenElement = stringTokenizer.nextToken();
				if (stringTokenizer.hasMoreTokens()) {
					buffer.append(tokenElement);
				}
			}
			bearerToken = buffer.toString();
			try {
				username = Jwts.parser().setAllowedClockSkewSeconds(EXPIRATION_DELAY_SECONDS_TOLERANCE)
						.parseClaimsJwt(bearerToken).getBody().getSubject();
				password = bearerToken;
			} catch(JwtException e) {
				username = null;
				e.printStackTrace();
			}
		}

		if (username != null) {
			username = username.trim();
			UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
			try {
				Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
				return authentication;
			} catch (AuthenticationException e) {
				e.printStackTrace();
			}
		}		
		return null;		
	}
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		
		super.doFilter(req, res, chain);		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (requiresAuthentication((HttpServletRequest) req, (HttpServletResponse) res) && authentication == null) {
			chain.doFilter(req, res);
		}		
	}
}
