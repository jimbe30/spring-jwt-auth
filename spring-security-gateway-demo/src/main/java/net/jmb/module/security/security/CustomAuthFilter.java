package net.jmb.module.security.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import net.jmb.module.security.exception.CustomException;

// Use OncePerRequestFilter, there is no point in doing this more than once
public class CustomAuthFilter extends OncePerRequestFilter {

	private CustomAuthProvider customAuthProvider;

	public CustomAuthFilter(CustomAuthProvider customAuthProvider) {
		this.customAuthProvider = customAuthProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {

		String token = customAuthProvider.resolveToken(httpServletRequest);
		try {
			if (token != null && customAuthProvider.validateToken(token)) {
				Authentication auth = customAuthProvider.getAuthentication(token);
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (CustomException ex) {
			// this is very important, since it guarantees the user is not authenticated at
			// all
			SecurityContextHolder.clearContext();
			httpServletResponse.sendError(ex.getHttpStatus().value(), ex.getMessage());
			return;
		}

		filterChain.doFilter(httpServletRequest, httpServletResponse);
	}

}
