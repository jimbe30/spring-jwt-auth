package net.jmb.module.security.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public interface SecurityConstants {
	
	static long EXPIRATION_DELAY_SECONDS_TOLERANCE = 3600;	
	
	static String[] PERMIT_ALL_REQUEST_MATCHER = new String[] {
		"/users/login/**", "/public/**", "/error/**", "/h2-console/**/**",
		"/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", 
		"/configuration/**", "/webjars/**"
	};

}
