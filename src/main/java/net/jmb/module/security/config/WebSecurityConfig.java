package net.jmb.module.security.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import net.jmb.module.security.filter.DaoTokenAuthenticationFilter;
import net.jmb.module.security.service.OidcUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {
	
	static String[] PERMIT_ALL_REQUEST_MATCHER = new String[] {
		"/users/login/**", "/public/**", "/tests/public/**", "/error/**", 
		"/h2-console/**/**", "/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", 
		"/configuration/**", "/webjars/**"
	};
	

	@Value(value = "${net.jmb.security.matchers.permitAll}") 
	String permitAllMatcher;
	
	
	@Bean
	String securityBaseURL(@Value("${net.jmb.security.baseUrl}") String securityBaseURL) {
		return securityBaseURL;
	}
	
	@Bean
	Integer expirationSessionDelay(@Value("${net.jmb.security.expiration.session.delay:15}") Integer expirationSessionDelay)  {
		return expirationSessionDelay;
	}
	
	@Bean
	Integer expirationJwtTolerance(@Value("${net.jmb.security.expiration.jwt.tolerance:60}") Integer expirationJwtTolerance)  {
		return expirationJwtTolerance;
	}
	
	@Bean
	UserDetailsManager oidcUserDetailsService(Integer expirationSessionDelay)  {
		return new OidcUserDetailsService(expirationSessionDelay);
	}

	
	@Bean
	String[] permitAllRequestMatcher() {		
		String[] result = PERMIT_ALL_REQUEST_MATCHER;		
		if (permitAllMatcher != null) {
			String[] matchers = permitAllMatcher.split(",[ ]*");
			result = new String[PERMIT_ALL_REQUEST_MATCHER.length + matchers.length];
			Arrays.setAll(result, i ->
				i < PERMIT_ALL_REQUEST_MATCHER.length ? 
					PERMIT_ALL_REQUEST_MATCHER[i]
					: matchers[i - PERMIT_ALL_REQUEST_MATCHER.length]);
		}		
		return result;
	}
	
	
	@Bean
	AuthenticationManager authenticationManager(HttpSecurity http, UserDetailsManager oidcUserDetailsService) throws Exception {
		
		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.userDetailsService(oidcUserDetailsService).passwordEncoder(passwordEncoder());
		AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
		return authenticationManager;
	}
	
	
	@Bean
	DaoTokenAuthenticationFilter daoTokenAuthenticationFilter(AuthenticationManager authenticationManager) throws Exception {
		RequestMatcher daoTokenRequestMatcher = request -> {
			boolean authorized = Arrays.stream(permitAllRequestMatcher())
				.anyMatch(pattern -> 
					new AntPathRequestMatcher(pattern).matches(request)
				);				
			String bearerToken = request.getHeader("Authorization");
			return (!authorized && bearerToken != null && bearerToken.startsWith("Bearer "));			    
		};
		DaoTokenAuthenticationFilter filter = new DaoTokenAuthenticationFilter(authenticationManager, daoTokenRequestMatcher);
		return filter;
	}
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, DaoTokenAuthenticationFilter daoTokenAuthenticationFilter) throws Exception {
		
		http
			.csrf(csrf -> csrf.disable())
			.cors(Customizer.withDefaults())
			.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeRequests(requests -> requests
				.antMatchers(permitAllRequestMatcher()).permitAll()
				.anyRequest().authenticated()
			)
			.addFilterBefore(daoTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
	

	@Bean
	WebSecurityCustomizer webSecurityCustomizer() throws Exception {
		return (web) -> web.ignoring().antMatchers(permitAllRequestMatcher());
	}
	

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

}
