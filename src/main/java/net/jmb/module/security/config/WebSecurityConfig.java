package net.jmb.module.security.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import net.jmb.module.security.filter.DaoTokenAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	static String[] PERMIT_ALL_REQUEST_MATCHER = new String[] {
		"/users/login/**", "/public/**", "/tests/public/**", "/error/**", 
		"/h2-console/**/**", "/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", 
		"/configuration/**", "/webjars/**"
	};
	
	@Autowired 
	UserDetailsManager oidcUserDetailsService ;
	
	@Value(value = "${net.jmb.security.matchers.permitAll}") 
	String permitAllMatcher;
	
	@Bean
	public String securityBaseURL(
			@Value("${net.jmb.security.baseUrl}") String securityBaseURL) {
		return securityBaseURL;
	}
	
	@Bean
	public Integer expirationSessionDelay(
			@Value("${net.jmb.security.expiration.session.delay:15}") Integer expirationSessionDelay)  {
		return expirationSessionDelay;
	}
	
	@Bean
	public Integer expirationJwtTolerance(
			@Value("${net.jmb.security.expiration.jwt.tolerance:60}") Integer expirationJwtTolerance)  {
		return expirationJwtTolerance;
	}
	
	@Bean
	public String[] permitAllRequestMatcher() {		
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
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(oidcUserDetailsService).passwordEncoder(passwordEncoder());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			.authorizeRequests()
				.antMatchers(permitAllRequestMatcher()).permitAll()
				.anyRequest().authenticated()
				.and()
			.addFilterBefore(daoTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Bean
	DaoTokenAuthenticationFilter daoTokenAuthenticationFilter() throws Exception {
		RequestMatcher daoTokenRequestMatcher = request -> {
			boolean authorized = Arrays.stream(permitAllRequestMatcher())
				.anyMatch(pattern -> 
					new AntPathRequestMatcher(pattern).matches(request)
				);				
			String bearerToken = request.getHeader("Authorization");
			return (!authorized && bearerToken != null && bearerToken.startsWith("Bearer "));			    
		};
		DaoTokenAuthenticationFilter filter = new DaoTokenAuthenticationFilter(authenticationManagerBean(), daoTokenRequestMatcher);
		return filter;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}	

	@Override
	public void configure(WebSecurity web) throws Exception {
		// Allow resources to be accessed without authentication
		web.ignoring().antMatchers(permitAllRequestMatcher());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

}
