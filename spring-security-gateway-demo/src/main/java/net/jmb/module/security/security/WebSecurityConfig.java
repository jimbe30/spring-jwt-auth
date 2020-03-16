package net.jmb.module.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

//	@Autowired
//	private CustomAuthProvider customAuthProvider;
//	@Autowired
//	private CustomUserDetailsService userDetailsService;
//	
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth
//			.userDetailsService(userDetailsService)
//			.passwordEncoder(passwordEncoder());
//	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			.authorizeRequests()
				.antMatchers("/users/signin", "/users/login/*", "/users/signup", "/h2-console/**/**")
					.permitAll()
				.anyRequest()
					.authenticated()
				.and()
			.exceptionHandling()
				.accessDeniedPage("/users/login")
				.and()
			.addFilterBefore(new DaoTokenAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
//			.addFilterAfter(new CustomAuthFilter(customAuthProvider), DaoTokenAuthenticationFilter.class)
			;
	}
	
//	@Bean
//	public AuthenticationManager authenticationManager() throws Exception {
//		return super.authenticationManager();
//	}
	
	@Bean
	public UserDetailsManager userDetailsService() {
		return new InMemoryUserDetailsManager();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// Allow swagger to be accessed without authentication
		web.ignoring()
				.antMatchers("/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", 
					"/configuration/**", "/webjars/**", "/public")				
				.and()
			.ignoring()
				.antMatchers("/h2-console/**/**");
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

}
