package net.jmb.module.security.service;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hibernate.mapping.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import net.jmb.module.security.model.User;

@Service
public class CustomUserService {

	@Autowired
	private UserDetailsManager userDetailsService;

	public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		String token = null;		
		for (Cookie cookie : request.getCookies()) {
			if (cookie.getName().equalsIgnoreCase("access_token")) {
				token = cookie.getValue();
				break;
			}
		}
		
		if (token == null) {
			String redirect = request.getParameter("redirect_to");
			redirect = redirect != null ? "?redirect_to=" + redirect : "";
			String authLocation = response.encodeRedirectURL("http://localhost:6969/login" + redirect);
			response.sendRedirect(authLocation);
		} else {
			register(token);
		}
		
	}
	
	public Object loginInfos() throws IOException {
		RestTemplate restTemplate = new RestTemplate();
		Object result = restTemplate.getForObject("http://localhost:6969/login/infos", Object.class);
		return result;
	}

	public void register(String accessToken) {
		userDetailsService.createUser(new User());
	}


}
