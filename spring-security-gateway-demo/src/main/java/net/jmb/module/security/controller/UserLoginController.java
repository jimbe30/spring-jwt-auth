package net.jmb.module.security.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.jmb.module.security.service.UserLoginService;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class UserLoginController {
	
	@Autowired
	private UserLoginService userLoginService;
	
	@Autowired
	private UserDetailsManager oidcUserDetailsService;
	
	@GetMapping(path = "/login/infos")
	@ApiOperation(value = "${UserLoginController.loginInfos}")
	public Object loginInfos() throws IOException {
		return userLoginService.loginInfos();
	}
	
	@RequestMapping(path = "/login/{idp}", method = { RequestMethod.GET, RequestMethod.POST })
	@ApiOperation(value = "${UserLoginController.loginIDP}")
	
	public void loginIdp(HttpServletRequest request, HttpServletResponse response,
			@PathVariable String idp) throws IOException {
		
		String url = (String) userLoginService.idpLoginUrl(idp);		
		String redirect = ServletUriComponentsBuilder.fromContextPath(request).build().toUriString();
		redirect = redirect != null ? "?redirect_to=" + redirect + "/users/login/accessToken" : "";
		String authLocation = response.encodeRedirectURL(url + redirect);
		response.sendRedirect(authLocation);		
	}
	
	@RequestMapping(path = "/login/refresh/{idp}", method = { RequestMethod.GET, RequestMethod.POST })
	@ApiOperation(value = "${UserLoginController.refreshToken}")
	
	public void refreshTokenIdp(HttpServletRequest request,	HttpServletResponse response, 
			@PathVariable String idp)  {
		/**
		 * TODO créer un service de raffraichissement des jetons
		 * On l'appellera en cas de jeton expiré pour un user ou à la demande
		 */
	}
	
	@RequestMapping(path = "/logout", method = { RequestMethod.GET, RequestMethod.POST })
	@ApiOperation(value = "${UserLoginController.logout}")
	
	public void logout(HttpServletRequest request,	HttpServletResponse response)  {
		/**
		 * TODO créer un service de logout
		 */
	}
	
	
	@GetMapping(path = "/login/accessToken")
	@ApiOperation(value = "${UserLoginController.login.accessToken}")
	
	public Object accessToken(HttpServletRequest request) throws IOException {
		
		String accessToken = request.getParameter("access_token");		
		return userLoginService.register(accessToken);
	}
	
	@GetMapping(path = "/{name}")
	@ApiOperation(value = "${UserLoginController.users.getUser}")
	
	public UserDetails getUser(@PathVariable("name") String name) {	
		
		return oidcUserDetailsService.loadUserByUsername(name);
	}



}
