package net.jmb.module.security.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
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
import net.jmb.module.security.service.IdentityProviderService;
import net.jmb.module.security.service.TokenService;
import net.jmb.oidc.model.IdentityProviderRegistration;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class UserLoginController {
	
	@Autowired
	private TokenService tokenService;
	@Autowired
	private IdentityProviderService idpService;	
	@Autowired
	private UserDetailsManager oidcUserDetailsService;
	
	
	@GetMapping(path = "/login/infos")
	@ApiOperation(value = "${UserLoginController.loginInfos}")
	
	public Object loginInfos() throws IOException {
		Map<String, IdentityProviderRegistration> loginInfos = idpService.findIdentityProviders();
		Map<String, Object> result = new HashMap<>();
		loginInfos.forEach((id, idp) -> {
			Map<String, String> data = new HashMap<>();
			data.put("description", idp.getDescription());
			data.put("iconUrl", idp.getIconUrl());
			data.put("authorizationPath", "/users/login/" + id);
			result.put(id, data);
		});
		return result;
	}
	
	
	@RequestMapping(path = "/login/{idp}", method = { RequestMethod.GET })
	@ApiOperation(value = "${UserLoginController.loginIDP}")
	
	public void loginIdp(
			HttpServletRequest request, HttpServletResponse response,
			@PathVariable String idp,
			@RequestParam(required = false, name = "redirect_to") String redirect
		) throws IOException {
		
		String url = (String) idpService.idpLoginUrl(idp);
		if (redirect == null) {
			redirect = ServletUriComponentsBuilder.fromContextPath(request).build().toUriString()
					.concat("/users/login/accessToken");
		}
		redirect = "?redirect_to=" + redirect;
		String authLocation = response.encodeRedirectURL(url + redirect);
		System.out.println("UserLoginController.loginIdp() - authLocation = " + authLocation);
		response.sendRedirect(authLocation);		
	}
	
	
	@RequestMapping(path = "/logout", method = { RequestMethod.GET })
	@ApiOperation(value = "${UserLoginController.logout}")
	
	public void logout(HttpServletRequest request,	HttpServletResponse response)  {
		/**
		 * TODO créer un service de logout
		 */
	}
	
	
	@GetMapping(path = "/login/registerToken")
	@ApiOperation(value = "${UserLoginController.registerToken}")
	public Object registerToken(
			@RequestParam("id_token") String idToken
	) throws IOException {

		Map<String, Object> data = new HashMap<>();
		try {

			UserDetails user = tokenService.registerUser(idToken);
			data.put("id_token", idToken);
			data.put("user", user);
		} catch (Exception e) {
			data.put("error", "Jeton invalide " + e.getMessage());
		}
		return data;
	}
	
	
	@GetMapping(path = "/{id}")
	@ApiOperation(value = "${UserLoginController.users.getUser}")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	
	public UserDetails getUser(
			@PathVariable(required = false) String id,
			@RequestParam(name = "name", required = false) String name
		) {	
		String zeName = name != null ? name : id;
		return oidcUserDetailsService.loadUserByUsername(zeName);
	}



}
