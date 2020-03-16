package net.jmb.module.security.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.jmb.module.security.service.CustomUserService;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class CustomUserController {

	@Autowired
	private CustomUserService customUserService;


	@GetMapping(path = "/login/infos")
	@ApiOperation(value = "${CustomUserController.loginInfos}")
	public Object loginInfos() throws IOException {
		return customUserService.loginInfos();
	}
	
	@RequestMapping(path = "/login/{idp}", method = { RequestMethod.GET, RequestMethod.POST })
	@ApiOperation(value = "${CustomUserController.login}")
	public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
		customUserService.login(request, response);
	}



}
