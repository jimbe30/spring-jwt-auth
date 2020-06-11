package net.jmb.module.security.controller;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;

@RestController
@RequestMapping("/tests")
@Api(tags = "tests")
public class AccessTestController {
	
	
	@GetMapping(path = "/private")
	public Object testPrivate(HttpServletRequest request) {
		
		StringBuffer retour = new StringBuffer(
				"Vous êtes en zone privée donc vous avez bien été authentifié via le header Authorization")
				.append("\n")
				.append("------	HEADERS	------").append("\n");
		
		for(Enumeration<String> data = request.getHeaderNames(); data.hasMoreElements();) {
			String name = data.nextElement().toString();
			retour.append(name + ": " + request.getHeader(name)).append("\n");
		}
		return retour;		
	}
	
	@GetMapping(path = "/public")	
	public Object testPublic(HttpServletRequest request) {
		
		StringBuffer retour = new StringBuffer(
				"Vous êtes en zone publique donc vous n'avez pas besoin de vous authentifier")
				.append("\n")
				.append("------	HEADERS	------").append("\n");
		
		for(Enumeration<String> data = request.getHeaderNames(); data.hasMoreElements();) {
			String name = data.nextElement().toString();
			retour.append(name + ": " + request.getHeader(name)).append("\n");
		}
		return retour;		
	}




}
