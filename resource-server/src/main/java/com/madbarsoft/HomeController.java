package com.madbarsoft;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
public class HomeController {

	Logger logger = LoggerFactory.getLogger(HomeController.class);

	@GetMapping(value = "/")
	public String welcomeMsg() {
		logger.info("welcomeMsgOAuth2ResourceServerApp from HomeController");
	

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
		return "Welcome to OAuth2ResourceServerApp";
	}

	@GetMapping(value = "/home")
	public String welcomeMsgHome() {
		logger.info("welcomeMsgHomeOAuth2ResourceServerApp Home");
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
		return "Welcome to OAuth2ResourceServerApp Home";
	}

}
