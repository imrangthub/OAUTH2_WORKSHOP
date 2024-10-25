package com.madbarsoft;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class MyResourcesController {
	
	Logger logger = LoggerFactory.getLogger(MyResourcesController.class);
	
	
	
    @GetMapping("/resource1")
    public Map<String, String> getEmployeeInfo() {
    	
    	System.out.println("HelloFromgetEmployeeInfo");
    	
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
        return Map.of(
            "employeeId", "EMP001",
            "name", "MD KORIM HOSSAIN",
            "department", "Engineering",
            "AuthObj", curretnAuthentication.toString()
        );
    }
    
    @GetMapping("/resource2")
    public Map<String, String> getEmployeeInfo2() {
    	
    	System.out.println("HelloFromgetEmployeeInfo");
    	
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
        return Map.of(
            "employeeId", "EMP002",
            "name", "MD ROHIME HOSSAIN",
            "department", "Engineering",
            "AuthObj", curretnAuthentication.toString()
        );
    }
	
	@GetMapping("/user")
	public String getUserInfo(Principal principal) {
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
		
		return "Authenticated user: " + principal;
	}
	
	

	@GetMapping("/role")
	public List<String> getUserRoles() {
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
	}

	
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