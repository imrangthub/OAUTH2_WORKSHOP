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
public class EmployeeController {
	
	Logger logger = LoggerFactory.getLogger(EmployeeController.class);
	
	@GetMapping("/user")
	public String getUserInfo(Principal principal) {
		return "Authenticated user: " + principal.getName();
	}

	@GetMapping("/roles")
	public List<String> getUserRoles() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
	}

    @GetMapping("/employee/info")
    public Map<String, String> getEmployeeInfo() {
    	
    	System.out.println("HelloFromgetEmployeeInfo");
    	
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		
        return Map.of(
            "employeeId", "12345",
            "name", "John Doe",
            "department", "Engineering",
            "AuthObj", curretnAuthentication.toString()
        );
    }
    
    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code) {
    	logger.info( "AuthorizationCode: " + code);
        return "AuthorizationCode: " + code;
        
    }
    
    
}