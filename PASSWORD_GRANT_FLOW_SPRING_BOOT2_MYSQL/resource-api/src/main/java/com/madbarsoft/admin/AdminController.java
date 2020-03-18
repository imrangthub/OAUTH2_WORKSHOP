package com.madbarsoft.admin;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {
	
	@GetMapping("/list")
	public String index(){
		
		System.out.println("From Admin Controller");
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
	
		System.out.println("Curretn Authentication Name      #: "+curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: "+curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: "+curretnAuthentication);
		
		return  "From Admin Controller";
				
	}
	
	@GetMapping("/per-write")
	@PreAuthorize("#oauth2.hasScope('write')")
	public String adminWrite(){
		
		System.out.println("From Admin Controller WRITE PERMISSION");
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: "+curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: "+curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: "+curretnAuthentication);
		
		return  "From Admin Controller";
				
	}
	
	@GetMapping("/per-read")
	@PreAuthorize("#oauth2.hasScope('read')")
	public String adminRead(){
		
		System.out.println("From Admin Controller Read PERMISSION");
		
		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: "+curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: "+curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: "+curretnAuthentication);
		
		return  "From Admin Controller";
				
	}
	
	
	

}
