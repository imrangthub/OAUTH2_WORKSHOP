package com.madbarsoft.home;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.madbarsoft.util.Response;


@RestController
public class HomeController {

	// @PreAuthorize("#oauth2.hasScope('read')")
	
	@GetMapping("/home")
	public Response testMsg() {

		System.out.println("From Admin Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		
		Response res = new Response();
		
		res.setSuccess(true);
		res.setMessage("From Resource server home Controller Get Mapping !");
		
		return res;
	}
	
	
	@PostMapping(value = "/home", produces = "application/json")
	@ResponseBody
    public Response getAll(@RequestBody(required = false) String reqObj) {
		
		System.out.println("From Admin Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		
		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		
		Response res = new Response();
		
		res.setSuccess(true);
		res.setMessage("From Resource server home Controller post Mapping !");

		return res;
	}

}
