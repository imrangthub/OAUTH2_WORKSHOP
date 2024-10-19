package com.madbarsoft.home;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@GetMapping({ "/home" })

	public String testMsg() {

		System.out.println("From Home Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		return "This message for all From Home Controller";
	}

	@PostMapping("/home")
	public String getAll(@RequestBody(required = false) String reqObj) {

		System.out.println("From Home Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		return "This is form Home Congroller";
	}

}