package com.madbarsoft.user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	@GetMapping("/list")
	public String index() {

		System.out.println("From User Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		return "From User Controller";

	}

	@GetMapping("/per-write")
	@PreAuthorize("#oauth2.hasScope('write')")
	public String adminWrite() {

		System.out.println("From User Controller WRITE PERMISSION");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		return "From User Controller";

	}

	@GetMapping("/per-read")
	@PreAuthorize("#oauth2.hasScope('read')")
	public String userWrite() {

		System.out.println("From User Controller READ PERMISITION");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();

		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);

		return "From User Controller";

	}

}
