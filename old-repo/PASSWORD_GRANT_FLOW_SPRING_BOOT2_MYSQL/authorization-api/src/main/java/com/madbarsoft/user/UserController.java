package com.madbarsoft.user;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserService userService;
	
	
	@GetMapping({ "/list" })

	public String testMsg() {

		System.out.println("From Authorization Server User Controller");

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		
		System.out.println("Curretn Authentication Name      #: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal #: " + curretnAuthentication.getPrincipal());
		System.out.println("Curretn Authentication All       #: " + curretnAuthentication);
		
		List<UserEntity> userList = userService.list();
		System.out.println("User List: "+userList);

		return userList.toString();
	}

}
