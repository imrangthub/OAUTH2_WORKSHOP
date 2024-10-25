package com.imranmadbar;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomePageController {
	
	
	@GetMapping("/")
	public String displayIndexPage(Model model) {
		
		return "index";
		
	}
	

	@GetMapping("/home")
	public String displayHomePage(Model model, @AuthenticationPrincipal OAuth2User principal) {
		System.out.println("principal: "+principal);
		if (principal != null) {
			String name = principal.getAttribute("name");
			model.addAttribute("result",principal);
			model.addAttribute("name",name);
		}
		
		return "home";
		
	}

	
	
}
