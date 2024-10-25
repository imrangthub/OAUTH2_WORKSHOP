package com.imranmadbar;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
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
		if (principal != null) {
			String name = principal.getAttribute("name");
			model.addAttribute("result", principal);

		}

		System.out.println("principalObj: " + principal.getName());

		String userName = (String) principal.getAttributes().get("name");
		model.addAttribute("name", userName);
		System.out.println("principalName: " + principal.getName());

		System.out.println("principalRole: " + principal.getAuthorities().toString());

		return "home";

	}

	@GetMapping("/home2")
	public String getUserInfo(Model model) {

		Authentication curretnAuthentication = SecurityContextHolder.getContext().getAuthentication();
		System.out.println("Curretn Authentication All       ####: " + curretnAuthentication);
		System.out.println("Curretn Authentication Name      ####: " + curretnAuthentication.getName());
		System.out.println("Curretn Authentication Principal ####: " + curretnAuthentication.getPrincipal());

		model.addAttribute("name", curretnAuthentication.getName());
		model.addAttribute("result", curretnAuthentication.getAuthorities());

		return "home";
	}

}
