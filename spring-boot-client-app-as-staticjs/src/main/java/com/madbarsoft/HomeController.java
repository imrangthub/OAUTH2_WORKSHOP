package com.madbarsoft;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
public class HomeController {

	@Autowired
	private AuthTokenService oAuthTokenService;

	@GetMapping("/")
	public String index() {
		return "home";
	}

	@GetMapping("/home")
	public String home() {
		return "home";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/logout")
	public String logout() {
		oAuthTokenService.removeToken();
		return "home";
	}

	@GetMapping("/get-resource1")
	public String getResource1(Model model) {
		String token = oAuthTokenService.getAccessToken();
		if (token == null) {
			return "login";
		}
		String resourceUrl = "http://localhost:8080/resource1";
		String result = accessResourceWithToken(token, resourceUrl);
		model.addAttribute("result", result);
		return "result";
	}

	@GetMapping("/get-resource2")
	public String getResource2(Model model) {
		String token = oAuthTokenService.getAccessToken();
		if (token == null) {
			return "login"; // Redirect to the login page
		}
		String resourceUrl = "http://localhost:8080/resource2";
		String result = accessResourceWithToken(token, resourceUrl);
		model.addAttribute("result", result);
		return "result";
	}

	@GetMapping("/callback")
	public String callback(@RequestParam("code") String code, Model model) {

		System.out.println("callbackCode: " + code);
		// Get or fetch the access token
		String token = oAuthTokenService.getAccessToken(code);
		System.out.println("getAccessToken: " + token);

		model.addAttribute("message", "Login sucessfull !");

		return "home"; // Redirect to the login page
	}

	private String accessResourceWithToken(String token, String resourceUrl) {

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(token);
		HttpEntity<String> request = new HttpEntity<>(headers);

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> response = restTemplate.exchange(resourceUrl, HttpMethod.GET, request, String.class);

		System.out.println("Resource Response: " + response.getBody());
		return response.getBody();
	}

}
