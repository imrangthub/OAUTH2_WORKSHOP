package com.madbarsoft;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
public class ResourceController {

    @Autowired
    private OAuthTokenService oAuthTokenService;
    
    
  @GetMapping("/")
  public String home() {
      return "home";  // Redirect to the login page
  }
  
  
  @GetMapping("/getinfo")
  public String getinfo(Model model) {

	     String token = oAuthTokenService.getAccessToken();

      // Access the resource server with the token
      String result = accessResourceWithToken(token);

      System.out.println("ResourceServerRes: " + result);
      
      model.addAttribute("result", result);

      return "result";  // Show the result on the result page
  }

    @GetMapping("/callback2")
    public String callback(@RequestParam("code") String code, Model model) {
        // Get or fetch the access token
        String token = oAuthTokenService.getAccessToken(code);

        // Access the resource server with the token
        String result = accessResourceWithToken(token);

        System.out.println("ResourceServerRes: " + result);
        model.addAttribute("result", result);

        return "result";  // Show the result on the result page
    }

    private String accessResourceWithToken(String token) {
        String resourceUrl = "http://localhost:8080/employee/info"; // Adjust as needed

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        HttpEntity<String> request = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(resourceUrl, HttpMethod.GET, request, String.class);

        System.out.println("Resource Response: " + response.getBody());
        return response.getBody();
    }
}