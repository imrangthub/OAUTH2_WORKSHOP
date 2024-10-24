package com.madbarsoft;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class AuthTokenService {

    private String accessToken;  // Cached access token
    private Instant tokenExpiry; // Token expiration time

    private final String tokenEndpoint = "http://localhost:9000/oauth2/token"; // Adjust as per your auth server
    private final String clientId = "myclientid";
    private final String clientSecret = "myclientsec";
    private final String redirectUri = "http://localhost:8081/callback2";
    
    
    public String getAccessToken() {
    	 return accessToken;
           
        }

    public String getAccessToken(String code) {
        // Check if the token is still valid
        if (accessToken != null && tokenExpiry != null && Instant.now().isBefore(tokenExpiry)) {
            System.out.println("Using cached access token");
            return accessToken;
        }

        // Fetch a new token if expired or not available
        return exchangeCodeForToken(code);
    }

    private String exchangeCodeForToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenEndpoint, request, Map.class);

        Map<String, Object> responseBody = response.getBody();
        if (responseBody == null) {
            throw new RuntimeException("Invalid response from authorization server");
        }

        accessToken = (String) responseBody.get("access_token");
        int expiresIn = (int) responseBody.get("expires_in");
        tokenExpiry = Instant.now().plusSeconds(expiresIn);

        System.out.println("New Access Token: " + accessToken);
        System.out.println("Token Expiry Time: " + tokenExpiry);
        return accessToken;
    }
}
