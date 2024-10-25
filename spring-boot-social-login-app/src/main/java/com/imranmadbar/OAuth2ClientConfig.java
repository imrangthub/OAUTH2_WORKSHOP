package com.imranmadbar;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
public class OAuth2ClientConfig {

    // GitHub OAuth2 credentials
    private static final String GITHUB_CLIENT_ID = "Ov23liX9o07z6ChoKznb";
    private static final String GITHUB_CLIENT_SECRET = "3b07295b2a426029b3aa84288702f994ddafad07";

    

    private ClientRegistration githubClientRegistration() {
        return ClientRegistration.withRegistrationId("github")
                .clientId(GITHUB_CLIENT_ID)
                .clientSecret(GITHUB_CLIENT_SECRET)
                .scope("user:email")
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("login")
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
    }
   
    

    
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
                githubClientRegistration());
    }

}