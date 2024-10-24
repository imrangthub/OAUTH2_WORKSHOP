package com.madbarsoft.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Configuration
public class OAuth2ClientConfig {


    private ClientRegistration myClientAppRegistration() {
        return ClientRegistration.withRegistrationId("spring-boot-client-app")
                .clientId("spring-boot-client-app")
                .clientSecret("spring-boot-client-app-sec")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:7070/callback")
                .scope("read", "profile")
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .tokenUri("http://localhost:9000/oauth2/token")
                .build();
    }
    
    private ClientRegistration myClientAppRegistration2() {
        return ClientRegistration.withRegistrationId("my-client-app")
                .clientId("myclientid")
                .clientSecret("myclientsecret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:7070/callback")
                .scope("read", "profile")
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .tokenUri("http://localhost:9000/oauth2/token")
                .build();
    }
    

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(myClientAppRegistration(),myClientAppRegistration2());
    }

   
}