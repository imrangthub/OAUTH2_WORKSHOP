package com.madbarsoft.config;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigDefault {
	
    private static final String RESOURCE_ID = "openapi-customer-information";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
        		.requestMatchers("/error").permitAll()
        		.requestMatchers("/","/home").permitAll()
        		.requestMatchers("/role").permitAll()
        		.requestMatchers("/user").permitAll()
                .requestMatchers("/resource1").hasRole("viewer")
                .requestMatchers("/resource2").hasAuthority("editor")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(
                    jwt ->
                        jwt.jwtAuthenticationConverter(
                            new CustomJwtAuthConverter(RESOURCE_ID))));

        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        RSAPublicKey publicKey = (RSAPublicKey) getPublicKey();                     // For Offline jwt validation with public key
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
    
//    @Bean
//    public JwtDecoder jwtDecoder() {                                               // For Online jwt validation with public key from idp server
//        String issuerUri = "http://idp-host:8080/auth/realms/myrealm";
//        return JwtDecoders.fromIssuerLocation(issuerUri);
//    }
    
    private PublicKey getPublicKey() {
        try {
            String publicKeyPEM ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyu3NB7Tr3nzETLNbZHYi" +
                    "ZvgNeg3/OZUJZl40LzBzYGOD/8575eJETjfQ3QXaNyvNThu6Uf9B/V73QUxKI4/+" +
                    "rwlbjA3niIga4MdDiY4b9K/KFA+HedvtZF1yE2p4smXGydPLOLBe31EgriGTob78" +
                    "EE3f7SMFxlNaqn4Pm7KJkOodnMz0ilwLseeL1IkTtiFn/2OrcMpPHMtTxyDn3pQl" +
                    "VCeJM5j/grDh+0YdyTMGdDHOBgM53VqSsDVyo1TNtP2yhPRYCIiI85hEHVaUnVM9" +
                    "jGwCjNZLJHWh10Mrmh6B3z8BEmLhMAZXeL4fQBjBd42DLvIIJwM1USKFhjK+XghN" +
                    "rQIDAQAB";
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    
      
}







