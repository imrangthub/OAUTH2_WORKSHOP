package com.madbarsoft.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigDefault {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
        		.requestMatchers("/error").permitAll()
        		.requestMatchers("/home").permitAll()
                .requestMatchers("/employee/info").hasAuthority("SCOPE_read")
                .requestMatchers("/role").hasRole("ADMIN")
                .requestMatchers("/user").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }

    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtAuthConverter());
   
        // Configure the converter if needed (e.g., extracting roles/authorities from JWT claims)
        return converter;
    }
    
    
    
}
