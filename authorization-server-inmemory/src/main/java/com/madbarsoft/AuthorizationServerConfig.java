package com.madbarsoft;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfig {
	

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }
    
    

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				  .logout(logout -> logout
			                .logoutUrl("/logout")  // Set the logout URL.
			                .logoutSuccessUrl("/login?logout")  // Redirect to login after logout.
			                .invalidateHttpSession(true)  // Invalidate session.
			                .deleteCookies("JSESSIONID"));
		return http.build();
	}

    
    @Bean
    public UserDetailsService userDetailsService() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails userDetails = User.withUsername("imran")
                .password(encoder.encode("mypass"))
                .roles("ADMIN","USER","SUPER_ADMIN")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
    
    
    
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
    	
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("spring-boot-client-app")
    			.clientSecret("{noop}spring-boot-client-app-sec")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    			.redirectUri("http://localhost:7070/callback")
                .scope("profile")
                .scope("read")
                .scope("write")
                .scope("openid") // Required for ID Token
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofHours(20))
                        .build())
    			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        
        RegisteredClient registeredClient2 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("myclientid")
    			.clientSecret("{noop}myclientsec")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    			.redirectUri("http://localhost:7070/callback")
                .scope("profile")
                .scope("read")
                .scope("write")
                .scope("openid") // Required for ID Token
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofHours(20))
                        .build())
    			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient,registeredClient2);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth2/authorize")    // If required any custom end-point
                .tokenEndpoint("/oauth2/token")
                .build();

    }
    
    
	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	  return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	  }
	 
    
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAPublicKey publicKey=null;
        RSAPrivateKey privateKey=null;
		try {
			publicKey = (RSAPublicKey) getPublicKey();
	        privateKey = (RSAPrivateKey) getPrivateKey();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> customTokenEnhancer(UserDetailsService userDetailsService) {
        return context -> {
            // Check if the token being generated is an access token
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Map<String, Object> additionalClaims = new HashMap<>();
                // Determine the grant type used
                String grantType = context.getAuthorizationGrantType().getValue();
                if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
                    // If grant type is 'client_credentials', add system-level roles
                    additionalClaims.put("roles", List.of("ROLE_SYSTEM_USER", "ROLE_SYSTEM_ADMIN"));
                } else if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
                    // If grant type is 'authorization_code', get user roles from UserDetailsService
                    String username = context.getPrincipal().getName();
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    additionalClaims.put("roles", userDetails.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .toList());
                }
                // Add the claims to the JWT
                context.getClaims().claims(claims -> claims.putAll(additionalClaims));
            }
        };
    }
    
    private static PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPublicKey = "-----BEGIN PUBLIC KEY-----" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyu3NB7Tr3nzETLNbZHYi" +
                "ZvgNeg3/OZUJZl40LzBzYGOD/8575eJETjfQ3QXaNyvNThu6Uf9B/V73QUxKI4/+" +
                "rwlbjA3niIga4MdDiY4b9K/KFA+HedvtZF1yE2p4smXGydPLOLBe31EgriGTob78" +
                "EE3f7SMFxlNaqn4Pm7KJkOodnMz0ilwLseeL1IkTtiFn/2OrcMpPHMtTxyDn3pQl" +
                "VCeJM5j/grDh+0YdyTMGdDHOBgM53VqSsDVyo1TNtP2yhPRYCIiI85hEHVaUnVM9" +
                "jGwCjNZLJHWh10Mrmh6B3z8BEmLhMAZXeL4fQBjBd42DLvIIJwM1USKFhjK+XghN" +
                "rQIDAQAB" +
                "-----END PUBLIC KEY-----";
        System.out.println("\n\nrsaPublicKey:\n"+rsaPublicKey);
        rsaPublicKey = rsaPublicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        rsaPublicKey = rsaPublicKey.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    private static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String rsaPrivateKey = "-----BEGIN PRIVATE KEY-----" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDK7c0HtOvefMRM" +
                "s1tkdiJm+A16Df85lQlmXjQvMHNgY4P/znvl4kRON9DdBdo3K81OG7pR/0H9XvdB" +
                "TEojj/6vCVuMDeeIiBrgx0OJjhv0r8oUD4d52+1kXXITaniyZcbJ08s4sF7fUSCu" +
                "IZOhvvwQTd/tIwXGU1qqfg+bsomQ6h2czPSKXAux54vUiRO2IWf/Y6twyk8cy1PH" +
                "IOfelCVUJ4kzmP+CsOH7Rh3JMwZ0Mc4GAzndWpKwNXKjVM20/bKE9FgIiIjzmEQd" +
                "VpSdUz2MbAKM1kskdaHXQyuaHoHfPwESYuEwBld4vh9AGMF3jYMu8ggnAzVRIoWG" +
                "Mr5eCE2tAgMBAAECggEBAKBPXiKRdahMzlJ9elyRyrmnihX7Cr41k7hwAS+qSetC" +
                "kpu6RjykFCvqgjCpF+tvyf/DfdybF0mPBStrlkIj1iH29YBd16QPSZR7NkprnoAd" +
                "gzl3zyGgcRhRjfXyrajZKEJ281s0Ua5/i56kXdlwY/aJXrYabcxwOvbnIXNxhqWY" +
                "NSejZn75fcacSyvaueRO6NqxmCTBG2IO4FDc/xGzsyFKIOVYS+B4o/ktUOlU3Kbf" +
                "vwtz7U5GAh9mpFF+Dkr77Kv3i2aQUonja6is7X3JlA93dPu4JDWK8jrhgdZqY9p9" +
                "Q8odbKYUaBV8Z8CnNgz2zaNQinshzwOeGfFlsd6H7SECgYEA7ScsDCL7omoXj4lV" +
                "Mt9RkWp6wQ8WDu5M+OCDrcM1/lfyta2wf7+9hv7iDb+FwQnWO3W7eFngYUTwSw5x" +
                "YP2uvOL5qbe7YntKI4Q9gHgUd4XdRJJSIdcoY9/d1pavkYwOGk7KsUrmSeoJJ2Jg" +
                "54ypVzZlVRkcHjuwiiXKvHwj2+UCgYEA2w5YvWSujExREmue0BOXtypOPgxuolZY" +
                "pS5LnuAr4rvrZakE8I4sdYjh0yLZ6qXJHzVlxW3DhTqhcrhTLhd54YDogy2IT2ff" +
                "0GzAV0kX+nz+mRhw0/u+Yw6h0QuzH9Q04Wg3T/u/K9+rG335j/RU1Tnh7nxetfGb" +
                "EwJ1oOqcXikCgYEAqBAWmxM/mL3urH36ru6r842uKJr0WuhuDAGvz7iDzxesnSvV" +
                "5PKQ8dY3hN6xfzflZoXssUGgTc55K/e0SbP93UZNAAWA+i29QKY6n4x5lKp9QFch" +
                "dXHw4baIk8Z97Xt/kw07f6FAyijdC9ggLHf2miOmdEQzNQm/9mcJ4cFn+DECgYEA" +
                "gvOepQntNr3gsUxY0jcEOWE3COzRroZD0+tLFZ0ZXx/L5ygVZeD4PwMnTNrGvvmA" +
                "tAFt54pomdqk7Tm3sBQkrmQrm0+67w0/xQ9eJE/z37CdWtQ7jt4twHXc0mVWHa70" +
                "NdPhTRVIAWhil7rFWANOO3Gw2KrMy6O1erW7sAjQlZECgYBmjXWzgasT7JcHrP72" +
                "fqrEx4cg/jQFNlqODNb515tfXSBBoAFiaxWJK3Uh/60/I6cFL/Qoner4trNDWSNo" +
                "YENBqXLZnWGfIo0vAIgniJ6OD67+1hEQtbenhSfeE8Hou2BnFOTajUxmYgGm3+hx" +
                "h8TPOvfHATdiwIm7Qu76gHhpzQ==" +
                "-----END PRIVATE KEY-----";
        System.out.println("rsaPrivateKey:\n"+rsaPrivateKey);

        rsaPrivateKey = rsaPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END PRIVATE KEY-----", "");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    
    



}