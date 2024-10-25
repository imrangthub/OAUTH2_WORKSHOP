package com.madbarsoft.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CustomJwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {


  private final String resourceId;

  public CustomJwtAuthConverter(String resourceId) {
    this.resourceId = resourceId;
  }
  
 
  @SuppressWarnings("unchecked")
  public AbstractAuthenticationToken convert(Jwt source) {
    Collection<GrantedAuthority> authorities =
        (Collection)
            Stream.concat(
                    (new JwtGrantedAuthoritiesConverter()).convert(source).stream(),
                    extractResourceRoles(source, this.resourceId).stream())
                .collect(Collectors.toSet());
    return new JwtAuthenticationToken(source, authorities);
  }


  @SuppressWarnings("unchecked")
  private static Collection<? extends GrantedAuthority> extractResourceRoles(
      Jwt jwt, String resourceId) {
    Map<String, Object> resourceAccess = (Map) jwt.getClaim("resource_access");
    Map resource;
    Collection resourceRoles;
    return (Collection)
        (resourceAccess != null
                && (resource = (Map) resourceAccess.get(resourceId)) != null
                && (resourceRoles = (Collection) resource.get("roles")) != null
            ? (Collection)
                resourceRoles.stream()
                    .map(
                        (x) -> {
                          return new SimpleGrantedAuthority("ROLE_" + x);
                        })
                    .collect(Collectors.toSet())
            : Collections.emptySet());
  }
  
  
}









