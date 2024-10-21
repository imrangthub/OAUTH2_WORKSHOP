package com.madbarsoft.config;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

public class CustomJwtAuthConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		// Extract default authorities from the `scope` claim
		Collection<GrantedAuthority> authorities = defaultConverter.convert(jwt);

		// Extract roles from the `roles` claim and map them to authorities
		List<GrantedAuthority> roleAuthorities = jwt.getClaimAsStringList("roles").stream()
				.map(SimpleGrantedAuthority::new) // No need to add "ROLE_" prefix here
				.collect(Collectors.toList());

		// Combine scope-based authorities with role-based authorities
		return Stream.concat(authorities.stream(), roleAuthorities.stream()).collect(Collectors.toList());
	}
}
