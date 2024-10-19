package com.madbarsoft.config;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import com.madbarsoft.role.RoleEntity;
import com.madbarsoft.user.UserEntity;
import com.madbarsoft.user.UserService;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private UserService userService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		System.out.println("### =============   Find user for Authentication =================== ####");

		String userName = authentication.getName();
		String password = authentication.getCredentials().toString();
		UserEntity user = userService.findByUserName(userName);

		List<RoleEntity> roles = user.getRoles();

		System.out.println("userName: " + userName);
		System.out.println("password: " + password);
		System.out.println("UserEntity" + user);
		System.out.println("roles" + roles);

		if (user != null) {
			
			if (password.equals(user.getPassword())) {    // For Non Encoded Password

				List<RoleEntity> userRoles = user.getRoles();
				List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

				for (RoleEntity role : userRoles) {
					authorities.add(new SimpleGrantedAuthority(role.getName().toString()));
				}
				
				return new UsernamePasswordAuthenticationToken(user.getUsername(),password, authorities);
			}
 
//			if (new BCryptPasswordEncoder().matches(password, user.getPassword())) {   // For Database Encoded Password
//
//				List<RoleEntity> userRoles = user.getRoles();
//				List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
//
//				for (RoleEntity role : userRoles) {
//					authorities.add(new SimpleGrantedAuthority(role.getName().toString()));
//				}
//				
//				return new UsernamePasswordAuthenticationToken(user.getUsername(),password, authorities);
//			}

		}

		return null;

	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
