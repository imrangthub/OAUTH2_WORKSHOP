package com.madbarsoft.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private CustomAccessDeniedHandler customAccessDeniedHandler;
	
	@Autowired
	private CustomAuthenticationProvider customAuthenticationProvider;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(customAuthenticationProvider);
		auth.eraseCredentials(false);
	}
	

	@Override	
	@Bean(name = "authServerAuthenticationManager")
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}


   @Override
   protected void configure(HttpSecurity http) throws Exception {
	   
	 //authorize requests		
	 		http.authorizeRequests()
	 				.antMatchers("/").permitAll()
	 				.antMatchers("/home").permitAll()
	 				.antMatchers("/user/**").permitAll()
	 				.antMatchers("/auth/**").permitAll()
	 				//.antMatchers("/user/doctor").hasAnyAuthority("ROLE_DOCTOR","ROLE_ADMIN")
	 				.anyRequest()
	 				.authenticated().and().csrf().disable();	 				
	 				
	 	//exception configuration				
	 				http.exceptionHandling()
	 				.accessDeniedHandler(customAccessDeniedHandler);
   }
   
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
   
//	@Bean
//	public BCryptPasswordEncoder passwordEncoder() {
//	    return new BCryptPasswordEncoder();
//	}
//	

}
