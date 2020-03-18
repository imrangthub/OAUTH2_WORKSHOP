package com.madbarsoft.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
		.antMatchers("/login").permitAll()
		.antMatchers("/home").permitAll()
		.antMatchers("/admin/**").hasRole("ADMIN")
		.antMatchers("/user").hasAnyAuthority("USER","ADMIN")
		.anyRequest().authenticated();
	}

	@Bean(name = "authServerAuthenticationManager")
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.inMemoryAuthentication()
		.withUser("user").password("12345").roles("USER")
		.and()
		.withUser("admin").password("123456").roles("USER", "ADMIN");

	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	// http.authorizeRequests()
	// .anyRequest().permitAll();
	// }

	// @Override
	// protected void configure(final HttpSecurity http) throws Exception {
	//
	// // @formatter:off
	// http.authorizeRequests().antMatchers("/login").permitAll()
	// //.antMatchers("/oauth/token/revokeById/**").permitAll()
	// .antMatchers("/home").permitAll()
	// .antMatchers("/oauth/token/logout").permitAll()
	// .antMatchers("/fapi/**").permitAll()
	// .antMatchers("/actuator/**").permitAll()
	// .antMatchers("/tokens/**").permitAll()
	// .anyRequest().authenticated()
	// .and().formLogin().permitAll()
	// .and().csrf().disable();
	//
	// }

	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	// http.authorizeRequests()
	// .anyRequest().authenticated()
	// .antMatchers("/login").permitAll()
	// .antMatchers("/home").permitAll()
	// .antMatchers("/user/**").hasRole("USER")
	// .antMatchers("/admin/**").hasRole("ADMIN");
	//
	// http.logout()
	// .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	// .logoutSuccessUrl("/home")
	// .and()
	// .formLogin().permitAll();
	// }

	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	//
	// //authorize requests
	// http.authorizeRequests()
	// .and().httpBasic()
	// .antMatchers("/").permitAll()
	// .antMatchers("/home").permitAll()
	// .antMatchers("/gnr-auth-token").permitAll()
	// .antMatchers("/auth/**").permitAll()
	// .antMatchers("/admin/**").hasRole("ADMIN")
	// .antMatchers("/user").hasAnyAuthority("USER","ADMIN")
	// .anyRequest()
	// .authenticated().and().csrf().disable();
	//
	// http.formLogin()
	// .loginPage("/login");
	//
	// http.logout()
	// .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	// //.deleteCookies("JSESSIONID")
	// .logoutSuccessUrl("/home");
	//
	// }

	//
	// @Override
	// protected void configure(HttpSecurity http) throws Exception {
	// http.authorizeRequests().anyRequest().permitAll();
	// }
}
