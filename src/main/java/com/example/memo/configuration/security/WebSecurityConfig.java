package com.example.memo.configuration.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

	private final AuthenticationConfiguration authenticationConfiguration;
	private JwtUtil jwtUtil;
	private UserDetailsService userDetailsService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
		JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil);
		filter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
		return filter;
	}

	@Bean
	public JwtAuthorizationFilter jwtAuthorizationFilter() {
		return new JwtAuthorizationFilter(jwtUtil, userDetailsService);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			.httpBasic(AbstractHttpConfigurer::disable)
			.csrf(AbstractHttpConfigurer::disable)
			.addFilter(jwtAuthenticationFilter())
			.addFilterAfter(jwtAuthorizationFilter(), JwtAuthenticationFilter.class)
			.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(
				SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(httpRequests -> httpRequests
				.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
				.requestMatchers("/api/members/**").permitAll()
				.anyRequest().authenticated());

		return httpSecurity.build();
	}
}
