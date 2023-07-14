package com.example.memo.configuration.security;

import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.dto.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final String AUTHORIZATION_HEADER = "Authorization";
	private final JwtUtil jwtUtil;

	JwtAuthenticationFilter(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		try {
			LoginRequest requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);

			return getAuthenticationManager().authenticate(
				new UsernamePasswordAuthenticationToken(
					requestDto.email(),
					requestDto.password(),
					null
				)
			);
		} catch (IOException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
		// TODO : 올바른 인증 요청에 대한 결과로 jwt token 만들고, 검증한 후에 201 response로 해당 token 세팅하기

		// 올바른 인증 요청에 대한 결과?


		//토큰 생성
		String username = ((UserDetails) authResult.getPrincipal()).getUsername();
		String token = jwtUtil.createToken(username);

		//검증하기??



		//토큰 세팅
		response.addHeader(AUTHORIZATION_HEADER , token);
		response.setStatus(201);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		response.setStatus(401);
	}
}
