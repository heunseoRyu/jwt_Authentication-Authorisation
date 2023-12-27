package com.example.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 모든 요청은 먼저 이 필터를 지나고 처리됨.
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull  HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) // http요청, http응답,
            throws ServletException, IOException {
        System.out.println("it's me");
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail; // 유저의 고유한 값 ex) email , id 등
        if (authHeader == null || !authHeader.startsWith("Bearer ")){ // check JWT token : 토큰 존재 여부 파악
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7); // extract jwt
        userEmail = jwtService.extractUsername(jwt); // extract the userEmail from jwtToken
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){ // 유저 이메일 존재 && SecurityContextHolder 뭔가 저장됨.
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); // 유저 조회
            if (jwtService.isTokenValid(jwt, userDetails)){ // token 유효성하다면
                // update SecurityContextHolder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            filterChain.doFilter(request, response);
        }

    }
}
