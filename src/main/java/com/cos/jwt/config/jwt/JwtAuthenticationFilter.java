package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있다.
// /login 요청 시 username, password 를 POST 전송하면 UsernamePasswordAuthenticationFilter 가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 핫무
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 받아서

        // 2. 정상유저인지 authenticationManager 로 로그인 시도를 한다.

        // 3. authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService 가 호출되면서 loadUserByUsername() 호출

        // 4. PrincipalDetails 를 세션에 담는다(세션에 안담으면 권한 관리가 안된다)

        // 5. JWT 토큰을 만들어서 응답해주면 됨.
        return super.attemptAuthentication(request, response);
    }
}
