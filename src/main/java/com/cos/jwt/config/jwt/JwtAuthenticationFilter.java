package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있다.
// /login 요청 시 username, password 를 POST 전송하면 UsernamePasswordAuthenticationFilter 가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        try {
            // 1. username, password 받아서
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            // 2. 정상유저인지 authenticationManager 로 로그인 시도를 한다.
            // Token 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // Token 을 AuthenticationManager 에 담는다 !
            // 이 때, PrincipalDetailsService 에 loadUserByUsername() 호출 !
            // authenticate 에 로그인정보가 담긴다.
            Authentication authenticate = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authenticate.getPrincipal();
            System.out.println("principalDetails.getUser() = " + principalDetails.getUser());

            // return 이 될때 세션에 저장된다.
            return authenticate;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 successfulAuthentication() 실행
    // 여기서 JWT 토큰을 만들어서 request 요청한 클라이언트에게 JWT 토큰을 응답해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        System.out.println("successfulAuthentication 실행됨 : 로그인 인증 완료");

        // RSA 방식이 아닌 Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject("cos 토큰") // 크게 상관없다하네요
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10))) // 만료시간(10분)
                .withClaim("id", principalDetails.getUser().getId()) // withClaim 은 비공개 Claim 이니까 아무거나 넣어도댐 !
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); // 내 서버만 아는 고유한 값

        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
