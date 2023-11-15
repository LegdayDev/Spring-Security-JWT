package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;


        // 토큰이 만들어 졌다고 가정하자 -> 토크 : 코스
        // 실제로는 ID,PW 정상적으로 들어와서 로그인이 완료되면 JWT 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때 마다 HTTP header 에 Authorization 에 Value 값으로 JWT 토큰을 가지고 요청한다.
        // 서버에서는 JWT 토큰을 받으면 받은 JWT 토큰을 서버에서 만든 JWT 토큰인지 검증만 하면 된다 !!(RSA, HS256)
        if(req.getMethod().equals("POST")){
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            if(headerAuth.equals("cos")){
                System.out.println("필터 정상 흐름");
                chain.doFilter(req,res);
            }else {
                PrintWriter writer = res.getWriter();
                writer.println("인증안됨");
            }
        }
    }
}
