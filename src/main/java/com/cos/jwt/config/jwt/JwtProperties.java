package com.cos.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "cos"; // 서버만 아는 고유의 값
    int EXPIRATION_TIME = 60000*10; // 10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
