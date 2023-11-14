package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(corsFilter)
            .formLogin().disable()
            .httpBasic().disable();

        http.authorizeRequests()
            .antMatchers("/api/v1/user/**")
            .access("hasRole('USER') or hasRole('MANAGER') or hasRole('ADMIN')")
            .antMatchers("/api/v1/manager/**")
            .access("hasRole('MANAGER') or hasRole('ADMIN')")
            .antMatchers("/api/v1/admin/**")
            .access("hasRole('ADMIN')")
            .anyRequest().permitAll();

        return http.build();
    }

}
