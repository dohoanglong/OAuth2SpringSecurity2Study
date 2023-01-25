package com.practice.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //        http.authorizeHttpRequests(auth -> auth
        //                .requestMatchers("/", "/error", "/webjars/**").permitAll()
        //                .anyRequest().authenticated())
        //            .exceptionHandling(
        //                e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        //            .oauth2Login()
        //            .and().logout(l -> l
        //                .logoutSuccessUrl("/").permitAll());

        http.authorizeHttpRequests(
            (request) -> request.requestMatchers("/", "/error", "/webjars/**","/index.html/**").permitAll()
                .anyRequest().authenticated());
        http.exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        http.oauth2Login().and().logout(l -> l
            .logoutSuccessUrl("/").permitAll());
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        return http.build();
    }
}
