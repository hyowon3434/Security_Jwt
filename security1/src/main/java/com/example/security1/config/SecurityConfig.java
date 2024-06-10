package com.example.security1.config;

import com.example.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig class)가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true /*secured 어노테이션 활성화*/, prePostEnabled = true /*preAuthorize, postAuthorize 어노테이션 활성화*/)
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .requestMatchers("/user/**").authenticated()
                .requestMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .requestMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip 코드 X, (액세스토큰 + 사용자 프로필정보 o)
                // 1.코드받기(인증), 2. 액세스 토큰(권한) 3. 사용자프로필 정보를 가져오기 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시킨다.
                // 4-2. 구글 프로필정보(이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 ->(vip등급, 일반등급)과 같은 추가정보가 필요

                return http.build();
    }


}
