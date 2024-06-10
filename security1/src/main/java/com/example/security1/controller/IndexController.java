package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
public class IndexController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication, // DI(의존성 주입)
                                          @AuthenticationPrincipal PrincipalDetails userDetails){  /* AuthenticationPrincipal 어노테이션을 통해 세션정보에 접근가능*/
        System.out.println("/test/login=======================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : " + principalDetails.getUser());

        System.out.println("userDetails : " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oauth){
        System.out.println("/test/oauth/login=======================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oauth2User : " + oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }
    @GetMapping({"", "/"})
    public String index(){
        // 머스테치 기본폴터 src/main/resources/
        // 뷰리졸버 설정: templates(prefix), .mustache(suffix) // 색량가능!!
        return "index"; // src/main.resources/templates/index.mustache
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("principalDetails : " + userDetails.getUser());

        return "user";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public @ResponseBody String join(User user){
        String rawPW = user.getPassword();
        String encPW = bCryptPasswordEncoder.encode(rawPW);
        user.setPassword(encPW);
        user.setRole("ROLE_USER");

        userRepository.save(user); // 회원가입 잘됨. 비밀번호: 1234 => 시큐리티로 로그인 x. 패스워드가 암호화 안됨.
        log.warn(user.toString());
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIK')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
}
