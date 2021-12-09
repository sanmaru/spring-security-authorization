package com.sanmaru.security.mfa.contoller;

import com.sanmaru.security.mfa.custom.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
class LoginController {

    @Autowired
    CustomUserRepository customUserRepository;

    private final AuthenticationSuccessHandler successHandler;

    private final AuthenticationFailureHandler failureHandler;

    final static Logger logger = LoggerFactory.getLogger(LoginController.class);

    LoginController(AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @GetMapping("/")
    public String login() {
        logger.info("============= LoginController GetMapping /");
//        return "mfa_totp";
        return "index";
    }

    @GetMapping("/mfa_totp")
    public String factor() {
        logger.info("============= LoginController GetMapping /mfa_totp");
        return "mfa_totp";
    }

    @PostMapping("/mfa_totp")
    public void processSecondFactor(@RequestParam("code") String code, MfaAuthentication authentication,
                                      HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("============= LoginController PostMapping /mfa_totp : " + code);
        logger.info("============= LoginController PostMapping /authentication : " + authentication);
        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
        logger.info("============= LoginController PostMapping /mfa_totp : " + user.getUsername());
//        CustomUser customUser = customUserRepository.getById(user.getUsername());
//        logger.info("============= LoginController PostMapping /mfa_totp customUser : " + customUser.getUsername());
//        logger.info("============= LoginController PostMapping /mfa_totp customUser : " + customUser.getMfa());
        SecurityContextHolder.getContext().setAuthentication(authentication.getFirst());
        this.successHandler.onAuthenticationSuccess(request, response, authentication.getFirst());
    }

}