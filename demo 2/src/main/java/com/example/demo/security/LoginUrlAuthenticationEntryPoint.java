package com.example.demo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.security.sasl.AuthenticationException;

public class LoginUrlAuthenticationEntryPoint extends org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint {
    public LoginUrlAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }


    protected String determineUrlToUseForThisRequest(HttpServletRequest request,
                                                     HttpServletResponse response, AuthenticationException exception) {
        return getLoginFormUrl()+"?"+request.getQueryString();
    }
}
