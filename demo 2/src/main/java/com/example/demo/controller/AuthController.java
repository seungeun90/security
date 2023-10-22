package com.example.demo.controller;

import com.example.demo.dto.ClientRequest;
import com.example.demo.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authService;
    /**
     * 로그인 페이지에서 로그인 버튼을 눌렀을 때 호출됨
     *
     * @param authorization
     * @author jmlee
     */
    @PostMapping("/oauth/login/")
    @ResponseStatus(HttpStatus.OK)
    public void login(@RequestBody ClientRequest request,
                      @RequestHeader(name = HttpHeaders.AUTHORIZATION) String authorization) {
        authService.login(authorization);
    }

}
