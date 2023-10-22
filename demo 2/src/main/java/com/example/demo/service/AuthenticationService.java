package com.example.demo.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {
    //TuyaApiCall.

    private final AuthenticationManager authenticationManager;
    public void login(String authorization) {
        log.info("AuthService : authorization = {}" , authorization);
        /* Authorization 헤더에서 값을 획득, 없거나 잘못된 값이면 에러 */
        String basicCredential = Optional.ofNullable(authorization)
                .filter(auth -> auth.toLowerCase().startsWith("basic"))
                .map(auth -> auth.substring("basic".length()))
                .map(String::trim)
                .orElseThrow(() -> new IllegalArgumentException("Authorization 헤더가 없거나 잘못된 형식입니다."));

        log.info("AuthService : basicCredential = {}" , basicCredential);
        /* Base64 디코딩 후 아이디, 패스워드 획득 */
        byte[] decodedCredential = Base64.getDecoder().decode(basicCredential);
        String credential = new String(decodedCredential, StandardCharsets.UTF_8);
        String[] splitedCredential = Optional.ofNullable(credential)
                .map(c -> credential.split(":"))
                .orElseThrow(() -> new IllegalArgumentException("잘못된 Authorziation 형식입니다."));
        String username = splitedCredential[0];
        String password = splitedCredential[1];
        log.info("AuthService : password = {}" , password);
        /* 인증 시작 */
        //tuya 호출

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        authenticationManager.authenticate(token);
    }
   /* public void register(OpenapiClientRequest openapiClientRequest, String clientId, String clientSecret) {
        jdbcTemplate.update(INSERT_CLIENT_SQL, clientId, openapiClientRequest.getVendorName(), clientSecret,
                openapiClientRequest.getDescription());
    }*/

    public String issueUuid() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}
