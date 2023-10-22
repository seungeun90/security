package com.example.demo.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class ProxyUserTokenProvider implements AuthenticationProvider {
    private final HttpServletRequest request;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("GoqualAuthenticationProvider : authentication = {}" , authentication);
        /* 로그인 성공시 업데이트를 위해 vendor 정보 획득 */
        String vendor = Optional.ofNullable(request.getParameter("vendor"))
                .orElse("openapi");
        /* 인증에 사용할 사용자 이름(아이디) 획득 */
        String username = authentication.getName();
        /* 인증에 사용할 사용자 비밀번호 획득 */
        String credential = authentication.getCredentials().toString();
        /*
         * 국가코드
         * XXX: 추후에 글로벌 서비스를 제공할 경우 로그인 페이지에서 국가 코드를 같이 전달해줘야함
         */
        String countryCode = "82";
     /*   UsernameType usernameType = UsernameType.resolve(username);
        *//* Tuya로 로그인 요청 *//*
        LoginRequest loginRequest = LoginRequest.builder()
                .username(usernameType.equals(UsernameType.MOBILE) ? countryCode + "-" + username : username)
                .countryCode(countryCode)
                .password(Md5Converter.convert(credential))
                .usernameType(usernameType)
                .build();
        *//* 응답 확인, 에러일 경우 에러 반환 *//*
        LoginResponse loginResponse = service.login("goqual", loginRequest);
        if (!loginResponse.isSuccess()) {
            if (loginResponse.getCode().equals(GlobalErrorCode.GEC_2006))
                throw new UsernameNotFoundException("존재하지 않는 아이디 입니다.");
            throw new InternalAuthenticationServiceException("내부 서버 오류에 의해 인증에 실패하였습니다.");
        }
        *//* 로그인 성공 후 DB에 업데이트, 사용자를 DB로 확인하기 쉽게 앞에 국가코드 제거 *//*
        username = username.startsWith(countryCode)
                ? username.substring(countryCode.length(), username.length() - 1)
                : username;
        username = username.contains("-")
                ? username.replaceAll("\\-", "")
                : username;
        *//* DB에 사용자정보 저장 *//*
        GoqualUser user = GoqualUser.builder()
                .countryCode(loginRequest.getCountryCode())
                .password(passwordEncoder.encode(credential))
                .uid(loginResponse.getResult().getUid())
                .username(username)
                .vendor(vendor)
                .build();
        //	userRepository.save(user);
        *//** 헤더 설정 *//*
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.AUTHORIZATION, ContextUtils.getHeader(HttpHeaders.AUTHORIZATION));

        Map<String, Object> body = ConvertUtils.convert(user, new TypeReference<>() {});
        *//** 게이트웨이 요청 *//*
        Object response = httpCaller.post(
                GatewayType.SYNC,  Api.USER,
                String.format("/user"),
                body, headers, Object.class).block();

        *//** 요청 결과 형변환 *//*
        GoqualUser goqualUser = ConvertUtils.convert(response, new TypeReference<GoqualUser>() {});
        *//*
         * 인증이 통과된 사용자 authentication 반환, UsernamePasswordAuthenticationToken은
         * Authenticatino의 가장 간단한 구현체로 아이디, 비밀번호, 권한 외에 다른 정보가 필요없음
         *//*
        return new UsernamePasswordAuthenticationToken(username, authentication.getCredentials(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_GOQUAL_USER")));*/
        return new UsernamePasswordAuthenticationToken(username, authentication.getCredentials(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_GOQUAL_USER")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
