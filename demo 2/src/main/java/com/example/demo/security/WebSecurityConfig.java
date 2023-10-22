package com.example.demo.security;


import com.example.demo.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final ProxyUserTokenProvider goqualAuthenticationProvider;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                /* csrf */
                .csrf((csrf) -> csrf.disable())
                /* 헤더 프레임옵션 사용하지 않음 */
                .headers(c-> c.frameOptions(f->f.disable()).disable())
                .authenticationProvider(goqualAuthenticationProvider)
                .authorizeHttpRequests(request -> request
                        /* embedded-db와 인증관련 url만 허용 */
                        .requestMatchers("/h2-console/**", "/oauth/**", "/oauth/login/**",
                                "/oauth/actuator/**","/loginPage.html")
                        .permitAll()
                        /* 다른 url은 인증 후 사용 가능 */
                        .anyRequest().authenticated()
                )
                //.and()
                .formLogin()
                .loginPage("/loginPage.html")
                .loginProcessingUrl("/oauth/login/")
                /* Basic Authorization 사용 */
                .and()
                .httpBasic()
                //.authenticationEntryPoint(new NoPopupBasicAuthenticationEntryPoint())
                .and()
                .exceptionHandling()
                // 로그인 페이지로 리디렉션 시, client 정보를 파라미터로 전달하기 위한 설정
                .defaultAuthenticationEntryPointFor(
                        hejLoginUrlAuthenticationEntryPoint(), new AntPathRequestMatcher("/auth/**")
                )
                /* 로그인시 vendor 정보 등록을 위해 사용자 인증 필터 실행 전에 vendor 값을 request의 attribute로 지정 */
                //.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
                .and()
                .getOrBuild();
    }
    @Bean
    public AuthenticationEntryPoint hejLoginUrlAuthenticationEntryPoint() {
        return new LoginUrlAuthenticationEntryPoint("/loginPage.html");
    }
    /*@Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }*/
/*    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder managerBuilder)
            throws Exception {
        return managerBuilder
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder()).and().build();
    }
    /*
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }*/

/*    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                *//* 사용자 정보 서비스 설정 *//*
                .userDetailsService(goqualUserDetailsService)
                *//* 암호 인코더 설정 *//*
                .passwordEncoder(bCryptPasswordEncoder);
    }*/

    @Bean
    protected UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
/*
    @Bean
    public AuthenticationProvider goqualAuthenticationProvider() {
        return new GoqualAuthenticationProvider(httpCaller,service,request,passwordEncoder());
    }*/

    /**
     * CORS 필터 설정
     *
     * @return {@link CorsFilter}
     * @author jmlee
     */
    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader(
                "Content-Type, Origin, Accept, Access-Control-Allow-Headers, Access-Control-Allow-Credentials, Authorization, X-Requested-With");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    /*@Bean
    public FilterRegistrationBean<AddMessageIdFilter> addMessageIdFilter()
    {
        FilterRegistrationBean<AddMessageIdFilter> registrationBean = new FilterRegistrationBean<>();

        AddMessageIdFilter filter = new AddMessageIdFilter();

        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/oauth/token/");
        registrationBean.setOrder(1);

        return registrationBean;
    }
*/
}
