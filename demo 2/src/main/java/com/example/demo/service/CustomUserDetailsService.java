package com.example.demo.service;

import com.example.demo.domain.UserDomain;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("GoqualUserDetailsService username = {}" , username);
        UserDomain goqualUser = UserDomain.builder()
                .uid("aadd")
                .password("dd")
                .vendor("thinq")
                .build();
        return  new User(username, goqualUser.getPassword(), true, true, true, true,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_GOQUAL_USER")));
    }
}
