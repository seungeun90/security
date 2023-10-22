package com.example.demo.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
public class UserDomain {
    private String uid;
    private String username;
    private String password;
    private String countryCode;
    private String vendor;
    private LocalDateTime lastUpdated = LocalDateTime.now();

    @Builder
    protected UserDomain(String uid, String username, String password, String countryCode, String vendor) {
        this.uid = uid;
        this.username = username;
        this.password = password;
        this.countryCode = countryCode;
        this.vendor = vendor;
    }
}
