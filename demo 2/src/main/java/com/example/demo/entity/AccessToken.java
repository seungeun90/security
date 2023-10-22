package com.example.demo.entity;

import com.example.demo.util.DateInstantConverter;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;
import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
@Embeddable
public class AccessToken {
    @Column(length = 4000)
    private String accessTokenValue;

    @Convert(converter = DateInstantConverter.class)
    private Instant accessTokenIssuedAt;

    //@Temporal(TemporalType.TIMESTAMP)
    @Convert(converter = DateInstantConverter.class)
    private Instant accessTokenExpiresAt;
    @Column(length = 2000)
    private String accessTokenMetadata;


    private String accessTokenType;
    @Column(length = 1000)
    private String accessTokenScopes;

}
