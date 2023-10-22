package com.example.demo.entity;

import com.example.demo.util.DateInstantConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;
import java.time.LocalDateTime;


@Getter
@AllArgsConstructor
@Embeddable
public class AuthorizationCode {

    @Column(length = 4000)
    private String authorizationCodeValue;

    @Convert(converter = DateInstantConverter.class)
    private Instant authorizationCodeIssuedAt;

    @Convert(converter = DateInstantConverter.class)
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;
}
