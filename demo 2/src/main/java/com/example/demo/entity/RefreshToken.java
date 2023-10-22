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
public class RefreshToken {
    @Column(length = 4000)
    private String refreshTokenValue;

    @Convert(converter = DateInstantConverter.class)
    private Instant refreshTokenIssuedAt;

    @Convert(converter = DateInstantConverter.class)
    private Instant refreshTokenExpiresAt;

    @Column(length = 2000)
    private String refreshTokenMetadata;
}
