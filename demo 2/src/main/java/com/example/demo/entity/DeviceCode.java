package com.example.demo.entity;

import jakarta.persistence.Column;
import lombok.Getter;

import java.time.Instant;

@Getter
public class DeviceCode {

    @Column(length = 4000)
    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;
    @Column(length = 2000)
    private String deviceCodeMetadata;
}
