package com.example.demo.entity.root;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Type;

import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name="oauth_client_details")
@Getter
public class Client {
    @Id
    @Column
    private String id;
    private String clientId;

    @Temporal(TemporalType.DATE)
    private Instant clientIdIssuedAt;
    private String clientSecret;

    @Temporal(TemporalType.DATE)
    private Instant clientSecretExpiresAt;
    private String clientName;
    @Column(length = 1000)
    private String clientAuthenticationMethods;
    @Column(length = 1000)
    private String authorizationGrantTypes;
    @Column(length = 1000)
    private String redirectUris;
    @Column(length = 1000)
    private String postLogoutRedirectUris;
    @Column(length = 1000)
    private String scopes;
    @Column(length = 2000)
    private String clientSettings;
    @Column(length = 2000)
    private String tokenSettings;

    @Builder
    public Client(
            String id,
            String clientId,
            Instant clientIdIssuedAt,
            String clientSecret,
            Instant clientSecretExpiresAt,
            String clientName,
            String clientAuthenticationMethods,
            String authorizationGrantTypes,
            String redirectUris,
            String postLogoutRedirectUris,
            String scopes,
            String clientSettings,
            String tokenSettings
    ){
        this.id = id;
        this.clientId = clientId;
        this.clientIdIssuedAt = clientIdIssuedAt;
        this.clientSecret = clientSecret;
        this.clientSecretExpiresAt = clientSecretExpiresAt;
        this.clientName = clientName;
        this.clientAuthenticationMethods = clientAuthenticationMethods;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.redirectUris = redirectUris;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.scopes = scopes;
        this.clientSettings = clientSettings;
        this.tokenSettings = tokenSettings;

    }

}
