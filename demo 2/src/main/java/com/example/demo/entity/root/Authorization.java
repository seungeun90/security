package com.example.demo.entity.root;

import com.example.demo.entity.AccessToken;
import com.example.demo.entity.AuthorizationCode;
import com.example.demo.entity.RefreshToken;
import com.example.demo.entity.RegisteredClientAuthority;
import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "oauth_approvals")
@Getter
public class Authorization {
    @Id

    private String id;

    @Column(length = 4000)
    private String attributes;

    @Column(length = 500)
    private String oauthState;

    @Embedded
    private RegisteredClientAuthority registeredClientAuthority;

    @Embedded
    private AuthorizationCode authorizationCode;

    @Embedded
    private AccessToken accessToken;
    @Embedded
    private RefreshToken refreshToken;
//    private UserCode userCode;

    public Authorization(
            String id,
            String attributes,
            String oauthState,
            RegisteredClientAuthority registeredClientAuthority
    ){
        this.id = id;
        this.attributes = attributes;
        this.oauthState = oauthState;
        this.registeredClientAuthority = registeredClientAuthority;
    }


    public void updateTokenInfo(
            AuthorizationCode authorizationCode,
            AccessToken accessToken,
            RefreshToken refreshToken){
        this.authorizationCode = authorizationCode;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

}
