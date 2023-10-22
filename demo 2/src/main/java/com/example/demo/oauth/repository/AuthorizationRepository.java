package com.example.demo.oauth.repository;

import com.example.demo.entity.root.Authorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface AuthorizationRepository extends JpaRepository<Authorization,String> {
    Optional<Authorization> findByOauthState(String state);
    Optional<Authorization> findByAuthorizationCodeAuthorizationCodeValue(String authorizationCode);
    Optional<Authorization> findByAccessTokenAccessTokenValue(String accessToken);
    Optional<Authorization> findByRefreshTokenRefreshTokenValue(String refreshToken);
   // Optional<Authorization> findByOidcIdTokenValue(String idToken);
   // Optional<Authorization> findByUserCodeValue(String userCode);
   // Optional<Authorization> findByDeviceCodeValue(String deviceCode);

}
