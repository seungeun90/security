package com.example.demo.oauth.service;

import com.example.demo.entity.AccessToken;
import com.example.demo.entity.AuthorizationCode;
import com.example.demo.entity.RefreshToken;
import com.example.demo.entity.RegisteredClientAuthority;
import com.example.demo.entity.root.Authorization;
import com.example.demo.oauth.repository.AuthorizationRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class JpaOAuth2AuthorizationService  implements OAuth2AuthorizationService {
    private final AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaOAuth2AuthorizationService(AuthorizationRepository authorizationRepository, RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;

        ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.save(toEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        Optional<Authorization> result;
        if (tokenType == null) {
            return null;
      //      result = this.authorizationRepository.findByStateOrAuthorizationCodeAuthorizationCodeValueOrAccessTokenAccessTokenValueOrRefreshTokenRefreshTokenValue(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByOauthState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAuthorizationCodeAuthorizationCodeValue(token);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAccessTokenAccessTokenValue(token);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByRefreshTokenRefreshTokenValue(token);
        } /*else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByOidcIdTokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByDeviceCodeValue(token);
        } */else {
            result = Optional.empty();
        }

        return result.map(this::toObject).orElse(null);
    }

    private OAuth2Authorization toObject(Authorization entity) {

        RegisteredClientAuthority registeredClientAuthority = entity.getRegisteredClientAuthority();

        RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientAuthority.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + entity.getRegisteredClientAuthority().getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(registeredClientAuthority.getPrincipalName())
                .authorizationGrantType(resolveAuthorizationGrantType(registeredClientAuthority.getAuthorizationGrantType()))
                .authorizedScopes(StringUtils.commaDelimitedListToSet(registeredClientAuthority.getAuthorizedScopes()))
                .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));
        if (entity.getOauthState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getOauthState());
        }

        AuthorizationCode authorizationCode1 = entity.getAuthorizationCode();

        if (authorizationCode1.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCode1.getAuthorizationCodeValue(),
                    authorizationCode1.getAuthorizationCodeIssuedAt(),
                    authorizationCode1.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(authorizationCode1.getAuthorizationCodeMetadata())));
        }

        AccessToken accessToken1 = entity.getAccessToken();
        if (accessToken1.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    accessToken1.getAccessTokenValue(),
                    accessToken1.getAccessTokenIssuedAt(),
                    accessToken1.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(accessToken1.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(accessToken1.getAccessTokenMetadata())));
        }

        RefreshToken refreshToken1 = entity.getRefreshToken();
        if (refreshToken1.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    refreshToken1.getRefreshTokenValue(),
                    refreshToken1.getRefreshTokenIssuedAt(),
                    refreshToken1.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(refreshToken1.getRefreshTokenMetadata())));
        }

        return builder.build();
    }

    private Authorization toEntity(OAuth2Authorization authorization) {
        RegisteredClientAuthority registeredClientAuthority = new RegisteredClientAuthority(
                authorization.getRegisteredClientId(),
                authorization.getPrincipalName(),
                authorization.getAuthorizationGrantType().getValue(),
                StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ",")
        );

        Authorization entity = new Authorization(
                authorization.getId(),
                writeMap(authorization.getAttributes()),
                authorization.getAttribute(OAuth2ParameterNames.STATE),
                registeredClientAuthority
        );

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

        OAuth2AuthorizationCode token = authorizationCode.getToken();

        AuthorizationCode authorizationCode1 = new AuthorizationCode(
                token.getTokenValue(),
                token.getIssuedAt(),
                token.getExpiresAt(),
                writeMap(authorizationCode.getMetadata())
        );

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        OAuth2AccessToken oAuth2AccessToken = accessToken.getToken();
        String accessScopes ="";
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            accessScopes = StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ",");
        }
        AccessToken accessToken1 = new AccessToken(
                oAuth2AccessToken.getTokenValue(),
                oAuth2AccessToken.getIssuedAt(),
                oAuth2AccessToken.getExpiresAt(),
                writeMap(accessToken.getMetadata()),
                accessToken.getToken().getTokenType().toString(),
                accessScopes
        );

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        OAuth2RefreshToken oAuth2RefreshToken = refreshToken.getToken();
        RefreshToken refreshToken1 = new RefreshToken(
                oAuth2RefreshToken.getTokenValue(),
                oAuth2RefreshToken.getIssuedAt(),
                oAuth2RefreshToken.getExpiresAt(),
                writeMap(refreshToken.getMetadata())
        );

        entity.updateTokenInfo(authorizationCode1, accessToken1, refreshToken1);
        return entity;
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> metadata) {
        try {
            return this.objectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        } /*else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.DEVICE_CODE;
        }*/
        return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
    }
}
