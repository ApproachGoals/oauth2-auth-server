package com.swc.authserver.utils;

import com.swc.authserver.config.JwtConfig;
import com.swc.authserver.entities.Permission;
import com.swc.authserver.entities.Role;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.swc.authserver.entities.User;
import com.swc.authserver.models.TokenValidationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Component
@Slf4j
public class JwtUtils {
    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private JwtDecoder jwtDecoder;
    @Autowired
    private StringRedisTemplate redisTemplate;
    public String[] getRolesAsArray(List<Role> roles) {
        return roles
                .stream()
                .map(Role::getName)  // Role -> String
                .toArray(String[]::new);
    }
    public String[] getPermissionsAsArray(List<Permission> permissions) {
        return permissions
                .stream()
                .map(Permission::getName)
                .toArray(String[]::new);

    }
    public String generateToken(String username, List<Role> roles, List<Permission> permissions,
                                String tokenId, int expirationSeconds, JWKSource<SecurityContext> jwkSource) throws JOSEException {
        String[] rolesArray = getRolesAsArray(roles);
        String[] permissionsArray = getPermissionsAsArray(permissions);
        return generateToken(username, rolesArray, permissionsArray, tokenId, expirationSeconds, jwkSource);
    }
    public String generateToken(String username, String[] roles, String[] permissions,
                                String tokenId, int expirationSeconds, JWKSource<SecurityContext> jwkSource) throws JOSEException {

        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .subject(username)
                .claim("roles", roles)
                .claim("permissions", permissions)
                .expiresAt(now.plusSeconds(expirationSeconds))
                .issuedAt(now)
                .id(tokenId)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
    public Jwt parseToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt;
        } catch (Exception e) {
            return null;
        }
    }
    public String readTokenId(String token) {
        return readTokenId(parseToken(token));
    }
    public String readTokenId(Jwt jwt) {
        return jwt.getId();
    }
    public boolean checkIsNotExpired(String token) {
        return checkIsNotExpired(parseToken(token));
    }
    public boolean checkIsNotExpired(Jwt jwt) {
        Instant now = Instant.now();
        if(jwt!=null) {
            if(jwt.getExpiresAt()!=null && jwt.getExpiresAt().isBefore(now)){
                return false;
            } else {
                return true;
            }
        }
        return false;
    }
    public String[] parseBasicAuthHeader(String authorization) {
        try {
            log.info("got authorization header: "+authorization);
            if (authorization != null && authorization.startsWith("Basic ")) {
                String base64Credentials = authorization.substring("Basic ".length());
                byte[] decodedBytes;
                try {
                    decodedBytes = Base64.getDecoder().decode(base64Credentials);
                } catch (IllegalArgumentException e) {
                    // 尝试 URL-safe Base64
                    decodedBytes = Base64.getUrlDecoder().decode(base64Credentials);
                }
                String credentials = new String(decodedBytes, StandardCharsets.UTF_8);

                String[] values = credentials.split(":", 2);
                return values;
            } else {
                // invalid basic authorization
                log.error("cannot parse basic authorization: "+authorization);
            }
        } catch (Exception e) {
            log.error("cannot parse basic authorization");
        }
        return new String[2];
    }
    public ResponseEntity validateToken(String token) {
        try {
            if(token==null){
                return new ResponseEntity(
                        TokenValidationResponse.builder()
                                .message("Invalid authorization")
                                .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                                .timestamp(Instant.now())
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }
            Jwt jwt = parseToken(token);
            String tokenId = jwt.getId();
            if (tokenId == null) {
                return new ResponseEntity(
                        TokenValidationResponse.builder()
                                .message("Invalid authorization")
                                .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                                .timestamp(Instant.now())
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }

            // read data from Redis
            Map<Object, Object> redisData = redisTemplate.opsForHash().entries("token:" + tokenId);
            if (redisData.isEmpty()) {
                log.warn("Token {} not found in Redis", tokenId);
                return new ResponseEntity(
                        TokenValidationResponse.builder()
                                .message("Invalid authorization")
                                .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                                .timestamp(Instant.now())
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }
            try {
                String storedToken = (String) redisData.get("token");
                if (!token.equals(storedToken)) {
                    log.warn("Token mismatch for {}", tokenId);
                    return new ResponseEntity(
                            TokenValidationResponse.builder()
                                    .message("Invalid authorization")
                                    .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                                    .timestamp(Instant.now())
                                    .build(),
                            HttpStatus.UNAUTHORIZED
                    );
                }
            } catch (Exception jwtException) {
                log.error("cannot get token from Redis", jwtException);
            }

            if(!checkIsNotExpired(jwt)){
                return new ResponseEntity(
                        TokenValidationResponse.builder()
                                .message("Expired token")
                                .status(String.valueOf(HttpStatus.UNAUTHORIZED.value()))
                                .timestamp(Instant.now())
                                .build(),
                        HttpStatus.UNAUTHORIZED
                );
            }

            return new ResponseEntity(
                    TokenValidationResponse.builder()
                            .status(String.valueOf(HttpStatus.OK.value()))
                            .timestamp(Instant.now())
                            .build(),
                    HttpStatus.OK
            );
        } catch (IllegalArgumentException e) {
            return new ResponseEntity(
                    TokenValidationResponse.builder()
                            .message("Cannot validate authorization")
                            .status(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()))
                            .timestamp(Instant.now())
                            .build(),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }
    public void saveInRedis(String username, Optional<User> user, String tokenId, String tokenValue, int expirationSeconds) {
        try {
            Map<String, String> redisData = new HashMap<>();
            redisData.put("username", username);
            redisData.put("roles", String.join(",", getRolesAsArray(user.get().getRoles())));
            redisData.put("permissions", String.join(",", getPermissionsAsArray(user.get().getPermissions())));
            redisData.put("token", tokenValue);
            redisData.put("createdAt", Instant.now().toString());

            String key = "token:" + tokenId;
            redisTemplate.opsForHash().putAll(key, redisData);
            redisTemplate.expire(key, Duration.ofSeconds(expirationSeconds));
            redisTemplate.opsForSet().add("user:" + username + ":tokens", tokenId);
        } catch (Exception e) {
            log.error("cannot save token on redis", e);
        }

    }
    public void revokeToken(String token) {
        Jwt jwt = parseToken(token);
        String tokenId = jwt.getId();
        String username = jwt.getSubject();
        redisTemplate.delete("token:" + tokenId);
        redisTemplate.opsForSet().remove("user:" + username + ":tokens", tokenId);
    }
}
