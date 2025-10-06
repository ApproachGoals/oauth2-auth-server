package com.swc.authserver.utils;

import com.swc.authserver.entities.Permission;
import com.swc.authserver.entities.Role;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

@Component
@Slf4j
public class JwtUtils {
    @Autowired
    private JwtEncoder jwtEncoder;
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
        //RSAKey rsaKey = (RSAKey) jwkSource.get(null, null).iterator().next();

        //JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());
        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .subject(username)
                .claim("roles", roles)
                .claim("permissions", permissions)
                .expiresAt(now.plusSeconds(expirationSeconds))
                .issuedAt(now)
                .build();

        /*SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .build(), claimsSet);

        signedJWT.sign(signer);

        return signedJWT.serialize();
         */
        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
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
}
