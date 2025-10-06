package com.swc.authserver.config;

import com.swc.authserver.repository.UserRepository;
import com.swc.authserver.utils.FilesUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@Slf4j
public class JwtConfig {
    @Value("${jwt.private-key}")
    private String privateKeyPath;

    @Value("${jwt.public-key}")
    private String publicKeyPath;

    @Autowired
    private FilesUtils filesUtils;
    @Bean
    public RSAKey rsaKey() throws Exception {
        return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    }

    //@Bean
    public JWKSource<SecurityContext> jwkSourceFromRsa(RSAKey rsaKey) {
        JWKSet set = new JWKSet(rsaKey.toPublicJWK());
        return new ImmutableJWKSet<>(set);
    }
    @Bean
    public JWKSource<SecurityContext> jwkSourceFull() throws Exception {
        RSAKey rsaKey = loadRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);//(selector, context) -> selector.select(jwkSet);
    }

    private RSAKey loadRsaKey() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        RSAPrivateKey privateKey = getRsaPrivateKey(kf);
        RSAPublicKey publicKey = getRsaPublicKey(kf);

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("auth-server-key")
                .build();
    }

    private RSAPrivateKey getRsaPrivateKey(KeyFactory kf) throws IOException, InvalidKeySpecException {
        String privateKeyContent = new String(Files.readAllBytes(filesUtils.resolveConfigPath(privateKeyPath)))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent))
        );
        return privateKey;
    }

    private RSAPublicKey getRsaPublicKey(KeyFactory kf) throws IOException, InvalidKeySpecException {
        String publicKeyContent = new String(Files.readAllBytes(filesUtils.resolveConfigPath((publicKeyPath))))
                .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent))
        );
        return publicKey;
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoderFromRsa(RSAKey rsaKey) throws Exception {
        //return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = getRsaPublicKey(kf);
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
    //@Bean
    public JwtDecoder jwtDecoderFromIssuer(@Value("${authorization.server.issuer}") String issuer) {
        log.info("detected issuer: "+issuer);
        return JwtDecoders.fromIssuerLocation(issuer);
    }
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(UserRepository userRepository) {
        return context -> {
            if (context.getPrincipal() != null) {
                Authentication auth = context.getPrincipal();
                Object principal = auth.getPrincipal();
                if (principal instanceof UserDetails ud) {
                    List<String> roles = ud.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());
                    context.getClaims().claim("roles", roles);
                }
            }
        };
    }


}
