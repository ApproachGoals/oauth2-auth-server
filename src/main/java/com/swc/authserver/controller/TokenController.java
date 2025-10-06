package com.swc.authserver.controller;

import com.swc.authserver.entities.User;
import com.swc.authserver.models.GeneralErrorResponse;
import com.swc.authserver.models.JwtResponse;
import com.swc.authserver.repository.UserRepository;
import com.swc.authserver.utils.JwtUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@Slf4j
@Schema(name = "authorization")
public class TokenController {
    private final UserRepository userRepository;
    private final StringRedisTemplate redisTemplate;
    private final JWKSource<SecurityContext> jwkSource;
    private final int expirationSeconds;
    @Autowired
    private JwtUtils jwtUtils;

    public TokenController(UserRepository userRepository,
                           StringRedisTemplate redisTemplate,
                           JWKSource<SecurityContext> jwkSource,
                           @Value("${jwt.expiration-seconds}") int expirationSeconds) {
        this.userRepository = userRepository;
        this.redisTemplate = redisTemplate;
        this.jwkSource = jwkSource;
        this.expirationSeconds = expirationSeconds;
    }

    @PostMapping("/login")
    public ResponseEntity<?> getToken(@RequestParam String username, @RequestParam String password) throws JOSEException {
        Optional<User> user = userRepository.findByUsername(username);

        ResponseEntity<GeneralErrorResponse> FORBIDDEN = getGeneralErrorResponseResponseEntity(user, password);
        if (FORBIDDEN != null) return FORBIDDEN;

        // 生成 token
        String tokenId = UUID.randomUUID().toString();
        String token = jwtUtils.generateToken(username, user.get().getRoles(), user.get().getPermissions(), tokenId, expirationSeconds, jwkSource);

        saveInRedis(username, user, tokenId);

        JwtResponse jwtResponse = JwtResponse.builder()
                .accessToken(token)
                .expiresIn(Long.valueOf(expirationSeconds))
                .tokenType("Bearer")
                .tokenId(tokenId)
                .success(true)
                .build();
        return ResponseEntity.ok(jwtResponse);
    }

    private void saveInRedis(String username, Optional<User> user, String tokenId) {
        Map<String, String> redisData = new HashMap<>();
        redisData.put("username", username);
        redisData.put("roles", String.join(",", jwtUtils.getRolesAsArray(user.get().getRoles())));
        redisData.put("permissions", String.join(",", jwtUtils.getPermissionsAsArray(user.get().getPermissions())));
        redisTemplate.opsForHash().putAll("token:" + tokenId, redisData);
        redisTemplate.expire("token:" + tokenId, Duration.ofSeconds(expirationSeconds));
    }

    @Operation(
            summary = "get JWT token",
            description = "return JWT token according to the basic token"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Success",
                    content = @Content(schema = @Schema(implementation = JwtResponse.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Invalid credentials",
                    content = @Content(schema = @Schema(implementation = GeneralErrorResponse.class))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal error",
                    content = @Content(schema = @Schema(implementation = GeneralErrorResponse.class))
            )
    })
    @PostMapping("/token")
    public ResponseEntity<?> getToken(@RequestHeader(value= HttpHeaders.AUTHORIZATION, required = false) String basicAuthHeader) throws JOSEException {
        try {
            String value[] = jwtUtils.parseBasicAuthHeader(basicAuthHeader);
            if(value==null){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            String username = value[0];
            String password = value[1];

            Optional<User> user = userRepository.findByUsername(username);
            ResponseEntity<GeneralErrorResponse> FORBIDDEN = getGeneralErrorResponseResponseEntity(user, password);
            if (FORBIDDEN != null) return FORBIDDEN;

            // generate token
            String tokenId = UUID.randomUUID().toString();
            String token = jwtUtils.generateToken(username, user.get().getRoles(), user.get().getPermissions(), tokenId, expirationSeconds, jwkSource);

            // save into Redis
            saveInRedis(username, user, tokenId);

            JwtResponse jwtResponse = JwtResponse.builder()
                    .accessToken(token)
                    .expiresIn(Long.valueOf(expirationSeconds))
                    .tokenType("Bearer")
                    .tokenId(tokenId)
                    .success(true)
                    .build();
            return ResponseEntity.ok(jwtResponse);
        } catch (Exception e) {
            return new ResponseEntity<>(GeneralErrorResponse.builder()
                    .timestamp(Instant.now())
                    .message("Internal Error")
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .build(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity<GeneralErrorResponse> getGeneralErrorResponseResponseEntity(Optional<User> user, String password) {
        if (user.isEmpty()) {
            return new ResponseEntity<>(GeneralErrorResponse.builder()
                    .timestamp(Instant.now())
                    .message("Invalid credentials")
                    .status(HttpStatus.FORBIDDEN.value())
                    .build(), HttpStatus.FORBIDDEN);
        }

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if (!encoder.matches(password, user.get().getPassword())) {
            return new ResponseEntity<>(GeneralErrorResponse.builder()
                    .timestamp(Instant.now())
                    .message("Invalid credentials")
                    .status(HttpStatus.FORBIDDEN.value())
                    .build(), HttpStatus.FORBIDDEN);
        }
        return null;
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam String tokenId) {
        Map<Object, Object> data = redisTemplate.opsForHash().entries("token:" + tokenId);
        if (data == null || data.isEmpty()) {
            return ResponseEntity.status(401).body("Token invalid or expired");
        }

        // generate token
        String newTokenId = UUID.randomUUID().toString();
        String token = null;
        try {
            token = jwtUtils.generateToken(
                    (String) data.get("username"),
                    ((String) data.get("roles")).split(","),
                    ((String) data.get("permissions")).split(","),
                    newTokenId,
                    expirationSeconds,
                    jwkSource
            );
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        // refresh Redis
        redisTemplate.opsForHash().putAll("token:" + newTokenId, data);
        redisTemplate.expire("token:" + newTokenId, Duration.ofSeconds(expirationSeconds));

        JwtResponse jwtResponse = JwtResponse.builder()
                .accessToken(token)
                .expiresIn(Long.valueOf(expirationSeconds))
                .tokenType("Bearer")
                .tokenId(newTokenId)
                .success(true)
                .build();
        return ResponseEntity.ok(jwtResponse);
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestParam String tokenId) {
        Map<Object, Object> data = redisTemplate.opsForHash().entries("token:" + tokenId);
        if (data == null || data.isEmpty()) {
            return ResponseEntity.status(401).body("Token invalid or expired");
        }
        return ResponseEntity.ok(data);
    }
}
