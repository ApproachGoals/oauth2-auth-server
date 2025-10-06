package com.swc.authserver.models;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder(toBuilder = true)
@Schema(description = "jwt response")
public class JwtResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long expiresIn;
    private String tokenId;
    private String message;
    private Boolean success;

    public JwtResponse(String accessToken, String refreshToken, Long expiresIn, String message) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.message = message;
        this.success = true;
    }

    public JwtResponse(String message, Boolean success) {
        this.message = message;
        this.success = success;
    }
}
