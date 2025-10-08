package com.swc.authserver.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder(toBuilder = true)
public class TokenValidationResponse {
    private String message;
    @JsonProperty(required = true)
    private String status;
    @JsonProperty(required = true)
    private Instant timestamp;
}
