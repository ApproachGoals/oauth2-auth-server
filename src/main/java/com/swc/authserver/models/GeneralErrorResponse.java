package com.swc.authserver.models;

import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class GeneralErrorResponse {
    private String message;
    private Instant timestamp;
    private Integer status;
}
