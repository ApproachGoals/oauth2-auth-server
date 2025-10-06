package com.swc.authserver.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.OpenAPI;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        final String basicSchemeName = "BasicAuth";
        final String bearerSchemeName = "BearerToken";

        return new OpenAPI()
                .info(new Info().title("JWT API").version("1.0").description("API with JWT and Basic Auth"))
                .components(new Components()
                        .addSecuritySchemes(basicSchemeName, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic"))
                        .addSecuritySchemes(bearerSchemeName, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT"))
                )
                .addSecurityItem(new SecurityRequirement().addList(basicSchemeName))
                .addSecurityItem(new SecurityRequirement().addList(bearerSchemeName));
    }
}
