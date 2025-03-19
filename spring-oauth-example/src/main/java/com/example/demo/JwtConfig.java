package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtConfig {

	/*
	 * @Bean JwtEncoder jwtEncoder() { // Use a secure key in production (32+
	 * characters) String secret = "my-secret-key-my-secret-key-my-secret-key-123";
	 * JWKSource<SecurityContext> jwkSource = new
	 * ImmutableSecret<>(secret.getBytes()); return new NimbusJwtEncoder(jwkSource);
	 * }
	 */
	
	// ✅ JWT Encoder (Required for Authorization Server)
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
