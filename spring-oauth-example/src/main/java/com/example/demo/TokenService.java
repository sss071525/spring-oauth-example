package com.example.demo;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenService {

	private final OAuth2AccessTokenRepository accessTokenRepository;
	private final OAuth2RefreshTokenRepository refreshTokenRepository;
	private final JwtEncoder jwtEncoder;

	public TokenService(OAuth2AccessTokenRepository accessTokenRepository,
			OAuth2RefreshTokenRepository refreshTokenRepository, JwtEncoder jwtEncoder) {
		this.accessTokenRepository = accessTokenRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.jwtEncoder = jwtEncoder;
	}

	@Transactional
	public String generateAccessToken(Authentication authentication, String clientId) {
		Instant now = Instant.now();
		Instant expiry = now.plus(1, ChronoUnit.HOURS);

		String tokenValue = generateJwtToken(authentication, now, expiry);
		String tokenId = UUID.randomUUID().toString();

		OAuth2AccessToken accessToken = new OAuth2AccessToken();
		accessToken.setTokenId(tokenId);
		accessToken.setTokenValue(tokenValue);
		accessToken.setIssuedAt(LocalDateTime.now());
		accessToken.setExpiresAt(LocalDateTime.now().plusHours(1));
		accessToken.setUsername(authentication.getName());
		accessToken.setClientId(clientId);
		accessToken.setRevoked(false);

		accessTokenRepository.save(accessToken);

		return tokenValue;
	}

	@Transactional
	public String generateRefreshToken(Authentication authentication, String clientId) {
		Instant now = Instant.now();
		Instant expiry = now.plus(30, ChronoUnit.DAYS);

		String tokenValue = UUID.randomUUID().toString();
		String refreshTokenId = UUID.randomUUID().toString();

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken();
		refreshToken.setRefreshTokenId(refreshTokenId);
		refreshToken.setRefreshTokenValue(tokenValue);
		refreshToken.setIssuedAt(LocalDateTime.now());
		refreshToken.setExpiresAt(LocalDateTime.now().plusDays(30));
		refreshToken.setUsername(authentication.getName());
		refreshToken.setClientId(clientId);
		refreshToken.setRevoked(false);

		refreshTokenRepository.save(refreshToken);

		return tokenValue;
	}

	public boolean validateToken(String token) {
		return accessTokenRepository.findByTokenId(token)
				.map(t -> !t.isRevoked() && t.getExpiresAt().isAfter(LocalDateTime.now())).orElse(false);
	}

	public void revokeToken(String tokenId) {
		accessTokenRepository.findByTokenId(tokenId).ifPresent(token -> {
			token.setRevoked(true);
			accessTokenRepository.save(token);
		});
	}

	private String generateJwtToken(Authentication authentication, Instant issuedAt, Instant expiry) {
		JwtClaimsSet claims = JwtClaimsSet.builder().issuer("oauth-server").issuedAt(issuedAt).expiresAt(expiry)
				.subject(authentication.getName()).claim("scope", authentication.getAuthorities().stream()
						.map(GrantedAuthority::getAuthority).collect(Collectors.joining(" ")))
				.build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}
}
