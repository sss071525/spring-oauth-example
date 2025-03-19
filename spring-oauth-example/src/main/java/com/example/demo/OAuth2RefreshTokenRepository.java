package com.example.demo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2RefreshTokenRepository extends JpaRepository<OAuth2RefreshToken, Long> {
    Optional<OAuth2RefreshToken> findByRefreshTokenId(String refreshTokenId);
}
