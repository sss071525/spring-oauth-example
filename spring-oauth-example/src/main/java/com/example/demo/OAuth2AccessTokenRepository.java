package com.example.demo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AccessTokenRepository extends JpaRepository<OAuth2AccessToken, Long> {
    Optional<OAuth2AccessToken> findByTokenId(String tokenId);
}
