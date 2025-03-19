package com.example.demo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final AuthenticationManager authenticationManager;

	public AuthController(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
		
		System.err.println("I am IN Controller"+username+"***"+password);
		try {
			Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, password));

			SecurityContextHolder.getContext().setAuthentication(authentication);

			// ✅ Generate Secure Code Verifier & Code Challenge
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);

            // ✅ Redirect to Authorization Server for Authorization Code Flow
            String redirectUri = "http://localhost:9000/oauth2/authorize?response_type=code"
                    + "&client_id=angular-client"
                    + "&redirect_uri=http://localhost:4200/callback"
                    + "&scope=openid%20profile" // ✅ Ensure scope is URL-encoded
                    + "&code_challenge=" + codeChallenge
                    + "&code_challenge_method=S256";

            // ✅ Store `code_verifier` in session (optional, needed later for token exchange)
            return ResponseEntity.ok().body(redirectUri);
		} catch (Exception e) {
			return ResponseEntity.status(401).body("Invalid username or password");
		}
	}
	
	// ✅ Generate Code Verifier (Random String)
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifierBytes = new byte[32];
        secureRandom.nextBytes(codeVerifierBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);
    }

    // ✅ Generate Code Challenge (SHA-256 Hash of Code Verifier)
    private String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error generating PKCE code challenge", e);
        }
    }
}
