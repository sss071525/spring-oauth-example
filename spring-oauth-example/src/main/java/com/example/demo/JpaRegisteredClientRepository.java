package com.example.demo;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Repository;

@Repository
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

	private final OAuth2ClientRepository clientRepository;
	private final PasswordEncoder passwordEncoder;

	public JpaRegisteredClientRepository(OAuth2ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
		this.clientRepository = clientRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		OAuth2Client client = new OAuth2Client();
		client.setClientId(registeredClient.getClientId());
		client.setClientSecret(passwordEncoder.encode(registeredClient.getClientSecret())); // Encrypt secret
		client.setRedirectUri(registeredClient.getRedirectUris().iterator().next());
		client.setScope(String.join(",", registeredClient.getScopes()));
		client.setGrantType(registeredClient.getAuthorizationGrantTypes().iterator().next().getValue());
		client.setRequireProofKey(registeredClient.getClientSettings().isRequireProofKey());

		clientRepository.save(client);
	}

	@Override
	public RegisteredClient findById(String id) {
		return clientRepository.findById(id).map(this::convertToRegisteredClient).orElse(null);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		System.out.println("Client Id" + clientId);
		return clientRepository.findByClientId(clientId).map(this::convertToRegisteredClient).orElse(null);
	}

	private RegisteredClient convertToRegisteredClient(OAuth2Client client) {
		return RegisteredClient.withId(client.getClientId()).clientId(client.getClientId())
				.clientSecret(client.getClientSecret()).redirectUri(client.getRedirectUri())
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // ✅ Required for PKCE (No client secret
				.authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // ✅ Enable refresh tokens
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // ✅ Required for
				.scopes(scopes -> scopes.addAll(parseScopes(client.getScope()))) // client_credentials
				.clientSettings(ClientSettings.builder().requireProofKey(client.isRequireProofKey()).build()).build();
	}

	// ✅ Convert "openid profile" (DB format) to Set<String>
	private Set<String> parseScopes(String scopeString) {
		return Arrays.stream(scopeString.split(" ")).map(String::trim).collect(Collectors.toSet());
	}
}
