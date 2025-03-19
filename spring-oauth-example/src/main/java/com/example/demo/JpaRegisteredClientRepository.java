package com.example.demo;

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
				.authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).scope(client.getScope())
				.clientSettings(ClientSettings.builder().requireProofKey(client.isRequireProofKey()).build()).build();
	}
}
