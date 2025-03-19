CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE oauth2_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    grant_type VARCHAR(255) NOT NULL
);


CREATE TABLE oauth2_access_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_id UUID UNIQUE NOT NULL,
    token_value TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    username VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_access_token_user FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    CONSTRAINT fk_access_token_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE
);


CREATE TABLE oauth2_refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    refresh_token_id UUID UNIQUE NOT NULL,
    refresh_token_value TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    username VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_refresh_token_user FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_token_client FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE
);


CREATE INDEX idx_access_token_token_id ON oauth2_access_tokens (token_id);
CREATE INDEX idx_refresh_token_id ON oauth2_refresh_tokens (refresh_token_id);
CREATE INDEX idx_access_token_username ON oauth2_access_tokens (username);
CREATE INDEX idx_refresh_token_username ON oauth2_refresh_tokens (username);


INSERT INTO users (username, password) 
VALUES ('testuser', '$2a$10$B9RhgmgOJVWxILaGWC4Ike.0LvOGcRzWmmN1szhaIeeiINxgrdUyG');
-- Password: 'angular-secret' (Bcrypt encoded)

INSERT INTO oauth2_clients (client_id, client_secret, redirect_uri, scope, grant_type, require_proof_key) 
VALUES ('angular-client', '$2a$10$B9RhgmgOJVWxILaGWC4Ike.0LvOGcRzWmmN1szhaIeeiINxgrdUyG', 'http://localhost:4200/callback', 'openid+profile', 'authorization_code', true);

--angular-secret

