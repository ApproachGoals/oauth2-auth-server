
CREATE TABLE IF NOT EXISTS oauth2_registered_client (
  id VARCHAR(100) PRIMARY KEY,
  client_id VARCHAR(100) UNIQUE,
  client_secret VARCHAR(200),
  client_id_issued_at TIMESTAMP,
  client_secret_expires_at TIMESTAMP,
  client_name VARCHAR(200),
  client_authentication_methods VARCHAR(1000),
  authorization_grant_types VARCHAR(1000),
  redirect_uris VARCHAR(2000),
  scopes VARCHAR(1000),
  client_settings VARCHAR(2000),
  token_settings VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization (
  id VARCHAR(100) PRIMARY KEY,
  registered_client_id VARCHAR(100),
  principal_name VARCHAR(200),
  authorization_grant_type VARCHAR(100),
  attributes VARCHAR(2000),
  state VARCHAR(500),
  authorization_code_value VARCHAR(2000),
  authorization_code_issued_at TIMESTAMP,
  authorization_code_expires_at TIMESTAMP,
  access_token_value VARCHAR(2000),
  access_token_issued_at TIMESTAMP,
  access_token_expires_at TIMESTAMP,
  access_token_metadata VARCHAR(2000),
  refresh_token_value VARCHAR(2000),
  refresh_token_issued_at TIMESTAMP,
  refresh_token_expires_at TIMESTAMP,
  refresh_token_metadata VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(200) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  tenant VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS roles (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(200) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_role (
  user_id BIGINT,
  role_id BIGINT,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permission (
  role_id BIGINT,
  permission_id BIGINT,
  PRIMARY KEY (role_id, permission_id)
);
