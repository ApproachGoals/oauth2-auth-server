# OAuth2 Authorization Server Example (Spring Authorization Server)
## What this project contains
- Spring Authorization Server configuration (Authorization Code + Refresh Token + Client Credentials)
- JPA entities for `User`, `Role`, `Permission`
- H2 in-memory database for demo (so you can run without external DB)
- Redis configured to 85.214.241.230 (as you requested) — used for demonstration if you want to store jti/blacklist
- JWT generation using RSA keys (JWK)

## How to run
```bash
mvn spring-boot:run
```
App runs on http://localhost:9000

## Demo accounts
- user / password
- admin / adminpass

## Demo client (created at startup)
- client_id: messaging-client
- client_secret: secret
- redirect_uri: http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc
- scopes: read, write

## Example: Client Credentials (server-to-server)
```bash
curl -u messaging-client:secret -X POST "http://localhost:9000/oauth2/token" -d "grant_type=client_credentials&scope=read"
```
## Example: Authorization Code (browser)
Open: `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=read&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc`

## Notes
- This is a learning/example project. For production: use persistent MySQL/Postgres, secure key management, HTTPS, rotate keys, and harden client secrets & policies.
- If you want password grant (Resource Owner Password Credentials), Spring Authorization Server discourages it — consider using the authorization_code flow with a first-party client or implement a custom token endpoint responsibly.
