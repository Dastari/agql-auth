use agql_auth::{AccessTokenValidator, AuthError, AuthResult};

fn main() -> AuthResult<()> {
    let public_pem = std::env::var("JWT_PUBLIC_KEY_PEM").map_err(|err| {
        AuthError::InvalidConfiguration(format!("JWT_PUBLIC_KEY_PEM is required: {err}"))
    })?;
    let authorization = std::env::var("AUTHORIZATION").ok();

    let validator = AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(public_pem)
        .key_id("auth-key-2026-07")
        .build()?;

    if let Some(header) = authorization.as_deref() {
        let user = validator.authenticate_bearer(header)?;
        println!("authenticated subject: {}", user.user_id);
    }

    Ok(())
}
