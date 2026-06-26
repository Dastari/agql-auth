use async_graphql::ErrorExtensions;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid bearer token")]
    InvalidBearerToken,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("access token expired")]
    AccessTokenExpired,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token replay detected")]
    RefreshTokenReplayDetected,
    #[error("user is disabled")]
    UserDisabled,
    #[error("invalid password reset token")]
    InvalidPasswordResetToken,
    #[error("password reset token expired")]
    PasswordResetTokenExpired,
    #[error("password reset token replay detected")]
    PasswordResetTokenReplayed,
    #[error("invalid login challenge")]
    InvalidLoginChallenge,
    #[error("login challenge expired")]
    LoginChallengeExpired,
    #[error("login challenge replay detected")]
    LoginChallengeReplayed,
    #[error("login challenge attempts exhausted")]
    LoginChallengeAttemptsExhausted,
    #[error("invalid login challenge code")]
    InvalidLoginCode,
    #[error("invalid totp code")]
    InvalidTotpCode,
    #[error("invalid totp secret")]
    InvalidTotpSecret,
    #[error("invalid oauth state")]
    InvalidOAuthState,
    #[error("oauth state expired")]
    OAuthStateExpired,
    #[error("oauth state replay detected")]
    OAuthStateReplayed,
    #[error("oidc discovery failed: {0}")]
    OidcDiscovery(String),
    #[error("oidc token exchange failed: {0}")]
    OidcTokenExchange(String),
    #[error("oidc callback failed: {0}")]
    OidcCallback(String),
    #[error("oidc token validation failed: {0}")]
    OidcTokenValidation(String),
    #[error("external login rejected: {0}")]
    ExternalLoginRejected(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("missing authorization data")]
    MissingAuthorizationData,
    #[error("missing websocket authorization payload")]
    MissingConnectionInitAuth,
    #[error("token creation failed: {0}")]
    TokenCreation(String),
    #[error("password hashing failed: {0}")]
    PasswordHashing(String),
    #[error("storage error: {0}")]
    Store(String),
    #[error("configuration error: {0}")]
    Config(String),
}

impl ErrorExtensions for AuthError {
    fn extend(&self) -> async_graphql::Error {
        async_graphql::Error::new(self.to_string()).extend_with(|_, e| {
            e.set(
                "code",
                match self {
                    AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
                    AuthError::Unauthenticated => "UNAUTHENTICATED",
                    AuthError::Forbidden => "FORBIDDEN",
                    AuthError::InvalidBearerToken => "INVALID_BEARER_TOKEN",
                    AuthError::InvalidAccessToken => "INVALID_ACCESS_TOKEN",
                    AuthError::AccessTokenExpired => "ACCESS_TOKEN_EXPIRED",
                    AuthError::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
                    AuthError::RefreshTokenExpired => "REFRESH_TOKEN_EXPIRED",
                    AuthError::RefreshTokenReplayDetected => "REFRESH_TOKEN_REPLAY_DETECTED",
                    AuthError::UserDisabled => "USER_DISABLED",
                    AuthError::InvalidPasswordResetToken => "INVALID_PASSWORD_RESET_TOKEN",
                    AuthError::PasswordResetTokenExpired => "PASSWORD_RESET_TOKEN_EXPIRED",
                    AuthError::PasswordResetTokenReplayed => "PASSWORD_RESET_TOKEN_REPLAYED",
                    AuthError::InvalidLoginChallenge => "INVALID_LOGIN_CHALLENGE",
                    AuthError::LoginChallengeExpired => "LOGIN_CHALLENGE_EXPIRED",
                    AuthError::LoginChallengeReplayed => "LOGIN_CHALLENGE_REPLAYED",
                    AuthError::LoginChallengeAttemptsExhausted => {
                        "LOGIN_CHALLENGE_ATTEMPTS_EXHAUSTED"
                    }
                    AuthError::InvalidLoginCode => "INVALID_LOGIN_CODE",
                    AuthError::InvalidTotpCode => "INVALID_TOTP_CODE",
                    AuthError::InvalidTotpSecret => "INVALID_TOTP_SECRET",
                    AuthError::InvalidOAuthState => "INVALID_OAUTH_STATE",
                    AuthError::OAuthStateExpired => "OAUTH_STATE_EXPIRED",
                    AuthError::OAuthStateReplayed => "OAUTH_STATE_REPLAYED",
                    AuthError::OidcDiscovery(_) => "OIDC_DISCOVERY_FAILED",
                    AuthError::OidcTokenExchange(_) => "OIDC_TOKEN_EXCHANGE_FAILED",
                    AuthError::OidcCallback(_) => "OIDC_CALLBACK_FAILED",
                    AuthError::OidcTokenValidation(_) => "OIDC_TOKEN_VALIDATION_FAILED",
                    AuthError::ExternalLoginRejected(_) => "EXTERNAL_LOGIN_REJECTED",
                    AuthError::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
                    AuthError::MissingAuthorizationData => "MISSING_AUTHORIZATION_DATA",
                    AuthError::MissingConnectionInitAuth => "MISSING_CONNECTION_INIT_AUTH",
                    AuthError::TokenCreation(_) => "TOKEN_CREATION_FAILED",
                    AuthError::PasswordHashing(_) => "PASSWORD_HASHING_FAILED",
                    AuthError::Store(_) => "STORE_ERROR",
                    AuthError::Config(_) => "CONFIG_ERROR",
                },
            );
        })
    }
}
