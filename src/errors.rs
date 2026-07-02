use async_graphql::ErrorExtensions;
use thiserror::Error;

/// Error type returned by `agql-auth` APIs.
///
/// The implementation also maps each variant to an `async-graphql` extension
/// code through [`async_graphql::ErrorExtensions`].
#[derive(Debug, Error)]
pub enum AuthError {
    /// Principal/password did not match.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// No authenticated user was present.
    #[error("unauthenticated")]
    Unauthenticated,
    /// The authenticated user lacks required authorization.
    #[error("forbidden")]
    Forbidden,
    /// Bearer token syntax was invalid.
    #[error("invalid bearer token")]
    InvalidBearerToken,
    /// Access token failed validation.
    #[error("invalid access token")]
    InvalidAccessToken,
    /// Access token is expired.
    #[error("access token expired")]
    AccessTokenExpired,
    /// Purpose token failed validation.
    #[error("invalid purpose token")]
    InvalidPurposeToken,
    /// Purpose token is expired.
    #[error("purpose token expired")]
    PurposeTokenExpired,
    /// API token failed validation.
    #[error("invalid api token")]
    InvalidApiToken,
    /// API token is expired.
    #[error("api token expired")]
    ApiTokenExpired,
    /// API token has been revoked.
    #[error("api token revoked")]
    ApiTokenRevoked,
    /// Refresh token was not found or is invalid.
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    /// Refresh token is expired.
    #[error("refresh token expired")]
    RefreshTokenExpired,
    /// A revoked refresh token was reused.
    #[error("refresh token replay detected")]
    RefreshTokenReplayDetected,
    /// User exists but is disabled.
    #[error("user is disabled")]
    UserDisabled,
    /// Authentication flow is temporarily throttled by exponential backoff.
    #[error("authentication flow is temporarily throttled")]
    AuthThrottled {
        /// Seconds until the caller may retry.
        retry_after_seconds: i64,
    },
    /// Authentication flow is temporarily locked.
    #[error("authentication flow is temporarily locked")]
    AuthLocked {
        /// Seconds until the caller may retry.
        retry_after_seconds: i64,
    },
    /// Password-reset token failed validation.
    #[error("invalid password reset token")]
    InvalidPasswordResetToken,
    /// Password-reset token is expired.
    #[error("password reset token expired")]
    PasswordResetTokenExpired,
    /// Password-reset token was consumed more than once.
    #[error("password reset token replay detected")]
    PasswordResetTokenReplayed,
    /// Login challenge was not found or is invalid.
    #[error("invalid login challenge")]
    InvalidLoginChallenge,
    /// Login challenge is expired.
    #[error("login challenge expired")]
    LoginChallengeExpired,
    /// Login challenge was consumed more than once.
    #[error("login challenge replay detected")]
    LoginChallengeReplayed,
    /// Login challenge exceeded allowed attempts.
    #[error("login challenge attempts exhausted")]
    LoginChallengeAttemptsExhausted,
    /// Login challenge code did not match.
    #[error("invalid login challenge code")]
    InvalidLoginCode,
    /// TOTP code did not match.
    #[error("invalid totp code")]
    InvalidTotpCode,
    /// TOTP code was already accepted for this principal/factor.
    #[error("totp code replay detected")]
    TotpCodeReplayed,
    /// TOTP secret could not be decoded or used.
    #[error("invalid totp secret")]
    InvalidTotpSecret,
    /// OAuth state was missing or invalid.
    #[error("invalid oauth state")]
    InvalidOAuthState,
    /// OAuth state is expired.
    #[error("oauth state expired")]
    OAuthStateExpired,
    /// OAuth state was consumed more than once.
    #[error("oauth state replay detected")]
    OAuthStateReplayed,
    /// OIDC discovery failed.
    #[error("oidc discovery failed: {0}")]
    OidcDiscovery(String),
    /// OIDC token exchange failed.
    #[error("oidc token exchange failed: {0}")]
    OidcTokenExchange(String),
    /// OIDC callback contained an error or was malformed.
    #[error("oidc callback failed: {0}")]
    OidcCallback(String),
    /// OIDC ID-token validation failed.
    #[error("oidc token validation failed: {0}")]
    OidcTokenValidation(String),
    /// Host provisioning or linking policy rejected external login.
    #[error("external login rejected: {0}")]
    ExternalLoginRejected(String),
    /// JWKS export is unavailable for the configured signing mode.
    #[error("JWKS export is unsupported for the configured JWT signing mode")]
    JwksUnsupported,
    /// Public configuration was invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    /// Authorization data was missing.
    #[error("missing authorization data")]
    MissingAuthorizationData,
    /// WebSocket connection-init payload had no usable auth data.
    #[error("missing websocket authorization payload")]
    MissingConnectionInitAuth,
    /// Token creation failed.
    #[error("token creation failed: {0}")]
    TokenCreation(String),
    /// Password hashing or verification failed unexpectedly.
    #[error("password hashing failed: {0}")]
    PasswordHashing(String),
    /// Host store operation failed.
    #[error("storage error: {0}")]
    Store(String),
    /// Legacy configuration error.
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
                    AuthError::InvalidPurposeToken => "INVALID_PURPOSE_TOKEN",
                    AuthError::PurposeTokenExpired => "PURPOSE_TOKEN_EXPIRED",
                    AuthError::InvalidApiToken => "INVALID_API_TOKEN",
                    AuthError::ApiTokenExpired => "API_TOKEN_EXPIRED",
                    AuthError::ApiTokenRevoked => "API_TOKEN_REVOKED",
                    AuthError::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
                    AuthError::RefreshTokenExpired => "REFRESH_TOKEN_EXPIRED",
                    AuthError::RefreshTokenReplayDetected => "REFRESH_TOKEN_REPLAY_DETECTED",
                    AuthError::UserDisabled => "USER_DISABLED",
                    AuthError::AuthThrottled { .. } => "AUTH_THROTTLED",
                    AuthError::AuthLocked { .. } => "AUTH_LOCKED",
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
                    AuthError::TotpCodeReplayed => "TOTP_CODE_REPLAYED",
                    AuthError::InvalidTotpSecret => "INVALID_TOTP_SECRET",
                    AuthError::InvalidOAuthState => "INVALID_OAUTH_STATE",
                    AuthError::OAuthStateExpired => "OAUTH_STATE_EXPIRED",
                    AuthError::OAuthStateReplayed => "OAUTH_STATE_REPLAYED",
                    AuthError::OidcDiscovery(_) => "OIDC_DISCOVERY_FAILED",
                    AuthError::OidcTokenExchange(_) => "OIDC_TOKEN_EXCHANGE_FAILED",
                    AuthError::OidcCallback(_) => "OIDC_CALLBACK_FAILED",
                    AuthError::OidcTokenValidation(_) => "OIDC_TOKEN_VALIDATION_FAILED",
                    AuthError::ExternalLoginRejected(_) => "EXTERNAL_LOGIN_REJECTED",
                    AuthError::JwksUnsupported => "JWKS_UNSUPPORTED",
                    AuthError::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
                    AuthError::MissingAuthorizationData => "MISSING_AUTHORIZATION_DATA",
                    AuthError::MissingConnectionInitAuth => "MISSING_CONNECTION_INIT_AUTH",
                    AuthError::TokenCreation(_) => "TOKEN_CREATION_FAILED",
                    AuthError::PasswordHashing(_) => "PASSWORD_HASHING_FAILED",
                    AuthError::Store(_) => "STORE_ERROR",
                    AuthError::Config(_) => "CONFIG_ERROR",
                },
            );
            match self {
                AuthError::AuthThrottled {
                    retry_after_seconds,
                }
                | AuthError::AuthLocked {
                    retry_after_seconds,
                } => {
                    e.set("retryAfterSeconds", *retry_after_seconds);
                }
                _ => {}
            }
        })
    }
}
