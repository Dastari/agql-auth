use async_graphql::ErrorExtensions;
use thiserror::Error;

/// Error type returned by `agql-auth` APIs.
///
/// Internal variants may carry diagnostic detail for server-side tracing.
/// GraphQL clients receive only [`Self::public_code`] and
/// [`Self::public_message`] through [`ErrorExtensions`].
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
    /// Token or session has been revoked.
    #[error("token revoked")]
    TokenRevoked,
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
    ///
    /// The inner string is for server-side diagnostics only.
    #[error("oidc discovery failed: {0}")]
    OidcDiscovery(String),
    /// OIDC token exchange failed.
    #[error("oidc token exchange failed: {0}")]
    OidcTokenExchange(String),
    /// OIDC callback contained an error or was malformed.
    #[error("oidc callback failed: {0}")]
    OidcCallback(String),
    /// Typed OIDC authorization options were invalid.
    ///
    /// The inner string is bounded diagnostic detail and must not contain raw
    /// state, nonce, PKCE material, URLs, or claim values.
    #[error("invalid oidc authorization options: {0}")]
    InvalidOidcAuthorizationOptions(String),
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
    /// Authentication dependency is temporarily unavailable.
    #[error("authentication service unavailable")]
    AuthServiceUnavailable,
    /// Legacy configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

impl AuthError {
    /// Stable public error code suitable for clients and contracts.
    pub fn public_code(&self) -> &'static str {
        match self {
            AuthError::InvalidCredentials => "INVALID_CREDENTIALS",
            AuthError::Unauthenticated => "UNAUTHENTICATED",
            AuthError::Forbidden => "FORBIDDEN",
            AuthError::InvalidBearerToken => "INVALID_BEARER_TOKEN",
            AuthError::InvalidAccessToken => "INVALID_ACCESS_TOKEN",
            AuthError::AccessTokenExpired => "ACCESS_TOKEN_EXPIRED",
            AuthError::TokenRevoked => "TOKEN_REVOKED",
            AuthError::InvalidPurposeToken => "INVALID_PURPOSE_TOKEN",
            AuthError::PurposeTokenExpired => "PURPOSE_TOKEN_EXPIRED",
            AuthError::InvalidApiToken => "INVALID_API_TOKEN",
            AuthError::ApiTokenExpired => "API_TOKEN_EXPIRED",
            AuthError::ApiTokenRevoked => "TOKEN_REVOKED",
            AuthError::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
            AuthError::RefreshTokenExpired => "REFRESH_TOKEN_EXPIRED",
            AuthError::RefreshTokenReplayDetected => "REFRESH_TOKEN_REPLAY_DETECTED",
            AuthError::UserDisabled => "USER_DISABLED",
            AuthError::AuthThrottled { .. } | AuthError::AuthLocked { .. } => "RATE_LIMITED",
            AuthError::InvalidPasswordResetToken => "INVALID_PASSWORD_RESET_TOKEN",
            AuthError::PasswordResetTokenExpired => "PASSWORD_RESET_TOKEN_EXPIRED",
            AuthError::PasswordResetTokenReplayed => "PASSWORD_RESET_TOKEN_REPLAYED",
            AuthError::InvalidLoginChallenge => "INVALID_LOGIN_CHALLENGE",
            AuthError::LoginChallengeExpired => "LOGIN_CHALLENGE_EXPIRED",
            AuthError::LoginChallengeReplayed => "LOGIN_CHALLENGE_REPLAYED",
            AuthError::LoginChallengeAttemptsExhausted => "LOGIN_CHALLENGE_ATTEMPTS_EXHAUSTED",
            AuthError::InvalidLoginCode => "INVALID_LOGIN_CODE",
            AuthError::InvalidTotpCode => "INVALID_TOTP_CODE",
            AuthError::TotpCodeReplayed => "TOTP_CODE_REPLAYED",
            AuthError::InvalidTotpSecret => "INVALID_TOTP_SECRET",
            AuthError::InvalidOAuthState => "INVALID_OAUTH_STATE",
            AuthError::OAuthStateExpired => "OAUTH_STATE_EXPIRED",
            AuthError::OAuthStateReplayed => "OAUTH_STATE_REPLAYED",
            AuthError::OidcDiscovery(_) => "AUTH_SERVICE_UNAVAILABLE",
            AuthError::OidcTokenExchange(_) => "AUTH_SERVICE_UNAVAILABLE",
            AuthError::OidcCallback(_) => "UNAUTHENTICATED",
            AuthError::InvalidOidcAuthorizationOptions(_) => "INVALID_CONFIGURATION",
            AuthError::OidcTokenValidation(_) => "UNAUTHENTICATED",
            AuthError::ExternalLoginRejected(_) => "FORBIDDEN",
            AuthError::JwksUnsupported => "INVALID_CONFIGURATION",
            AuthError::InvalidConfiguration(_) => "INVALID_CONFIGURATION",
            AuthError::MissingAuthorizationData => "UNAUTHENTICATED",
            AuthError::MissingConnectionInitAuth => "UNAUTHENTICATED",
            AuthError::TokenCreation(_) => "AUTH_SERVICE_UNAVAILABLE",
            AuthError::PasswordHashing(_) => "AUTH_SERVICE_UNAVAILABLE",
            AuthError::Store(_) | AuthError::AuthServiceUnavailable => "AUTH_SERVICE_UNAVAILABLE",
            AuthError::Config(_) => "INVALID_CONFIGURATION",
        }
    }

    /// Safe public message that never includes internal diagnostics.
    pub fn public_message(&self) -> &'static str {
        match self {
            AuthError::InvalidCredentials => "invalid credentials",
            AuthError::Unauthenticated
            | AuthError::MissingAuthorizationData
            | AuthError::MissingConnectionInitAuth
            | AuthError::OidcCallback(_)
            | AuthError::OidcTokenValidation(_) => "unauthenticated",
            AuthError::Forbidden | AuthError::ExternalLoginRejected(_) => "forbidden",
            AuthError::InvalidBearerToken => "invalid bearer token",
            AuthError::InvalidAccessToken => "invalid access token",
            AuthError::AccessTokenExpired => "access token expired",
            AuthError::TokenRevoked => "token revoked",
            AuthError::InvalidPurposeToken => "invalid purpose token",
            AuthError::PurposeTokenExpired => "purpose token expired",
            AuthError::InvalidApiToken => "invalid api token",
            AuthError::ApiTokenExpired => "api token expired",
            AuthError::ApiTokenRevoked => "token revoked",
            AuthError::InvalidRefreshToken => "invalid refresh token",
            AuthError::RefreshTokenExpired => "refresh token expired",
            AuthError::RefreshTokenReplayDetected => "refresh token replay detected",
            AuthError::UserDisabled => "user is disabled",
            AuthError::AuthThrottled { .. } | AuthError::AuthLocked { .. } => "rate limited",
            AuthError::InvalidPasswordResetToken => "invalid password reset token",
            AuthError::PasswordResetTokenExpired => "password reset token expired",
            AuthError::PasswordResetTokenReplayed => "password reset token replay detected",
            AuthError::InvalidLoginChallenge => "invalid login challenge",
            AuthError::LoginChallengeExpired => "login challenge expired",
            AuthError::LoginChallengeReplayed => "login challenge replay detected",
            AuthError::LoginChallengeAttemptsExhausted => "login challenge attempts exhausted",
            AuthError::InvalidLoginCode => "invalid login challenge code",
            AuthError::InvalidTotpCode => "invalid totp code",
            AuthError::TotpCodeReplayed => "totp code replay detected",
            AuthError::InvalidTotpSecret => "invalid totp secret",
            AuthError::InvalidOAuthState => "invalid oauth state",
            AuthError::OAuthStateExpired => "oauth state expired",
            AuthError::OAuthStateReplayed => "oauth state replay detected",
            AuthError::OidcDiscovery(_)
            | AuthError::OidcTokenExchange(_)
            | AuthError::TokenCreation(_)
            | AuthError::PasswordHashing(_)
            | AuthError::Store(_)
            | AuthError::AuthServiceUnavailable => "authentication service unavailable",
            AuthError::JwksUnsupported
            | AuthError::InvalidOidcAuthorizationOptions(_)
            | AuthError::InvalidConfiguration(_)
            | AuthError::Config(_) => "invalid configuration",
        }
    }

    /// Internal diagnostic detail suitable for server-side tracing only.
    pub fn internal_detail(&self) -> Option<&str> {
        match self {
            AuthError::OidcDiscovery(detail)
            | AuthError::OidcTokenExchange(detail)
            | AuthError::OidcCallback(detail)
            | AuthError::OidcTokenValidation(detail)
            | AuthError::ExternalLoginRejected(detail)
            | AuthError::InvalidConfiguration(detail)
            | AuthError::TokenCreation(detail)
            | AuthError::PasswordHashing(detail)
            | AuthError::Store(detail)
            | AuthError::Config(detail) => Some(detail.as_str()),
            _ => None,
        }
    }
}

impl ErrorExtensions for AuthError {
    fn extend(&self) -> async_graphql::Error {
        async_graphql::Error::new(self.public_message()).extend_with(|_, e| {
            e.set("code", self.public_code());
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
