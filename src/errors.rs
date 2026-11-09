use std::fmt;

use async_graphql::ErrorExtensions;

/// Error type returned by `agql-auth` APIs.
///
/// Internal variants may carry diagnostic detail for server-side tracing.
/// That detail is never part of `Display`: `to_string()` and a resolver's plain
/// `?` conversion into `async_graphql::Error` yield only
/// [`Self::public_message`]. Use [`ErrorExtensions::extend`] to also attach the
/// stable [`Self::public_code`]. Server logs read the detail explicitly through
/// [`Self::diagnostic`], [`Self::internal_detail`] or `Debug`, none of which
/// may be sent to clients.
#[derive(Debug)]
pub enum AuthError {
    /// Principal/password did not match.
    InvalidCredentials,
    /// No authenticated user was present.
    Unauthenticated,
    /// The authenticated user lacks required authorization.
    Forbidden,
    /// Bearer token syntax was invalid.
    InvalidBearerToken,
    /// Access token failed validation.
    InvalidAccessToken,
    /// Access token is expired.
    AccessTokenExpired,
    /// Token or session has been revoked.
    TokenRevoked,
    /// Purpose token failed validation.
    InvalidPurposeToken,
    /// Purpose token is expired.
    PurposeTokenExpired,
    /// A single-use purpose token was consumed more than once.
    PurposeTokenReplayed,
    /// API token failed validation.
    InvalidApiToken,
    /// API token is expired.
    ApiTokenExpired,
    /// API token has been revoked.
    ApiTokenRevoked,
    /// Refresh token was not found or is invalid.
    InvalidRefreshToken,
    /// Refresh token is expired.
    RefreshTokenExpired,
    /// A revoked refresh token was reused.
    RefreshTokenReplayDetected,
    /// User exists but is disabled.
    UserDisabled,
    /// Authentication flow is temporarily throttled by exponential backoff.
    AuthThrottled {
        /// Seconds until the caller may retry.
        retry_after_seconds: i64,
    },
    /// Authentication flow is temporarily locked.
    AuthLocked {
        /// Seconds until the caller may retry.
        retry_after_seconds: i64,
    },
    /// Password-reset token failed validation.
    InvalidPasswordResetToken,
    /// Password-reset token is expired.
    PasswordResetTokenExpired,
    /// Password-reset token was consumed more than once.
    PasswordResetTokenReplayed,
    /// Login challenge was not found or is invalid.
    InvalidLoginChallenge,
    /// Login challenge is expired.
    LoginChallengeExpired,
    /// Login challenge was consumed more than once.
    LoginChallengeReplayed,
    /// Login challenge exceeded allowed attempts.
    LoginChallengeAttemptsExhausted,
    /// Login challenge code did not match.
    InvalidLoginCode,
    /// TOTP code did not match.
    InvalidTotpCode,
    /// TOTP code was already accepted for this principal/factor.
    TotpCodeReplayed,
    /// TOTP secret could not be decoded or used.
    InvalidTotpSecret,
    /// OAuth state was missing or invalid.
    InvalidOAuthState,
    /// OAuth state is expired.
    OAuthStateExpired,
    /// OAuth state was consumed more than once.
    OAuthStateReplayed,
    /// OIDC discovery failed.
    ///
    /// The inner string is for server-side diagnostics only.
    OidcDiscovery(String),
    /// OIDC token exchange failed.
    OidcTokenExchange(String),
    /// OIDC callback contained an error or was malformed.
    OidcCallback(String),
    /// Typed OIDC authorization options were invalid.
    ///
    /// The inner string is bounded diagnostic detail and must not contain raw
    /// state, nonce, PKCE material, URLs, or claim values.
    InvalidOidcAuthorizationOptions(String),
    /// OIDC ID-token validation failed.
    OidcTokenValidation(String),
    /// An OAuth 2.0 provider redirected back with an authorization error
    /// (for example the user cancelled). Provider text is never retained.
    OAuthProviderError,
    /// An OAuth 2.0 callback was malformed, for example missing its code.
    ///
    /// The inner string is for server-side diagnostics only.
    OAuthCallback(String),
    /// The OAuth 2.0 token endpoint request failed or returned an error or an
    /// invalid response.
    ///
    /// The inner string is for server-side diagnostics only and never contains
    /// provider response text.
    OAuthTokenExchange(String),
    /// The OAuth 2.0 userinfo or verified-email request failed or returned an
    /// invalid response.
    ///
    /// The inner string is for server-side diagnostics only and never contains
    /// provider response text.
    OAuthUserInfo(String),
    /// The OAuth 2.0 profile had no usable subject at the configured pointer.
    OAuthMissingSubject,
    /// Host provisioning or linking policy rejected external login.
    ExternalLoginRejected(String),
    /// JWKS export is unavailable for the configured signing mode.
    JwksUnsupported,
    /// Public configuration was invalid.
    InvalidConfiguration(String),
    /// Authorization data was missing.
    MissingAuthorizationData,
    /// WebSocket connection-init payload had no usable auth data.
    MissingConnectionInitAuth,
    /// Token creation failed.
    TokenCreation(String),
    /// Password hashing or verification failed unexpectedly.
    PasswordHashing(String),
    /// Host store operation failed.
    Store(String),
    /// Authentication dependency is temporarily unavailable.
    AuthServiceUnavailable,
    /// Legacy configuration error.
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
            AuthError::PurposeTokenReplayed => "PURPOSE_TOKEN_REPLAYED",
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
            AuthError::OAuthProviderError
            | AuthError::OAuthCallback(_)
            | AuthError::OAuthMissingSubject => "UNAUTHENTICATED",
            AuthError::OAuthTokenExchange(_) | AuthError::OAuthUserInfo(_) => {
                "AUTH_SERVICE_UNAVAILABLE"
            }
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
            | AuthError::OidcTokenValidation(_)
            | AuthError::OAuthProviderError
            | AuthError::OAuthCallback(_)
            | AuthError::OAuthMissingSubject => "unauthenticated",
            AuthError::Forbidden | AuthError::ExternalLoginRejected(_) => "forbidden",
            AuthError::InvalidBearerToken => "invalid bearer token",
            AuthError::InvalidAccessToken => "invalid access token",
            AuthError::AccessTokenExpired => "access token expired",
            AuthError::TokenRevoked => "token revoked",
            AuthError::InvalidPurposeToken => "invalid purpose token",
            AuthError::PurposeTokenExpired => "purpose token expired",
            AuthError::PurposeTokenReplayed => "purpose token replay detected",
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
            | AuthError::OAuthTokenExchange(_)
            | AuthError::OAuthUserInfo(_)
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

    /// Returns a `Display` value carrying the full internal diagnostic, for
    /// server-side logs and tracing only.
    ///
    /// ```
    /// use agql_auth::AuthError;
    ///
    /// let err = AuthError::Store("connection reset".into());
    /// assert_eq!(err.to_string(), "authentication service unavailable");
    /// assert_eq!(err.diagnostic().to_string(), "storage error: connection reset");
    /// ```
    pub fn diagnostic(&self) -> AuthErrorDiagnostic<'_> {
        AuthErrorDiagnostic(self)
    }

    /// Internal diagnostic detail suitable for server-side tracing only.
    pub fn internal_detail(&self) -> Option<&str> {
        match self {
            AuthError::OidcDiscovery(detail)
            | AuthError::OidcTokenExchange(detail)
            | AuthError::OidcCallback(detail)
            | AuthError::OidcTokenValidation(detail)
            | AuthError::InvalidOidcAuthorizationOptions(detail)
            | AuthError::OAuthCallback(detail)
            | AuthError::OAuthTokenExchange(detail)
            | AuthError::OAuthUserInfo(detail)
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

/// Client-safe: writes [`AuthError::public_message`] and never internal detail.
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.public_message())
    }
}

impl std::error::Error for AuthError {}

/// Full internal diagnostic for an [`AuthError`], returned by
/// [`AuthError::diagnostic`].
///
/// It may contain store messages, provider transport detail or configuration
/// text. Write it to server logs only; never return it to a client.
#[derive(Clone, Copy)]
pub struct AuthErrorDiagnostic<'a>(&'a AuthError);

impl fmt::Debug for AuthErrorDiagnostic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for AuthErrorDiagnostic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            AuthError::InvalidCredentials => f.write_str("invalid credentials"),
            AuthError::Unauthenticated => f.write_str("unauthenticated"),
            AuthError::Forbidden => f.write_str("forbidden"),
            AuthError::InvalidBearerToken => f.write_str("invalid bearer token"),
            AuthError::InvalidAccessToken => f.write_str("invalid access token"),
            AuthError::AccessTokenExpired => f.write_str("access token expired"),
            AuthError::TokenRevoked => f.write_str("token revoked"),
            AuthError::InvalidPurposeToken => f.write_str("invalid purpose token"),
            AuthError::PurposeTokenExpired => f.write_str("purpose token expired"),
            AuthError::PurposeTokenReplayed => f.write_str("purpose token replay detected"),
            AuthError::InvalidApiToken => f.write_str("invalid api token"),
            AuthError::ApiTokenExpired => f.write_str("api token expired"),
            AuthError::ApiTokenRevoked => f.write_str("api token revoked"),
            AuthError::InvalidRefreshToken => f.write_str("invalid refresh token"),
            AuthError::RefreshTokenExpired => f.write_str("refresh token expired"),
            AuthError::RefreshTokenReplayDetected => f.write_str("refresh token replay detected"),
            AuthError::UserDisabled => f.write_str("user is disabled"),
            AuthError::AuthThrottled { .. } => {
                f.write_str("authentication flow is temporarily throttled")
            }
            AuthError::AuthLocked { .. } => {
                f.write_str("authentication flow is temporarily locked")
            }
            AuthError::InvalidPasswordResetToken => f.write_str("invalid password reset token"),
            AuthError::PasswordResetTokenExpired => f.write_str("password reset token expired"),
            AuthError::PasswordResetTokenReplayed => {
                f.write_str("password reset token replay detected")
            }
            AuthError::InvalidLoginChallenge => f.write_str("invalid login challenge"),
            AuthError::LoginChallengeExpired => f.write_str("login challenge expired"),
            AuthError::LoginChallengeReplayed => f.write_str("login challenge replay detected"),
            AuthError::LoginChallengeAttemptsExhausted => {
                f.write_str("login challenge attempts exhausted")
            }
            AuthError::InvalidLoginCode => f.write_str("invalid login challenge code"),
            AuthError::InvalidTotpCode => f.write_str("invalid totp code"),
            AuthError::TotpCodeReplayed => f.write_str("totp code replay detected"),
            AuthError::InvalidTotpSecret => f.write_str("invalid totp secret"),
            AuthError::InvalidOAuthState => f.write_str("invalid oauth state"),
            AuthError::OAuthStateExpired => f.write_str("oauth state expired"),
            AuthError::OAuthStateReplayed => f.write_str("oauth state replay detected"),
            AuthError::OidcDiscovery(detail) => write!(f, "oidc discovery failed: {detail}"),
            AuthError::OidcTokenExchange(detail) => {
                write!(f, "oidc token exchange failed: {detail}")
            }
            AuthError::OidcCallback(detail) => write!(f, "oidc callback failed: {detail}"),
            AuthError::InvalidOidcAuthorizationOptions(detail) => {
                write!(f, "invalid oidc authorization options: {detail}")
            }
            AuthError::OidcTokenValidation(detail) => {
                write!(f, "oidc token validation failed: {detail}")
            }
            AuthError::OAuthProviderError => {
                f.write_str("oauth provider returned an authorization error")
            }
            AuthError::OAuthCallback(detail) => write!(f, "oauth callback failed: {detail}"),
            AuthError::OAuthTokenExchange(detail) => {
                write!(f, "oauth token exchange failed: {detail}")
            }
            AuthError::OAuthUserInfo(detail) => {
                write!(f, "oauth userinfo request failed: {detail}")
            }
            AuthError::OAuthMissingSubject => {
                f.write_str("oauth profile is missing a usable subject")
            }
            AuthError::ExternalLoginRejected(detail) => {
                write!(f, "external login rejected: {detail}")
            }
            AuthError::JwksUnsupported => {
                f.write_str("JWKS export is unsupported for the configured JWT signing mode")
            }
            AuthError::InvalidConfiguration(detail) => write!(f, "invalid configuration: {detail}"),
            AuthError::MissingAuthorizationData => f.write_str("missing authorization data"),
            AuthError::MissingConnectionInitAuth => {
                f.write_str("missing websocket authorization payload")
            }
            AuthError::TokenCreation(detail) => write!(f, "token creation failed: {detail}"),
            AuthError::PasswordHashing(detail) => write!(f, "password hashing failed: {detail}"),
            AuthError::Store(detail) => write!(f, "storage error: {detail}"),
            AuthError::AuthServiceUnavailable => f.write_str("authentication service unavailable"),
            AuthError::Config(detail) => write!(f, "configuration error: {detail}"),
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
