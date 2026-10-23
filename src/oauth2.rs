//! OAuth 2.0 authorization-code + PKCE providers without OpenID Connect.
//!
//! [`OAuth2Provider`] serves providers that issue no ID token and publish no
//! JWKS (for example GitHub). Identity comes from an authenticated userinfo
//! request, so it is only as trustworthy as the TLS connection to the
//! configured endpoints. Account linking, user creation and email-trust policy
//! remain host decisions.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::{Duration, OffsetDateTime};

use crate::client_auth::{
    ClientJwtSigner, TokenEndpointAuthMethod, client_authentication, validate_client_authentication,
};
use crate::clock::{Clock, SystemClock};
use crate::config::OAuthResponseMode;
use crate::models::{OAuthLoginState, OidcCallbackInput};
use crate::oidc::{
    ACCEPT_JSON, OidcHttpClient, append_query, ensure_no_reserved_authorization_parameters,
    generate_oauth_state, generate_pkce_pair, hash_oauth_state, parse_email_verified,
};
use crate::stores::OAuthStateStore;
use crate::{AuthError, AuthResult};

/// Longest accepted provider subject, in bytes.
pub const MAX_OAUTH2_SUBJECT_LENGTH: usize = 255;

/// Most entries inspected in a verified-email list response.
pub const MAX_OAUTH2_VERIFIED_EMAIL_ENTRIES: usize = 100;

/// How the provider's `email_verified` state is determined from the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OAuth2EmailVerification {
    /// The profile does not state verification; `email_verified` is `None`
    /// unless a verified-email list selects an address.
    Unknown,
    /// Read a JSON boolean or the strings `"true"` / `"false"` at this JSON
    /// pointer. Other values are `None`.
    Pointer(String),
    /// The provider documents that every profile email is verified.
    /// `email_verified` is `Some(true)` whenever an email is present.
    ProviderVerifiesAll,
}

/// JSON pointers locating profile values in the userinfo response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OAuth2ProfileMapping {
    /// Required stable subject. A non-empty string or an integer (normalized
    /// to its decimal string) is accepted; anything else is
    /// [`AuthError::OAuthMissingSubject`].
    pub subject_pointer: String,
    /// Optional email string.
    pub email_pointer: Option<String>,
    /// Email verification source.
    pub email_verification: OAuth2EmailVerification,
    /// Optional display name string.
    pub name_pointer: Option<String>,
    /// Optional picture URL string.
    pub picture_pointer: Option<String>,
}

impl Default for OAuth2ProfileMapping {
    /// OIDC standard-claim names: `sub`, `email`, `email_verified`, `name`, `picture`.
    fn default() -> Self {
        Self {
            subject_pointer: "/sub".to_string(),
            email_pointer: Some("/email".to_string()),
            email_verification: OAuth2EmailVerification::Pointer("/email_verified".to_string()),
            name_pointer: Some("/name".to_string()),
            picture_pointer: Some("/picture".to_string()),
        }
    }
}

/// Which entry of a verified-email list is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OAuth2VerifiedEmailSelection {
    /// The first entry that is both primary and verified.
    PrimaryVerified,
    /// The first verified entry.
    FirstVerified,
}

/// Secondary authenticated JSON GET listing the account's addresses, for
/// providers whose profile does not state a verified email (for example
/// GitHub `GET /user/emails`).
///
/// It is consulted only when the profile did not already yield
/// `email_verified == Some(true)`. A selected entry replaces the profile email
/// with `email_verified = Some(true)`. When nothing qualifies, the profile
/// email and its verification state are kept. A failed request fails the
/// callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OAuth2VerifiedEmailList {
    /// Endpoint URL, requested with the provider access token as a bearer.
    pub endpoint: String,
    /// Pointer to the entry array. `None` means the response is the array.
    pub entries_pointer: Option<String>,
    /// Pointer to the address string within an entry.
    pub email_pointer: String,
    /// Pointer to the verified flag within an entry (boolean or `"true"`).
    pub verified_pointer: String,
    /// Pointer to the primary flag within an entry. Required by
    /// [`OAuth2VerifiedEmailSelection::PrimaryVerified`].
    pub primary_pointer: Option<String>,
    /// Selection rule.
    pub selection: OAuth2VerifiedEmailSelection,
}

impl OAuth2VerifiedEmailList {
    /// Creates a list read as a top-level array of `{email, verified, primary}`
    /// entries selecting the primary verified address.
    pub fn primary_verified(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            entries_pointer: None,
            email_pointer: "/email".to_string(),
            verified_pointer: "/verified".to_string(),
            primary_pointer: Some("/primary".to_string()),
            selection: OAuth2VerifiedEmailSelection::PrimaryVerified,
        }
    }
}

/// Configuration for an OAuth 2.0 provider without OpenID Connect.
///
/// Endpoints are explicit (no discovery) and must be `https://` URLs; plain
/// `http://` is accepted only for loopback hosts used in development and tests.
/// `Debug` redacts `client_secret` and `client_jwt`.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OAuth2ProviderConfig {
    /// Stable provider name used in state storage and as the identity namespace.
    /// It must not be shared with an [`crate::OidcProvider`] or another provider.
    pub provider_name: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Userinfo (profile) endpoint, requested with the access token as a bearer.
    pub userinfo_endpoint: String,
    /// OAuth 2.0 client ID.
    pub client_id: String,
    /// Optional static client secret for confidential clients. Deserialized
    /// but never serialized; `Debug` redacts it.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Host-supplied client JWT signer. Mutually exclusive with
    /// `client_secret`. Never serialized.
    #[serde(skip)]
    pub client_jwt: Option<ClientJwtSigner>,
    /// Token-endpoint client authentication.
    #[serde(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Requested scopes, sent space-delimited. May be empty.
    pub scopes: Vec<String>,
    /// Lifetime for OAuth state records.
    pub state_ttl: Duration,
    /// Userinfo profile mapping.
    pub profile: OAuth2ProfileMapping,
    /// Optional verified-email list request.
    pub verified_email_list: Option<OAuth2VerifiedEmailList>,
}

impl fmt::Debug for OAuth2ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2ProviderConfig")
            .field("provider_name", &self.provider_name)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("client_jwt", &self.client_jwt)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("state_ttl", &self.state_ttl)
            .field("profile", &self.profile)
            .field("verified_email_list", &self.verified_email_list)
            .finish()
    }
}

impl OAuth2ProviderConfig {
    /// Creates a configuration with default OIDC-style profile pointers, no
    /// scopes, `client_secret_post` and a ten-minute state lifetime.
    pub fn new(
        provider_name: impl Into<String>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
        userinfo_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            provider_name: provider_name.into(),
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            userinfo_endpoint: userinfo_endpoint.into(),
            client_id: client_id.into(),
            client_secret: None,
            client_jwt: None,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            redirect_uri: redirect_uri.into(),
            scopes: Vec::new(),
            state_ttl: Duration::minutes(10),
            profile: OAuth2ProfileMapping::default(),
            verified_email_list: None,
        }
    }

    /// GitHub OAuth App or GitHub App user authorization.
    ///
    /// Requests `read:user user:email`, maps the numeric `id` as subject,
    /// `name` and `avatar_url`, treats the public profile email as unverified
    /// and selects the primary verified address from `GET /user/emails`.
    /// GitHub's API requires a `User-Agent` header, which the host HTTP client
    /// must send.
    pub fn github(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let mut config = Self::new(
            "github",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            client_id,
            redirect_uri,
        );
        config.client_secret = Some(client_secret.into());
        config.scopes = vec!["read:user".to_string(), "user:email".to_string()];
        config.profile = OAuth2ProfileMapping {
            subject_pointer: "/id".to_string(),
            email_pointer: Some("/email".to_string()),
            email_verification: OAuth2EmailVerification::Unknown,
            name_pointer: Some("/name".to_string()),
            picture_pointer: Some("/avatar_url".to_string()),
        };
        config.verified_email_list = Some(OAuth2VerifiedEmailList::primary_verified(
            "https://api.github.com/user/emails",
        ));
        config
    }

    /// Validates required provider configuration.
    pub fn validate(&self) -> AuthResult<()> {
        for (name, value) in [
            ("provider_name", &self.provider_name),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
        ] {
            if value.trim().is_empty() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "OAuth 2.0 {name} must not be empty"
                )));
            }
        }
        for (name, value) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("userinfo_endpoint", &self.userinfo_endpoint),
        ] {
            validate_endpoint(name, value)?;
        }
        ensure_no_reserved_authorization_parameters(&self.authorization_endpoint).map_err(
            |_| {
                AuthError::InvalidConfiguration(
                    "OAuth 2.0 authorization_endpoint contains a reserved query parameter"
                        .to_string(),
                )
            },
        )?;
        if self.client_secret.as_deref().is_some_and(str::is_empty) {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 client_secret must not be empty when set".to_string(),
            ));
        }
        validate_client_authentication(
            "OAuth 2.0",
            self.token_endpoint_auth_method,
            self.client_secret.as_deref(),
            self.client_jwt.as_ref(),
        )?;
        if self.scopes.iter().any(|scope| {
            scope.is_empty()
                || scope
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control())
        }) {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 scopes must be non-empty tokens without whitespace".to_string(),
            ));
        }
        if self.state_ttl <= Duration::ZERO {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 state_ttl must be greater than zero".to_string(),
            ));
        }
        validate_pointer("subject_pointer", &self.profile.subject_pointer)?;
        for (name, pointer) in [
            ("email_pointer", &self.profile.email_pointer),
            ("name_pointer", &self.profile.name_pointer),
            ("picture_pointer", &self.profile.picture_pointer),
        ] {
            if let Some(pointer) = pointer {
                validate_pointer(name, pointer)?;
            }
        }
        if let OAuth2EmailVerification::Pointer(pointer) = &self.profile.email_verification {
            validate_pointer("email_verification", pointer)?;
        }
        if let Some(list) = &self.verified_email_list {
            validate_endpoint("verified_email_list.endpoint", &list.endpoint)?;
            if let Some(pointer) = &list.entries_pointer {
                validate_pointer("verified_email_list.entries_pointer", pointer)?;
            }
            validate_pointer("verified_email_list.email_pointer", &list.email_pointer)?;
            validate_pointer(
                "verified_email_list.verified_pointer",
                &list.verified_pointer,
            )?;
            match (&list.primary_pointer, list.selection) {
                (Some(pointer), _) => {
                    validate_pointer("verified_email_list.primary_pointer", pointer)?
                }
                (None, OAuth2VerifiedEmailSelection::PrimaryVerified) => {
                    return Err(AuthError::InvalidConfiguration(
                        "OAuth 2.0 primary-verified email selection requires primary_pointer"
                            .to_string(),
                    ));
                }
                (None, OAuth2VerifiedEmailSelection::FirstVerified) => {}
            }
        }
        Ok(())
    }
}

fn validate_endpoint(name: &str, value: &str) -> AuthResult<()> {
    let invalid = || {
        AuthError::InvalidConfiguration(format!(
            "OAuth 2.0 {name} must be an https URL (http only for loopback hosts)"
        ))
    };
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid());
    }
    let (scheme, remainder) = value.split_once("://").ok_or_else(invalid)?;
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or_else(invalid)?;
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(invalid());
    }
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http")
        && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1")
    {
        return Ok(());
    }
    Err(invalid())
}

fn validate_pointer(name: &str, pointer: &str) -> AuthResult<()> {
    if pointer.len() < 2 || !pointer.starts_with('/') {
        return Err(AuthError::InvalidConfiguration(format!(
            "OAuth 2.0 {name} must be a non-root JSON pointer"
        )));
    }
    Ok(())
}

/// Authorization request created by [`OAuth2Provider`].
#[derive(Clone)]
pub struct OAuth2AuthorizationRequest {
    /// Fully built provider authorization URL.
    pub authorization_url: String,
    /// Provider name.
    pub provider_name: String,
    /// Raw OAuth state sent to the browser.
    pub state: String,
    /// PKCE code verifier stored in state.
    pub code_verifier: String,
    /// PKCE S256 challenge sent to the provider.
    pub code_challenge: String,
    /// State expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for OAuth2AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2AuthorizationRequest")
            .field("authorization_url", &"[redacted]")
            .field("provider_name", &self.provider_name)
            .field("state", &"[redacted]")
            .field("code_verifier", &"[redacted]")
            .field("code_challenge", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// OAuth 2.0 token endpoint response.
///
/// The access token is returned only in memory for the host's optional use;
/// `agql-auth` never stores it. `Debug` redacts every token and the raw body.
#[derive(Clone)]
pub struct OAuth2TokenResponse {
    /// Provider access token.
    pub access_token: String,
    /// Token type; always `bearer` (case-insensitive) once accepted.
    pub token_type: String,
    /// Provider refresh token, if returned.
    pub refresh_token: Option<String>,
    /// Access-token lifetime in seconds, if returned.
    pub expires_in: Option<i64>,
    /// Provider-returned scope string, if returned.
    pub scope: Option<String>,
    /// Raw token response.
    pub raw: JsonValue,
}

impl fmt::Debug for OAuth2TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2TokenResponse")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("raw", &"[redacted]")
            .finish()
    }
}

/// Profile resolved from the userinfo response.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2UserProfile {
    /// Provider name. Identities are keyed by `(provider_name, subject)`.
    pub provider_name: String,
    /// Stable provider subject (integers normalized to decimal strings).
    pub subject: String,
    /// Email, when present.
    pub email: Option<String>,
    /// Email verification. Only `Some(true)` asserts a verified address;
    /// whether to trust it remains host policy.
    pub email_verified: Option<bool>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Picture URL, when present.
    pub picture: Option<String>,
    /// Raw userinfo JSON object.
    pub raw: JsonValue,
}

impl fmt::Debug for OAuth2UserProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2UserProfile")
            .field("provider_name", &self.provider_name)
            .field("subject", &self.subject)
            .field("email", &self.email)
            .field("email_verified", &self.email_verified)
            .field("name", &self.name)
            .field("picture", &self.picture.as_ref().map(|_| "[present]"))
            .field("raw", &"[redacted]")
            .finish()
    }
}

/// Result of a validated OAuth 2.0 callback before local user resolution.
#[derive(Debug, Clone)]
pub struct OAuth2CallbackOutcome {
    /// Consumed state record.
    pub state: OAuthLoginState,
    /// Token endpoint response.
    pub token_response: OAuth2TokenResponse,
    /// Resolved provider profile.
    pub profile: OAuth2UserProfile,
}

/// OAuth 2.0 authorization-code + PKCE provider resolving identity through a
/// userinfo request.
///
/// State hashing, one-time consumption, expiry and replay semantics are the
/// same as [`crate::OidcProvider`]. No nonce is generated: stored states carry
/// an empty nonce, which [`crate::OidcProvider`] refuses, and this provider
/// refuses states that carry a nonce.
#[derive(Clone)]
pub struct OAuth2Provider {
    config: OAuth2ProviderConfig,
    http_client: Arc<dyn OidcHttpClient>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for OAuth2Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Provider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OAuth2Provider {
    /// Creates a provider from validated configuration and a host HTTP client.
    ///
    /// The HTTP client must support request headers (bearer userinfo requests).
    pub fn new(
        config: OAuth2ProviderConfig,
        http_client: Arc<dyn OidcHttpClient>,
    ) -> AuthResult<Self> {
        Self::new_with_clock(config, http_client, Arc::new(SystemClock))
    }

    /// Creates a provider with an injected clock.
    pub fn new_with_clock(
        config: OAuth2ProviderConfig,
        http_client: Arc<dyn OidcHttpClient>,
        clock: Arc<dyn Clock>,
    ) -> AuthResult<Self> {
        config.validate()?;
        if !http_client.supports_request_headers() {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 provider requires an HTTP client that supports request headers"
                    .to_string(),
            ));
        }
        Ok(Self {
            config,
            http_client,
            clock,
        })
    }

    /// Returns provider configuration.
    pub fn config(&self) -> &OAuth2ProviderConfig {
        &self.config
    }

    /// Creates an authorization URL with PKCE S256 and stores one-time state.
    pub async fn create_authorization_request<S>(
        &self,
        state_store: &S,
    ) -> AuthResult<OAuth2AuthorizationRequest>
    where
        S: OAuthStateStore,
    {
        let state = generate_oauth_state();
        let pkce = generate_pkce_pair();
        let now = self.clock.now();
        let expires_at = now.checked_add(self.config.state_ttl).ok_or_else(|| {
            AuthError::InvalidConfiguration("OAuth 2.0 state expiry overflowed".to_string())
        })?;
        state_store
            .insert_oauth_state(OAuthLoginState {
                provider_name: self.config.provider_name.clone(),
                state_hash: hash_oauth_state(&state),
                nonce: String::new(),
                code_verifier: pkce.code_verifier.clone(),
                redirect_uri: self.config.redirect_uri.clone(),
                scopes: self.config.scopes.clone(),
                authorization_policy: None,
                response_mode: OAuthResponseMode::Query,
                created_at: now,
                expires_at,
                consumed_at: None,
            })
            .await?;

        let mut params = vec![
            ("client_id".to_string(), self.config.client_id.clone()),
            ("redirect_uri".to_string(), self.config.redirect_uri.clone()),
            ("response_type".to_string(), "code".to_string()),
        ];
        if !self.config.scopes.is_empty() {
            params.push(("scope".to_string(), self.config.scopes.join(" ")));
        }
        params.extend([
            ("state".to_string(), state.clone()),
            ("code_challenge".to_string(), pkce.code_challenge.clone()),
            ("code_challenge_method".to_string(), "S256".to_string()),
        ]);

        Ok(OAuth2AuthorizationRequest {
            authorization_url: append_query(&self.config.authorization_endpoint, &params),
            provider_name: self.config.provider_name.clone(),
            state,
            code_verifier: pkce.code_verifier,
            code_challenge: pkce.code_challenge,
            expires_at,
        })
    }

    /// Handles a query-mode callback: consumes state once, exchanges the code
    /// with the stored verifier and resolves the profile.
    ///
    /// An error callback returns [`AuthError::OAuthProviderError`] without
    /// consuming state, matching [`crate::OidcProvider`].
    pub async fn handle_callback<S>(
        &self,
        state_store: &S,
        input: OidcCallbackInput,
    ) -> AuthResult<OAuth2CallbackOutcome>
    where
        S: OAuthStateStore,
    {
        if input.error.is_some() {
            return Err(AuthError::OAuthProviderError);
        }
        let code = input.code.filter(|code| !code.is_empty()).ok_or_else(|| {
            AuthError::OAuthCallback("authorization callback is missing code".to_string())
        })?;
        let raw_state = input
            .state
            .filter(|state| !state.is_empty())
            .ok_or(AuthError::InvalidOAuthState)?;
        let now = self.clock.now();
        let state = state_store
            .consume_oauth_state(
                &self.config.provider_name,
                &hash_oauth_state(&raw_state),
                now,
            )
            .await?
            .ok_or(AuthError::InvalidOAuthState)?;
        if state.is_consumed() {
            return Err(AuthError::OAuthStateReplayed);
        }
        if state.is_expired(now) {
            return Err(AuthError::OAuthStateExpired);
        }
        if !state.nonce.is_empty()
            || state.authorization_policy.is_some()
            || state.response_mode != OAuthResponseMode::Query
        {
            return Err(AuthError::InvalidOAuthState);
        }

        let token_response = self.exchange_code(&code, &state).await?;
        let profile = self.fetch_profile(&token_response.access_token).await?;
        Ok(OAuth2CallbackOutcome {
            state,
            token_response,
            profile,
        })
    }

    /// Exchanges an authorization code using the stored PKCE verifier.
    pub async fn exchange_code(
        &self,
        code: &str,
        state: &OAuthLoginState,
    ) -> AuthResult<OAuth2TokenResponse> {
        let authentication = client_authentication(
            self.config.token_endpoint_auth_method,
            &self.config.client_id,
            self.config.client_secret.as_deref(),
            self.config.client_jwt.as_ref(),
            &self.config.token_endpoint,
            self.clock.now(),
        )
        .map_err(|_| {
            AuthError::OAuthTokenExchange("client authentication could not be prepared".to_string())
        })?;
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), state.redirect_uri.clone()),
            ("code_verifier".to_string(), state.code_verifier.clone()),
        ];
        form.extend(authentication.form);
        let mut headers = authentication.headers;
        headers.push((ACCEPT_JSON.0.to_string(), ACCEPT_JSON.1.to_string()));

        let raw = self
            .http_client
            .post_form_json_with_headers(&self.config.token_endpoint, &headers, &form)
            .await
            .map_err(|_| {
                AuthError::OAuthTokenExchange("provider token endpoint request failed".to_string())
            })?;
        let object = raw.as_object().ok_or_else(|| {
            AuthError::OAuthTokenExchange("provider token response was not an object".to_string())
        })?;
        if object.contains_key("error") {
            return Err(AuthError::OAuthTokenExchange(
                "provider token endpoint returned an error".to_string(),
            ));
        }
        let access_token = object
            .get("access_token")
            .and_then(JsonValue::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                AuthError::OAuthTokenExchange(
                    "provider token response is missing access_token".to_string(),
                )
            })?
            .to_string();
        let token_type = object
            .get("token_type")
            .and_then(JsonValue::as_str)
            .filter(|token_type| token_type.eq_ignore_ascii_case("bearer"))
            .ok_or_else(|| {
                AuthError::OAuthTokenExchange(
                    "provider token response is not a bearer token".to_string(),
                )
            })?
            .to_string();
        let optional_string = |name: &str| -> AuthResult<Option<String>> {
            match object.get(name) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(JsonValue::String(value)) => Ok(Some(value.clone())),
                Some(_) => Err(AuthError::OAuthTokenExchange(format!(
                    "provider token response {name} has an invalid type"
                ))),
            }
        };
        let refresh_token = optional_string("refresh_token")?;
        let scope = optional_string("scope")?;
        let expires_in = match object.get("expires_in") {
            None | Some(JsonValue::Null) => None,
            Some(value) => Some(value.as_i64().ok_or_else(|| {
                AuthError::OAuthTokenExchange(
                    "provider token response expires_in has an invalid type".to_string(),
                )
            })?),
        };

        Ok(OAuth2TokenResponse {
            access_token,
            token_type,
            refresh_token,
            expires_in,
            scope,
            raw,
        })
    }

    /// Requests the userinfo profile (and the verified-email list when
    /// configured) with `access_token` as a bearer credential.
    pub async fn fetch_profile(&self, access_token: &str) -> AuthResult<OAuth2UserProfile> {
        let raw = self
            .bearer_get(&self.config.userinfo_endpoint, access_token)
            .await?;
        if !raw.is_object() {
            return Err(AuthError::OAuthUserInfo(
                "provider userinfo response was not an object".to_string(),
            ));
        }
        let mapping = &self.config.profile;
        let subject = profile_subject(&raw, &mapping.subject_pointer)?;
        let mut email = mapping
            .email_pointer
            .as_deref()
            .and_then(|pointer| pointer_string(&raw, pointer));
        let mut email_verified = match &mapping.email_verification {
            OAuth2EmailVerification::Unknown => None,
            OAuth2EmailVerification::Pointer(pointer) => {
                raw.pointer(pointer).and_then(parse_email_verified)
            }
            OAuth2EmailVerification::ProviderVerifiesAll => email.as_ref().map(|_| true),
        };
        if email.is_none() {
            email_verified = None;
        }
        if email_verified != Some(true)
            && let Some(list) = &self.config.verified_email_list
            && let Some(selected) = self.select_verified_email(list, access_token).await?
        {
            email = Some(selected);
            email_verified = Some(true);
        }

        Ok(OAuth2UserProfile {
            provider_name: self.config.provider_name.clone(),
            subject,
            email,
            email_verified,
            name: mapping
                .name_pointer
                .as_deref()
                .and_then(|pointer| pointer_string(&raw, pointer)),
            picture: mapping
                .picture_pointer
                .as_deref()
                .and_then(|pointer| pointer_string(&raw, pointer)),
            raw,
        })
    }

    async fn select_verified_email(
        &self,
        list: &OAuth2VerifiedEmailList,
        access_token: &str,
    ) -> AuthResult<Option<String>> {
        let raw = self.bearer_get(&list.endpoint, access_token).await?;
        let entries = match &list.entries_pointer {
            Some(pointer) => raw.pointer(pointer),
            None => Some(&raw),
        }
        .and_then(JsonValue::as_array)
        .ok_or_else(|| {
            AuthError::OAuthUserInfo("provider email list response was not an array".to_string())
        })?;
        if entries.len() > MAX_OAUTH2_VERIFIED_EMAIL_ENTRIES {
            return Err(AuthError::OAuthUserInfo(
                "provider email list response has too many entries".to_string(),
            ));
        }
        let is_true = |entry: &JsonValue, pointer: &str| {
            entry.pointer(pointer).and_then(parse_email_verified) == Some(true)
        };
        Ok(entries
            .iter()
            .filter(|entry| is_true(entry, &list.verified_pointer))
            .filter(|entry| match list.selection {
                OAuth2VerifiedEmailSelection::PrimaryVerified => list
                    .primary_pointer
                    .as_deref()
                    .is_some_and(|pointer| is_true(entry, pointer)),
                OAuth2VerifiedEmailSelection::FirstVerified => true,
            })
            .find_map(|entry| pointer_string(entry, &list.email_pointer)))
    }

    async fn bearer_get(&self, url: &str, access_token: &str) -> AuthResult<JsonValue> {
        let headers = [
            (
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            ),
            (ACCEPT_JSON.0.to_string(), ACCEPT_JSON.1.to_string()),
        ];
        self.http_client
            .get_json_with_headers(url, &headers)
            .await
            .map_err(|_| AuthError::OAuthUserInfo("provider profile request failed".to_string()))
    }
}

fn profile_subject(raw: &JsonValue, pointer: &str) -> AuthResult<String> {
    let subject = match raw.pointer(pointer) {
        Some(JsonValue::String(value)) => value.clone(),
        Some(JsonValue::Number(number)) if number.is_i64() || number.is_u64() => number.to_string(),
        _ => return Err(AuthError::OAuthMissingSubject),
    };
    if subject.is_empty()
        || subject.len() > MAX_OAUTH2_SUBJECT_LENGTH
        || subject.chars().any(char::is_control)
    {
        return Err(AuthError::OAuthMissingSubject);
    }
    Ok(subject)
}

fn pointer_string(raw: &JsonValue, pointer: &str) -> Option<String> {
    raw.pointer(pointer)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
