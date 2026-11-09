//! OAuth 2.0 authorization-code + PKCE providers without OpenID Connect.
//!
//! [`OAuth2Provider`] serves providers that issue no ID token and publish no
//! JWKS (for example GitHub). Identity comes from an authenticated userinfo
//! request, so it is only as trustworthy as the TLS connection to the
//! configured endpoints. User creation and email-trust policy remain host
//! decisions, made in an [`OAuth2UserProvisioner`].

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::{Duration, OffsetDateTime};

use crate::client_auth::{
    ClientJwtAudiences, ClientJwtSigner, TokenEndpointAuthMethod, client_authentication,
    validate_client_authentication, zeroize_pairs,
};
use crate::clock::{Clock, SystemClock};
use crate::config::{ClientMetadata, OAuthBrowserBinding, OAuthResponseMode, zeroize_secret};
use crate::models::{AuthPayload, ExternalIdentity, OAuthLoginState, OidcCallbackInput};
use crate::oidc::{
    ACCEPT_JSON, OidcHttpClient, ProvisionedExternalUser, append_query,
    ensure_no_reserved_authorization_parameters, generate_oauth_state, generate_pkce_pair,
    hash_oauth_state, is_secure_endpoint_url, is_valid_redirect_uri, new_browser_binding,
    parse_email_verified, verify_browser_binding, zeroize_json, zeroize_provider_tokens,
};
use crate::service::AuthService;
use crate::session::{AuthMethod, SessionContext};
use crate::stores::{ExternalIdentityStore, OAuthStateStore, RefreshTokenStore, UserStore};
use crate::{AuthError, AuthResult};

/// Longest accepted provider subject, in bytes.
pub const MAX_OAUTH2_SUBJECT_LENGTH: usize = 255;

/// Longest kept profile email, in bytes. Longer values are treated as absent
/// (also for OIDC `email`).
pub const MAX_OAUTH2_EMAIL_LENGTH: usize = 320;

/// Longest kept profile display name, in bytes. Longer values are treated as
/// absent (also for OIDC `name` and `preferred_username`).
pub const MAX_OAUTH2_NAME_LENGTH: usize = 512;

/// Longest kept profile picture URL, in bytes. Longer values are treated as
/// absent.
pub const MAX_OAUTH2_PICTURE_LENGTH: usize = 2_048;

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
    /// Redirect URI registered with the provider: an absolute `https://` URL
    /// (`http://` only for loopback hosts) without a fragment. Give every
    /// provider its own redirect URI.
    pub redirect_uri: String,
    /// Authorization server issuer identifier, when the provider has one.
    /// It is the default `private_key_jwt` audience, and a callback `iss`
    /// parameter (RFC 9207) must equal it. Without it a callback carrying
    /// `iss` is refused.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Require the RFC 9207 `iss` authorization-response parameter. Set it
    /// when the provider advertises `authorization_response_iss_parameter_supported`.
    /// Requires `issuer`.
    #[serde(default)]
    pub require_authorization_response_iss: bool,
    /// Requested scopes, sent space-delimited. May be empty.
    pub scopes: Vec<String>,
    /// Lifetime for OAuth state records, at most
    /// [`crate::MAX_OAUTH_STATE_TTL_SECONDS`].
    pub state_ttl: Duration,
    /// Browser binding of the one-time state. Defaults to
    /// [`OAuthBrowserBinding::Required`].
    #[serde(default)]
    pub browser_binding: OAuthBrowserBinding,
    /// Userinfo profile mapping.
    pub profile: OAuth2ProfileMapping,
    /// Optional verified-email list request.
    pub verified_email_list: Option<OAuth2VerifiedEmailList>,
}

impl Drop for OAuth2ProviderConfig {
    fn drop(&mut self) {
        zeroize_secret(&mut self.client_secret);
    }
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
            .field("issuer", &self.issuer)
            .field(
                "require_authorization_response_iss",
                &self.require_authorization_response_iss,
            )
            .field("scopes", &self.scopes)
            .field("state_ttl", &self.state_ttl)
            .field("browser_binding", &self.browser_binding)
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
            issuer: None,
            require_authorization_response_iss: false,
            scopes: Vec::new(),
            state_ttl: Duration::minutes(10),
            browser_binding: OAuthBrowserBinding::Required,
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
        ] {
            if value.trim().is_empty() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "OAuth 2.0 {name} must not be empty"
                )));
            }
        }
        if !is_valid_redirect_uri(&self.redirect_uri) {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 redirect_uri must be an absolute https URL without a fragment (http only for loopback hosts)"
                    .to_string(),
            ));
        }
        if let Some(issuer) = &self.issuer {
            validate_endpoint("issuer", issuer)?;
        } else if self.require_authorization_response_iss {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 require_authorization_response_iss requires issuer".to_string(),
            ));
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
            &self.client_id,
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
        if self.state_ttl <= Duration::ZERO
            || self.state_ttl > Duration::seconds(crate::MAX_OAUTH_STATE_TTL_SECONDS)
        {
            return Err(AuthError::InvalidConfiguration(
                "OAuth 2.0 state_ttl must be greater than zero and at most the supported maximum"
                    .to_string(),
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
    if is_secure_endpoint_url(value) {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(format!(
            "OAuth 2.0 {name} must be an https URL (http only for loopback hosts)"
        )))
    }
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
///
/// The PKCE verifier stays in the stored [`OAuthLoginState`] only.
#[derive(Clone)]
pub struct OAuth2AuthorizationRequest {
    /// Fully built provider authorization URL.
    pub authorization_url: String,
    /// Provider name.
    pub provider_name: String,
    /// Raw OAuth state sent to the browser.
    pub state: String,
    /// PKCE S256 challenge sent to the provider.
    pub code_challenge: String,
    /// Raw browser-binding secret to store in a cookie on the initiating
    /// browser and pass back as [`OidcCallbackInput::browser_binding`]. `None`
    /// only with [`OAuthBrowserBinding::NotRequiredHostBindsState`].
    pub browser_binding: Option<String>,
    /// State expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for OAuth2AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2AuthorizationRequest")
            .field("authorization_url", &"[redacted]")
            .field("provider_name", &self.provider_name)
            .field("state", &"[redacted]")
            .field("code_challenge", &"[redacted]")
            .field(
                "browser_binding",
                &self.browser_binding.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// OAuth 2.0 token endpoint response.
///
/// The access token is returned only in memory for the host's optional use;
/// `agql-auth` never stores it. `Debug` redacts every token and the raw body,
/// and dropping the response overwrites the tokens and the raw body.
#[derive(Clone)]
pub struct OAuth2TokenResponse {
    /// Provider access token.
    pub access_token: String,
    /// Token type; always `bearer` (case-insensitive) once accepted.
    pub token_type: String,
    /// Provider refresh token, if returned.
    pub refresh_token: Option<String>,
    /// Access-token lifetime in seconds, if returned. Never negative.
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

impl Drop for OAuth2TokenResponse {
    fn drop(&mut self) {
        zeroize_provider_tokens(
            [Some(&mut self.access_token), self.refresh_token.as_mut()],
            &mut self.raw,
        );
    }
}

/// Profile resolved from the userinfo response.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2UserProfile {
    /// Provider name. Identities are keyed by `(provider_name, subject)`.
    pub provider_name: String,
    /// Stable provider subject (integers normalized to decimal strings).
    pub subject: String,
    /// Email, when present and at most [`MAX_OAUTH2_EMAIL_LENGTH`] bytes.
    pub email: Option<String>,
    /// Email verification. Only `Some(true)` asserts a verified address;
    /// whether to trust it remains host policy.
    pub email_verified: Option<bool>,
    /// Display name, when present and at most [`MAX_OAUTH2_NAME_LENGTH`] bytes.
    pub name: Option<String>,
    /// Picture URL, when present and at most [`MAX_OAUTH2_PICTURE_LENGTH`] bytes.
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

#[async_trait]
/// Host extension point resolving an OAuth 2.0 profile to a local user.
///
/// Implementations may create a user, link to an existing user, or reject the
/// login by returning an error. [`OAuth2Provider::login_with_callback`]
/// re-reads the returned user afterwards and refuses a missing or disabled
/// user, so implementations need not check `disabled` themselves.
pub trait OAuth2UserProvisioner: Send + Sync {
    /// Resolves a provider profile to a local user. `existing_identity` is the
    /// identity linked to `(provider_name, subject)`, if any; returning a
    /// different user for it is refused.
    async fn resolve_oauth2_user(
        &self,
        profile: &OAuth2UserProfile,
        existing_identity: Option<&ExternalIdentity>,
    ) -> AuthResult<ProvisionedExternalUser>;
}

/// Result of a completed OAuth 2.0 login and local session issuance.
#[derive(Clone)]
pub struct OAuth2LoginResult {
    /// Local `agql-auth` session payload.
    pub auth: AuthPayload,
    /// Resolved provider profile.
    pub profile: OAuth2UserProfile,
    /// External identity that was linked or updated.
    pub external_identity: ExternalIdentity,
    /// Token endpoint response.
    pub token_response: OAuth2TokenResponse,
}

impl fmt::Debug for OAuth2LoginResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2LoginResult")
            .field("auth", &self.auth)
            .field("profile", &self.profile)
            .field("external_identity", &self.external_identity)
            .field("token_response", &self.token_response)
            .finish()
    }
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
    ///
    /// With the default [`OAuthBrowserBinding::Required`], set
    /// [`OAuth2AuthorizationRequest::browser_binding`] as a cookie on the
    /// browser before redirecting it.
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
        let (browser_binding, browser_binding_hash) =
            new_browser_binding(self.config.browser_binding);
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
                browser_binding_hash,
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
            code_challenge: pkce.code_challenge.clone(),
            browser_binding,
            expires_at,
        })
    }

    /// Handles a query-mode callback: consumes state once, exchanges the code
    /// with the stored verifier and resolves the profile.
    ///
    /// An error callback returns [`AuthError::OAuthProviderError`] without
    /// consuming state, matching [`crate::OidcProvider`]. After consumption
    /// the browser binding must match ([`AuthError::InvalidOAuthState`]), and
    /// an `iss` parameter must equal [`OAuth2ProviderConfig::issuer`]
    /// ([`AuthError::OAuthCallback`]).
    ///
    /// This resolves a profile only. Use [`Self::login_with_callback`] to
    /// enforce the local account state and issue a session.
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
        verify_browser_binding(
            self.config.browser_binding,
            state.browser_binding_hash.as_deref(),
            input.browser_binding.as_deref(),
        )?;
        match (input.iss.as_deref(), self.config.issuer.as_deref()) {
            (Some(iss), Some(issuer)) if iss == issuer => {}
            (None, _) if !self.config.require_authorization_response_iss => {}
            _ => {
                return Err(AuthError::OAuthCallback(
                    "authorization response iss does not match the provider".to_string(),
                ));
            }
        }

        let token_response = self.exchange_code(&code, &state).await?;
        let profile = self.fetch_profile(&token_response.access_token).await?;
        Ok(OAuth2CallbackOutcome {
            state,
            token_response,
            profile,
        })
    }

    /// Completes an OAuth 2.0 login and issues a local `agql-auth` session.
    ///
    /// Runs [`Self::handle_callback`], looks up the identity linked to
    /// `(provider_name, subject)`, and asks `provisioner` for the local user.
    /// The user is then re-read from the [`AuthService`]'s [`UserStore`]: a
    /// disabled user is refused with [`AuthError::UserDisabled`] and a missing
    /// user with [`AuthError::ExternalLoginRejected`], before any identity is
    /// linked or updated and before a session is issued. The session uses
    /// [`AuthMethod::OAuth2`] and the provisioner's roles and scopes.
    #[allow(clippy::too_many_arguments)]
    pub async fn login_with_callback<U, R, S, E, P>(
        &self,
        auth_service: &AuthService<U, R>,
        state_store: &S,
        external_identity_store: &E,
        provisioner: &P,
        input: OidcCallbackInput,
        metadata: ClientMetadata,
    ) -> AuthResult<OAuth2LoginResult>
    where
        U: UserStore + 'static,
        R: RefreshTokenStore + 'static,
        S: OAuthStateStore,
        E: ExternalIdentityStore,
        P: OAuth2UserProvisioner,
    {
        let OAuth2CallbackOutcome {
            token_response,
            profile,
            ..
        } = self.handle_callback(state_store, input).await?;
        let existing_identity = external_identity_store
            .find_external_identity(&profile.provider_name, &profile.subject)
            .await?;
        let provisioned_user = provisioner
            .resolve_oauth2_user(&profile, existing_identity.as_ref())
            .await?;
        if let Some(existing) = existing_identity.as_ref()
            && existing.user_id != provisioned_user.user_id
        {
            return Err(AuthError::ExternalLoginRejected(
                "provisioner returned a different user for an existing external identity"
                    .to_string(),
            ));
        }
        auth_service
            .require_enabled_external_user(&provisioned_user.user_id)
            .await?;

        let now = self.clock.now();
        let claims_snapshot = profile.raw.clone();
        let external_identity = if let Some(mut identity) = existing_identity {
            identity.claims_snapshot = claims_snapshot.clone();
            identity.updated_at = now;
            external_identity_store
                .update_external_identity_claims_snapshot(
                    &identity.provider_name,
                    &identity.external_subject,
                    claims_snapshot,
                    now,
                )
                .await?;
            identity
        } else {
            let identity = ExternalIdentity {
                provider_name: profile.provider_name.clone(),
                external_subject: profile.subject.clone(),
                user_id: provisioned_user.user_id.clone(),
                issuer: self
                    .config
                    .issuer
                    .clone()
                    .unwrap_or_else(|| self.config.authorization_endpoint.clone()),
                tenant_id: None,
                provider_user_id: Some(profile.subject.clone()),
                claims_snapshot,
                created_at: now,
                updated_at: now,
            };
            if provisioned_user.link_external_identity {
                external_identity_store
                    .link_external_identity(identity.clone())
                    .await?;
            }
            identity
        };

        let auth = auth_service
            .issue_session_for_user_with_metadata(
                provisioned_user.user_id,
                provisioned_user.roles,
                provisioned_user.scopes,
                SessionContext::for_auth_method(AuthMethod::OAuth2),
                crate::RefreshableTokenMetadata::default(),
                metadata,
            )
            .await?;

        Ok(OAuth2LoginResult {
            auth,
            profile,
            external_identity,
            token_response,
        })
    }

    /// Exchanges an authorization code using the stored PKCE verifier.
    ///
    /// Only the callback path calls this, after it consumed the state.
    pub(crate) async fn exchange_code(
        &self,
        code: &str,
        state: &OAuthLoginState,
    ) -> AuthResult<OAuth2TokenResponse> {
        let authentication = client_authentication(
            self.config.token_endpoint_auth_method,
            &self.config.client_id,
            self.config.client_secret.as_deref(),
            self.config.client_jwt.as_ref(),
            ClientJwtAudiences {
                assertion: self
                    .config
                    .issuer
                    .as_deref()
                    .unwrap_or(&self.config.token_endpoint),
                signed_secret: &self.config.token_endpoint,
            },
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

        let response = self
            .http_client
            .post_form_json_with_headers(&self.config.token_endpoint, &headers, &form)
            .await;
        zeroize_pairs(&mut headers);
        zeroize_pairs(&mut form);
        let mut raw = response.map_err(|_| {
            AuthError::OAuthTokenExchange("provider token endpoint request failed".to_string())
        })?;
        let parsed = Self::parse_token_response(&raw);
        if parsed.is_err() {
            zeroize_json(&mut raw);
        }
        let (access_token, token_type, refresh_token, expires_in, scope) = parsed?;

        Ok(OAuth2TokenResponse {
            access_token,
            token_type,
            refresh_token,
            expires_in,
            scope,
            raw,
        })
    }

    #[allow(clippy::type_complexity)]
    fn parse_token_response(
        raw: &JsonValue,
    ) -> AuthResult<(String, String, Option<String>, Option<i64>, Option<String>)> {
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
            Some(value) => Some(
                value
                    .as_i64()
                    .filter(|expires_in| *expires_in >= 0)
                    .ok_or_else(|| {
                        AuthError::OAuthTokenExchange(
                            "provider token response expires_in is invalid".to_string(),
                        )
                    })?,
            ),
        };

        Ok((access_token, token_type, refresh_token, expires_in, scope))
    }

    /// Requests the userinfo profile (and the verified-email list when
    /// configured) with `access_token` as a bearer credential.
    ///
    /// The access token must come from this provider's own code exchange: a
    /// userinfo response proves nothing about which client a token was issued
    /// to, so a client-supplied token would yield another application's user.
    pub(crate) async fn fetch_profile(&self, access_token: &str) -> AuthResult<OAuth2UserProfile> {
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
            .and_then(|pointer| pointer_string(&raw, pointer, MAX_OAUTH2_EMAIL_LENGTH));
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
                .and_then(|pointer| pointer_string(&raw, pointer, MAX_OAUTH2_NAME_LENGTH)),
            picture: mapping
                .picture_pointer
                .as_deref()
                .and_then(|pointer| pointer_string(&raw, pointer, MAX_OAUTH2_PICTURE_LENGTH)),
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
            .find_map(|entry| pointer_string(entry, &list.email_pointer, MAX_OAUTH2_EMAIL_LENGTH)))
    }

    async fn bearer_get(&self, url: &str, access_token: &str) -> AuthResult<JsonValue> {
        let mut headers = [
            (
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            ),
            (ACCEPT_JSON.0.to_string(), ACCEPT_JSON.1.to_string()),
        ];
        let response = self.http_client.get_json_with_headers(url, &headers).await;
        zeroize_pairs(&mut headers);
        response
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

fn pointer_string(raw: &JsonValue, pointer: &str, max_length: usize) -> Option<String> {
    raw.pointer(pointer)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty() && value.len() <= max_length)
        .map(str::to_string)
}
