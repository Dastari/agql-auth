use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::config::{ClientMetadata, OidcProviderConfig, OidcProviderKind};
use crate::models::{
    ExternalIdentity, OAuthLoginState, OidcAuthorizationRequest, OidcCallbackInput,
    OidcLoginResult, OidcTokenResponse, ValidatedOidcClaims,
};
use crate::service::AuthService;
use crate::session::{AuthMethod, SessionContext};
use crate::stores::{ExternalIdentityStore, OAuthStateStore, RefreshTokenStore, UserStore};
use crate::{AuthError, AuthResult};

const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');
const MICROSOFT_CONSUMER_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

#[async_trait]
/// Minimal HTTP abstraction used by [`OidcProvider`].
///
/// Host applications implement this with their preferred HTTP client.
pub trait OidcHttpClient: Send + Sync {
    /// Performs a JSON GET request.
    async fn get_json(&self, url: &str) -> AuthResult<JsonValue>;

    /// Performs a form-encoded POST request and returns JSON.
    async fn post_form_json(&self, url: &str, form: &[(String, String)]) -> AuthResult<JsonValue>;
}

/// OIDC discovery document fields used by `agql-auth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    /// Provider issuer.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// JWKS URI.
    pub jwks_uri: String,
    /// Raw discovery response.
    #[serde(default)]
    pub raw: JsonValue,
}

/// PKCE verifier and S256 challenge pair.
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// Random PKCE code verifier.
    pub code_verifier: String,
    /// Base64url-encoded SHA-256 challenge.
    pub code_challenge: String,
}

/// Result of validating an OIDC callback before local user resolution.
#[derive(Debug, Clone)]
pub struct OidcCallbackOutcome {
    /// Consumed state record.
    pub state: OAuthLoginState,
    /// Provider token endpoint response.
    pub token_response: OidcTokenResponse,
    /// Validated ID-token claims.
    pub claims: ValidatedOidcClaims,
}

/// Local roles and scopes derived from provider claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappedClaims {
    /// Local roles to assign.
    pub roles: Vec<String>,
    /// Local scopes to assign.
    pub scopes: Vec<String>,
}

/// Local user resolution returned by an [`ExternalUserProvisioner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedExternalUser {
    /// Local user ID.
    pub user_id: String,
    /// Local roles for the issued session.
    pub roles: Vec<String>,
    /// Local scopes for the issued session.
    pub scopes: Vec<String>,
    /// Whether to link this external identity when no link exists yet.
    pub link_external_identity: bool,
}

impl ProvisionedExternalUser {
    /// Creates a provisioned external-user result that links by default.
    pub fn new(user_id: impl Into<String>, roles: Vec<String>, scopes: Vec<String>) -> Self {
        Self {
            user_id: user_id.into(),
            roles,
            scopes,
            link_external_identity: true,
        }
    }

    /// Creates a provisioned user using mapped local roles and scopes.
    pub fn from_mapped_claims(user_id: impl Into<String>, mapped_claims: &MappedClaims) -> Self {
        Self::new(
            user_id,
            mapped_claims.roles.clone(),
            mapped_claims.scopes.clone(),
        )
    }
}

#[async_trait]
/// Maps validated provider claims into local roles and scopes.
pub trait ClaimsMapper: Send + Sync {
    /// Returns local roles and scopes derived from validated claims.
    async fn map_claims(&self, claims: &ValidatedOidcClaims) -> AuthResult<MappedClaims>;
}

/// Claims mapper that assigns no roles or scopes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopClaimsMapper;

#[async_trait]
impl ClaimsMapper for NoopClaimsMapper {
    async fn map_claims(&self, _claims: &ValidatedOidcClaims) -> AuthResult<MappedClaims> {
        Ok(MappedClaims::default())
    }
}

#[async_trait]
/// Host extension point for external user provisioning and account linking.
pub trait ExternalUserProvisioner: Send + Sync {
    /// Resolves a validated external identity to a local user.
    ///
    /// Implementations may create a user, link to an existing user, or reject
    /// the login by returning an error.
    async fn resolve_external_user(
        &self,
        claims: &ValidatedOidcClaims,
        existing_identity: Option<&ExternalIdentity>,
        mapped_claims: &MappedClaims,
    ) -> AuthResult<ProvisionedExternalUser>;
}

/// Claims mapper for common Microsoft Entra role, group, tenant, and object-ID mappings.
#[derive(Debug, Clone, Default)]
pub struct MicrosoftClaimsMapper {
    /// Microsoft app role to local roles.
    pub role_to_roles: HashMap<String, Vec<String>>,
    /// Microsoft app role to local scopes.
    pub role_to_scopes: HashMap<String, Vec<String>>,
    /// Microsoft group ID to local roles.
    pub group_to_roles: HashMap<String, Vec<String>>,
    /// Microsoft group ID to local scopes.
    pub group_to_scopes: HashMap<String, Vec<String>>,
    /// Microsoft tenant ID to local roles.
    pub tenant_to_roles: HashMap<String, Vec<String>>,
    /// Microsoft tenant ID to local scopes.
    pub tenant_to_scopes: HashMap<String, Vec<String>>,
    /// Microsoft object ID to local roles.
    pub object_id_to_roles: HashMap<String, Vec<String>>,
    /// Microsoft object ID to local scopes.
    pub object_id_to_scopes: HashMap<String, Vec<String>>,
}

impl MicrosoftClaimsMapper {
    /// Creates an empty Microsoft claims mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps a Microsoft role claim to a local role.
    pub fn map_role_to_role(
        mut self,
        microsoft_role: impl Into<String>,
        local_role: impl Into<String>,
    ) -> Self {
        self.role_to_roles
            .entry(microsoft_role.into())
            .or_default()
            .push(local_role.into());
        self
    }

    /// Maps a Microsoft role claim to a local scope.
    pub fn map_role_to_scope(
        mut self,
        microsoft_role: impl Into<String>,
        local_scope: impl Into<String>,
    ) -> Self {
        self.role_to_scopes
            .entry(microsoft_role.into())
            .or_default()
            .push(local_scope.into());
        self
    }

    /// Maps a Microsoft group ID to a local role.
    pub fn map_group_to_role(
        mut self,
        microsoft_group: impl Into<String>,
        local_role: impl Into<String>,
    ) -> Self {
        self.group_to_roles
            .entry(microsoft_group.into())
            .or_default()
            .push(local_role.into());
        self
    }

    /// Maps a Microsoft group ID to a local scope.
    pub fn map_group_to_scope(
        mut self,
        microsoft_group: impl Into<String>,
        local_scope: impl Into<String>,
    ) -> Self {
        self.group_to_scopes
            .entry(microsoft_group.into())
            .or_default()
            .push(local_scope.into());
        self
    }

    /// Maps a Microsoft tenant ID to a local role.
    pub fn map_tenant_to_role(
        mut self,
        tenant_id: impl Into<String>,
        local_role: impl Into<String>,
    ) -> Self {
        self.tenant_to_roles
            .entry(tenant_id.into())
            .or_default()
            .push(local_role.into());
        self
    }

    /// Maps a Microsoft tenant ID to a local scope.
    pub fn map_tenant_to_scope(
        mut self,
        tenant_id: impl Into<String>,
        local_scope: impl Into<String>,
    ) -> Self {
        self.tenant_to_scopes
            .entry(tenant_id.into())
            .or_default()
            .push(local_scope.into());
        self
    }

    /// Maps a Microsoft object ID to a local role.
    pub fn map_object_id_to_role(
        mut self,
        object_id: impl Into<String>,
        local_role: impl Into<String>,
    ) -> Self {
        self.object_id_to_roles
            .entry(object_id.into())
            .or_default()
            .push(local_role.into());
        self
    }

    /// Maps a Microsoft object ID to a local scope.
    pub fn map_object_id_to_scope(
        mut self,
        object_id: impl Into<String>,
        local_scope: impl Into<String>,
    ) -> Self {
        self.object_id_to_scopes
            .entry(object_id.into())
            .or_default()
            .push(local_scope.into());
        self
    }
}

#[async_trait]
impl ClaimsMapper for MicrosoftClaimsMapper {
    async fn map_claims(&self, claims: &ValidatedOidcClaims) -> AuthResult<MappedClaims> {
        let mut roles = Vec::new();
        let mut scopes = Vec::new();
        let mut seen_roles = HashSet::new();
        let mut seen_scopes = HashSet::new();

        for remote_role in &claims.roles {
            push_mapped(
                self.role_to_roles.get(remote_role),
                &mut roles,
                &mut seen_roles,
            );
            push_mapped(
                self.role_to_scopes.get(remote_role),
                &mut scopes,
                &mut seen_scopes,
            );
        }

        for group in &claims.groups {
            push_mapped(self.group_to_roles.get(group), &mut roles, &mut seen_roles);
            push_mapped(
                self.group_to_scopes.get(group),
                &mut scopes,
                &mut seen_scopes,
            );
        }

        if let Some(tenant_id) = &claims.tenant_id {
            push_mapped(
                self.tenant_to_roles.get(tenant_id),
                &mut roles,
                &mut seen_roles,
            );
            push_mapped(
                self.tenant_to_scopes.get(tenant_id),
                &mut scopes,
                &mut seen_scopes,
            );
        }

        if let Some(object_id) = &claims.object_id {
            push_mapped(
                self.object_id_to_roles.get(object_id),
                &mut roles,
                &mut seen_roles,
            );
            push_mapped(
                self.object_id_to_scopes.get(object_id),
                &mut scopes,
                &mut seen_scopes,
            );
        }

        Ok(MappedClaims { roles, scopes })
    }
}

fn push_mapped(values: Option<&Vec<String>>, output: &mut Vec<String>, seen: &mut HashSet<String>) {
    if let Some(values) = values {
        for value in values {
            if seen.insert(value.clone()) {
                output.push(value.clone());
            }
        }
    }
}

/// OIDC provider client for discovery, authorization, token exchange, and validation.
#[derive(Clone)]
pub struct OidcProvider {
    config: OidcProviderConfig,
    http_client: Arc<dyn OidcHttpClient>,
    discovery_cache: Arc<Mutex<Option<OidcDiscoveryDocument>>>,
    jwks_cache: Arc<Mutex<Option<CachedJwks>>>,
}

impl OidcProvider {
    /// Creates a provider from validated OIDC configuration and a host HTTP client.
    pub fn new(
        config: OidcProviderConfig,
        http_client: Arc<dyn OidcHttpClient>,
    ) -> AuthResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            http_client,
            discovery_cache: Arc::new(Mutex::new(None)),
            jwks_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns provider configuration.
    pub fn config(&self) -> &OidcProviderConfig {
        &self.config
    }

    /// Fetches and caches the OIDC discovery document.
    pub async fn discover(&self) -> AuthResult<OidcDiscoveryDocument> {
        if let Some(document) = self
            .discovery_cache
            .lock()
            .map_err(|_| AuthError::OidcDiscovery("discovery cache lock poisoned".to_string()))?
            .clone()
        {
            return Ok(document);
        }

        let raw = self
            .http_client
            .get_json(&self.config.discovery_url)
            .await
            .map_err(|err| AuthError::OidcDiscovery(err.to_string()))?;
        let mut document: OidcDiscoveryDocument = serde_json::from_value(raw.clone())
            .map_err(|err| AuthError::OidcDiscovery(err.to_string()))?;
        document.raw = raw;

        *self
            .discovery_cache
            .lock()
            .map_err(|_| AuthError::OidcDiscovery("discovery cache lock poisoned".to_string()))? =
            Some(document.clone());

        Ok(document)
    }

    /// Creates an authorization URL and stores one-time state.
    ///
    /// The generated request always includes PKCE and nonce.
    pub async fn create_authorization_request<S>(
        &self,
        state_store: &S,
    ) -> AuthResult<OidcAuthorizationRequest>
    where
        S: OAuthStateStore,
    {
        let discovery = self.discover().await?;
        let state = generate_oauth_state();
        let nonce = generate_oidc_nonce();
        let pkce = generate_pkce_pair();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + self.config.state_ttl;
        let scopes = self.config.scopes();
        let scope = scopes.join(" ");
        let state_record = OAuthLoginState {
            provider_name: self.config.provider_name.clone(),
            state_hash: hash_oauth_state(&state),
            nonce: nonce.clone(),
            code_verifier: pkce.code_verifier.clone(),
            redirect_uri: self.config.redirect_uri.clone(),
            scopes: scopes.clone(),
            created_at: now,
            expires_at,
            consumed_at: None,
        };

        state_store.insert_oauth_state(state_record).await?;

        let authorization_url = append_query(
            &discovery.authorization_endpoint,
            &[
                ("client_id", self.config.client_id.as_str()),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("response_type", "code"),
                ("response_mode", "query"),
                ("scope", &scope),
                ("state", &state),
                ("nonce", &nonce),
                ("code_challenge", &pkce.code_challenge),
                ("code_challenge_method", "S256"),
            ],
        );

        Ok(OidcAuthorizationRequest {
            authorization_url,
            provider_name: self.config.provider_name.clone(),
            state,
            nonce,
            code_verifier: pkce.code_verifier,
            code_challenge: pkce.code_challenge,
            expires_at,
        })
    }

    /// Handles a callback through state consumption, token exchange, and ID-token validation.
    pub async fn handle_callback<S>(
        &self,
        state_store: &S,
        input: OidcCallbackInput,
    ) -> AuthResult<OidcCallbackOutcome>
    where
        S: OAuthStateStore,
    {
        if let Some(error) = input.error {
            let detail = input
                .error_description
                .map(|description| format!("{error}: {description}"))
                .unwrap_or(error);
            return Err(AuthError::OidcCallback(detail));
        }

        let code = input.code.ok_or_else(|| {
            AuthError::OidcCallback("authorization callback is missing code".to_string())
        })?;
        let raw_state = input.state.ok_or(AuthError::InvalidOAuthState)?;
        let state_hash = hash_oauth_state(&raw_state);
        let now = OffsetDateTime::now_utc();
        let state = state_store
            .consume_oauth_state(&self.config.provider_name, &state_hash, now)
            .await?
            .ok_or(AuthError::InvalidOAuthState)?;

        if state.is_consumed() {
            return Err(AuthError::OAuthStateReplayed);
        }

        if state.is_expired(now) {
            return Err(AuthError::OAuthStateExpired);
        }

        let token_response = self.exchange_code(&code, &state).await?;
        let claims = self
            .validate_id_token(&token_response.id_token, &state.nonce)
            .await?;

        Ok(OidcCallbackOutcome {
            state,
            token_response,
            claims,
        })
    }

    /// Completes an OIDC login and issues a local `agql-auth` session.
    ///
    /// This method validates the provider callback, resolves or links a local
    /// user through host extension points, and returns an [`OidcLoginResult`].
    #[allow(clippy::too_many_arguments)]
    pub async fn login_with_callback<U, R, S, E, P, M>(
        &self,
        auth_service: &AuthService<U, R>,
        state_store: &S,
        external_identity_store: &E,
        provisioner: &P,
        claims_mapper: &M,
        input: OidcCallbackInput,
        metadata: ClientMetadata,
    ) -> AuthResult<OidcLoginResult>
    where
        U: UserStore + 'static,
        R: RefreshTokenStore + 'static,
        S: OAuthStateStore,
        E: ExternalIdentityStore,
        P: ExternalUserProvisioner,
        M: ClaimsMapper,
    {
        let outcome = self.handle_callback(state_store, input).await?;
        let now = OffsetDateTime::now_utc();
        let existing_identity = external_identity_store
            .find_external_identity(
                &outcome.claims.provider_name,
                &outcome.claims.external_subject,
            )
            .await?;
        let mapped_claims = claims_mapper.map_claims(&outcome.claims).await?;
        let provisioned_user = provisioner
            .resolve_external_user(&outcome.claims, existing_identity.as_ref(), &mapped_claims)
            .await?;

        if let Some(existing) = existing_identity.as_ref()
            && existing.user_id != provisioned_user.user_id
        {
            return Err(AuthError::ExternalLoginRejected(
                "provisioner returned a different user for an existing external identity"
                    .to_string(),
            ));
        }

        let claims_snapshot = outcome.claims.raw.clone();
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
                provider_name: outcome.claims.provider_name.clone(),
                external_subject: outcome.claims.external_subject.clone(),
                user_id: provisioned_user.user_id.clone(),
                issuer: outcome.claims.issuer.clone(),
                tenant_id: outcome.claims.tenant_id.clone(),
                provider_user_id: outcome
                    .claims
                    .object_id
                    .clone()
                    .or_else(|| Some(outcome.claims.subject.clone())),
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

        let auth_method = match self.config.provider_kind {
            OidcProviderKind::MicrosoftEntra => AuthMethod::MicrosoftOidc,
            OidcProviderKind::Generic => AuthMethod::Oidc,
        };

        let auth = auth_service
            .issue_session_for_user_with_scopes(
                provisioned_user.user_id,
                provisioned_user.roles,
                provisioned_user.scopes,
                SessionContext::for_auth_method(auth_method),
                metadata,
            )
            .await?;

        Ok(OidcLoginResult {
            auth,
            claims: outcome.claims,
            external_identity,
            token_response: outcome.token_response,
        })
    }

    /// Exchanges an authorization code using the stored PKCE verifier.
    pub async fn exchange_code(
        &self,
        code: &str,
        state: &OAuthLoginState,
    ) -> AuthResult<OidcTokenResponse> {
        let discovery = self.discover().await?;
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("client_id".to_string(), self.config.client_id.clone()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), state.redirect_uri.clone()),
            ("code_verifier".to_string(), state.code_verifier.clone()),
        ];

        if let Some(client_secret) = &self.config.client_secret {
            form.push(("client_secret".to_string(), client_secret.clone()));
        }

        let raw = self
            .http_client
            .post_form_json(&discovery.token_endpoint, &form)
            .await
            .map_err(|err| AuthError::OidcTokenExchange(err.to_string()))?;

        if let Some(error) = raw.get("error").and_then(JsonValue::as_str) {
            let detail = raw
                .get("error_description")
                .and_then(JsonValue::as_str)
                .map(|description| format!("{error}: {description}"))
                .unwrap_or_else(|| error.to_string());
            return Err(AuthError::OidcTokenExchange(detail));
        }

        let mut token_response: OidcTokenResponse = serde_json::from_value(raw.clone())
            .map_err(|err| AuthError::OidcTokenExchange(err.to_string()))?;
        token_response.raw = raw;

        Ok(token_response)
    }

    /// Validates an OIDC ID token against discovery, JWKS, audience, issuer, and nonce.
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> AuthResult<ValidatedOidcClaims> {
        let discovery = self.discover().await?;
        let header = decode_header(id_token)
            .map_err(|err| AuthError::OidcTokenValidation(err.to_string()))?;
        let kid = header.kid.clone().ok_or_else(|| {
            AuthError::OidcTokenValidation("ID token header is missing kid".to_string())
        })?;
        let allowed_algorithms = self.allowed_algorithms()?;

        if !allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::OidcTokenValidation(format!(
                "ID token alg {:?} is not allowed",
                header.alg
            )));
        }

        let jwk = self.jwk_for_kid(&kid, false).await?;
        let jwk = match jwk {
            Some(jwk) => jwk,
            None => self
                .jwk_for_kid(&kid, true)
                .await?
                .ok_or_else(|| AuthError::OidcTokenValidation("unknown key ID".to_string()))?,
        };

        validate_jwk_for_header(&jwk, header.alg)?;

        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|err| AuthError::OidcTokenValidation(err.to_string()))?;
        let mut validation = Validation::new(header.alg);
        validation.algorithms = allowed_algorithms;
        validation.set_audience(std::slice::from_ref(&self.config.client_id));
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = self.clock_skew_seconds()?;

        let token_data = decode::<RawOidcIdTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|err| AuthError::OidcTokenValidation(err.to_string()))?;

        self.validate_claims(token_data.claims, expected_nonce, &discovery)
    }

    async fn jwk_for_kid(&self, kid: &str, force_refresh: bool) -> AuthResult<Option<Jwk>> {
        let jwks = self.jwks(force_refresh).await?;
        Ok(jwks.find(kid).cloned())
    }

    async fn jwks(&self, force_refresh: bool) -> AuthResult<JwkSet> {
        let now = OffsetDateTime::now_utc();
        if !force_refresh
            && let Some(cache) = self
                .jwks_cache
                .lock()
                .map_err(|_| AuthError::OidcDiscovery("JWKS cache lock poisoned".to_string()))?
                .as_ref()
                .cloned()
            && cache.expires_at > now
        {
            return Ok(cache.jwks);
        }

        let discovery = self.discover().await?;
        let raw = self
            .http_client
            .get_json(&discovery.jwks_uri)
            .await
            .map_err(|err| AuthError::OidcDiscovery(err.to_string()))?;
        let jwks: JwkSet =
            serde_json::from_value(raw).map_err(|err| AuthError::OidcDiscovery(err.to_string()))?;
        let expires_at = now + self.config.jwks_cache_ttl;

        *self
            .jwks_cache
            .lock()
            .map_err(|_| AuthError::OidcDiscovery("JWKS cache lock poisoned".to_string()))? =
            Some(CachedJwks {
                jwks: jwks.clone(),
                expires_at,
            });

        Ok(jwks)
    }

    fn validate_claims(
        &self,
        claims: RawOidcIdTokenClaims,
        expected_nonce: &str,
        discovery: &OidcDiscoveryDocument,
    ) -> AuthResult<ValidatedOidcClaims> {
        let nonce = claims.nonce.clone().ok_or_else(|| {
            AuthError::OidcTokenValidation("ID token is missing nonce".to_string())
        })?;
        if nonce != expected_nonce {
            return Err(AuthError::OidcTokenValidation(
                "ID token nonce does not match authorization state".to_string(),
            ));
        }

        let tenant_id = claims.tid.clone();
        if !self.issuer_allowed(&claims.iss, tenant_id.as_deref(), discovery) {
            return Err(AuthError::OidcTokenValidation(
                "ID token issuer is not allowed".to_string(),
            ));
        }

        if matches!(self.config.provider_kind, OidcProviderKind::MicrosoftEntra) {
            let tid = tenant_id.as_deref().ok_or_else(|| {
                AuthError::OidcTokenValidation(
                    "Microsoft Entra ID token is missing tid".to_string(),
                )
            })?;

            if !self.config.allowed_tenants.is_empty()
                && !self
                    .config
                    .allowed_tenants
                    .iter()
                    .any(|allowed| allowed == tid)
            {
                return Err(AuthError::OidcTokenValidation(
                    "Microsoft Entra tenant is not allowed".to_string(),
                ));
            }

            if tid == MICROSOFT_CONSUMER_TENANT_ID && !self.config.allow_consumer_accounts {
                return Err(AuthError::OidcTokenValidation(
                    "Microsoft consumer accounts are not enabled".to_string(),
                ));
            }
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        if claims.iat > now + self.config.clock_skew.whole_seconds() {
            return Err(AuthError::OidcTokenValidation(
                "ID token iat is in the future".to_string(),
            ));
        }

        let external_subject = stable_external_subject(
            &self.config.provider_kind,
            &claims.iss,
            &claims.sub,
            tenant_id.as_deref(),
            claims.oid.as_deref(),
        );

        let raw = serde_json::to_value(&claims)
            .map_err(|err| AuthError::OidcTokenValidation(err.to_string()))?;
        let audiences = claims.aud.into_vec();

        Ok(ValidatedOidcClaims {
            provider_name: self.config.provider_name.clone(),
            issuer: claims.iss,
            audiences,
            subject: claims.sub,
            external_subject,
            expires_at: unix_timestamp_to_datetime(claims.exp)?,
            not_before: unix_timestamp_to_datetime(claims.nbf)?,
            issued_at: unix_timestamp_to_datetime(claims.iat)?,
            nonce,
            tenant_id,
            object_id: claims.oid,
            email: claims.email,
            name: claims.name,
            preferred_username: claims.preferred_username,
            roles: claims.roles,
            groups: claims.groups,
            raw,
        })
    }

    fn issuer_allowed(
        &self,
        issuer: &str,
        tenant_id: Option<&str>,
        discovery: &OidcDiscoveryDocument,
    ) -> bool {
        let mut allowed = self.config.allowed_issuers.clone();
        if !discovery.issuer.is_empty() && !allowed.iter().any(|issuer| issuer == &discovery.issuer)
        {
            allowed.push(discovery.issuer.clone());
        }

        allowed
            .iter()
            .any(|allowed| issuer_pattern_matches(allowed, issuer, tenant_id))
    }

    fn allowed_algorithms(&self) -> AuthResult<Vec<Algorithm>> {
        self.config
            .allowed_id_token_algs
            .iter()
            .map(|alg| {
                Algorithm::from_str(alg).map_err(|_| {
                    AuthError::InvalidConfiguration(format!(
                        "unsupported OIDC ID token algorithm: {alg}"
                    ))
                })
            })
            .collect()
    }

    fn clock_skew_seconds(&self) -> AuthResult<u64> {
        u64::try_from(self.config.clock_skew.whole_seconds()).map_err(|_| {
            AuthError::InvalidConfiguration("OIDC clock_skew is too large".to_string())
        })
    }
}

#[derive(Clone)]
struct CachedJwks {
    jwks: JwkSet,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawOidcIdTokenClaims {
    iss: String,
    aud: OneOrMany,
    sub: String,
    exp: i64,
    nbf: i64,
    iat: i64,
    nonce: Option<String>,
    tid: Option<String>,
    oid: Option<String>,
    email: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

/// Generates a random PKCE verifier and S256 challenge.
pub fn generate_pkce_pair() -> PkcePair {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
    let code_challenge = pkce_s256_challenge(&code_verifier);
    PkcePair {
        code_verifier,
        code_challenge,
    }
}

/// Computes the PKCE S256 challenge for a verifier.
pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Generates a random OAuth state value.
pub fn generate_oauth_state() -> String {
    generate_urlsafe_secret()
}

/// Generates a random OIDC nonce value.
pub fn generate_oidc_nonce() -> String {
    generate_urlsafe_secret()
}

/// Hashes an OAuth state value for storage.
pub fn hash_oauth_state(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());
    encode_hex(digest)
}

/// Selects the stable external subject used for account linking.
///
/// Microsoft Entra work/school accounts prefer `tenant_id:object_id`. Generic
/// OIDC and Microsoft tokens without an object ID fall back to `issuer:subject`.
pub fn stable_external_subject(
    provider_kind: &OidcProviderKind,
    issuer: &str,
    subject: &str,
    tenant_id: Option<&str>,
    object_id: Option<&str>,
) -> String {
    match provider_kind {
        OidcProviderKind::MicrosoftEntra => {
            if let (Some(tenant_id), Some(object_id)) = (tenant_id, object_id) {
                return format!("{tenant_id}:{object_id}");
            }
            format!("{issuer}:{subject}")
        }
        OidcProviderKind::Generic => format!("{issuer}:{subject}"),
    }
}

fn validate_jwk_for_header(jwk: &Jwk, alg: Algorithm) -> AuthResult<()> {
    if let Some(public_key_use) = &jwk.common.public_key_use
        && public_key_use != &PublicKeyUse::Signature
    {
        return Err(AuthError::OidcTokenValidation(
            "JWK is not marked for signature verification".to_string(),
        ));
    }

    if let Some(key_operations) = &jwk.common.key_operations
        && !key_operations.iter().any(|op| op == &KeyOperations::Verify)
    {
        return Err(AuthError::OidcTokenValidation(
            "JWK is not marked for verify operations".to_string(),
        ));
    }

    if let Some(key_algorithm) = &jwk.common.key_algorithm {
        let key_alg = key_algorithm.to_string();
        let token_alg = format!("{alg:?}");
        if key_alg != token_alg {
            return Err(AuthError::OidcTokenValidation(
                "JWK alg does not match ID token header alg".to_string(),
            ));
        }
    }

    Ok(())
}

fn issuer_pattern_matches(pattern: &str, issuer: &str, tenant_id: Option<&str>) -> bool {
    if pattern == issuer {
        return true;
    }

    let Some(tenant_id) = tenant_id else {
        return false;
    };

    pattern
        .replace("{tenantid}", tenant_id)
        .replace("{tid}", tenant_id)
        == issuer
}

fn unix_timestamp_to_datetime(timestamp: i64) -> AuthResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|err| AuthError::OidcTokenValidation(err.to_string()))
}

fn generate_urlsafe_secret() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn append_query(base_url: &str, params: &[(&str, &str)]) -> String {
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let query = params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(key, QUERY_ENCODE_SET),
                utf8_percent_encode(value, QUERY_ENCODE_SET)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{base_url}{separator}{query}")
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}
