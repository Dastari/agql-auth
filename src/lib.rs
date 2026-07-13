//! Database-agnostic authentication primitives and `async-graphql` helpers.
//!
//! `agql-auth` gives host applications reusable authentication building blocks
//! without taking over the host's database, HTTP framework, cookie policy, user
//! provisioning, or business authorization model.
//!
//! ## Core Pieces
//!
//! - [`AuthService`] issues and validates local sessions.
//! - [`AccessTokenValidator`] validates access tokens in resource servers
//!   without stores.
//! - [`AuthConfig`] configures issuer, audience, TTLs, and JWT signing mode.
//! - [`UserStore`] and [`RefreshTokenStore`] let the host provide persistence.
//! - [`ApiTokenService`] issues and authenticates opaque service-to-service
//!   tokens through [`ApiTokenStore`].
//! - [`AuthUser`] is injected into `async-graphql` request data after
//!   authentication.
//! - [`AuthPrincipal`] represents either a user session or an API-token
//!   principal for handlers that accept both.
//! - [`CombinedAuth`] injects either a user JWT or API token into one
//!   [`AuthPrincipal`].
//! - [`ScopeMatch`] supports exact default matching and opt-in hierarchical
//!   matching through [`AuthRuntime`].
//! - [`ChannelIdentity`] carries host-verified channel data for channel guards.
//! - [`RequireAuth`], [`RequireAnyRole`], [`RequireScope`], and related guards
//!   protect resolvers.
//!
//! ## Local Sessions
//!
//! Access tokens are short-lived JWTs containing the local user ID, session ID,
//! roles, scopes, and [`SessionContext`]. Refresh tokens are opaque, hashed
//! before storage, and rotated on refresh. A replayed refresh token revokes the
//! token family through the host's [`RefreshTokenStore`].
//! [`SessionAssurance`] carries host-accepted authentication time, AMR, ACR,
//! and MFA acceptance unchanged through refresh rotation. Resource servers can
//! enforce freshness with [`RecentMfaPolicy`] and an injected [`Clock`].
//!
//! ## API And Service Tokens
//!
//! [`ApiTokenService`] provides long-lived opaque credentials for
//! server-to-server calls. Tokens are generated with a non-JWT-like prefix,
//! returned once, stored only as hashes through [`ApiTokenStore`], and
//! authenticated to [`ApiTokenPrincipal`]. Use [`AuthPrincipal`] and the
//! `RequirePrincipal*` guards when a resolver can accept either a user session
//! or an API token.
//!
//! Use [`AuthService::issue_access_token_only`] for short-lived user-shaped JWT
//! grants that should not create refresh-token rows.
//!
//! ## JWT Signing And JWKS
//!
//! [`AuthConfig::new`] preserves the legacy HS256 behavior. New deployments that
//! need routers or other services to validate local `agql-auth` tokens should
//! use [`AuthConfig::with_rs256_pem`]. RS256 tokens include the configured
//! `kid`, validate locally with public key material, and can be exposed through
//! [`AuthService::jwks`].
//!
//! ## OIDC And Microsoft Entra ID
//!
//! [`OidcProvider`] owns OIDC discovery, authorization URL generation, token
//! exchange, JWKS caching, ID-token validation, state and nonce validation, and
//! the handoff into local [`AuthService`] session issuance.
//!
//! Microsoft Entra ID setup starts with [`MicrosoftEntraConfig`]. Host
//! applications provide an [`OAuthStateStore`] with atomic one-time state
//! consumption, an [`ExternalIdentityStore`] for stable provider links, an
//! [`ExternalUserProvisioner`] for account creation/linking/rejection, and an
//! optional [`ClaimsMapper`] for local roles and scopes.
//!
//! Microsoft access tokens are not used as local authorization tokens. After a
//! successful OIDC callback, `agql-auth` returns an [`OidcLoginResult`] whose
//! `auth` field is a normal local [`AuthPayload`].
//!
//! ## More Documentation
//!
//! The repository README links focused guides for storage traits, authorization,
//! JWT signing and JWKS, Microsoft Entra OIDC, recovery flows, and MFA
//! primitives.

mod api_tokens;
mod assurance;
mod channel;
mod claims;
mod clock;
mod combined;
mod config;
mod decision;
mod errors;
mod grant;
mod graphql;
mod guards;
mod keys;
mod models;
mod oidc;
pub mod prelude;
mod principal_reference;
mod purpose_grant;
mod scope_match;
mod scopes;
mod service;
mod session;
mod stores;
mod token_decode;
mod token_status;
mod util;
mod validator;

#[cfg(test)]
mod tests;

pub use api_tokens::{ApiTokenService, DEFAULT_API_TOKEN_PREFIX};
pub use assurance::{
    AssuranceDenial, AssuranceDenialCode, AssuranceInputError, AssuranceMatchMode,
    MAX_ASSURANCE_CONTEXT_LENGTH, MAX_ASSURANCE_METHOD_LENGTH, MAX_ASSURANCE_METHODS,
    MfaAcceptance, RecentMfaPolicy, RefreshableTokenMetadata, SessionAssurance,
    StepUpAuthentication,
};
pub use channel::ChannelIdentity;
pub use claims::{
    AccessTokenMetadata, ActorIdentity, ClaimRequirementError, ClaimRequirements,
    ConfirmationClaims,
};
pub use clock::{Clock, FixedClock, SystemClock};
pub use combined::{AccessTokenAuth, CombinedAuth};
pub use config::{
    AuthConfig, AuthRateLimitConfig, AuthRateLimitPolicy, ClientMetadata, JwtSigningConfig,
    MicrosoftEntraConfig, MicrosoftEntraTenant, OidcProviderConfig, OidcProviderKind,
};
pub use decision::{
    AuthorizationDecision, AuthorizationDecisionHook, AuthorizationInvocation,
    AuthorizationOutcome, AuthorizationReasonCode, LinkedAuthorizationDecision,
    NoopAuthorizationDecisionHook, emit_decision,
};
pub use errors::AuthError;
pub use grant::{AccessTokenOnlyGrant, AccessTokenOnlyRequest};
pub use graphql::{
    GraphqlRefreshCookieConfig, GraphqlRefreshCookieDirective, GraphqlTopLevelField,
    auth_runtime_from_ctx_opt, auth_user_from_ctx, auth_user_from_ctx_opt,
    channel_identity_from_ctx, channel_identity_from_ctx_opt, graphql_refresh_cookie_directive,
    principal_from_ctx, principal_from_ctx_opt, scope_matcher_from_ctx,
};
pub use guards::{
    RequireAllPrincipalScopes, RequireAllRoles, RequireAllScopes, RequireAnyPrincipalScope,
    RequireAnyRole, RequireAnyScope, RequireAuth, RequireChannelScheme, RequirePrincipal,
    RequirePrincipalScope, RequireScope,
};
pub use keys::{
    AccessTokenKeyResolver, KeyRefreshPolicy, ResolvedKey, RotatingJwksKeySet, StaleKeyPolicy,
    StaticHs256Key, StaticJwksKeySet, StaticRs256Key,
};
pub use models::{
    ApiTokenIssueRequest, ApiTokenPrincipal, ApiTokenPrincipalKind, ApiTokenRevocationReason,
    AuthPayload, AuthPrincipal, AuthRateLimitBucket, AuthRateLimitFlow, AuthRateLimitKey,
    AuthRateLimitState, AuthUser, ExternalIdentity, IssuedApiToken, IssuedLoginChallenge,
    IssuedPurposeToken, LoginChallengeOptions, MicrosoftEntraClaims, OAuthLoginState,
    OidcAuthorizationRequest, OidcCallbackInput, OidcLoginResult, OidcTokenResponse,
    PasswordResetToken, PurposeTokenIssueRequest, PurposeTokenValidation,
    RefreshTokenRevocationReason, StoredApiToken, StoredLoginChallenge, StoredRefreshToken,
    StoredUser, TotpOptions, TotpProvisioning, TotpSecret, ValidatedOidcClaims,
    VerifiedLoginChallenge, VerifiedPasswordResetToken, VerifiedPurposeToken,
};
pub use oidc::{
    ClaimsMapper, ExternalUserProvisioner, MappedClaims, MicrosoftClaimsMapper, NoopClaimsMapper,
    OidcCallbackOutcome, OidcDiscoveryDocument, OidcHttpClient, OidcProvider, PkcePair,
    ProvisionedExternalUser, generate_oauth_state, generate_oidc_nonce, generate_pkce_pair,
    hash_oauth_state, pkce_s256_challenge, stable_external_subject,
};
pub use principal_reference::{
    CurrentPrincipalResolver, PrincipalReference, PrincipalReferenceKind, ResolvedPrincipal,
};
pub use purpose_grant::{PurposeBoundGrantReference, PurposeGrantStatus};
pub use scope_match::{
    AuthRuntime, ExactScopeMatch, HierarchicalScopeMatch, HierarchicalScopeOptions, ScopeMatch,
    ScopeMatcher,
};
pub use scopes::{has_all_scopes, has_any_scope, has_scope};
pub use service::AuthService;
pub use session::{ActiveScope, AuthMethod, MfaFactor, MfaState, SessionContext};
pub use stores::{
    ApiTokenStore, AuthRateLimitStore, ExternalIdentityStore, LoginChallengeStore,
    MemoryAuthRateLimitStore, OAuthStateStore, OAuthTokenStore, PasswordResetTokenStore,
    RefreshTokenStore, TotpReplayStore, UserStore,
};
pub use token_decode::{BearerParseMode, PurposePolicy};
pub use token_status::{
    AlwaysActiveTokenStatus, ReauthorizationPolicy, StatusCheckFailureMode, TokenStatus,
    TokenStatusChecker, TokenStatusRequest,
};
pub use validator::{AccessTokenValidator, AccessTokenValidatorBuilder};

pub type AuthResult<T> = Result<T, AuthError>;
