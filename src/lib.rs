//! Database-agnostic authentication primitives and `async-graphql` helpers.
//!
//! The crate is designed around a few principles:
//!
//! - short-lived JWT access tokens
//! - rotated opaque refresh tokens
//! - configurable HS256 or RS256 local JWT signing
//! - JWKS export for asymmetric local token validation by routers
//! - OpenID Connect authorization-code + PKCE login primitives
//! - Microsoft Entra ID provider configuration and ID-token validation
//! - database-agnostic storage via traits
//! - thin integration points for `async-graphql` HTTP requests and subscriptions
//! - minimal assumptions about the consuming application's ORM or transport setup
//!
//! ## OIDC and Microsoft Entra ID
//!
//! `OidcProvider` owns provider discovery, authorization URL generation, token
//! exchange, JWKS caching, ID-token validation, and the handoff into local
//! `AuthService` session issuance. Host applications keep ownership of HTTP
//! transport, redirect handlers, database schemas, provisioning policy, and
//! provider token persistence.
//!
//! For Microsoft Entra ID, start from `MicrosoftEntraConfig`, implement
//! `OAuthStateStore` with atomic one-time state consumption, implement
//! `ExternalIdentityStore` for stable provider links, and provide an
//! `ExternalUserProvisioner` to create, link, or reject local users. After a
//! successful callback, `login_with_callback` returns a local `AuthPayload` with
//! normal `agql-auth` access and refresh tokens. Microsoft access tokens are not
//! used as local authorization tokens.
//!
//! ## Local JWT Signing
//!
//! `AuthConfig::new(secret)` preserves legacy HS256 behavior. For deployments
//! where a router or another service needs to validate local `agql-auth` access
//! tokens without sharing a symmetric secret, use `AuthConfig::with_rs256_pem`.
//! RS256 tokens include the configured `kid`, validate locally with the public
//! key, and can be exposed through `AuthService::jwks()`.

mod config;
mod errors;
mod graphql;
mod guards;
mod models;
mod oidc;
pub mod prelude;
mod scopes;
mod service;
mod session;
mod stores;
mod util;

#[cfg(test)]
mod tests;

pub use config::{
    AuthConfig, ClientMetadata, JwtSigningConfig, MicrosoftEntraConfig, MicrosoftEntraTenant,
    OidcProviderConfig, OidcProviderKind,
};
pub use errors::AuthError;
pub use graphql::{auth_user_from_ctx, auth_user_from_ctx_opt};
pub use guards::{
    RequireAllRoles, RequireAllScopes, RequireAnyRole, RequireAnyScope, RequireAuth, RequireScope,
};
pub use models::{
    AuthPayload, AuthUser, ExternalIdentity, IssuedLoginChallenge, LoginChallengeOptions,
    MicrosoftEntraClaims, OAuthLoginState, OidcAuthorizationRequest, OidcCallbackInput,
    OidcLoginResult, OidcTokenResponse, PasswordResetToken, RefreshTokenRevocationReason,
    StoredLoginChallenge, StoredRefreshToken, StoredUser, TotpOptions, TotpProvisioning,
    TotpSecret, ValidatedOidcClaims, VerifiedLoginChallenge, VerifiedPasswordResetToken,
};
pub use oidc::{
    ClaimsMapper, ExternalUserProvisioner, MappedClaims, MicrosoftClaimsMapper, NoopClaimsMapper,
    OidcCallbackOutcome, OidcDiscoveryDocument, OidcHttpClient, OidcProvider, PkcePair,
    ProvisionedExternalUser, generate_oauth_state, generate_oidc_nonce, generate_pkce_pair,
    hash_oauth_state, pkce_s256_challenge, stable_external_subject,
};
pub use scopes::{has_all_scopes, has_any_scope, has_scope};
pub use service::AuthService;
pub use session::{ActiveScope, AuthMethod, MfaMethod, MfaState, SessionContext};
pub use stores::{
    ExternalIdentityStore, LoginChallengeStore, OAuthStateStore, OAuthTokenStore,
    PasswordResetTokenStore, RefreshTokenStore, UserStore,
};

pub type AuthResult<T> = Result<T, AuthError>;
