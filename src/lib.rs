//! Database-agnostic authentication primitives and `async-graphql` helpers.
//!
//! The crate is designed around a few principles:
//!
//! - short-lived JWT access tokens
//! - rotated opaque refresh tokens
//! - database-agnostic storage via traits
//! - thin integration points for `async-graphql` HTTP requests and subscriptions
//! - minimal assumptions about the consuming application's ORM or transport setup

mod config;
mod errors;
mod graphql;
mod guards;
mod models;
pub mod prelude;
mod scopes;
mod service;
mod session;
mod stores;
mod util;

#[cfg(test)]
mod tests;

pub use config::{AuthConfig, ClientMetadata};
pub use errors::AuthError;
pub use graphql::{auth_user_from_ctx, auth_user_from_ctx_opt};
pub use guards::{RequireAllRoles, RequireAnyRole, RequireAuth};
pub use models::{
    AuthPayload, AuthUser, IssuedLoginChallenge, LoginChallengeOptions, PasswordResetToken,
    RefreshTokenRevocationReason, StoredLoginChallenge, StoredRefreshToken, StoredUser,
    TotpOptions, TotpProvisioning, TotpSecret, VerifiedLoginChallenge, VerifiedPasswordResetToken,
};
pub use scopes::{has_all_scopes, has_any_scope, has_scope};
pub use service::AuthService;
pub use session::{ActiveScope, AuthMethod, MfaMethod, MfaState, SessionContext};
pub use stores::{LoginChallengeStore, PasswordResetTokenStore, RefreshTokenStore, UserStore};

pub type AuthResult<T> = Result<T, AuthError>;
