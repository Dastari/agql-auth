//! Safe principal references and current-principal rehydration.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    AccessTokenGrantKind, AuthError, AuthPrincipal, AuthResult, AuthUser, ExactOperationBinding,
};

/// Maximum UTF-8 byte length of an authoritative session/security version.
pub const MAX_SESSION_VERSION_LENGTH: usize = 256;

/// Durable principal kind without any credential material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalReferenceKind {
    /// A local user session.
    UserSession,
    /// An opaque API token. The value describes the host-defined token kind.
    ApiToken {
        /// Host-defined principal kind such as `service` or `integration`.
        principal_kind: String,
    },
}

/// Serializable, non-secret reference to an authenticated principal.
///
/// This type intentionally omits bearer tokens, cookies, token hashes, roles,
/// and scopes. Long-lived work must resolve current authority through
/// [`CurrentPrincipalResolver`] rather than trusting a stored authorization
/// snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalReference {
    /// Principal kind.
    pub kind: PrincipalReferenceKind,
    /// Stable subject.
    pub subject: String,
    /// User session identifier when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// JWT ID or opaque API-token identifier, never the token itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Session-family identifier when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_family_id: Option<String>,
    /// Closed classification of the source access-token grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_kind: Option<AccessTokenGrantKind>,
    /// Authoritative session/security version when present on the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_version: Option<String>,
    /// Tenant binding when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Audience binding when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Resource type binding when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Resource identifier binding when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    /// Original actor subject for on-behalf-of work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_subject: Option<String>,
    /// Known credential expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<OffsetDateTime>,
    /// Safe correlation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Exact registered operation binding when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ExactOperationBinding>,
}

impl PrincipalReference {
    /// Returns whether a resolved principal retains the immutable identity and
    /// binding represented by this reference.
    ///
    /// Roles and scopes are deliberately excluded: callers must use the fresh
    /// values on the resolved principal.
    pub fn matches(&self, principal: &AuthPrincipal) -> bool {
        let current = principal.reference();
        match (&self.kind, &current.kind) {
            (PrincipalReferenceKind::UserSession, PrincipalReferenceKind::UserSession) => {
                if self.grant_kind == Some(AccessTokenGrantKind::SessionBoundDelegation) {
                    return self.subject == current.subject
                        && self.session_id == current.session_id
                        && self.session_family_id == current.session_family_id
                        && self.session_version == current.session_version
                        && self.tenant_id == current.tenant_id
                        && !matches!(
                            current.grant_kind,
                            Some(
                                AccessTokenGrantKind::Sessionless
                                    | AccessTokenGrantKind::SessionBoundDelegation
                            )
                        );
                }
                self.subject == current.subject
                    && self.session_id == current.session_id
                    && self.session_family_id == current.session_family_id
                    && !matches!(
                        self.grant_kind,
                        Some(
                            AccessTokenGrantKind::Sessionless
                                | AccessTokenGrantKind::SessionBoundDelegation
                        )
                    )
                    && !matches!(
                        current.grant_kind,
                        Some(
                            AccessTokenGrantKind::Sessionless
                                | AccessTokenGrantKind::SessionBoundDelegation
                        )
                    )
                    && self
                        .session_version
                        .as_ref()
                        .is_none_or(|version| current.session_version.as_ref() == Some(version))
                    && self.tenant_id == current.tenant_id
                    && self.resource_type == current.resource_type
                    && self.resource_id == current.resource_id
                    && self.actor_subject == current.actor_subject
                    && self.operation == current.operation
            }
            (
                PrincipalReferenceKind::ApiToken {
                    principal_kind: expected_kind,
                },
                PrincipalReferenceKind::ApiToken {
                    principal_kind: current_kind,
                },
            ) => {
                expected_kind == current_kind
                    && self.subject == current.subject
                    && self.token_id == current.token_id
                    && self.audience == current.audience
                    && self.resource_type == current.resource_type
                    && self.resource_id == current.resource_id
            }
            _ => false,
        }
    }
}

impl AuthPrincipal {
    /// Creates a durable, non-secret reference suitable for background work.
    pub fn reference(&self) -> PrincipalReference {
        match self {
            AuthPrincipal::User(user) => {
                let metadata = &user.token_claims;
                PrincipalReference {
                    kind: PrincipalReferenceKind::UserSession,
                    subject: user.user_id.clone(),
                    session_id: Some(user.session_id.to_string()),
                    token_id: metadata.jti.clone(),
                    session_family_id: metadata.session_family_id.clone(),
                    grant_kind: metadata.grant_kind,
                    session_version: metadata.session_version.clone(),
                    tenant_id: metadata.tenant_id.clone(),
                    audience: None,
                    resource_type: metadata.resource_type.clone(),
                    resource_id: metadata.resource_id.clone(),
                    actor_subject: metadata.actor.as_ref().map(|actor| actor.sub.clone()),
                    expires_at: metadata.expires_at,
                    correlation_id: metadata.correlation_id.clone(),
                    operation: metadata.operation.clone(),
                }
            }
            AuthPrincipal::ApiToken(token) => PrincipalReference {
                kind: PrincipalReferenceKind::ApiToken {
                    principal_kind: token.principal_kind.as_str().to_owned(),
                },
                subject: token.subject.clone(),
                session_id: None,
                token_id: Some(token.token_id.to_string()),
                session_family_id: None,
                grant_kind: None,
                session_version: None,
                tenant_id: None,
                audience: token.audience.clone(),
                resource_type: token.resource_type.clone(),
                resource_id: token.resource_id.clone(),
                actor_subject: None,
                expires_at: Some(token.expires_at),
                correlation_id: None,
                operation: None,
            },
        }
    }
}

/// Freshly rehydrated principal paired with the reference used to resolve it.
#[derive(Debug, Clone)]
pub struct ResolvedPrincipal {
    reference: PrincipalReference,
    principal: AuthPrincipal,
    resolved_at: OffsetDateTime,
}

impl ResolvedPrincipal {
    /// Creates a resolved principal after verifying immutable identity and
    /// resource bindings.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] when the host resolved a different
    /// principal or binding than the requested reference. For a
    /// session-bound delegation, token-specific actor/resource/operation
    /// bindings remain on the reference while the resolved principal is the
    /// underlying authoritative user session; subject, session, family,
    /// tenant, and session version must still match exactly.
    pub fn new(
        reference: PrincipalReference,
        principal: AuthPrincipal,
        resolved_at: OffsetDateTime,
    ) -> AuthResult<Self> {
        if !reference.matches(&principal) {
            return Err(AuthError::Forbidden);
        }

        Ok(Self {
            reference,
            principal,
            resolved_at,
        })
    }

    /// Returns the durable reference.
    pub fn reference(&self) -> &PrincipalReference {
        &self.reference
    }

    /// Returns the freshly resolved principal and its current authority.
    pub fn principal(&self) -> &AuthPrincipal {
        &self.principal
    }

    /// Returns when resolution completed.
    pub fn resolved_at(&self) -> OffsetDateTime {
        self.resolved_at
    }

    /// Consumes the wrapper and returns the principal.
    pub fn into_principal(self) -> AuthPrincipal {
        self.principal
    }
}

/// Host implementation that resolves current principal authority from a safe
/// durable reference.
#[async_trait]
pub trait CurrentPrincipalResolver: Send + Sync {
    /// Rehydrates current identity, roles, scopes, membership, assurance, and
    /// token/session status.
    ///
    /// Implementations must fail closed on store/status errors and construct
    /// the result with [`ResolvedPrincipal::new`].
    async fn resolve(&self, reference: &PrincipalReference) -> AuthResult<ResolvedPrincipal>;
}

/// Opaque result of a read-only authoritative active-session verification.
///
/// Hosts construct this only inside [`VerifiedActiveUserSessionResolver`]
/// after reading the active-session record without touching idle-expiry or
/// last-active state. The issuance API verifies the result is for the exact
/// requested subject/session and never accepts an `AuthUser` directly as
/// verification proof.
#[derive(Clone)]
pub struct VerifiedActiveUserSession {
    reference: PrincipalReference,
    user: AuthUser,
    session_version: String,
    absolute_expires_at: OffsetDateTime,
    idle_expires_at: Option<OffsetDateTime>,
    verified_at: OffsetDateTime,
}

impl VerifiedActiveUserSession {
    /// Creates a verified snapshot from one authoritative active-session read.
    ///
    /// Returns an error when identity, session, family, tenant, version, or
    /// lifetime does not match the requested reference. Revoked sessions must
    /// be rejected by the resolver before constructing this value.
    pub fn from_authoritative_record(
        reference: PrincipalReference,
        mut user: AuthUser,
        session_version: impl Into<String>,
        absolute_expires_at: OffsetDateTime,
        idle_expires_at: Option<OffsetDateTime>,
        verified_at: OffsetDateTime,
    ) -> AuthResult<Self> {
        if reference.kind != PrincipalReferenceKind::UserSession {
            return Err(AuthError::Forbidden);
        }
        let session_version = session_version.into();
        if session_version.trim().is_empty() || session_version.len() > MAX_SESSION_VERSION_LENGTH {
            return Err(AuthError::InvalidConfiguration(
                "authoritative session version is invalid".to_string(),
            ));
        }
        if reference
            .session_version
            .as_ref()
            .is_some_and(|expected| expected != &session_version)
        {
            return Err(AuthError::Forbidden);
        }
        let current = AuthPrincipal::User(user.clone()).reference();
        if reference.subject != current.subject
            || reference.session_id != current.session_id
            || reference.session_family_id != current.session_family_id
            || reference.tenant_id != current.tenant_id
        {
            return Err(AuthError::Forbidden);
        }
        let effective_expires_at = idle_expires_at
            .map(|idle| idle.min(absolute_expires_at))
            .unwrap_or(absolute_expires_at);
        if effective_expires_at <= verified_at {
            return Err(AuthError::AccessTokenExpired);
        }

        user.token_claims.session_version = Some(session_version.clone());
        Ok(Self {
            reference,
            user,
            session_version,
            absolute_expires_at,
            idle_expires_at,
            verified_at,
        })
    }

    /// Returns the exact reference verified by the authoritative read.
    pub fn reference(&self) -> &PrincipalReference {
        &self.reference
    }

    /// Returns the current authoritative user/session projection.
    pub fn user(&self) -> &AuthUser {
        &self.user
    }

    /// Returns the authoritative session/security version.
    pub fn session_version(&self) -> &str {
        &self.session_version
    }

    /// Returns the absolute session expiry.
    pub fn absolute_expires_at(&self) -> OffsetDateTime {
        self.absolute_expires_at
    }

    /// Returns the idle expiry, when the host session uses one.
    pub fn idle_expires_at(&self) -> Option<OffsetDateTime> {
        self.idle_expires_at
    }

    /// Returns when the authoritative read completed.
    pub fn verified_at(&self) -> OffsetDateTime {
        self.verified_at
    }

    pub(crate) fn effective_expires_at(&self) -> OffsetDateTime {
        self.idle_expires_at
            .map(|idle| idle.min(self.absolute_expires_at))
            .unwrap_or(self.absolute_expires_at)
    }
}

impl std::fmt::Debug for VerifiedActiveUserSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedActiveUserSession")
            .field("reference", &self.reference)
            .field("user", &self.user)
            .field("session_version", &self.session_version)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("verified_at", &self.verified_at)
            .finish()
    }
}

/// Read-only host adapter used by delegated issuance to re-read the current
/// active session inside [`crate::AuthService`].
#[async_trait]
pub trait VerifiedActiveUserSessionResolver: Send + Sync {
    /// Re-reads one authoritative session without extending idle expiry or
    /// updating interactive last-active state.
    ///
    /// Implementations must reject revoked/expired records and return a value
    /// created with [`VerifiedActiveUserSession::from_authoritative_record`].
    async fn resolve_active_user_session(
        &self,
        reference: &PrincipalReference,
    ) -> AuthResult<VerifiedActiveUserSession>;
}
