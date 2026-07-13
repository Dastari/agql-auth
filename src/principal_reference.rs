//! Safe principal references and current-principal rehydration.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{AuthError, AuthPrincipal, AuthResult};

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
                self.subject == current.subject
                    && self.session_id == current.session_id
                    && self.session_family_id == current.session_family_id
                    && self.tenant_id == current.tenant_id
                    && self.resource_type == current.resource_type
                    && self.resource_id == current.resource_id
                    && self.actor_subject == current.actor_subject
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
                    tenant_id: metadata.tenant_id.clone(),
                    audience: None,
                    resource_type: metadata.resource_type.clone(),
                    resource_id: metadata.resource_id.clone(),
                    actor_subject: metadata.actor.as_ref().map(|actor| actor.sub.clone()),
                    expires_at: metadata.expires_at,
                    correlation_id: metadata.correlation_id.clone(),
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
                tenant_id: None,
                audience: token.audience.clone(),
                resource_type: token.resource_type.clone(),
                resource_id: token.resource_id.clone(),
                actor_subject: None,
                expires_at: Some(token.expires_at),
                correlation_id: None,
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
    /// principal or binding than the requested reference.
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
