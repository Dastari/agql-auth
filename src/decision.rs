//! Structured authorization decision hooks for safe auditing.

use time::OffsetDateTime;

use crate::models::AuthPrincipal;

/// Safe invocation metadata that links authorization and application audits.
///
/// The authenticated principal remains the actor. This metadata describes the
/// mechanism and causal operation without granting any additional authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationInvocation {
    /// Host-defined mechanism such as `graphql_transport` or `internal_service`.
    pub mechanism: String,
    /// Causal operation identifier.
    pub causation_id: Option<String>,
    /// Delegation/grant reference when applicable.
    pub delegation_ref: Option<String>,
}

impl AuthorizationInvocation {
    /// Creates invocation metadata for a mechanism.
    pub fn new(mechanism: impl Into<String>) -> Self {
        Self {
            mechanism: mechanism.into(),
            causation_id: None,
            delegation_ref: None,
        }
    }

    /// Sets the causal operation identifier.
    pub fn with_causation_id(mut self, causation_id: impl Into<String>) -> Self {
        self.causation_id = Some(causation_id.into());
        self
    }

    /// Sets the delegation/grant reference.
    pub fn with_delegation_ref(mut self, delegation_ref: impl Into<String>) -> Self {
        self.delegation_ref = Some(delegation_ref.into());
        self
    }
}

/// An authorization decision linked to safe invocation metadata.
///
/// This wrapper keeps [`AuthorizationDecision`] source-compatible for hosts
/// that construct it directly. The invocation metadata provides correlation
/// only and does not change the actor, outcome, or authority of the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedAuthorizationDecision {
    /// The original authorization decision.
    pub decision: AuthorizationDecision,
    /// Safe invocation and causation metadata.
    pub invocation: AuthorizationInvocation,
}

/// Stable authorization decision outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    /// Requirement was satisfied.
    Allow,
    /// Requirement was denied.
    Deny,
}

/// Stable reason codes for authorization decisions.
///
/// These codes are safe for logs and audits. They never include raw tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationReasonCode {
    /// Principal was authenticated and requirement passed.
    Allowed,
    /// No authenticated principal was present.
    Unauthenticated,
    /// Role requirement failed.
    MissingRole,
    /// Scope requirement failed.
    MissingScope,
    /// Channel scheme requirement failed.
    MissingChannel,
    /// Resource binding requirement failed.
    ResourceMismatch,
    /// Host policy denied the request.
    PolicyDenied,
}

/// Safe structured authorization decision metadata.
///
/// Intentionally omits complete scope arrays, JWTs, API tokens, cookies,
/// authorization headers, OIDC bodies, and secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    /// Principal kind label (`user` or `api_token`).
    pub principal_kind: &'static str,
    /// Stable principal subject reference (never a raw token).
    pub principal_ref: String,
    /// Tenant reference when present.
    pub tenant_ref: Option<String>,
    /// Requested requirement description (for example a scope name).
    pub requirement: String,
    /// Optional resource type.
    pub resource_type: Option<String>,
    /// Optional resource reference.
    pub resource_ref: Option<String>,
    /// Allow/deny outcome.
    pub outcome: AuthorizationOutcome,
    /// Stable reason code.
    pub reason_code: AuthorizationReasonCode,
    /// Token/session reference (`jti` or session id), never a raw token.
    pub token_or_session_ref: Option<String>,
    /// Correlation/audit identifier when present.
    pub correlation_id: Option<String>,
    /// Decision timestamp.
    pub timestamp: OffsetDateTime,
}

impl AuthorizationDecision {
    /// Builds a decision snapshot from a principal and requirement.
    pub fn from_principal(
        principal: &AuthPrincipal,
        requirement: impl Into<String>,
        outcome: AuthorizationOutcome,
        reason_code: AuthorizationReasonCode,
        timestamp: OffsetDateTime,
    ) -> Self {
        let (principal_kind, principal_ref, token_or_session_ref) = match principal {
            AuthPrincipal::User(user) => (
                "user",
                user.user_id.clone(),
                Some(user.session_id.to_string()),
            ),
            AuthPrincipal::ApiToken(token) => (
                "api_token",
                token.subject.clone(),
                Some(token.token_id.to_string()),
            ),
        };

        Self {
            principal_kind,
            principal_ref,
            tenant_ref: None,
            requirement: requirement.into(),
            resource_type: principal.resource_type().map(str::to_string),
            resource_ref: principal.resource_id().map(str::to_string),
            outcome,
            reason_code,
            token_or_session_ref,
            correlation_id: None,
            timestamp,
        }
    }

    /// Links invocation metadata without changing actor, outcome, or authority.
    pub fn with_invocation(
        self,
        invocation: AuthorizationInvocation,
    ) -> LinkedAuthorizationDecision {
        LinkedAuthorizationDecision {
            decision: self,
            invocation,
        }
    }
}

/// Observability hook for authorization decisions.
///
/// Implementations may log or export decisions. They must not influence the
/// allow/deny outcome of guards.
pub trait AuthorizationDecisionHook: Send + Sync {
    /// Receives a completed decision.
    fn on_decision(&self, decision: &AuthorizationDecision);
}

/// No-op decision hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuthorizationDecisionHook;

impl AuthorizationDecisionHook for NoopAuthorizationDecisionHook {
    fn on_decision(&self, _decision: &AuthorizationDecision) {}
}

/// Records a decision without ever flipping deny to allow.
pub fn emit_decision(
    hook: Option<&dyn AuthorizationDecisionHook>,
    decision: &AuthorizationDecision,
) {
    if let Some(hook) = hook {
        hook.on_decision(decision);
    }
}
