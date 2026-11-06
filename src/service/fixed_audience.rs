use std::fmt;
use std::sync::{Arc, Weak};

use jsonwebtoken::Algorithm;
use serde_json::Value as JsonValue;

use super::AuthService;
use crate::AuthResult;
use crate::errors::AuthError;
use crate::grant::{
    AccessTokenOnlyGrant, SessionBoundAccessTokenOnlyRequest, SessionBoundDelegationBinding,
};
use crate::models::AuthUser;
use crate::principal_reference::ResolvedPrincipal;
use crate::stores::{RefreshTokenStore, UserStore};

const MAX_FIXED_AUDIENCE_LENGTH: usize = 1024;

/// Restricted session-bound delegation issuer for one startup-selected audience.
///
/// Create it with [`AuthService::into_shared_with_fixed_audience_delegation`].
/// It is a view of its owner, not a second service: it has no keys, policy,
/// stores, abuse state, or clocks of its own, and only the JWT `aud` differs
/// from [`AuthService::issue_session_bound_access_token_only`]. Every call runs
/// the owner's existing preparation and second authoritative read. Both reads
/// also require a current, enabled parent user in the owner's [`UserStore`].
///
/// It holds a weak reference and never extends the owner's lifetime. Once every
/// [`Arc`] to the owner is gone, including when the host retires it to change
/// keys or policy, each method fails closed with
/// [`AuthError::AuthServiceUnavailable`]. Build a new owner and facade together.
///
/// The audience cannot be changed through the facade or by a request:
///
/// ```compile_fail
/// # fn f<U, R>(mut facade: agql_auth::FixedAudienceDelegation<U, R>) {
/// facade.audience = "another-receiver".into();
/// # }
/// ```
///
/// ```compile_fail
/// # fn f<U: agql_auth::UserStore + 'static, R: agql_auth::RefreshTokenStore + 'static>(
/// #     facade: agql_auth::FixedAudienceDelegation<U, R>,
/// # ) {
/// let _ = facade.with_audience("another-receiver");
/// # }
/// ```
///
/// ```compile_fail
/// # fn f(request: agql_auth::SessionBoundAccessTokenOnlyRequest) {
/// let _ = request.with_audience("another-receiver");
/// # }
/// ```
pub struct FixedAudienceDelegation<U, R> {
    owner: Weak<AuthService<U, R>>,
    audience: Arc<str>,
}

impl<U, R> Clone for FixedAudienceDelegation<U, R> {
    fn clone(&self) -> Self {
        Self {
            owner: self.owner.clone(),
            audience: self.audience.clone(),
        }
    }
}

impl<U, R> fmt::Debug for FixedAudienceDelegation<U, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedAudienceDelegation")
            .field("audience", &self.audience)
            .field("owner_live", &(self.owner.strong_count() > 0))
            .finish()
    }
}

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Shares this fully configured owner and creates its restricted
    /// fixed-audience delegation facade.
    ///
    /// Call this once from trusted startup code in place of `Arc::new`. Taking
    /// the service by value is the audience policy: code sharing an
    /// `Arc<AuthService>` with other holders cannot select an audience, so give
    /// issuance callers the facade and never a value they can influence. A sole
    /// holder could unwrap the `Arc`, which retires the owner and its facade.
    /// [`AuthService::issue_purpose_token`] refuses the reserved audience. Keep
    /// the returned `Arc` for the service's lifetime; the facade fails closed
    /// without it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfiguration`] when the audience is empty,
    /// over 1024 bytes, padded with whitespace, contains control characters, or
    /// matches the owner's normal audience ignoring ASCII case. Also refuses an
    /// owner without an active-session resolver, and any owner not signing with
    /// RS256: a receiver verifying an HS256 token would hold the secret that
    /// signs normal-audience tokens, so the audience would not confine it.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use agql_auth::*;
    /// # async fn example<U, R, S>(
    /// #     config: AuthConfig, users: Arc<U>, refresh_tokens: Arc<R>, sessions: Arc<S>,
    /// #     resolved: ResolvedPrincipal, binding: SessionBoundDelegationBinding,
    /// # ) -> AuthResult<()>
    /// # where
    /// #     U: UserStore + 'static,
    /// #     R: RefreshTokenStore + 'static,
    /// #     S: VerifiedActiveUserSessionResolver + 'static,
    /// # {
    /// // Trusted startup: the audience comes from deployment configuration.
    /// let (auth, receiver) = AuthService::new(config, users, refresh_tokens)?
    ///     .with_active_user_session_resolver(sessions)
    ///     .into_shared_with_fixed_audience_delegation("private-receiver")?;
    ///
    /// // Issuance: callers hold `receiver` and cannot choose the audience.
    /// let request = receiver
    ///     .prepare_session_bound_access_token_only(
    ///         &resolved,
    ///         vec!["Editor".into()],
    ///         vec!["records.read".into()],
    ///         binding,
    ///     )
    ///     .await?;
    /// let grant = receiver.issue_session_bound_access_token_only(request).await?;
    /// # drop((auth, grant));
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_shared_with_fixed_audience_delegation(
        mut self,
        audience: impl Into<String>,
    ) -> AuthResult<(Arc<Self>, FixedAudienceDelegation<U, R>)> {
        let audience = audience.into();
        if audience.is_empty()
            || audience.len() > MAX_FIXED_AUDIENCE_LENGTH
            || audience.trim() != audience
            || audience.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidConfiguration(
                "fixed delegation audience is invalid".to_string(),
            ));
        }
        if audience.eq_ignore_ascii_case(&self.config.audience) {
            return Err(AuthError::InvalidConfiguration(
                "fixed delegation audience must differ from the normal audience".to_string(),
            ));
        }
        if self.signing_algorithm != Algorithm::RS256 {
            return Err(AuthError::InvalidConfiguration(
                "fixed-audience delegation requires an RS256 owner".to_string(),
            ));
        }
        if self.active_user_session_resolver.is_none() {
            return Err(AuthError::InvalidConfiguration(
                "session-bound delegation requires an active-user-session resolver".to_string(),
            ));
        }

        self.fixed_delegation_audience = Some(audience.clone());
        let owner = Arc::new(self);
        let facade = FixedAudienceDelegation {
            owner: Arc::downgrade(&owner),
            audience: audience.into(),
        };
        Ok((owner, facade))
    }
}

impl<U, R> FixedAudienceDelegation<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Returns the audience selected at startup.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Runs the owner's [`AuthService::prepare_session_bound_access_token_only`]
    /// and binds the opaque request to this facade's audience.
    ///
    /// The bound request is accepted only by a facade for the same audience; a
    /// request prepared by the owner or for another audience is refused.
    pub async fn prepare_session_bound_access_token_only(
        &self,
        resolved: &ResolvedPrincipal,
        roles: Vec<String>,
        scopes: Vec<String>,
        binding: SessionBoundDelegationBinding,
    ) -> AuthResult<SessionBoundAccessTokenOnlyRequest> {
        let owner = self.owner()?;
        let mut request = owner
            .prepare_session_bound_access_token_only(resolved, roles, scopes, binding)
            .await?;
        owner
            .require_enabled_delegation_parent(&request.reference.subject)
            .await?;
        request.fixed_audience = Some(self.audience.to_string());
        Ok(request)
    }

    /// Issues a delegated token for this audience through the owner's existing
    /// session-bound path.
    ///
    /// The owner re-reads the authoritative session, current grant, and parent
    /// user, and applies the same TTL, delegation ceiling, and session caps. No
    /// refresh token, store row, session family, or idle extension is created.
    pub async fn issue_session_bound_access_token_only(
        &self,
        request: SessionBoundAccessTokenOnlyRequest,
    ) -> AuthResult<AccessTokenOnlyGrant> {
        let owner = self.owner()?;
        if request.fixed_audience.as_deref() != Some(&*self.audience) {
            return Err(AuthError::Forbidden);
        }
        owner
            .issue_session_bound_access_token_only_for_audience(request, &self.audience)
            .await
    }

    /// Validates a delegated token for this audience with the owner's key.
    ///
    /// Only fully bound session-bound delegation tokens are accepted. Like every
    /// JWT validation this is signature and claim proof only: the receiver must
    /// still run its current-session/status check and enforce the bindings.
    pub fn authenticate_access_token(&self, token: &str) -> AuthResult<AuthUser> {
        self.owner()?
            .authenticate_fixed_audience_access_token(token, &self.audience)
    }

    /// Returns the owner's public JWKS document.
    pub fn jwks(&self) -> AuthResult<JsonValue> {
        self.owner()?.jwks()
    }

    fn owner(&self) -> AuthResult<Arc<AuthService<U, R>>> {
        self.owner
            .upgrade()
            .ok_or(AuthError::AuthServiceUnavailable)
    }

    #[cfg(test)]
    pub(crate) fn live_owner(&self) -> Option<Arc<AuthService<U, R>>> {
        self.owner.upgrade()
    }
}
