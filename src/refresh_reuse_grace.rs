//! Optional grace window for reuse of a just-rotated refresh token.
//!
//! See [`crate::AuthService::with_refresh_reuse_grace`] and
//! `docs/refresh-reuse-grace.md` for behavior, store requirements and cost.

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::StoredRefreshToken;

/// Largest window accepted by [`crate::AuthService::with_refresh_reuse_grace`].
pub const MAX_REFRESH_REUSE_GRACE: Duration = Duration::seconds(30);

/// One accepted reuse of a superseded refresh token.
///
/// It identifies records and never carries a raw token or a token hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshReuseGraceEvent {
    /// Session family of every token named here.
    pub session_family_id: Uuid,
    /// Local session ID.
    pub session_id: Uuid,
    /// Local user ID.
    pub user_id: String,
    /// Record of the superseded token that was presented.
    pub presented_token_id: Uuid,
    /// When the presented token was superseded.
    pub presented_revoked_at: OffsetDateTime,
    /// Record of the family's newest token, revoked by this reuse.
    pub superseded_token_id: Uuid,
    /// Record of the token issued by this reuse.
    pub replacement_token_id: Uuid,
    /// When this reuse was accepted.
    pub occurred_at: OffsetDateTime,
    /// Client IP address reported for this reuse.
    pub ip_address: Option<String>,
    /// Client user agent reported for this reuse.
    pub user_agent: Option<String>,
}

/// Receives accepted grace reuses, for host audit and alerting.
///
/// Ordinary rotation and refused reuse do not call it.
#[async_trait]
pub trait RefreshReuseGraceObserver: Send + Sync {
    /// Called once after the reuse has committed.
    ///
    /// It cannot refuse the reuse, because the replacement already exists.
    /// A crash or a cancelled request between the commit and this call loses
    /// the event, so it is not a durable record.
    async fn refresh_reuse_granted(&self, event: &RefreshReuseGraceEvent);
}

/// Whether `token` was superseded by rotation less than `window` ago.
///
/// A rotation is the only revocation that records a replacement. The window is
/// symmetric so that small clock differences between instances do not turn the
/// race this exists for into a sign-out, and a timestamp further in the future
/// than the window is refused rather than treated as recent.
pub(crate) fn superseded_within(
    token: &StoredRefreshToken,
    now: OffsetDateTime,
    window: Duration,
) -> bool {
    let Some(revoked_at) = token.revoked_at else {
        return false;
    };
    token.replaced_by_token_id.is_some()
        && !token.is_expired(now)
        && (now - revoked_at).abs() < window
}

/// Whether `newest` can be replaced on behalf of `presented`.
///
/// A store that returns anything else has broken its contract, so the reuse
/// fails closed instead of minting a token from inconsistent records.
pub(crate) fn can_replace_newest(
    presented: &StoredRefreshToken,
    newest: &StoredRefreshToken,
    now: OffsetDateTime,
) -> bool {
    newest.id != presented.id
        && !newest.is_revoked()
        && !newest.is_expired(now)
        && newest.session_family_id == presented.session_family_id
        && newest.session_id == presented.session_id
        && newest.user_id == presented.user_id
        && newest.grant_source == presented.grant_source
}
