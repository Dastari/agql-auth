use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};

use crate::prelude::*;

struct ChannelQuery;

#[Object]
impl ChannelQuery {
    #[graphql(guard = "RequireChannelScheme::new(\"mtls\")")]
    async fn channel_subject(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        Ok(channel_identity_from_ctx(ctx)?.subject.clone())
    }
}

#[tokio::test]
async fn require_channel_scheme_allows_matching_scheme() {
    let schema = Schema::build(ChannelQuery, EmptyMutation, EmptySubscription).finish();
    let request = Request::new("{ channelSubject }")
        .data(ChannelIdentity::new("mtls", "device-1").with_claim("fingerprint", "sha256:abc"));

    let response = schema.execute(request).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap()["channelSubject"],
        "device-1"
    );
}

#[tokio::test]
async fn require_channel_scheme_denies_missing_or_mismatched_scheme() {
    let schema = Schema::build(ChannelQuery, EmptyMutation, EmptySubscription).finish();

    let missing = schema.execute(Request::new("{ channelSubject }")).await;
    assert_eq!(missing.errors.len(), 1);

    let mismatch = schema
        .execute(Request::new("{ channelSubject }").data(ChannelIdentity::new("hmac", "device-1")))
        .await;
    assert_eq!(mismatch.errors.len(), 1);
}
