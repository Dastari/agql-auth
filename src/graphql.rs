use async_graphql::{Context, ErrorExtensions, Result as GraphqlResult};
use serde_json::Value as JsonValue;

use std::sync::Arc;

use crate::{
    ApiTokenPrincipal, AuthError, AuthPrincipal, AuthRuntime, AuthUser, ChannelIdentity,
    ExactScopeMatch, ScopeMatch,
};

/// Reads the authenticated user from an `async-graphql` context.
///
/// Returns an unauthenticated GraphQL error when no user has been injected.
pub fn auth_user_from_ctx<'a>(ctx: &'a Context<'_>) -> GraphqlResult<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
        .ok_or(AuthError::Unauthenticated.extend())
}

/// Reads the authenticated user from an `async-graphql` context, if present.
pub fn auth_user_from_ctx_opt<'a>(ctx: &'a Context<'_>) -> Option<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
}

/// Reads a generic authenticated principal from an `async-graphql` context.
///
/// This accepts either an explicitly injected [`AuthPrincipal`], an existing
/// user-session [`AuthUser`], or an API-token [`ApiTokenPrincipal`].
pub fn principal_from_ctx(ctx: &Context<'_>) -> GraphqlResult<AuthPrincipal> {
    principal_from_ctx_opt(ctx).ok_or(AuthError::Unauthenticated.extend())
}

/// Reads a generic authenticated principal from an `async-graphql` context, if present.
pub fn principal_from_ctx_opt(ctx: &Context<'_>) -> Option<AuthPrincipal> {
    if let Some(principal) = ctx.data_opt::<AuthPrincipal>() {
        return Some(principal.clone());
    }

    if let Some(user) = ctx.data_opt::<AuthUser>() {
        return Some(AuthPrincipal::User(user.clone()));
    }

    ctx.data_opt::<ApiTokenPrincipal>()
        .map(|principal| AuthPrincipal::ApiToken(principal.clone()))
}

/// Reads auth runtime data from an `async-graphql` context, if present.
pub fn auth_runtime_from_ctx_opt<'a>(ctx: &'a Context<'_>) -> Option<&'a AuthRuntime> {
    ctx.data_opt::<AuthRuntime>()
}

/// Reads the configured scope matcher from context or returns exact matching.
pub fn scope_matcher_from_ctx(ctx: &Context<'_>) -> Arc<dyn ScopeMatch> {
    auth_runtime_from_ctx_opt(ctx)
        .map(|runtime| runtime.scope_matcher.clone())
        .unwrap_or_else(|| Arc::new(ExactScopeMatch))
}

/// Reads the host-verified channel identity from context.
pub fn channel_identity_from_ctx<'a>(ctx: &'a Context<'_>) -> GraphqlResult<&'a ChannelIdentity> {
    ctx.data_opt::<ChannelIdentity>()
        .ok_or(AuthError::Unauthenticated.extend())
}

/// Reads the host-verified channel identity from context, if present.
pub fn channel_identity_from_ctx_opt<'a>(ctx: &'a Context<'_>) -> Option<&'a ChannelIdentity> {
    ctx.data_opt::<ChannelIdentity>()
}

/// Top-level GraphQL field selected by a request.
///
/// `schema_field` is the real schema field name. `response_key` is the response
/// object key, which may be an alias. Passing response keys lets the helper
/// sanitize only the auth payload fields that produced session data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlTopLevelField {
    /// Real schema field name selected by the operation.
    pub schema_field: String,
    /// Response object key, usually the alias when one was used.
    pub response_key: Option<String>,
}

impl GraphqlTopLevelField {
    /// Creates a selected field without response-key information.
    pub fn new(schema_field: impl Into<String>) -> Self {
        Self {
            schema_field: schema_field.into(),
            response_key: None,
        }
    }

    /// Creates a selected field with its response key.
    pub fn with_response_key(
        schema_field: impl Into<String>,
        response_key: impl Into<String>,
    ) -> Self {
        Self {
            schema_field: schema_field.into(),
            response_key: Some(response_key.into()),
        }
    }
}

/// Configures refresh-token extraction from GraphQL auth payloads.
#[derive(Debug, Clone)]
pub struct GraphqlRefreshCookieConfig {
    /// Schema fields whose successful payloads contain a session refresh token.
    pub issuing_fields: Vec<String>,
    /// Schema fields whose successful payloads should clear the refresh cookie.
    pub clearing_fields: Vec<String>,
    /// Field name containing the session payload.
    pub session_field: String,
    /// Field name containing the raw refresh token.
    pub refresh_token_field: String,
    /// Field name containing the refresh-token expiry timestamp.
    pub refresh_token_expires_at_field: String,
    /// Whether to remove raw refresh tokens from the GraphQL response.
    ///
    /// On by default. Turn it off only for clients that must read the token
    /// from the body; the response then keeps every token it contains.
    pub sanitize_response: bool,
}

impl GraphqlRefreshCookieConfig {
    /// Creates a config with conventional session field names.
    pub fn new<I, C>(issuing_fields: I, clearing_fields: C) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
        C: IntoIterator,
        C::Item: Into<String>,
    {
        Self {
            issuing_fields: issuing_fields.into_iter().map(Into::into).collect(),
            clearing_fields: clearing_fields.into_iter().map(Into::into).collect(),
            session_field: "session".to_string(),
            refresh_token_field: "refreshToken".to_string(),
            refresh_token_expires_at_field: "refreshTokenExpiresAt".to_string(),
            sanitize_response: true,
        }
    }
}

/// Refresh-cookie transport action derived from a GraphQL response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphqlRefreshCookieDirective {
    /// Set or rotate the refresh cookie using this raw token and expiry.
    Set {
        /// Raw refresh token to place in the cookie.
        refresh_token: String,
        /// Refresh-token expiry timestamp from the GraphQL payload.
        refresh_token_expires_at: String,
    },
    /// Clear the refresh cookie.
    Clear,
}

/// Extracts a refresh-cookie directive from a GraphQL response and, unless
/// [`GraphqlRefreshCookieConfig::sanitize_response`] is off, removes every raw
/// refresh token from the response body.
///
/// This helper uses selected schema field names rather than GraphQL operation
/// names. When a selected field includes `response_key`, only that response
/// entry is inspected. Without response keys, every top-level entry is
/// inspected once an issuing schema field was selected.
///
/// `Set` is returned for the first issuing entry whose `session` object holds
/// both a non-empty refresh token and its expiry, also when other fields of the
/// response failed. `Clear` is returned only for a response without errors.
///
/// Whenever an issuing field was selected, sanitizing runs on the whole body,
/// whatever its shape: in the issuing entries, at any depth, every value under
/// the refresh-token field name and every string shaped like a token issued by
/// [`crate::AuthService`] is blanked, and every copy of a token found anywhere
/// in the response is blanked. Client aliases therefore cannot carry the token
/// past it. To keep tokens out of the body by construction, do not expose the
/// refresh token in the schema and set the cookie from the resolver instead,
/// for example with `async_graphql::Context::insert_http_header`.
pub fn graphql_refresh_cookie_directive(
    response: &mut async_graphql::Response,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) -> Option<GraphqlRefreshCookieDirective> {
    if selected_fields_match(selected_fields, &config.issuing_fields) {
        let data = response.data.clone().into_json();
        let directive = data
            .as_ref()
            .ok()
            .and_then(|data| find_refresh_cookie_set_directive(data, selected_fields, config));
        if config.sanitize_response {
            // Fail closed: a body that cannot be inspected is not returned.
            response.data = data
                .ok()
                .and_then(|mut data| {
                    sanitize_refresh_tokens(&mut data, selected_fields, config);
                    async_graphql::Value::from_json(data).ok()
                })
                .unwrap_or(async_graphql::Value::Null);
        }
        if directive.is_some() {
            return directive;
        }
    }

    (response.errors.is_empty() && selected_fields_match(selected_fields, &config.clearing_fields))
        .then_some(GraphqlRefreshCookieDirective::Clear)
}

fn selected_fields_match(selected_fields: &[GraphqlTopLevelField], field_names: &[String]) -> bool {
    selected_fields
        .iter()
        .any(|field| field_names.iter().any(|name| name == &field.schema_field))
}

/// The raw refresh token at the configured `session.refreshToken` path.
fn canonical_refresh_token<'a>(
    entry: &'a JsonValue,
    config: &GraphqlRefreshCookieConfig,
) -> Option<&'a str> {
    entry
        .get(&config.session_field)?
        .get(&config.refresh_token_field)?
        .as_str()
        .filter(|token| !token.trim().is_empty())
}

fn find_refresh_cookie_set_directive(
    data: &JsonValue,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) -> Option<GraphqlRefreshCookieDirective> {
    candidate_response_entries(data, selected_fields, &config.issuing_fields).find_map(|entry| {
        let refresh_token = canonical_refresh_token(entry, config)?;
        let refresh_token_expires_at = entry
            .get(&config.session_field)?
            .get(&config.refresh_token_expires_at_field)?
            .as_str()?;
        Some(GraphqlRefreshCookieDirective::Set {
            refresh_token: refresh_token.to_string(),
            refresh_token_expires_at: refresh_token_expires_at.to_string(),
        })
    })
}

fn sanitize_refresh_tokens(
    data: &mut JsonValue,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) {
    let found: Vec<String> =
        candidate_response_entries(data, selected_fields, &config.issuing_fields)
            .filter_map(|entry| canonical_refresh_token(entry, config))
            .map(str::to_owned)
            .collect();

    let Some(object) = data.as_object_mut() else {
        return;
    };
    let response_keys = selected_response_keys(selected_fields, &config.issuing_fields);
    for (key, entry) in object.iter_mut() {
        if response_keys.is_empty() || response_keys.contains(&key.as_str()) {
            sanitize_issuing_entry(entry, config);
        }
    }
    if !found.is_empty() {
        blank_copies(data, &found);
    }
}

/// Blanks token-carrying values at any depth of an issuing entry.
fn sanitize_issuing_entry(value: &mut JsonValue, config: &GraphqlRefreshCookieConfig) {
    match value {
        JsonValue::Object(object) => {
            for (key, child) in object.iter_mut() {
                if key == &config.refresh_token_field && !child.is_null() {
                    *child = JsonValue::String(String::new());
                } else {
                    sanitize_issuing_entry(child, config);
                }
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                sanitize_issuing_entry(item, config);
            }
        }
        JsonValue::String(text) if crate::util::is_opaque_token_shape(text) => text.clear(),
        _ => {}
    }
}

/// Blanks every string equal to a found token, anywhere in the body.
fn blank_copies(value: &mut JsonValue, tokens: &[String]) {
    match value {
        JsonValue::Object(object) => {
            for child in object.values_mut() {
                blank_copies(child, tokens);
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                blank_copies(item, tokens);
            }
        }
        JsonValue::String(text) if tokens.iter().any(|token| token == text) => text.clear(),
        _ => {}
    }
}

fn candidate_response_entries<'a>(
    data: &'a JsonValue,
    selected_fields: &'a [GraphqlTopLevelField],
    field_names: &[String],
) -> Box<dyn Iterator<Item = &'a JsonValue> + 'a> {
    let Some(object) = data.as_object() else {
        return Box::new(std::iter::empty());
    };

    let response_keys = selected_response_keys(selected_fields, field_names);
    if response_keys.is_empty() {
        Box::new(object.values())
    } else {
        Box::new(response_keys.into_iter().filter_map(|key| object.get(key)))
    }
}

fn selected_response_keys<'a>(
    selected_fields: &'a [GraphqlTopLevelField],
    field_names: &[String],
) -> Vec<&'a str> {
    selected_fields
        .iter()
        .filter(|field| field_names.iter().any(|name| name == &field.schema_field))
        .filter_map(|field| field.response_key.as_deref())
        .collect()
}
