use async_graphql::{Context, ErrorExtensions, Result as GraphqlResult};
use serde_json::Value as JsonValue;

use crate::{ApiTokenPrincipal, AuthError, AuthPrincipal, AuthUser};

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
    /// Whether to blank the refresh token in the GraphQL response.
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

/// Extracts a refresh-cookie directive from a successful GraphQL response.
///
/// This helper uses selected schema field names rather than GraphQL operation
/// names. When a selected field includes `response_key`, only that response
/// entry is inspected and sanitized. Without response keys, the helper scans
/// top-level response entries after confirming an issuing schema field was
/// selected.
pub fn graphql_refresh_cookie_directive(
    response: &mut async_graphql::Response,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) -> Option<GraphqlRefreshCookieDirective> {
    if !response.errors.is_empty() {
        return None;
    }

    if selected_fields_match(selected_fields, &config.issuing_fields) {
        let mut data = response.data.clone().into_json().ok()?;
        let directive = find_refresh_cookie_set_directive(&data, selected_fields, config);
        if directive.is_some() && config.sanitize_response {
            sanitize_refresh_token_fields(&mut data, selected_fields, config);
            if let Ok(next_value) = async_graphql::Value::from_json(data) {
                response.data = next_value;
            }
        }
        if directive.is_some() {
            return directive;
        }
    }

    selected_fields_match(selected_fields, &config.clearing_fields)
        .then_some(GraphqlRefreshCookieDirective::Clear)
}

fn selected_fields_match(selected_fields: &[GraphqlTopLevelField], field_names: &[String]) -> bool {
    selected_fields
        .iter()
        .any(|field| field_names.iter().any(|name| name == &field.schema_field))
}

fn find_refresh_cookie_set_directive(
    data: &JsonValue,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) -> Option<GraphqlRefreshCookieDirective> {
    for entry in candidate_response_entries(data, selected_fields, &config.issuing_fields) {
        let session = entry.get(&config.session_field)?;
        let refresh_token = session.get(&config.refresh_token_field)?.as_str()?;
        let refresh_token_expires_at = session
            .get(&config.refresh_token_expires_at_field)?
            .as_str()?;
        if refresh_token.trim().is_empty() {
            continue;
        }
        return Some(GraphqlRefreshCookieDirective::Set {
            refresh_token: refresh_token.to_string(),
            refresh_token_expires_at: refresh_token_expires_at.to_string(),
        });
    }

    None
}

fn sanitize_refresh_token_fields(
    data: &mut JsonValue,
    selected_fields: &[GraphqlTopLevelField],
    config: &GraphqlRefreshCookieConfig,
) {
    let Some(object) = data.as_object_mut() else {
        return;
    };

    let response_keys = selected_response_keys(selected_fields, &config.issuing_fields);
    if response_keys.is_empty() {
        for entry in object.values_mut() {
            sanitize_refresh_token_entry(entry, config);
        }
    } else {
        for key in response_keys {
            if let Some(entry) = object.get_mut(key) {
                sanitize_refresh_token_entry(entry, config);
            }
        }
    }
}

fn sanitize_refresh_token_entry(entry: &mut JsonValue, config: &GraphqlRefreshCookieConfig) {
    if let Some(refresh_token) = entry
        .get_mut(&config.session_field)
        .and_then(|session| session.get_mut(&config.refresh_token_field))
    {
        *refresh_token = JsonValue::String(String::new());
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
