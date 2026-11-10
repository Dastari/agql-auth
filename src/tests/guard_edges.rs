use std::sync::Arc;

use async_graphql::{EmptyMutation, EmptySubscription, Object, Request, Schema};

use crate::prelude::*;

fn user(roles: &[&str], scopes: &[&str], token_claims: AccessTokenMetadata) -> AuthUser {
    AuthUser {
        user_id: "user-1".to_string(),
        session_id: uuid::Uuid::new_v4(),
        roles: roles.iter().map(|role| role.to_string()).collect(),
        scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        session: SessionContext::for_auth_method(AuthMethod::Password),
        token_claims,
    }
}

fn request(query: &str, user: AuthUser) -> Request {
    Request::new(query)
        .data(AuthPrincipal::User(user.clone()))
        .data(user)
}

struct EmptyListQuery;

#[Object]
impl EmptyListQuery {
    #[graphql(guard = "RequireAllRoles::new(Vec::<String>::new())")]
    async fn all_roles(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllScopes::new(Vec::<String>::new())")]
    async fn all_scopes(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllPrincipalScopes::new(Vec::<String>::new())")]
    async fn all_principal_scopes(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyRole::new(Vec::<String>::new())")]
    async fn any_role(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyScope::new(Vec::<String>::new())")]
    async fn any_scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyPrincipalScope::new(Vec::<String>::new())")]
    async fn any_principal_scope(&self) -> bool {
        true
    }
}

// an empty requirement list is a configuration mistake and must deny.
#[tokio::test]
async fn guards_with_empty_requirement_lists_deny() {
    let schema = Schema::build(EmptyListQuery, EmptyMutation, EmptySubscription).finish();
    let user = user(&["Admin"], &["orders.read"], AccessTokenMetadata::default());
    for field in [
        "allRoles",
        "allScopes",
        "allPrincipalScopes",
        "anyRole",
        "anyScope",
        "anyPrincipalScope",
    ] {
        let response = schema
            .execute(request(&format!("{{ {field} }}"), user.clone()))
            .await;
        assert_eq!(
            response.errors.len(),
            1,
            "{field} passed with an empty list"
        );
        assert_eq!(
            response.errors[0].extensions.as_ref().unwrap().get("code"),
            Some(&async_graphql::Value::from("FORBIDDEN")),
            "{field}"
        );
    }
}

#[test]
fn all_scope_helpers_deny_an_empty_requirement_list() {
    let granted = vec!["orders.read".to_string()];
    let none: [&str; 0] = [];
    assert!(!has_all_scopes(&granted, &none));
    assert!(!ExactScopeMatch.has_all_scopes(&granted, &none));
    assert!(!HierarchicalScopeMatch::with_defaults().has_all_scopes(&granted, &none));
    assert!(!ScopeMatcher::exact().has_all_scopes(&granted, &none));
    let user = user(&[], &["orders.read"], AccessTokenMetadata::default());
    assert!(!user.has_all_scopes(&none));
    assert!(!user.has_all_scopes_with(&ExactScopeMatch, &none));
    let principal = AuthPrincipal::User(user);
    assert!(!principal.has_all_scopes(&none));
    assert!(!principal.has_all_scopes_with(&ExactScopeMatch, &none));
}

// a trailing wildcard matches whole segments, never a raw prefix.
#[test]
fn trailing_wildcard_matches_whole_segments_only() {
    let multi = HierarchicalScopeMatch::with_defaults();
    let single = HierarchicalScopeMatch::new(
        HierarchicalScopeOptions::default().with_wildcard_matches_multi_segment(false),
    )
    .unwrap();
    for matcher in [&multi, &single] {
        assert!(!matcher.matches("tenant.1*", "tenant.10.read"));
        assert!(!matcher.matches("tenant.1*", "tenant.1"));
        assert!(!matcher.matches("tenant.1*", "tenant.10"));
        assert!(!matcher.matches("a.b*", "a.bc"));
        assert!(matcher.matches("a.b*", "a.b*"));
        assert!(matcher.matches("tenant.1.*", "tenant.1.read"));
        assert!(!matcher.matches("tenant.1.*", "tenant.10.read"));
        assert!(!matcher.matches("tenant.1.*", "tenant.1"));
    }
    assert!(multi.matches("tenant.1.*", "tenant.1.orders.read"));
    assert!(!single.matches("tenant.1.*", "tenant.1.orders.read"));

    // Exact-only patterns follow the same segment rule.
    let guarded = HierarchicalScopeMatch::new(
        HierarchicalScopeOptions::default()
            .with_super_scopes(["platform.admin"])
            .with_exact_only_scope_patterns(["payments.1*"]),
    )
    .unwrap();
    assert!(guarded.matches("platform.admin", "payments.10.release"));
    assert!(!guarded.matches("platform.admin", "payments.1*"));
}

struct DefaultGuardQuery;

#[Object]
impl DefaultGuardQuery {
    #[graphql(guard = "RequireAuth::new()")]
    async fn auth(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireScope::new(\"orders.read\")")]
    async fn scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyScope::new([\"orders.read\"])")]
    async fn any_scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllScopes::new([\"orders.read\"])")]
    async fn all_scopes(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyRole::new([\"Editor\"])")]
    async fn any_role(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllRoles::new([\"Editor\"])")]
    async fn all_roles(&self) -> bool {
        true
    }

    #[graphql(guard = "RequirePrincipal::new()")]
    async fn principal(&self) -> bool {
        true
    }

    #[graphql(guard = "RequirePrincipalScope::new(\"orders.read\")")]
    async fn principal_scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAnyPrincipalScope::new([\"orders.read\"])")]
    async fn any_principal_scope(&self) -> bool {
        true
    }

    #[graphql(guard = "RequireAllPrincipalScopes::new([\"orders.read\"])")]
    async fn all_principal_scopes(&self) -> bool {
        true
    }
}

const DEFAULT_GUARD_FIELDS: [&str; 10] = [
    "auth",
    "scope",
    "anyScope",
    "allScopes",
    "anyRole",
    "allRoles",
    "principal",
    "principalScope",
    "anyPrincipalScope",
    "allPrincipalScopes",
];

fn delegated_claims() -> Vec<(&'static str, AccessTokenMetadata)> {
    vec![
        (
            "session-bound delegation",
            AccessTokenMetadata {
                grant_kind: Some(AccessTokenGrantKind::SessionBoundDelegation),
                ..AccessTokenMetadata::default()
            },
        ),
        (
            "actor on a user session",
            AccessTokenMetadata {
                grant_kind: Some(AccessTokenGrantKind::UserSession),
                actor: Some(ActorIdentity {
                    sub: "support-agent".to_string(),
                    amr: Vec::new(),
                }),
                ..AccessTokenMetadata::default()
            },
        ),
        (
            "actor on a sessionless grant",
            AccessTokenMetadata {
                grant_kind: Some(AccessTokenGrantKind::Sessionless),
                actor: Some(ActorIdentity {
                    sub: "automation".to_string(),
                    amr: Vec::new(),
                }),
                ..AccessTokenMetadata::default()
            },
        ),
    ]
}

// delegated and actor tokens are not ordinary bearers.
#[tokio::test]
async fn default_guards_refuse_delegated_and_actor_tokens() {
    let schema = Schema::build(DefaultGuardQuery, EmptyMutation, EmptySubscription).finish();
    for (label, claims) in delegated_claims() {
        let user = user(&["Editor"], &["orders.read"], claims);
        for field in DEFAULT_GUARD_FIELDS {
            let response = schema
                .execute(request(&format!("{{ {field} }}"), user.clone()))
                .await;
            assert_eq!(response.errors.len(), 1, "{label}: {field} passed");
        }
    }

    // Ordinary user sessions, sessionless grants and legacy tokens still pass.
    for grant_kind in [
        None,
        Some(AccessTokenGrantKind::UserSession),
        Some(AccessTokenGrantKind::Sessionless),
    ] {
        let user = user(
            &["Editor"],
            &["orders.read"],
            AccessTokenMetadata {
                grant_kind,
                ..AccessTokenMetadata::default()
            },
        );
        for field in DEFAULT_GUARD_FIELDS {
            let response = schema
                .execute(
                    request(&format!("{{ {field} }}"), user.clone())
                        .data(AuthRuntime::new(Arc::new(ExactScopeMatch))),
                )
                .await;
            assert!(response.errors.is_empty(), "{grant_kind:?}: {field}");
        }
    }
}
