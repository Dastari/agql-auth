use std::sync::Arc;

use async_graphql::{EmptyMutation, EmptySubscription, Object, Request, Schema};

use crate::prelude::*;

#[test]
fn hierarchical_matcher_satisfies_golden_vectors() {
    let matcher = HierarchicalScopeMatch::with_defaults();
    let vectors = [
        (1, "a.b.c.d", "a.b.c.d", true),
        (2, "a.b.c.read", "a.b.c.write", false),
        (3, "a.b.*", "a.b.c", true),
        (4, "a.b.*", "a.b.c.d", true),
        (5, "a.b.*", "a.bc.d", false),
        (6, "a.b.*", "a.b", false),
        // Bare "*" has no meaning unless allow_universal_wildcard is enabled.
        (7, "*", "anything.at.all", false),
        (8, "a.b*", "a.bc", true),
        (9, "a.*.d", "a.c.d", true),
        (10, "a.*.d", "a.c.x.d", false),
        (11, "a.*.d", "a.d", false),
        (12, "a.b.*.read", "a.b.c.write", false),
        (13, "a.b.*.read", "a.b.c.read", true),
        (14, "a.b.*", "a.b.*", true),
        (15, "a.b.*", "a.b.*.read", true),
        (16, "x.*", "y.b.c", false),
        (17, "a.b.c.read", "a.*.c.read", false),
        (18, "a.b.c.d", "a.b.c.d.e", false),
        (20, "a.b.c.read", "a.b.c.read.extra", false),
    ];

    for (id, granted, required, expected) in vectors {
        assert_eq!(
            matcher.matches(granted, required),
            expected,
            "golden matcher vector {id}"
        );
    }

    assert!(!matcher.has_scope(&[], "a.b.c"));
    assert!(matcher.has_scope(&["a.b.read".to_string(), "x.*".to_string()], "a.b.read"));
    assert!(matcher.has_scope(&["a.b.read".to_string(), "x.*".to_string()], "x.y.z"));
    assert!(!matcher.has_scope(&["platform.admin".to_string()], "a.b.c.read"));
}

#[test]
fn hierarchical_matcher_conforms_to_json_golden_file() {
    let raw = include_str!("../../testdata/scope_match_golden.json");
    let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
    for vector in doc["matcher_vectors"].as_array().unwrap() {
        let id = vector["id"].as_u64().unwrap();
        let mut options = HierarchicalScopeOptions::default();
        if let Some(opts) = vector.get("options") {
            if let Some(multi) = opts.get("wildcard_matches_multi_segment") {
                options.wildcard_matches_multi_segment = multi.as_bool().unwrap();
            }
            if let Some(universal) = opts.get("allow_universal_wildcard") {
                options.allow_universal_wildcard = universal.as_bool().unwrap();
            }
            if let Some(supers) = opts.get("super_scopes").and_then(|v| v.as_array()) {
                options.super_scopes = supers
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
            }
        }
        let matcher = HierarchicalScopeMatch::new(options);
        let granted = vector["granted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let required = vector["required"].as_str().unwrap();
        let expected = vector["expected"].as_bool().unwrap();
        assert_eq!(
            matcher.has_scope(&granted, required),
            expected,
            "json golden vector {id}"
        );
    }
}

#[test]
fn hierarchical_matcher_satisfies_guard_golden_vectors() {
    let matcher = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
        super_scopes: vec!["platform.admin".to_string()],
        ..Default::default()
    });
    let vectors = [
        (
            "G1",
            "any",
            vec!["a.b.read", "a.b.write"],
            vec!["a.b.read"],
            true,
        ),
        (
            "G2",
            "any",
            vec!["a.b.read", "a.b.write"],
            vec!["a.b.*"],
            true,
        ),
        (
            "G3",
            "any",
            vec!["a.b.read", "a.b.write"],
            vec!["z.q.r"],
            false,
        ),
        (
            "G4",
            "all",
            vec!["a.b.read", "a.b.write"],
            vec!["a.b.read", "a.b.write"],
            true,
        ),
        (
            "G5",
            "all",
            vec!["a.b.read", "a.b.write"],
            vec!["a.b.*"],
            true,
        ),
        (
            "G6",
            "all",
            vec!["a.b.read", "a.b.write"],
            vec!["a.b.read"],
            false,
        ),
        (
            "G7",
            "any",
            vec!["a.b.read", "a.b.write"],
            vec!["platform.admin"],
            true,
        ),
        (
            "G8",
            "all",
            vec!["a.b.read", "a.b.write"],
            vec!["platform.admin"],
            true,
        ),
        (
            "G9",
            "require",
            vec!["platform.admin"],
            vec!["a.admin.users.read"],
            false,
        ),
        ("G10", "any", vec!["a.b.read"], vec![], false),
    ];

    for (id, mode, required, granted, expected) in vectors {
        let granted = granted.into_iter().map(str::to_string).collect::<Vec<_>>();
        let actual = match mode {
            "any" => matcher.has_any_scope(&granted, &required),
            "all" | "require" => matcher.has_all_scopes(&granted, &required),
            _ => unreachable!("unknown guard mode"),
        };
        assert_eq!(actual, expected, "golden guard vector {id}");
    }

    assert!(matcher.has_scope(&["platform.admin".to_string()], "anything"));
}

#[test]
fn hierarchical_matcher_supports_appendix_b_options() {
    let multi = HierarchicalScopeMatch::with_defaults();
    let single = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
        wildcard_matches_multi_segment: false,
        ..Default::default()
    });

    assert!(multi.matches("orders.read", "orders.read"));
    assert!(!multi.matches("orders.read", "orders.write"));
    assert!(multi.matches("orders.*", "orders.read"));
    assert!(multi.matches("orders.*", "orders.items.read"));
    assert!(!single.matches("orders.*", "orders.items.read"));
    assert!(single.matches("orders.*", "orders.read"));
    assert!(multi.matches("orders.items.*", "orders.items.read"));
    assert!(!multi.matches("orders.*", "billing.read"));
    assert!(!multi.matches("orders.read", "orders.read.extra"));
    assert!(!multi.matches("*", "orders.read"));
    let universal = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
        allow_universal_wildcard: true,
        ..Default::default()
    });
    assert!(universal.matches("*", "orders.read"));

    let with_super = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
        super_scopes: vec!["platform.admin".to_string()],
        ..Default::default()
    });
    assert!(with_super.matches("platform.admin", "orders.delete"));
    assert!(!multi.matches("platform.admin", "orders.delete"));
}

#[tokio::test]
async fn graphql_guards_use_runtime_matcher_when_present() {
    let schema = Schema::build(MatcherQuery, EmptyMutation, EmptySubscription).finish();
    let user = AuthUser {
        user_id: "user-1".to_string(),
        session_id: uuid::Uuid::new_v4(),
        roles: Vec::new(),
        scopes: vec!["orders.*".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::Password),
        token_claims: Default::default(),
    };

    let exact_response = schema
        .execute(Request::new("{ guarded }").data(user.clone()))
        .await;
    assert_eq!(exact_response.errors.len(), 1);

    let hierarchical_response = schema
        .execute(
            Request::new("{ guarded }")
                .data(user)
                .data(AuthRuntime::new(Arc::new(
                    HierarchicalScopeMatch::with_defaults(),
                ))),
        )
        .await;
    assert!(
        hierarchical_response.errors.is_empty(),
        "{:?}",
        hierarchical_response.errors
    );
}

struct MatcherQuery;

#[Object]
impl MatcherQuery {
    #[graphql(guard = "RequireScope::new(\"orders.items.read\")")]
    async fn guarded(&self) -> bool {
        true
    }
}
