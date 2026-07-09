# Scope Matching

`agql-auth` has two layers:

- exact helpers (`has_scope`, `AuthUser::has_scope`) that keep existing exact
  behavior
- pluggable matchers used by GraphQL guards through `AuthRuntime`

The default matcher is [`ExactScopeMatch`](../src/scope_match.rs), so upgrading
does not change runtime authorization decisions unless the host explicitly
injects a different matcher.

## Exact Default

```rust
use agql_auth::{AuthUser, has_scope};

assert!(has_scope(&user.scopes, "orders.read"));
assert!(!has_scope(&user.scopes, "orders.*"));
assert!(user.has_scope("orders.read"));
```

Direct helper calls remain exact even when a request runtime uses a hierarchical
matcher. Use `has_scope_with` when application code needs the configured
matcher:

```rust
use agql_auth::{HierarchicalScopeMatch, ScopeMatch};

let matcher = HierarchicalScopeMatch::with_defaults();
assert!(user.has_scope_with(&matcher, "orders.items.read"));
```

## Hierarchical Matcher

`HierarchicalScopeMatch` is opt-in:

```rust
use agql_auth::{HierarchicalScopeMatch, HierarchicalScopeOptions};

let matcher = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
    separator: '.',
    wildcard: "*".to_string(),
    wildcard_matches_multi_segment: true,
    super_scopes: Vec::new(),
});
```

Defaults:

- `separator = '.'`
- `wildcard = "*"`
- `wildcard_matches_multi_segment = true`
- `super_scopes = []`

No hidden admin scope is configured by the crate.

## Normative Algorithm

For `matches(granted, required)`:

1. If `granted` is configured in `super_scopes`, allow.
2. If `granted == required`, allow.
3. If `granted` ends with the wildcard and multi-segment mode is enabled, strip
   the trailing wildcard and require `required.starts_with(prefix)`.
4. If `granted` ends with the wildcard and multi-segment mode is disabled, the
   trailing wildcard consumes exactly one remaining segment.
5. Otherwise split both strings on the separator. Segment counts must be equal,
   and each granted segment must equal the required segment or equal the
   wildcard.

Wildcards are interpreted only in the granted scope. The required scope is
treated literally.

## Golden Vectors

These vectors are part of the conformance suite:

| # | Granted | Required | Expected |
|---|---------|----------|----------|
| 1 | `a.b.c.d` | `a.b.c.d` | allow |
| 2 | `a.b.c.read` | `a.b.c.write` | deny |
| 3 | `a.b.*` | `a.b.c` | allow |
| 4 | `a.b.*` | `a.b.c.d` | allow |
| 5 | `a.b.*` | `a.bc.d` | deny |
| 6 | `a.b.*` | `a.b` | deny |
| 7 | `*` | `anything.at.all` | allow |
| 8 | `a.b*` | `a.bc` | allow |
| 9 | `a.*.d` | `a.c.d` | allow |
| 10 | `a.*.d` | `a.c.x.d` | deny |
| 11 | `a.*.d` | `a.d` | deny |
| 12 | `a.b.*.read` | `a.b.c.write` | deny |
| 13 | `a.b.*.read` | `a.b.c.read` | allow |
| 14 | `a.b.*` | `a.b.*` | allow |
| 15 | `a.b.*` | `a.b.*.read` | allow |
| 16 | `x.*` | `y.b.c` | deny |
| 17 | `a.b.c.read` | `a.*.c.read` | deny |
| 18 | `a.b.c.d` | `a.b.c.d.e` | deny |
| 19 | empty granted set | `a.b.c` | deny |
| 20 | `a.b.c.read` | `a.b.c.read.extra` | deny |

Rows 7 and 8 intentionally preserve legacy compatibility for the hierarchical
matcher. Hosts that do not want bare `*` or raw partial-prefix behavior should
avoid issuing those grants or provide a custom matcher.

## Super-Scopes

`super_scopes` are empty by default. If a host configures
`super_scopes = ["platform.admin"]`, then a principal holding `platform.admin`
satisfies every required scope through that matcher.

This is a behavioral opt-in. It also affects direct `has_scope_with` calls:

```rust
let matcher = HierarchicalScopeMatch::new(HierarchicalScopeOptions {
    super_scopes: vec!["platform.admin".to_string()],
    ..Default::default()
});

assert!(matcher.has_scope(&["platform.admin".to_string()], "orders.delete"));
```

## GraphQL Guards

`RequireScope`, `RequireAnyScope`, `RequireAllScopes`, and the
`Require*PrincipalScope` guards read `AuthRuntime` from request data and fall
back to exact matching when no runtime is present. `AuthService`,
`AccessTokenValidator`, and `CombinedAuth` inject runtime data on successful
authentication.
