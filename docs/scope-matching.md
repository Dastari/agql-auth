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

let matcher = HierarchicalScopeMatch::new(HierarchicalScopeOptions::default())?;
```

Defaults:

- `separator = '.'`
- `wildcard = "*"`
- `wildcard_matches_multi_segment = true`
- `allow_universal_wildcard = false`
- `super_scopes = []`
- `exact_only_scopes = []`
- `exact_only_scope_patterns = []`

No hidden admin scope is configured by the crate. Scope comparison is
**case-sensitive**.

`HierarchicalScopeOptions` is non-exhaustive. Start from `Default` and use its
`with_*` methods instead of a struct literal so future options remain a
compatible addition.

## Normative Algorithm

For `matches(granted, required)`:

1. If `required` is configured in `exact_only_scopes`, or is selected by a
   configured `exact_only_scope_patterns` entry under the same wildcard rules,
   allow only when `granted == required` and stop.
2. If `granted` is configured in `super_scopes`, allow.
3. If `granted == required`, allow.
4. If `granted` equals the bare wildcard, allow only when
   `allow_universal_wildcard` is true.
5. If `granted` ends with the wildcard and multi-segment mode is enabled, strip
   the trailing wildcard and require `required.starts_with(prefix)`.
6. If `granted` ends with the wildcard and multi-segment mode is disabled, the
   trailing wildcard consumes exactly one remaining segment.
7. Otherwise split both strings on the separator. Segment counts must be equal,
   and each granted segment must equal the required segment or equal the
   wildcard (middle wildcards are whole segments only).

Wildcards are interpreted only in the granted scope. The required scope is
treated literally. Leading wildcards and partial middle globs are not given
special product-specific meaning beyond the rules above.

## Golden Vectors

Language-neutral JSON vectors live at
[`testdata/scope_match_golden.json`](../testdata/scope_match_golden.json) so
non-Rust routers can implement identical behavior.

Summary:

| # | Granted | Required | Expected |
|---|---------|----------|----------|
| 1 | `a.b.c.d` | `a.b.c.d` | allow |
| 2 | `a.b.c.read` | `a.b.c.write` | deny |
| 3 | `a.b.*` | `a.b.c` | allow |
| 4 | `a.b.*` | `a.b.c.d` | allow (multi-segment) |
| 7 | `*` | `anything.at.all` | deny by default |
| 30 | `*` | `orders.read` | allow when `allow_universal_wildcard` |
| 25 | `orders.*` | `orders.items.read` | deny when single-segment mode |
| 29 | `platform.admin` | `orders.delete` | allow only as configured super-scope |
| 35 | `platform.admin` | `payments.account.42.read` | allow when an exact-only pattern does not match |
| 36 | `*` | `payments.credentials.release` | deny when exact-only, even with universal wildcard enabled |

## Super-Scopes

`super_scopes` are empty by default. If a host configures
`super_scopes = ["platform.admin"]`, then a principal holding `platform.admin`
satisfies every required scope through that matcher.

This is a behavioral opt-in. It also affects direct `has_scope_with` calls:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default().with_super_scopes(["platform.admin"]),
)?;

assert!(matcher.has_scope(&["platform.admin".to_string()], "orders.delete"));
```

## Exact-Only Scopes

`exact_only_scopes` lets a host declare requirements that blanket authority or
wildcard grants must never satisfy. The crate supplies no built-in values. A
consumer can configure a sensitive operation while retaining ordinary
hierarchical behavior elsewhere:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["platform.admin"])
        .with_exact_only_scopes(["payments.credentials.release"]),
)?;

assert!(!matcher.matches("platform.admin", "payments.credentials.release"));
assert!(!matcher.matches("payments.*", "payments.credentials.release"));
assert!(matcher.matches(
    "payments.credentials.release",
    "payments.credentials.release",
));
```

Membership is an exact, case-sensitive comparison against the required scope.
Hosts remain responsible for supplying and maintaining the set.

Resource-qualified families can be selected without enumerating identifiers:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["platform.admin"])
        .with_exact_only_scope_patterns([
            "payments.account.*.credentials.release",
        ]),
)?;

assert!(!matcher.matches(
    "platform.admin",
    "payments.account.42.credentials.release",
));
```

Pattern selection uses the configured separator, wildcard, multi-segment, and
universal-wildcard options. Pattern values select which requirements are
exact-only; they never become grants.

Validation rejects an exact-only pattern equal to the configured bare
wildcard. Every other wildcard-bearing exact-only pattern is accepted with a
[`HierarchicalScopeValidationWarning`](../src/scope_match.rs), because it can
make an entire requirement subtree exact-only. Configuration loaders should
surface `matcher.validation_warnings()` rather than hiding those diagnostics.

## GraphQL Guards

`RequireScope`, `RequireAnyScope`, `RequireAllScopes`, and the
`Require*PrincipalScope` guards read `AuthRuntime` from request data and fall
back to exact matching when no runtime is present. `AuthService`,
`AccessTokenValidator`, and `CombinedAuth` inject runtime data on successful
authentication.
