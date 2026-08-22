# Role-to-scope expansion

`agql-auth` access tokens carry application roles and scopes. A host that
grants reusable authorization roles can keep tokens compact by carrying their
IDs in the distinct `authorization_roles` claim plus exceptional direct scopes,
then expanding only those IDs at each resource server.

The crate provides a provider-neutral, bounded contract for that expansion:

```rust
use agql_auth::{
    RoleScopeCatalogue, RoleScopeDefinition, RoleScopeExpansionProvider,
    RoleScopeGrant, StaticRoleScopeExpansion, effective_scopes,
};

let catalogue = RoleScopeCatalogue::new(
    "revision-7",
    [
        RoleScopeDefinition::new("inventory.read"),
        RoleScopeDefinition::new("inventory.write").exact_only(),
    ],
    [RoleScopeGrant::new(
        "inventory-operator",
        "Inventory operator",
        ["inventory.read", "inventory.write"],
    )],
);
let provider = StaticRoleScopeExpansion::new(&catalogue)?;
let expanded = provider.expand_roles(&["inventory-operator".to_owned()])?;
let effective = effective_scopes(["profile.read"], &expanded);
assert_eq!(
    effective,
    ["inventory.read", "inventory.write", "profile.read"]
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`StaticRoleScopeExpansion` accepts only a validated catalogue, sorts and
deduplicates output, and returns `UnknownRole` for an identifier absent from the
snapshot. Hosts that retrieve catalogues remotely implement
`RoleScopeExpansionProvider` over their own verified cache, refresh immediately
on that error, and return `Unavailable` when no signature-verified snapshot is
usable. This avoids silently dropping inherited scopes without putting HTTP or
database policy into this crate.

Issuers can install `AdditionalTokenRolesProvider` to load current membership
for refreshable sessions. The hook runs on initial issuance and every refresh,
but never for sessionless or session-bound delegated grants. Decoded values are
available at `AuthUser::token_claims.authorization_roles`; ordinary
`AuthUser::roles` keep their application-defined meaning.

## Signed transport

`SignedRoleScopeCatalogue` and `RoleScopeCatalogueClaims` define a neutral wire
shape. The claims contain the exact clear-text catalogue, issuer, audience,
issued-at time, expiry, and the fixed `role_scope_catalogue` purpose. A host:

1. signs serialized claims with its chosen asymmetric-token facility;
2. publishes the clear catalogue and compact signature as one envelope;
3. verifies the signature, algorithm, key, issuer, and audience at the
   resource server; and
4. calls `validate_binding_with_options` before constructing expansion state.

The crate intentionally does not fetch URLs, choose keys, assign memberships,
or name roles/scopes. Signed maximum lifetime and clock leeway are independent
of local refresh cadence. A remote cache can retain a previously verified
snapshot for stale-while-revalidate service while loudly reporting staleness;
the transport and stale policy remain host concerns. Role-definition edits take
effect according to the host's token and catalogue refresh policy; direct
scopes remain separate from expanded scopes.
