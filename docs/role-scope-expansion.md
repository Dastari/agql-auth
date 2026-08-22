# Role-to-scope expansion

`agql-auth` access tokens already carry roles and scopes. A host that grants
reusable roles can keep tokens compact by carrying role IDs plus exceptional
direct scopes, then expanding those role IDs at each resource server.

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
deduplicates output, and gives unknown roles no authority. Hosts that retrieve
catalogues remotely implement `RoleScopeExpansionProvider` over their own
verified cache and return `Unavailable` when no current verified snapshot is
usable. That makes stale, missing, or forged state fail closed without putting
HTTP or database policy into this crate.

## Signed transport

`SignedRoleScopeCatalogue` and `RoleScopeCatalogueClaims` define a neutral wire
shape. The claims contain the exact clear-text catalogue, issuer, audience,
issued-at time, expiry, and the fixed `role_scope_catalogue` purpose. A host:

1. signs serialized claims with its chosen asymmetric-token facility;
2. publishes the clear catalogue and compact signature as one envelope;
3. verifies the signature, algorithm, key, issuer, and audience at the
   resource server; and
4. calls `validate_binding` before constructing expansion state.

The crate intentionally does not fetch URLs, choose keys, assign memberships,
or name roles/scopes. Cache TTLs must be no longer than the signed lifetime.
Role-definition edits take effect according to the host's token and catalogue
refresh policy; direct scopes remain separate from expanded scopes.

