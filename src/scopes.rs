/// Returns `true` when the exact required scope is present.
pub fn has_scope(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| scope == required)
}

/// Returns `true` when any required scope is present.
pub fn has_any_scope<S>(scopes: &[String], required: &[S]) -> bool
where
    S: AsRef<str>,
{
    required
        .iter()
        .any(|scope| has_scope(scopes, scope.as_ref()))
}

/// Returns `true` when all required scopes are present.
pub fn has_all_scopes<S>(scopes: &[String], required: &[S]) -> bool
where
    S: AsRef<str>,
{
    required
        .iter()
        .all(|scope| has_scope(scopes, scope.as_ref()))
}
