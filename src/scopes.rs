pub fn has_scope(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| scope == required)
}

pub fn has_any_scope<S>(scopes: &[String], required: &[S]) -> bool
where
    S: AsRef<str>,
{
    required
        .iter()
        .any(|scope| has_scope(scopes, scope.as_ref()))
}

pub fn has_all_scopes<S>(scopes: &[String], required: &[S]) -> bool
where
    S: AsRef<str>,
{
    required
        .iter()
        .all(|scope| has_scope(scopes, scope.as_ref()))
}
