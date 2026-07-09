use std::sync::Arc;

/// Matches granted scopes against required scopes.
///
/// Implementations decide whether wildcards, hierarchy, or other host-defined
/// semantics are supported. The crate defaults to [`ExactScopeMatch`].
pub trait ScopeMatch: Send + Sync + std::fmt::Debug {
    /// Returns `true` when one granted scope satisfies one required scope.
    fn matches(&self, granted: &str, required: &str) -> bool;

    /// Returns `true` when any granted scope satisfies the required scope.
    fn has_scope(&self, granted: &[String], required: &str) -> bool {
        granted.iter().any(|scope| self.matches(scope, required))
    }

    /// Returns `true` when at least one required scope is satisfied.
    fn has_any_scope(&self, granted: &[String], required: &[&str]) -> bool {
        required.iter().any(|scope| self.has_scope(granted, scope))
    }

    /// Returns `true` when every required scope is satisfied.
    fn has_all_scopes(&self, granted: &[String], required: &[&str]) -> bool {
        required.iter().all(|scope| self.has_scope(granted, scope))
    }
}

/// Exact string scope matcher.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactScopeMatch;

impl ScopeMatch for ExactScopeMatch {
    fn matches(&self, granted: &str, required: &str) -> bool {
        granted == required
    }
}

/// Options for [`HierarchicalScopeMatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchicalScopeOptions {
    /// Segment separator. Defaults to `'.'`.
    pub separator: char,
    /// Wildcard segment/string. Defaults to `"*"`.
    pub wildcard: String,
    /// When `true`, a trailing wildcard uses the multi-segment prefix behavior.
    /// When `false`, a trailing wildcard consumes one remaining segment.
    pub wildcard_matches_multi_segment: bool,
    /// When `true`, a granted scope equal to the bare wildcard satisfies every
    /// requirement. Defaults to `false` so bare `*` has no implicit meaning.
    pub allow_universal_wildcard: bool,
    /// Scopes that satisfy every requirement. Empty by default.
    pub super_scopes: Vec<String>,
}

impl Default for HierarchicalScopeOptions {
    fn default() -> Self {
        Self {
            separator: '.',
            wildcard: "*".to_string(),
            wildcard_matches_multi_segment: true,
            allow_universal_wildcard: false,
            super_scopes: Vec::new(),
        }
    }
}

/// Hierarchical/wildcard scope matcher.
///
/// With default options this preserves the legacy raw trailing-wildcard
/// behavior captured by the crate's golden vectors: wildcards live only in the
/// granted scope, a trailing wildcard is a raw prefix match, and interior
/// wildcard segments match exactly one segment with equal segment counts.
#[derive(Debug, Clone)]
pub struct HierarchicalScopeMatch {
    options: HierarchicalScopeOptions,
}

impl HierarchicalScopeMatch {
    /// Creates a matcher with explicit options.
    pub fn new(options: HierarchicalScopeOptions) -> Self {
        Self { options }
    }

    /// Creates a matcher with default hierarchical options and no super-scopes.
    pub fn with_defaults() -> Self {
        Self::new(HierarchicalScopeOptions::default())
    }

    /// Returns the configured options.
    pub fn options(&self) -> &HierarchicalScopeOptions {
        &self.options
    }
}

impl ScopeMatch for HierarchicalScopeMatch {
    fn matches(&self, granted: &str, required: &str) -> bool {
        if self
            .options
            .super_scopes
            .iter()
            .any(|scope| scope == granted)
        {
            return true;
        }

        if granted == required {
            return true;
        }

        if granted.is_empty() || required.is_empty() || self.options.wildcard.is_empty() {
            return false;
        }

        if granted == self.options.wildcard {
            return self.options.allow_universal_wildcard;
        }

        if granted.ends_with(&self.options.wildcard) {
            let prefix = &granted[..granted.len() - self.options.wildcard.len()];
            // Bare multi-segment trailing wildcard: "orders.*"
            // Reject empty prefix (already handled as universal above).
            if prefix.is_empty() {
                return self.options.allow_universal_wildcard;
            }
            if self.options.wildcard_matches_multi_segment {
                return required.starts_with(prefix);
            }

            let Some(rest) = required.strip_prefix(prefix) else {
                return false;
            };
            return !rest.is_empty() && !rest.contains(self.options.separator);
        }

        let granted_segments: Vec<&str> = granted.split(self.options.separator).collect();
        let required_segments: Vec<&str> = required.split(self.options.separator).collect();
        // Middle wildcards are supported only as whole segments with equal counts.
        granted_segments.len() == required_segments.len()
            && granted_segments.iter().zip(required_segments.iter()).all(
                |(granted_segment, required_segment)| {
                    *granted_segment == self.options.wildcard || granted_segment == required_segment
                },
            )
    }
}

/// Ergonomic matcher enum for common configurations.
#[derive(Clone, Debug, Default)]
pub enum ScopeMatcher {
    /// Exact string matching.
    #[default]
    Exact,
    /// Configured hierarchical matching.
    Hierarchical(HierarchicalScopeMatch),
    /// Host-provided matcher.
    Custom(Arc<dyn ScopeMatch>),
}

impl ScopeMatcher {
    /// Creates an exact matcher enum.
    pub fn exact() -> Self {
        Self::Exact
    }

    /// Creates a hierarchical matcher enum from options.
    pub fn hierarchical(options: HierarchicalScopeOptions) -> Self {
        Self::Hierarchical(HierarchicalScopeMatch::new(options))
    }

    /// Converts this matcher into a trait object suitable for request runtime.
    pub fn into_arc(self) -> Arc<dyn ScopeMatch> {
        Arc::new(self)
    }
}

impl ScopeMatch for ScopeMatcher {
    fn matches(&self, granted: &str, required: &str) -> bool {
        match self {
            Self::Exact => ExactScopeMatch.matches(granted, required),
            Self::Hierarchical(matcher) => matcher.matches(granted, required),
            Self::Custom(matcher) => matcher.matches(granted, required),
        }
    }
}

/// Request data injected beside authenticated principals so guards use the
/// same matcher as the validator or issuer.
#[derive(Clone, Debug)]
pub struct AuthRuntime {
    /// Scope matcher used for guard checks in this request.
    pub scope_matcher: Arc<dyn ScopeMatch>,
}

impl AuthRuntime {
    /// Creates request runtime data with a scope matcher.
    pub fn new(scope_matcher: Arc<dyn ScopeMatch>) -> Self {
        Self { scope_matcher }
    }
}

impl Default for AuthRuntime {
    fn default() -> Self {
        Self {
            scope_matcher: Arc::new(ExactScopeMatch),
        }
    }
}
