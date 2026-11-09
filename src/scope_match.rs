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
    ///
    /// An empty requirement list is a configuration mistake and returns
    /// `false`.
    fn has_all_scopes(&self, granted: &[String], required: &[&str]) -> bool {
        !required.is_empty() && required.iter().all(|scope| self.has_scope(granted, scope))
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
#[non_exhaustive]
pub struct HierarchicalScopeOptions {
    /// Segment separator. Defaults to `'.'`.
    pub separator: char,
    /// Wildcard segment/string. Defaults to `"*"`.
    pub wildcard: String,
    /// When `true`, a trailing wildcard segment consumes one or more remaining
    /// segments. When `false`, it consumes exactly one remaining segment.
    pub wildcard_matches_multi_segment: bool,
    /// When `true`, a granted scope equal to the bare wildcard satisfies every
    /// requirement. Defaults to `false` so bare `*` has no implicit meaning.
    pub allow_universal_wildcard: bool,
    /// Scopes that satisfy every requirement. Empty by default.
    pub super_scopes: Vec<String>,
    /// When `true`, configured super-scopes may satisfy exact-only
    /// requirements. Defaults to `false` for compatibility.
    pub allow_super_scopes_for_exact_only: bool,
    /// Required scopes that refuse wildcard-derived satisfaction.
    ///
    /// Exact-only requirements always reject wildcard-derived matches.
    /// Configured super-scopes are also rejected unless
    /// [`Self::allow_super_scopes_for_exact_only`] is enabled. Empty by default.
    pub exact_only_scopes: Vec<String>,
    /// Required-scope patterns that select exact-only behavior.
    ///
    /// Patterns use the configured hierarchical wildcard rules. This lets a
    /// host declare resource-qualified scope families without enumerating
    /// every resource identifier. Empty by default.
    pub exact_only_scope_patterns: Vec<String>,
}

impl Default for HierarchicalScopeOptions {
    fn default() -> Self {
        Self {
            separator: '.',
            wildcard: "*".to_string(),
            wildcard_matches_multi_segment: true,
            allow_universal_wildcard: false,
            super_scopes: Vec::new(),
            allow_super_scopes_for_exact_only: false,
            exact_only_scopes: Vec::new(),
            exact_only_scope_patterns: Vec::new(),
        }
    }
}

impl HierarchicalScopeOptions {
    /// Sets the segment separator.
    pub fn with_separator(mut self, separator: char) -> Self {
        self.separator = separator;
        self
    }

    /// Sets the wildcard segment/string.
    pub fn with_wildcard(mut self, wildcard: impl Into<String>) -> Self {
        self.wildcard = wildcard.into();
        self
    }

    /// Sets whether a trailing wildcard matches multiple segments.
    pub fn with_wildcard_matches_multi_segment(mut self, enabled: bool) -> Self {
        self.wildcard_matches_multi_segment = enabled;
        self
    }

    /// Sets whether a bare wildcard grant satisfies every requirement.
    pub fn with_allow_universal_wildcard(mut self, enabled: bool) -> Self {
        self.allow_universal_wildcard = enabled;
        self
    }

    /// Sets the consumer-supplied super-scopes.
    pub fn with_super_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.super_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets whether configured super-scopes satisfy exact-only requirements.
    pub fn with_allow_super_scopes_for_exact_only(mut self, enabled: bool) -> Self {
        self.allow_super_scopes_for_exact_only = enabled;
        self
    }

    /// Sets the consumer-supplied exact-only scopes.
    pub fn with_exact_only_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_only_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the consumer-supplied exact-only scope patterns.
    pub fn with_exact_only_scope_patterns<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exact_only_scope_patterns = patterns.into_iter().map(Into::into).collect();
        self
    }

    /// Validates the options and returns non-fatal configuration warnings.
    ///
    /// A bare wildcard exact-only pattern is rejected because, when universal
    /// wildcard behavior is enabled, it selects every required scope. Other
    /// wildcard-bearing exact-only patterns are valid but reported so hosts can
    /// make the resulting subtree policy visible during configuration loading.
    pub fn validate(
        &self,
    ) -> Result<Vec<HierarchicalScopeValidationWarning>, HierarchicalScopeValidationError> {
        let mut warnings = Vec::new();

        for pattern in &self.exact_only_scope_patterns {
            if !self.wildcard.is_empty() && pattern == &self.wildcard {
                return Err(
                    HierarchicalScopeValidationError::BareWildcardExactOnlyPattern {
                        pattern: pattern.clone(),
                    },
                );
            }

            if !self.wildcard.is_empty() && pattern.contains(&self.wildcard) {
                warnings.push(
                    HierarchicalScopeValidationWarning::WildcardExactOnlyPattern {
                        pattern: pattern.clone(),
                    },
                );
            }
        }

        Ok(warnings)
    }
}

/// Fatal validation error for [`HierarchicalScopeOptions`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HierarchicalScopeValidationError {
    /// An exact-only pattern is exactly the configured wildcard.
    #[error("exact-only scope pattern {pattern:?} must not be the bare wildcard")]
    BareWildcardExactOnlyPattern {
        /// Rejected pattern.
        pattern: String,
    },
}

/// Non-fatal validation warning for [`HierarchicalScopeOptions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HierarchicalScopeValidationWarning {
    /// An exact-only pattern contains the configured wildcard.
    WildcardExactOnlyPattern {
        /// Pattern whose subtree becomes exact-only.
        pattern: String,
    },
}

impl std::fmt::Display for HierarchicalScopeValidationWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WildcardExactOnlyPattern { pattern } => write!(
                formatter,
                "exact-only scope pattern {pattern:?} contains a wildcard and may select a scope subtree"
            ),
        }
    }
}

/// Hierarchical/wildcard scope matcher.
///
/// Wildcards live only in the granted scope and only as whole segments. A
/// trailing wildcard segment (`orders.*`) matches one or more further
/// non-empty segments (exactly one when
/// [`HierarchicalScopeOptions::wildcard_matches_multi_segment`] is `false`)
/// after literally equal prefix segments, so `tenant.1.*` never covers
/// `tenant.10.read`. Interior wildcard segments match exactly one segment with
/// equal segment counts. A wildcard inside a segment (`tenant.1*`) has no
/// wildcard meaning. The crate's golden vectors pin these rules.
#[derive(Debug, Clone)]
pub struct HierarchicalScopeMatch {
    options: HierarchicalScopeOptions,
    validation_warnings: Vec<HierarchicalScopeValidationWarning>,
}

impl HierarchicalScopeMatch {
    /// Creates a matcher with validated explicit options.
    ///
    /// Call [`Self::validation_warnings`] after construction and surface each
    /// warning through the host's configuration diagnostics.
    pub fn new(
        options: HierarchicalScopeOptions,
    ) -> Result<Self, HierarchicalScopeValidationError> {
        let validation_warnings = options.validate()?;
        Ok(Self {
            options,
            validation_warnings,
        })
    }

    /// Creates a matcher with default hierarchical options and no super-scopes.
    pub fn with_defaults() -> Self {
        Self::new(HierarchicalScopeOptions::default())
            .expect("default hierarchical scope options are valid")
    }

    /// Returns the configured options.
    pub fn options(&self) -> &HierarchicalScopeOptions {
        &self.options
    }

    /// Returns non-fatal diagnostics found while validating the options.
    pub fn validation_warnings(&self) -> &[HierarchicalScopeValidationWarning] {
        &self.validation_warnings
    }
}

impl ScopeMatch for HierarchicalScopeMatch {
    fn matches(&self, granted: &str, required: &str) -> bool {
        let exact_only = self.is_exact_only_requirement(required);
        self.matches_with_exact_only(granted, required, exact_only)
    }

    fn has_scope(&self, granted: &[String], required: &str) -> bool {
        let exact_only = self.is_exact_only_requirement(required);
        granted
            .iter()
            .any(|scope| self.matches_with_exact_only(scope, required, exact_only))
    }
}

impl HierarchicalScopeMatch {
    fn is_exact_only_requirement(&self, required: &str) -> bool {
        self.options
            .exact_only_scopes
            .iter()
            .any(|scope| scope == required)
            || self
                .options
                .exact_only_scope_patterns
                .iter()
                .any(|pattern| self.matches_hierarchy(pattern, required))
    }

    fn matches_with_exact_only(&self, granted: &str, required: &str, exact_only: bool) -> bool {
        if granted == required {
            return true;
        }

        if exact_only {
            return self.options.allow_super_scopes_for_exact_only
                && self.is_configured_super_scope(granted);
        }

        if self.is_configured_super_scope(granted) {
            return true;
        }

        self.matches_hierarchy(granted, required)
    }

    fn is_configured_super_scope(&self, granted: &str) -> bool {
        self.options
            .super_scopes
            .iter()
            .any(|scope| scope == granted)
    }

    fn matches_hierarchy(&self, granted: &str, required: &str) -> bool {
        if granted == required {
            return true;
        }

        if granted.is_empty() || required.is_empty() || self.options.wildcard.is_empty() {
            return false;
        }

        if granted == self.options.wildcard {
            return self.options.allow_universal_wildcard;
        }

        let granted_segments: Vec<&str> = granted.split(self.options.separator).collect();
        let required_segments: Vec<&str> = required.split(self.options.separator).collect();

        // A trailing wildcard is a whole final segment ("orders.*"). Its
        // prefix segments match literally, so "tenant.1.*" never covers
        // "tenant.10.read". A wildcard inside a segment ("tenant.1*") has no
        // wildcard meaning and matches only itself (handled above).
        if let Some((last, prefix)) = granted_segments.split_last()
            && *last == self.options.wildcard
            && !prefix.is_empty()
        {
            let consumed = required_segments.get(prefix.len()..).unwrap_or_default();
            let width_ok = if self.options.wildcard_matches_multi_segment {
                !consumed.is_empty()
            } else {
                consumed.len() == 1
            };
            return width_ok
                && consumed.iter().all(|segment| !segment.is_empty())
                && prefix.iter().zip(required_segments.iter()).all(
                    |(granted_segment, required_segment)| granted_segment == required_segment,
                );
        }

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
    pub fn hierarchical(
        options: HierarchicalScopeOptions,
    ) -> Result<Self, HierarchicalScopeValidationError> {
        Ok(Self::Hierarchical(HierarchicalScopeMatch::new(options)?))
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

    fn has_scope(&self, granted: &[String], required: &str) -> bool {
        match self {
            Self::Exact => ExactScopeMatch.has_scope(granted, required),
            Self::Hierarchical(matcher) => matcher.has_scope(granted, required),
            Self::Custom(matcher) => matcher.has_scope(granted, required),
        }
    }

    fn has_any_scope(&self, granted: &[String], required: &[&str]) -> bool {
        match self {
            Self::Exact => ExactScopeMatch.has_any_scope(granted, required),
            Self::Hierarchical(matcher) => matcher.has_any_scope(granted, required),
            Self::Custom(matcher) => matcher.has_any_scope(granted, required),
        }
    }

    fn has_all_scopes(&self, granted: &[String], required: &[&str]) -> bool {
        match self {
            Self::Exact => ExactScopeMatch.has_all_scopes(granted, required),
            Self::Hierarchical(matcher) => matcher.has_all_scopes(granted, required),
            Self::Custom(matcher) => matcher.has_all_scopes(granted, required),
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
