use agql_auth::{
    AssurancePolicyId, AssurancePolicySet, AssuranceRequirement, FixedClock, RecentMfaPolicy,
    SessionAssuranceStatus,
};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = AssurancePolicyId::new("interactive.recent-auth")?;
    let requirement = AssuranceRequirement::new(policy_id.clone());
    let mut policies = AssurancePolicySet::new();
    policies.insert(
        policy_id,
        RecentMfaPolicy {
            maximum_age: Duration::minutes(5),
            clock_skew: Duration::seconds(30),
            allowed_amr: vec!["totp".to_string(), "webauthn".to_string()],
            allowed_acr: vec![],
            match_mode: Default::default(),
        },
    );

    let clock = FixedClock::new(OffsetDateTime::UNIX_EPOCH);
    let evaluation = policies.evaluate(&requirement, None, &clock);
    assert_eq!(
        evaluation.state.graphql_extension_code(),
        Some("UNAUTHENTICATED")
    );

    // Both values are credential-free client projections. A protected resource
    // must still reevaluate its requirement immediately before execution.
    println!("{}", serde_json::to_string_pretty(&evaluation)?);
    println!(
        "{}",
        serde_json::to_string_pretty(&SessionAssuranceStatus::from_user(None))?
    );
    Ok(())
}
