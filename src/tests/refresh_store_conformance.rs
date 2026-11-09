//! Concurrency contracts every `RefreshTokenStore` must meet, with or without
//! refresh reuse grace.
//!
//! The `*_contract` functions are generic so that `consumer_refresh_store` runs
//! the same assertions on real transactions.
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::MemoryRefreshTokenStore;
use super::refresh_reuse_grace::seed_record;
use crate::prelude::*;
use crate::util::hash_refresh_token;

/// Races are repeated because one interleaving proves little.
const ROUNDS: usize = 4;

async fn find<S: RefreshTokenStore>(store: &S, raw: &str) -> Option<StoredRefreshToken> {
    store
        .find_refresh_token_by_hash(&hash_refresh_token(raw))
        .await
        .unwrap()
}

/// A rotation and a family revocation of the same family run at once.
///
/// Whichever commits first, no token of the family is live afterwards: either
/// the rotation lost and inserted nothing, or the revocation saw its replacement.
pub(super) async fn rotation_racing_family_revocation_contract<S: RefreshTokenStore + 'static>(
    store: Arc<S>,
) {
    for round in 0..ROUNDS {
        let now = OffsetDateTime::now_utc();
        let family = Uuid::new_v4();
        let current_raw = format!("family-race-current-{family}");
        let replacement_raw = format!("family-race-replacement-{family}");
        let current = seed_record(&current_raw, family, Uuid::new_v4(), now);
        store.insert_refresh_token(current.clone()).await.unwrap();
        let replacement = seed_record(&replacement_raw, family, current.session_id, now);

        let rotation = tokio::spawn({
            let store = store.clone();
            async move {
                store
                    .rotate_refresh_token(current.id, replacement, now, None, None)
                    .await
            }
        });
        let revocation = tokio::spawn({
            let store = store.clone();
            async move {
                store
                    .revoke_refresh_token_family(family, now, RefreshTokenRevocationReason::Logout)
                    .await
            }
        });
        let rotated = rotation.await.unwrap().unwrap();
        revocation.await.unwrap().unwrap();

        assert!(find(&*store, &current_raw).await.unwrap().is_revoked());
        match find(&*store, &replacement_raw).await {
            Some(replacement) => {
                assert!(
                    rotated,
                    "round {round}: a lost rotation inserted its replacement"
                );
                assert!(
                    replacement.is_revoked(),
                    "round {round}: the replacement survived the family revocation"
                );
            }
            None => assert!(
                !rotated,
                "round {round}: a won rotation left no replacement"
            ),
        }
    }
}

/// Two rotations of the same token run at once: exactly one wins, and only the
/// winner's replacement exists.
pub(super) async fn racing_rotations_contract<S: RefreshTokenStore + 'static>(store: Arc<S>) {
    for round in 0..ROUNDS {
        let now = OffsetDateTime::now_utc();
        let family = Uuid::new_v4();
        let current = seed_record(
            &format!("rotation-race-current-{family}"),
            family,
            Uuid::new_v4(),
            now,
        );
        store.insert_refresh_token(current.clone()).await.unwrap();
        let replacements: Vec<String> = (0..2)
            .map(|index| format!("rotation-race-replacement-{index}-{family}"))
            .collect();
        let tasks: Vec<_> = replacements
            .iter()
            .map(|raw| {
                let store = store.clone();
                let replacement = seed_record(raw, family, current.session_id, now);
                let current = current.id;
                tokio::spawn(async move {
                    store
                        .rotate_refresh_token(current, replacement, now, None, None)
                        .await
                })
            })
            .collect();
        let mut won = Vec::new();
        for task in tasks {
            won.push(task.await.unwrap().unwrap());
        }
        assert_eq!(
            won.iter().filter(|won| **won).count(),
            1,
            "round {round}: exactly one rotation replaces a token"
        );
        for (raw, won) in replacements.iter().zip(won) {
            let record = find(&*store, raw).await;
            assert_eq!(
                record.is_some(),
                won,
                "round {round}: only the winner inserts"
            );
            if let Some(record) = record {
                assert!(!record.is_revoked());
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_store_rotation_racing_family_revocation_leaves_no_live_token() {
    rotation_racing_family_revocation_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_store_racing_rotations_have_one_winner() {
    racing_rotations_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}
