//! Runtime-neutral, process-wide bounded password work for async entry points.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc, Mutex, OnceLock,
    mpsc::{self, Receiver, SyncSender},
};

use crate::{AuthError, AuthResult};

type Job = Box<dyn FnOnce() + Send + 'static>;
const WORKERS: usize = 2;
const QUEUED_JOBS: usize = 32;
static SHARED: OnceLock<Result<Arc<PasswordWorkPool>, ()>> = OnceLock::new();

pub(crate) struct PasswordWorkPool {
    sender: SyncSender<Job>,
}
impl PasswordWorkPool {
    pub(crate) fn shared() -> AuthResult<Arc<Self>> {
        SHARED
            .get_or_init(|| {
                Self::new(WORKERS, QUEUED_JOBS)
                    .map(Arc::new)
                    .map_err(|_| ())
            })
            .as_ref()
            .cloned()
            .map_err(|_| AuthError::AuthServiceUnavailable)
    }

    fn new(workers: usize, queued_jobs: usize) -> AuthResult<Self> {
        Self::with_spawner(workers, queued_jobs, |worker| {
            std::thread::Builder::new()
                .name("agql-auth-password".into())
                .spawn(worker)
                .map(|_| ())
        })
    }

    fn with_spawner(
        workers: usize,
        queued_jobs: usize,
        mut spawn: impl FnMut(Job) -> std::io::Result<()>,
    ) -> AuthResult<Self> {
        if workers == 0 || queued_jobs == 0 {
            return Err(AuthError::AuthServiceUnavailable);
        }
        let (sender, receiver) = mpsc::sync_channel(queued_jobs);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..workers {
            let receiver = receiver.clone();
            spawn(Box::new(move || {
                while let Some(job) = receive(&receiver) {
                    // Never run caller work while holding the queue lock. A job
                    // failure must not silently remove a worker from the bound.
                    let _ = catch_unwind(AssertUnwindSafe(job));
                }
            }))
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        }
        Ok(Self { sender })
    }

    pub(crate) async fn execute<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> AuthResult<T> + Send + 'static,
    ) -> AuthResult<T> {
        let (sender, receiver) = futures_channel::oneshot::channel();
        let job = Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(work))
                .unwrap_or(Err(AuthError::AuthServiceUnavailable));
            let _ = sender.send(result);
        });
        self.sender
            .try_send(job)
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        receiver
            .await
            .map_err(|_| AuthError::AuthServiceUnavailable)?
    }
}

fn receive(receiver: &Mutex<Receiver<Job>>) -> Option<Job> {
    receiver.lock().ok()?.recv().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn cancellation_keeps_running_and_queued_work_charged() {
        let pool = PasswordWorkPool::new(1, 1).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (started, observed) = mpsc::channel();
        let worker_barrier = barrier.clone();
        let mut first = Box::pin(pool.execute(move || {
            started.send(()).unwrap();
            worker_barrier.wait();
            Ok(())
        }));
        assert!(poll(first.as_mut()).is_pending());
        observed.recv().unwrap();
        drop(first); // Work still owns the sole running worker.
        let (queued_done, queued_observed) = mpsc::channel();
        let mut queued = Box::pin(pool.execute(move || {
            queued_done.send(()).unwrap();
            Ok(())
        }));
        assert!(poll(queued.as_mut()).is_pending());
        drop(queued); // Queued work is not removed or refunded either.
        assert!(matches!(
            pool.execute(|| Ok(())).await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        barrier.wait();
        queued_observed.recv().unwrap();
        assert_eq!(pool.execute(|| Ok(7)).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn panic_and_disconnected_queue_fail_closed() {
        let pool = PasswordWorkPool::new(1, 1).unwrap();
        let result = pool
            .execute(|| -> AuthResult<()> { panic!("synthetic worker fault") })
            .await;
        assert!(matches!(result, Err(AuthError::AuthServiceUnavailable)));
        assert_eq!(pool.execute(|| Ok(7)).await.unwrap(), 7);
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        assert!(matches!(
            PasswordWorkPool { sender }.execute(|| Ok(())).await,
            Err(AuthError::AuthServiceUnavailable)
        ));
    }

    #[test]
    fn spawn_failure_and_poisoned_receiver_fail_closed() {
        assert!(
            PasswordWorkPool::with_spawner(2, 1, |_| Err(std::io::Error::other(
                "synthetic spawn failure"
            )))
            .is_err()
        );
        let (_, receiver) = mpsc::sync_channel::<Job>(1);
        let receiver = Mutex::new(receiver);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = receiver.lock().unwrap();
            panic!("synthetic queue fault");
        }));
        assert!(receive(&receiver).is_none());
    }
    #[test]
    fn all_services_share_one_process_pool() {
        assert!(Arc::ptr_eq(
            &PasswordWorkPool::shared().unwrap(),
            &PasswordWorkPool::shared().unwrap()
        ));
    }
    #[tokio::test]
    async fn service_saturation_is_unavailable_without_bad_credential_counters() {
        use crate::tests::{
            MemoryLoginChallengeStore, MemoryUserStore, stored_user, test_auth_service,
        };
        use crate::{
            AuthRateLimitFlow, ClientMetadata, LoginChallengeOptions, LoginChallengeStore,
        };
        let users = MemoryUserStore::default();
        let mut auth = test_auth_service(users.clone(), Default::default());
        users.insert(stored_user(&auth, "active", "active", "correct"));
        let mut disabled = stored_user(&auth, "disabled", "disabled", "correct");
        disabled.disabled = true;
        users.insert(disabled);
        let challenges = MemoryLoginChallengeStore::default();
        let challenge = auth
            .create_login_challenge(&challenges, "active", LoginChallengeOptions::default())
            .await
            .unwrap();
        auth.password_executor = Arc::new(PasswordWorkPool::new(1, 1).unwrap());
        let pool = auth.password_executor.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        let (started, observed) = mpsc::channel();
        let mut running = Box::pin(pool.execute(move || {
            started.send(()).unwrap();
            worker_barrier.wait();
            Ok(())
        }));
        assert!(poll(running.as_mut()).is_pending());
        observed.recv().unwrap();
        let (done, observed_done) = mpsc::channel();
        let mut queued = Box::pin(pool.execute(move || {
            done.send(()).unwrap();
            Ok(())
        }));
        assert!(poll(queued.as_mut()).is_pending());
        for principal in ["active", "disabled", "unknown"] {
            assert!(matches!(
                auth.login(principal, "wrong", ClientMetadata::default())
                    .await,
                Err(AuthError::AuthServiceUnavailable)
            ));
            for key in auth.rate_limit_keys(
                AuthRateLimitFlow::PasswordLogin,
                Some(principal),
                &ClientMetadata::default(),
            ) {
                assert!(
                    auth.rate_limit_store
                        .find_auth_rate_limit_state(&key)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert!(auth.password_work.lock().unwrap().is_empty());
        assert!(matches!(
            auth.verify_login_challenge(&challenges, challenge.challenge_id, &challenge.code)
                .await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert_eq!(
            challenges
                .find_login_challenge(challenge.challenge_id)
                .await
                .unwrap()
                .unwrap()
                .attempts,
            1
        );
        for key in auth.rate_limit_keys(
            AuthRateLimitFlow::LoginCodeVerification,
            Some("active"),
            &ClientMetadata::default(),
        ) {
            assert!(
                auth.rate_limit_store
                    .find_auth_rate_limit_state(&key)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(matches!(
            auth.create_login_challenge(&challenges, "active", LoginChallengeOptions::default())
                .await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert_eq!(challenges.challenges.lock().unwrap().len(), 1);
        barrier.wait();
        observed_done.recv().unwrap();
        assert!(
            auth.login("active", "correct", ClientMetadata::default())
                .await
                .is_ok()
        );
        assert!(matches!(
            auth.login("disabled", "correct", ClientMetadata::default())
                .await,
            Err(AuthError::UserDisabled)
        ));
        assert_eq!(auth.password_work.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn password_work_runs_on_worker_not_polling_thread() {
        let pool = PasswordWorkPool::new(1, 1).unwrap();
        let polling = std::thread::current().id();
        let worker = pool
            .execute(|| Ok(std::thread::current().id()))
            .await
            .unwrap();
        assert_ne!(polling, worker);
    }
    #[tokio::test]
    async fn queued_login_observes_user_changes_before_session_creation() {
        use crate::ClientMetadata;
        use crate::tests::{
            MemoryRefreshTokenStore, MemoryUserStore, stored_user, test_auth_service,
        };
        for change in 0..5 {
            let users = MemoryUserStore::default();
            let refresh = MemoryRefreshTokenStore::default();
            let mut auth = test_auth_service(users.clone(), refresh.clone());
            let original = stored_user(&auth, "user", "principal", "correct");
            users.insert(original.clone());
            auth.password_executor = Arc::new(PasswordWorkPool::new(1, 1).unwrap());
            let pool = auth.password_executor.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let worker_barrier = barrier.clone();
            let (started, observed) = mpsc::channel();
            let mut running = Box::pin(pool.execute(move || {
                started.send(()).unwrap();
                worker_barrier.wait();
                Ok(())
            }));
            assert!(poll(running.as_mut()).is_pending());
            observed.recv().unwrap();
            let mut login = Box::pin(auth.login("principal", "correct", ClientMetadata::default()));
            assert!(poll(login.as_mut()).is_pending());
            let mut current = original;
            match change {
                0 => current.disabled = true,
                1 => users.remove("user"),
                2 => current.password_hash = auth.hash_password("changed-password").unwrap(),
                3 => {
                    current.roles.clear();
                    current.scopes.clear();
                }
                _ => users.corrupt_returned_id("user"),
            }
            if change != 1 && change != 4 {
                users.insert(current);
            }
            barrier.wait();
            let result = login.await;
            if change == 3 {
                let payload = result.unwrap();
                assert!(payload.user.roles.is_empty());
                assert!(payload.user.scopes.is_empty());
                let decoded = auth
                    .authenticate_access_token(&payload.access_token)
                    .unwrap();
                assert!(decoded.roles.is_empty());
                assert!(decoded.scopes.is_empty());
                assert_eq!(refresh.tokens_by_id.lock().unwrap().len(), 1);
            } else {
                assert!(matches!(
                    result,
                    Err(AuthError::UserDisabled
                        | AuthError::InvalidCredentials
                        | AuthError::AuthServiceUnavailable)
                ));
                assert!(refresh.tokens_by_id.lock().unwrap().is_empty());
                assert_eq!(auth.token_work.load(std::sync::atomic::Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn challenge_expiring_in_worker_queue_never_starts_argon() {
        use crate::tests::{MemoryLoginChallengeStore, test_auth_service};
        use crate::{FixedClock, LoginChallengeOptions, LoginChallengeStore};
        let clock = FixedClock::new(time::OffsetDateTime::now_utc());
        let mut auth = test_auth_service(Default::default(), Default::default())
            .with_login_challenge_clock(Arc::new(clock.clone()));
        let store = MemoryLoginChallengeStore::default();
        let issued = auth
            .create_login_challenge(
                &store,
                "principal",
                LoginChallengeOptions {
                    ttl: time::Duration::seconds(60),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        auth.password_executor = Arc::new(PasswordWorkPool::new(1, 1).unwrap());
        let pool = auth.password_executor.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        let (started, observed) = mpsc::channel();
        let mut running = Box::pin(pool.execute(move || {
            started.send(()).unwrap();
            worker_barrier.wait();
            Ok(())
        }));
        assert!(poll(running.as_mut()).is_pending());
        observed.recv().unwrap();
        auth.password_work.lock().unwrap().clear();
        let mut verification =
            Box::pin(auth.verify_login_challenge(&store, issued.challenge_id, &issued.code));
        assert!(poll(verification.as_mut()).is_pending());
        assert_eq!(
            store
                .find_login_challenge(issued.challenge_id)
                .await
                .unwrap()
                .unwrap()
                .attempts,
            1
        );
        clock.advance_seconds(61);
        barrier.wait();
        assert!(matches!(
            verification.await,
            Err(AuthError::LoginChallengeExpired)
        ));
        assert!(auth.password_work.lock().unwrap().is_empty());
        assert!(
            store
                .find_login_challenge(issued.challenge_id)
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_none()
        );
    }
}
