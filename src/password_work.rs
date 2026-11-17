//! Runtime-neutral, bounded password work for async entry points.
//!
//! Argon2 runs on dedicated threads, never on the caller's async executor.
//! Admitted work stays charged after the caller cancels: a running job keeps
//! its worker and a queued job keeps its slot until it has run.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc, Mutex, OnceLock,
    mpsc::{self, Receiver, SyncSender},
};

use crate::{AuthError, AuthResult};

type Job = Box<dyn FnOnce() + Send + 'static>;
type Spawner = Box<dyn Fn(Job) -> std::io::Result<()> + Send + Sync>;

/// Upper bound for [`PasswordWorkPoolConfig::workers`].
pub const MAX_PASSWORD_WORKERS: usize = 256;
/// Upper bound for [`PasswordWorkPoolConfig::queued_jobs`].
pub const MAX_QUEUED_PASSWORD_JOBS: usize = 65_536;
/// Most workers the default sizing uses, whatever the core count. Each worker
/// holds one Argon2 memory block while it hashes.
pub const DEFAULT_MAX_PASSWORD_WORKERS: usize = 8;
/// Queued jobs per worker in the default sizing.
pub const DEFAULT_QUEUED_PASSWORD_JOBS_PER_WORKER: usize = 16;

static SHARED: OnceLock<Arc<PasswordWorkPool>> = OnceLock::new();

/// Sizing for a [`PasswordWorkPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordWorkPoolConfig {
    /// Threads that run Argon2. At least 1, at most [`MAX_PASSWORD_WORKERS`].
    pub workers: usize,
    /// Jobs that may wait for a worker. At least 1, at most
    /// [`MAX_QUEUED_PASSWORD_JOBS`]. A job that finds the queue full fails
    /// with [`AuthError::AuthServiceUnavailable`] without waiting.
    pub queued_jobs: usize,
}

impl Default for PasswordWorkPoolConfig {
    /// One worker per available core, at most
    /// [`DEFAULT_MAX_PASSWORD_WORKERS`], and
    /// [`DEFAULT_QUEUED_PASSWORD_JOBS_PER_WORKER`] queued jobs per worker.
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map_or(2, usize::from)
            .clamp(1, DEFAULT_MAX_PASSWORD_WORKERS);
        Self {
            workers,
            queued_jobs: workers * DEFAULT_QUEUED_PASSWORD_JOBS_PER_WORKER,
        }
    }
}

/// Bounded worker pool for password hashing and verification.
///
/// Every [`crate::AuthService`] uses [`PasswordWorkPool::shared`] unless
/// [`crate::AuthService::with_password_work_pool`] gives it another pool, so
/// by default one process-wide budget bounds Argon2's CPU and memory however
/// many services exist. Build a pool with [`PasswordWorkPool::new`] to size it,
/// and share or isolate it between services explicitly.
///
/// Threads start on first use. If a thread cannot be started, that call fails
/// with [`AuthError::AuthServiceUnavailable`] when no worker runs, and the next
/// call tries again; a failure is never cached.
///
/// The pool bounds work, not request rates. Every admitted password login runs
/// one Argon2 verification, including for unknown and disabled users, and a
/// full queue is not counted as a credential failure. Throttle the login route
/// at the edge, per client and globally, so that a modest request rate cannot
/// keep the queue full and turn legitimate logins away.
pub struct PasswordWorkPool {
    sender: SyncSender<Job>,
    receiver: Arc<Mutex<Receiver<Job>>>,
    workers: usize,
    started: Mutex<usize>,
    spawn: Spawner,
}

impl std::fmt::Debug for PasswordWorkPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordWorkPool")
            .field("workers", &self.workers)
            .field(
                "started",
                &self.started.lock().map_or(0, |started| *started),
            )
            .finish_non_exhaustive()
    }
}

impl PasswordWorkPool {
    /// Creates a pool. Threads start on first use.
    ///
    /// Returns [`AuthError::InvalidConfiguration`] for sizes outside the
    /// documented bounds.
    pub fn new(config: PasswordWorkPoolConfig) -> AuthResult<Arc<Self>> {
        Self::with_spawner(
            config,
            Box::new(|worker| {
                std::thread::Builder::new()
                    .name("agql-auth-password".into())
                    .spawn(worker)
                    .map(|_| ())
            }),
        )
        .map(Arc::new)
    }

    /// The process-wide pool with [`PasswordWorkPoolConfig::default`] sizing.
    pub fn shared() -> Arc<Self> {
        SHARED
            .get_or_init(|| {
                Self::new(PasswordWorkPoolConfig::default())
                    .expect("default password pool sizing is within bounds")
            })
            .clone()
    }

    fn with_spawner(config: PasswordWorkPoolConfig, spawn: Spawner) -> AuthResult<Self> {
        if !(1..=MAX_PASSWORD_WORKERS).contains(&config.workers)
            || !(1..=MAX_QUEUED_PASSWORD_JOBS).contains(&config.queued_jobs)
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "password work pool needs 1..={MAX_PASSWORD_WORKERS} workers and \
                 1..={MAX_QUEUED_PASSWORD_JOBS} queued jobs"
            )));
        }
        let (sender, receiver) = mpsc::sync_channel(config.queued_jobs);
        Ok(Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            workers: config.workers,
            started: Mutex::new(0),
            spawn,
        })
    }

    /// Starts any workers not yet running. Fails only when none runs.
    fn ensure_workers(&self) -> AuthResult<()> {
        let mut started = self
            .started
            .lock()
            .map_err(|_| AuthError::AuthServiceUnavailable)?;
        while *started < self.workers {
            let receiver = self.receiver.clone();
            let worker: Job = Box::new(move || {
                while let Some(job) = receive(&receiver) {
                    // Never run caller work while holding the queue lock. A job
                    // failure must not silently remove a worker from the bound.
                    let _ = catch_unwind(AssertUnwindSafe(job));
                }
            });
            if (self.spawn)(worker).is_err() {
                break;
            }
            *started += 1;
        }
        if *started == 0 {
            return Err(AuthError::AuthServiceUnavailable);
        }
        Ok(())
    }

    pub(crate) async fn execute<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> AuthResult<T> + Send + 'static,
    ) -> AuthResult<T> {
        self.ensure_workers()?;
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

    fn pool(workers: usize, queued_jobs: usize) -> Arc<PasswordWorkPool> {
        PasswordWorkPool::new(PasswordWorkPoolConfig {
            workers,
            queued_jobs,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn cancellation_keeps_running_and_queued_work_charged() {
        let pool = pool(1, 1);
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
        let pool = pool(1, 1);
        let result = pool
            .execute(|| -> AuthResult<()> { panic!("synthetic worker fault") })
            .await;
        assert!(matches!(result, Err(AuthError::AuthServiceUnavailable)));
        assert_eq!(pool.execute(|| Ok(7)).await.unwrap(), 7);
        let mut disconnected = PasswordWorkPool::with_spawner(
            PasswordWorkPoolConfig {
                workers: 1,
                queued_jobs: 1,
            },
            Box::new(|_| Ok(())),
        )
        .unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        disconnected.sender = sender;
        assert!(matches!(
            disconnected.execute(|| Ok(())).await,
            Err(AuthError::AuthServiceUnavailable)
        ));
    }

    #[tokio::test]
    async fn a_spawn_failure_is_unavailable_and_retried_on_the_next_call() {
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let remaining = failures.clone();
        let pool = PasswordWorkPool::with_spawner(
            PasswordWorkPoolConfig {
                workers: 1,
                queued_jobs: 1,
            },
            Box::new(move |worker| {
                if remaining
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |left| left.checked_sub(1),
                    )
                    .is_ok()
                {
                    return Err(std::io::Error::other("synthetic spawn failure"));
                }
                std::thread::Builder::new().spawn(worker).map(|_| ())
            }),
        )
        .unwrap();
        assert!(matches!(
            pool.execute(|| Ok(())).await,
            Err(AuthError::AuthServiceUnavailable)
        ));
        assert_eq!(pool.execute(|| Ok(7)).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn a_partial_spawn_runs_with_the_workers_it_has_and_adds_the_rest_later() {
        let allowed = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let remaining = allowed.clone();
        let spawned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = spawned.clone();
        let pool = PasswordWorkPool::with_spawner(
            PasswordWorkPoolConfig {
                workers: 3,
                queued_jobs: 1,
            },
            Box::new(move |worker| {
                remaining
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |left| left.checked_sub(1),
                    )
                    .map_err(|_| std::io::Error::other("synthetic spawn failure"))?;
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::thread::Builder::new().spawn(worker).map(|_| ())
            }),
        )
        .unwrap();
        assert_eq!(pool.execute(|| Ok(1)).await.unwrap(), 1);
        assert_eq!(spawned.load(std::sync::atomic::Ordering::SeqCst), 1);
        allowed.store(5, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(pool.execute(|| Ok(2)).await.unwrap(), 2);
        assert_eq!(spawned.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(pool.execute(|| Ok(3)).await.unwrap(), 3);
        assert_eq!(spawned.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn sizing_is_bounded_and_the_default_follows_the_cores() {
        for (workers, queued_jobs) in [
            (0, 1),
            (1, 0),
            (MAX_PASSWORD_WORKERS + 1, 1),
            (1, MAX_QUEUED_PASSWORD_JOBS + 1),
        ] {
            assert!(matches!(
                PasswordWorkPool::new(PasswordWorkPoolConfig {
                    workers,
                    queued_jobs
                }),
                Err(AuthError::InvalidConfiguration(_))
            ));
        }
        let default = PasswordWorkPoolConfig::default();
        let cores = std::thread::available_parallelism().map_or(2, usize::from);
        assert_eq!(
            default.workers,
            cores.clamp(1, DEFAULT_MAX_PASSWORD_WORKERS)
        );
        assert_eq!(
            default.queued_jobs,
            default.workers * DEFAULT_QUEUED_PASSWORD_JOBS_PER_WORKER
        );
        assert!(PasswordWorkPool::new(default).is_ok());
    }

    #[test]
    fn poisoned_receiver_fails_closed() {
        let (_, receiver) = mpsc::sync_channel::<Job>(1);
        let receiver = Mutex::new(receiver);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = receiver.lock().unwrap();
            panic!("synthetic queue fault");
        }));
        assert!(receive(&receiver).is_none());
    }
    #[test]
    fn services_share_the_process_pool_unless_given_one() {
        use crate::tests::test_auth_service;
        assert!(Arc::ptr_eq(
            &PasswordWorkPool::shared(),
            &PasswordWorkPool::shared()
        ));
        let auth = test_auth_service(Default::default(), Default::default());
        assert!(Arc::ptr_eq(
            &auth.password_executor,
            &PasswordWorkPool::shared()
        ));
        let own = pool(1, 1);
        let auth = auth.with_password_work_pool(own.clone());
        assert!(Arc::ptr_eq(&auth.password_executor, &own));
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
        auth.password_executor = pool(1, 1);
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
        for (principal, user_id) in [
            ("active", Some("active")),
            ("disabled", Some("disabled")),
            ("unknown", None),
        ] {
            assert!(matches!(
                auth.login(principal, "wrong", ClientMetadata::default())
                    .await,
                Err(AuthError::AuthServiceUnavailable)
            ));
            // Known accounts are counted by user ID; a saturated pool refunds
            // the reservation, so neither key may hold state.
            for key in auth
                .password_login_rate_limit_keys(principal, user_id, &ClientMetadata::default())
                .into_iter()
                .chain(auth.rate_limit_keys(
                    AuthRateLimitFlow::PasswordLogin,
                    Some(principal),
                    &ClientMetadata::default(),
                ))
            {
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
        let pool = pool(1, 1);
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
            auth.password_executor = pool(1, 1);
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
        auth.password_executor = pool(1, 1);
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
