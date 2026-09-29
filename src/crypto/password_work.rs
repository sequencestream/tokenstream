//! Shared, non-queueing admission for CPU and memory intensive password work.
use std::sync::Arc;
use tokio::sync::Semaphore;

const DEFAULT_PASSWORD_CAPACITY: usize = 32;

#[derive(Clone, Debug)]
pub struct PasswordWork {
    slots: Arc<Semaphore>,
}

/// Why a password computation was not completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordWorkError {
    /// No compute slot was available; admission never queues.
    Busy,
    /// The blocking task ended without a result.
    Failed,
}

impl Default for PasswordWork {
    /// A self-contained budget. Independent components never share a default
    /// budget, so an unconfigured caller cannot starve an unrelated one.
    fn default() -> Self {
        Self::new(DEFAULT_PASSWORD_CAPACITY)
    }
}

impl PasswordWork {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            slots: Arc::new(Semaphore::new(capacity)),
        }
    }

    pub async fn run<F, T>(&self, work: F) -> Result<T, PasswordWorkError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| PasswordWorkError::Busy)?;
        tokio::task::spawn_blocking(move || {
            // The computation owns admission even if its async caller is cancelled.
            let _permit = permit;
            work()
        })
        .await
        .map_err(|_| PasswordWorkError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_call_keeps_capacity_until_work_finishes_and_runtime_progresses() {
        let work = PasswordWork::new(1);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let copy = work.clone();
        let task = tokio::spawn(async move {
            copy.run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), ready)
            .await
            .unwrap()
            .unwrap();
        assert!(
            work.run(|| panic!("must never be submitted"))
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
        assert!(
            work.run(|| ()).await.is_err(),
            "cancelled caller cannot free running work"
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while work.slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(work.run(|| 42).await.unwrap(), 42);
        assert!(
            work.run(|| panic!("simulated computation failure"))
                .await
                .is_err()
        );
        assert_eq!(work.run(|| 43).await.unwrap(), 43);
    }

    #[tokio::test]
    async fn an_unconfigured_budget_never_starves_an_independent_one() {
        let configured = PasswordWork::new(1);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let copy = configured.clone();
        let task = tokio::spawn(async move {
            copy.run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
        });
        ready.await.unwrap();
        assert!(configured.run(|| ()).await.is_err());

        // A component that never opted into a shared budget keeps its own.
        assert_eq!(PasswordWork::default().run(|| 7).await.unwrap(), 7);
        assert_eq!(PasswordWork::default().run(|| 8).await.unwrap(), 8);

        release.send(()).unwrap();
        task.await.unwrap().unwrap();
    }
}
