use crate::{
    engine::hooks::{EngineHook, EngineHookContext, EngineHookError, EngineHookEvent},
    hooks::EngineHookDBAccessLevel,
};
use futures::FutureExt;
use reth_errors::{ProviderError, RethResult};
use reth_tasks::TaskSpawner;
use std::{
    fmt::Display, path::{Path, PathBuf}, task::{ready, Context, Poll}
};
use reth_db::backup_producer::{self, backup_dir};
use tokio::{fs, sync::oneshot};
use tracing::trace;

/// Manages backing up a data directory under the control of the engine.
///
/// This type controls the backup operation.
#[derive(Debug)]
pub struct BackupHook {
    /// The current state of the backup operation.
    state: BackupProducerState,
    /// The type that can spawn the backup task.
    task_spawner: Box<dyn TaskSpawner>,
    /// The source directory to backup.
    source_dir: PathBuf,
    /// The destination directory where the backup will be stored.
    dest_dir: PathBuf,
}

impl BackupHook {
    /// Creates a new instance of `BackupHook`.
    pub fn new(
        source_dir: PathBuf,
        dest_dir: PathBuf,
        task_spawner: Box<dyn TaskSpawner>,
    ) -> Self {
        Self {
            state: BackupProducerState::Idle,
            task_spawner,
            source_dir,
            dest_dir,
        }
    }

    /// Advances the backup operation state.
    ///
    /// This checks for the result in the channel or returns pending if the backup
    /// is idle.
    fn poll_backup_producer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<RethResult<EngineHookEvent>> {
        let result = match &mut self.state {
            BackupProducerState::Idle => return Poll::Pending,
            BackupProducerState::Running(ref mut rx) => {
                ready!(rx.poll_unpin(cx))
            }
        };

        let event = match result {
            Ok(result) => {
                self.state = BackupProducerState::Idle;
                match result {
                    Ok(_) => EngineHookEvent::Finished(Ok(())),
                    Err(err) => {
                        EngineHookEvent::Finished(Err(EngineHookError::Common(err.into())))
                    }
                }
            }
            Err(_) => {
                // Failed to receive the result.
                EngineHookEvent::Finished(Err(EngineHookError::ChannelClosed))
            }
        };

        Poll::Ready(Ok(event))
    }

    /// Attempts to spawn the backup task if it is idle.
    ///
    /// If the backup is already running, it does nothing.
    fn try_spawn_backup(&mut self) -> RethResult<Option<EngineHookEvent>> {
        match &self.state {
            BackupProducerState::Idle => {
                let source_dir = self.source_dir.clone();
                let dest_dir = self.dest_dir.clone();
                let (tx, rx) = oneshot::channel();

                self.task_spawner.spawn_critical_blocking(
                    "backup_task",
                    Box::pin(async move {
                        let result = backup_dir(&source_dir, &dest_dir).await;
                        let _ = tx.send(result);
                    }),
                );
                self.state = BackupProducerState::Running(rx);

                Ok(Some(EngineHookEvent::Started))
            }
            BackupProducerState::Running(_) => Ok(None),
        }
    }
}

impl EngineHook for BackupHook {
    fn name(&self) -> &'static str {
        "Backup"
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _ctx: EngineHookContext,
    ) -> Poll<RethResult<EngineHookEvent>> {
        // Try to spawn the backup task.
        match self.try_spawn_backup()? {
            Some(event) => return Poll::Ready(Ok(event)),
            None => (),
        }

        // Poll the backup task and check its status.
        self.poll_backup_producer(cx)
    }

    fn db_access_level(&self) -> EngineHookDBAccessLevel {
        EngineHookDBAccessLevel::ReadOnly
    }
}

/// The possible backup operation states within the sync controller.
///
/// [`BackupProducerState::Idle`] means that the backup is currently idle.
/// [`BackupProducerState::Running`] means that the backup is currently running.
#[derive(Debug)]
enum BackupProducerState {
    /// The backup operation is idle.
    Idle,
    /// The backup operation is running and waiting for a response.
    Running(oneshot::Receiver<Result<(), ProviderError>>),
}
