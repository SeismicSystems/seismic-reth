//! reth's database backup functionality
use alloy_eips::BlockNumHash;
use reth_errors::ProviderError;
use reth_node_core::dirs::{ChainPath, DataDirPath};
use std::{
    path::PathBuf,
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::*;

/// Configuration for the backup service
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Source directory to backup
    pub source_dir: PathBuf,
    /// Destination directory for backups
    pub dest_dir: PathBuf,
}

/// Service that handles database backups based on block events
#[derive(Debug)]
pub struct BackupService {
    /// Incoming backup requests
    incoming: Receiver<BackupAction>,
    /// The data directory for the engine tree.
    data_dir: ChainPath<DataDirPath>,
}
/// A signal to the backup service that a backup should be performed.
#[derive(Debug)]
pub enum BackupAction {
    /// Perform a backup at the given block number.
    BackupAtBlock(BlockNumHash, oneshot::Sender<Option<BlockNumHash>>),
}
impl BackupService {
    /// Create a new backup service
    pub fn new(incoming: Receiver<BackupAction>, data_dir: ChainPath<DataDirPath>) -> Self {
        Self { incoming, data_dir }
    }

    /// Main loop that processes backup actions
    pub fn run(self) -> Result<(), ProviderError> {
        debug!(target: "engine::backup", service=?self, "Backup service starting to run");
        while let Ok(action) = self.incoming.recv() {
            debug!(target: "engine::backup", action=?action, "Backup service received action");
            match action {
                BackupAction::BackupAtBlock(block_number, sender) => {
                    let result = self.perform_backup(block_number);
                    if let Err(e) = result {
                        error!(target: "engine::backup", ?e, "Backup failed");
                        let _ = sender.send(None);
                    } else {
                        let _ = sender.send(Some(block_number));
                    }
                }
            }
        }
        Ok(())
    }

    /// Perform the actual backup operation
    fn perform_backup(&self, block_number: BlockNumHash) -> Result<(), ProviderError> {
        debug!(target: "engine::backup", ?block_number, "Starting backup");
        let backup_path = PathBuf::from(format!("{}_backup", self.data_dir.data_dir().display(),));

        // Perform the actual backup using the provider
        BackupService::backup_dir(&PathBuf::from(self.data_dir.data_dir()), &backup_path)?;

        info!(
            target: "engine::backup",
            ?block_number,
            "Backup completed successfully"
        );

        Ok(())
    }

    /// Recursively copies the source directory to the destination directory.
    ///
    /// This function uses asynchronous file operations to perform the backup.
    ///
    /// # Arguments
    ///
    /// * `source` - The source directory to backup.
    /// * `destination` - The destination directory where the backup will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the backup is successful.
    /// * `Err(anyhow::Error)` if an error occurs during the backup.
    pub fn backup_dir(source: &PathBuf, destination: &PathBuf) -> Result<(), ProviderError> {
        debug!(target: "engine::backup", ?source, ?destination);

        let source_path = source.as_path();
        let destination_path = destination.as_path();

        // Retrieve the metadata of the source path
        let metadata = std::fs::metadata(source_path)
            .expect(&format!("Failed to access source path: {} ", source_path.display(),));

        // If the source is a directory, create the destination directory if it does not exist
        if metadata.is_dir() {
            if !destination_path.exists() {
                std::fs::create_dir_all(destination_path)
                    .expect(&format!("Failed to create destination directory"));
            }

            // Stack to manage recursive copying
            let mut entries_stack =
                vec![(source_path.to_path_buf(), destination_path.to_path_buf())];

            while let Some((current_src, current_dst)) = entries_stack.pop() {
                let mut entries = std::fs::read_dir(&current_src)
                    .expect(&format!("Failed to read directory {}", current_src.display(),));

                while let Some(entry) =
                    entries.next().transpose().expect(&format!("Failed to get diredctory entry"))
                {
                    let entry_path = entry.path();
                    let entry_name = entry.file_name();
                    let dst_path = current_dst.join(&entry_name);
                    let entry_metadata =
                        entry.metadata().expect(&format!("Failed to get diredctory entry"));

                    if entry_metadata.is_dir() {
                        if !dst_path.exists() {
                            std::fs::create_dir_all(&dst_path).expect(&format!(
                                "Failed to create directory {}",
                                dst_path.display(),
                            ));
                        }
                        entries_stack.push((entry_path, dst_path));
                    } else {
                        std::fs::copy(&entry_path, &dst_path).expect(&format!(
                            "Failed to copy file from {} to {}",
                            entry_path.display(),
                            dst_path.display(),
                        ));
                    }
                }
            }
        } else {
            // If the source is a file, copy it directly, creating parent directories if necessary
            if let Some(parent) = destination_path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .expect(
                            &format!("Failed to create parent directory {}", parent.display(),),
                        );
                }
            }
            std::fs::copy(source_path, destination_path).expect(&format!(
                "Failed to copy file from {} to {}",
                source_path.display(),
                destination_path.display(),
            ));
        }

        Ok(())
    }
}

/// Errors that can occur during backup operations
#[derive(Debug, Error)]
pub enum BackupError {
    /// IO error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Provider error
    #[error(transparent)]
    Provider(#[from] reth_provider::ProviderError),
}

/// Handle to interact with the backup service
#[derive(Debug)]
pub struct BackupHandle {
    /// The sender for backup actions
    pub sender: Sender<BackupAction>,
    /// The receiver from backup service
    pub rx: Option<(oneshot::Receiver<Option<BlockNumHash>>, Instant)>,
    /// The latest backup block number
    pub latest_backup_block: BlockNumHash,
}

impl BackupHandle {
    /// Create a new backup handle
    pub fn new(sender: Sender<BackupAction>) -> Self {
        Self { sender, rx: None, latest_backup_block: BlockNumHash::default() }
    }

    /// Spawn a new backup service
    pub fn spawn_service(data_dir: ChainPath<DataDirPath>) -> BackupHandle {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = BackupHandle::new(tx);

        let service = BackupService::new(rx, data_dir);
        std::thread::Builder::new()
            .name("Backup Service".to_string())
            .spawn(move || {
                if let Err(err) = service.run() {
                    error!(target: "engine::backup", ?err, "Backup service failed");
                }
            })
            .unwrap();

        handle
    }

    /// Checks if a backup is currently in progress.
    pub fn in_progress(&self) -> bool {
        self.rx.is_some()
    }

    /// Sets state for a started backup task.
    pub(crate) fn start(&mut self, rx: oneshot::Receiver<Option<BlockNumHash>>) {
        self.rx = Some((rx, Instant::now()));
    }

    /// Sets state for a finished backup task.
    pub fn finish(&mut self, block_number: BlockNumHash) {
        self.latest_backup_block = block_number;
        self.rx = None;
    }
}
