//! reth's database backup functionality
use reth_primitives::{constants::BACKUP_SLOTS, BlockNumber};
use reth_storage_errors::provider::ProviderError;
use reth_tracing::tracing::*;
use std::path::PathBuf;
use tokio::fs;

/// Back up every epoch
pub fn should_backup(finalized_block_number: BlockNumber) -> bool {
    let remainder = finalized_block_number % BACKUP_SLOTS;
    let ans = finalized_block_number != 0 && remainder == 0;
    debug!(target: "consensus::engine::hooks::backup", ?remainder, ?finalized_block_number, ?ans);
    return ans;
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
pub async fn backup_dir(source: &PathBuf, destination: &PathBuf) -> Result<(), ProviderError> {
    debug!(target: "consensus::engine::hooks::backup", ?source, ?destination);

    let source_path = source.as_path();
    let destination_path = destination.as_path();

    // Retrieve the metadata of the source path
    let metadata = fs::metadata(source_path)
        .await
        .map_err(|e| ProviderError::FsPathError(format!("Failed to access source path: {}", e)))?;

    // If the source is a directory, create the destination directory if it does not exist
    if metadata.is_dir() {
        if !destination_path.exists() {
            fs::create_dir_all(destination_path).await.map_err(|e| {
                ProviderError::FsPathError(format!("Failed to create destination directory: {}", e))
            })?;
        }

        // Stack to manage recursive copying
        let mut entries_stack = vec![(source_path.to_path_buf(), destination_path.to_path_buf())];

        while let Some((current_src, current_dst)) = entries_stack.pop() {
            let mut entries = fs::read_dir(&current_src).await.map_err(|e| {
                ProviderError::FsPathError(format!(
                    "Failed to read directory {}: {}",
                    current_src.display(),
                    e
                ))
            })?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| {
                ProviderError::FsPathError(format!("Failed to get diredctory entry: {}", e))
            })? {
                let entry_path = entry.path();
                let entry_name = entry.file_name();
                let dst_path = current_dst.join(&entry_name);
                let entry_metadata = entry.metadata().await.map_err(|e| {
                    ProviderError::FsPathError(format!("Failed to get diredctory entry: {}", e))
                })?;

                if entry_metadata.is_dir() {
                    if !dst_path.exists() {
                        fs::create_dir_all(&dst_path).await.map_err(|e| {
                            ProviderError::FsPathError(format!(
                                "Failed to create directory {}: {}",
                                dst_path.display(),
                                e
                            ))
                        })?;
                    }
                    entries_stack.push((entry_path, dst_path));
                } else {
                    fs::copy(&entry_path, &dst_path).await.map_err(|e| {
                        ProviderError::FsPathError(format!(
                            "Failed to copy file from {} to {}: {}",
                            entry_path.display(),
                            dst_path.display(),
                            e
                        ))
                    })?;
                }
            }
        }
    } else {
        // If the source is a file, copy it directly, creating parent directories if necessary
        if let Some(parent) = destination_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    ProviderError::FsPathError(format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
        }
        fs::copy(source_path, destination_path).await.map_err(|e| {
            ProviderError::FsPathError(format!(
                "Failed to copy file from {} to {}: {}",
                source_path.display(),
                destination_path.display(),
                e
            ))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_recursion::async_recursion;
    use fs::File;
    use std::{collections::HashSet, path::Path};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use ProviderError;

    #[tokio::test]
    async fn test_backup_directory() -> Result<(), ProviderError> {
        // Create temporary source and destination directories
        let source_dir = tempdir().expect("Failed to create temporary source directory");
        let destination_dir = tempdir().expect("Failed to create temporary destination directory");

        let source_path = source_dir.path().to_path_buf();
        let destination_path = destination_dir.path().to_path_buf();

        // Set up source directory structure with files and subdirectories
        create_sample_directory_structure(&source_path).await?;

        // Run the backup
        backup_dir(&source_path, &destination_path).await?;

        // Verify that the contents match
        assert!(directories_are_equal(&source_path, &destination_path).await);

        Ok(())
    }

    /// Helper function to create a sample directory structure with files
    async fn create_sample_directory_structure(root: &Path) -> Result<(), ProviderError> {
        let sub_dir = root.join("subdir");
        tokio::fs::create_dir_all(&sub_dir).await.expect("create directory failed");

        // Create a file in the root directory
        let mut root_file = File::create(root.join("file1.txt")).await.expect("crate file failed");
        root_file.write_all(b"Hello from file1!").await.expect("write failed");

        // Create a file in the subdirectory
        let mut sub_file =
            File::create(sub_dir.join("file2.txt")).await.expect("crate file failed");
        sub_file.write_all(b"Hello from file2!").await.expect("write failed");

        Ok(())
    }

    #[async_recursion]
    async fn directories_are_equal(dir1: &Path, dir2: &Path) -> bool {
        // Try to read dir1 entries asynchronously
        let mut dir1_entries = match fs::read_dir(dir1).await {
            Ok(entries) => entries,
            Err(_) => return false,
        };

        // Collect entries and names from dir1
        let mut dir1_names = HashSet::new();
        let mut dir1_entries_vec = Vec::new();

        while let Ok(Some(entry)) = dir1_entries.next_entry().await {
            let file_name = entry.file_name();
            dir1_names.insert(file_name.clone());
            dir1_entries_vec.push(entry);
        }

        // Try to read dir2 entries asynchronously
        let mut dir2_entries = match fs::read_dir(dir2).await {
            Ok(entries) => entries,
            Err(_) => return false,
        };

        // Collect names from dir2
        let mut dir2_names = HashSet::new();

        while let Ok(Some(entry)) = dir2_entries.next_entry().await {
            let file_name = entry.file_name();
            dir2_names.insert(file_name);
        }

        // If the sets of file names are not equal, the directories are not equal
        if dir1_names != dir2_names {
            return false;
        }

        // Now iterate over entries in dir1
        for entry in dir1_entries_vec {
            let entry_path = entry.path();
            let relative_path = match entry_path.strip_prefix(dir1) {
                Ok(p) => p,
                Err(_) => return false,
            };
            let corresponding_path = dir2.join(relative_path);

            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => return false,
            };

            if metadata.is_dir() {
                // Check that the corresponding directory exists and recurse
                let corresponding_metadata = match fs::metadata(&corresponding_path).await {
                    Ok(m) => m,
                    Err(_) => return false,
                };

                if !corresponding_metadata.is_dir() ||
                    !directories_are_equal(&entry_path, &corresponding_path).await
                {
                    return false;
                }
            } else {
                // Check that the corresponding file exists with matching contents
                let mut file1 = match fs::File::open(&entry_path).await {
                    Ok(f) => f,
                    Err(_) => return false,
                };
                let mut file2 = match fs::File::open(&corresponding_path).await {
                    Ok(f) => f,
                    Err(_) => return false,
                };

                let mut file1_contents = Vec::new();
                let mut file2_contents = Vec::new();

                if file1.read_to_end(&mut file1_contents).await.is_err() {
                    return false;
                }
                if file2.read_to_end(&mut file2_contents).await.is_err() {
                    return false;
                }

                if file1_contents != file2_contents {
                    return false;
                }
            }
        }

        true
    }
}
