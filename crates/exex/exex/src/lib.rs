//! Execution extensions (`ExEx`).
//!
//! An execution extension is a task that listens to state changes of the node.
//!
//! Some examples of such state derives are rollups, bridges, and indexers.
//!
//! An `ExEx` is a [`Future`] resolving to a `Result<()>` that is run indefinitely alongside the
//! node.
//!
//! `ExEx`'s are initialized using an async closure that resolves to the `ExEx`; this closure gets
//! passed an [`ExExContext`] where it is possible to spawn additional tasks and modify Reth.
//!
//! Most `ExEx`'s will want to derive their state from the [`CanonStateNotification`] channel given
//! in [`ExExContext`]. A new notification is emitted whenever blocks are executed in live and
//! historical sync.
//!
//! # Pruning
//!
//! `ExEx`'s **SHOULD** emit an `ExExEvent::FinishedHeight` event to signify what blocks have been
//! processed. This event is used by Reth to determine what state can be pruned.
//!
//! An `ExEx` will only receive notifications for blocks greater than the block emitted in the
//! event. To clarify: if the `ExEx` emits `ExExEvent::FinishedHeight(0)` it will receive
//! notifications for any `block_number > 0`.
//!
//! # Examples, Assumptions, and Invariants
//!
//! ## Examples
//!
//! ### Simple Indexer ExEx
//! ```no_run
//! use alloy_consensus::BlockHeader;
//! use futures::StreamExt;
//! use reth_exex::ExExContext;
//! use reth_node_api::FullNodeComponents;
//! use reth_provider::CanonStateNotification;
//!
//! async fn my_indexer<N: FullNodeComponents>(
//!     mut ctx: ExExContext<N>,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     // Subscribe to canonical state notifications
//!
//!     while let Some(Ok(notification)) = ctx.notifications.next().await {
//!         if let Some(committed) = notification.committed_chain() {
//!             for block in committed.blocks_iter() {
//!                 // Index or process block data
//!                 println!("Processed block: {}", block.number());
//!             }
//!
//!             // Signal completion for pruning
//!             ctx.send_finished_height(committed.tip().num_hash());
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Assumptions
//!
//! - `ExExs` run indefinitely alongside Reth
//! - `ExExs` receive canonical state notifications for block execution
//! - `ExExs` should handle potential network or database errors gracefully
//! - `ExExs` must emit `FinishedHeight` events for proper state pruning
//!
//! ## Invariants
//!
//! - An ExEx must not block the main Reth execution
//! - Notifications are processed in canonical order
//! - `ExExs` should be able to recover from temporary failures
//! - Memory and resource usage must be controlled
//!
//! ## Performance Considerations
//!
//! - Minimize blocking operations
//! - Use efficient data structures for state tracking
//! - Implement proper error handling and logging
//! - Consider batching operations for better performance
//!
//! [`Future`]: std::future::Future
//! [`ExExContext`]: crate::ExExContext
//! [`CanonStateNotification`]: reth_provider::CanonStateNotification
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod backfill;
pub use backfill::*;

mod context;
pub use context::*;

mod dyn_context;
pub use dyn_context::*;

mod event;
pub use event::*;

mod manager;
pub use manager::*;

mod notifications;
pub use notifications::*;

mod wal;
pub use wal::*;

// Re-export exex types
#[doc(inline)]
pub use reth_exex_types::*;
