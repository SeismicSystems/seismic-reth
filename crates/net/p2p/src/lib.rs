//! Provides abstractions and commonly used types for p2p.
//!
//! ## Feature Flags
//!
//! - `test-utils`: Export utilities for testing
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// Shared abstractions for downloader implementations.
pub mod download;

/// Traits for implementing P2P block body clients.
pub mod bodies;

/// A downloader that combines two different downloaders/client implementations.
pub mod either;

/// An implementation that uses headers and bodies traits to download full blocks
pub mod full_block;
pub use full_block::{FullBlockClient, NoopFullBlockClient};

/// Traits for implementing P2P Header Clients. Also includes implementations
/// of a Linear and a Parallel downloader generic over the [`Consensus`] and
/// [`HeadersClient`].
///
/// [`Consensus`]: reth_consensus::Consensus
/// [`HeadersClient`]: crate::headers::client::HeadersClient
pub mod headers;

/// Error types broadly used by p2p interfaces for any operation which may produce an error when
/// interacting with the network implementation
pub mod error;

/// Priority enum for `BlockHeader` and `BlockBody` requests
pub mod priority;

/// Syncing related traits.
pub mod sync;

/// Snap related traits.
pub mod snap;

/// Common test helpers for mocking out Consensus, Downloaders and Header Clients.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use bodies::client::BodiesClient;
pub use headers::client::HeadersClient;
use reth_primitives_traits::Block;

/// Helper trait that unifies network behaviour needed for fetching entire blocks.
pub trait BlockClient:
    HeadersClient<Header = <Self::Block as Block>::Header>
    + BodiesClient<Body = <Self::Block as Block>::Body>
    + Unpin
    + Clone
{
    /// The Block type that this client fetches.
    type Block: Block;
}

/// The [`BlockClient`] providing Ethereum block parts.
pub trait EthBlockClient: BlockClient<Block = reth_ethereum_primitives::Block> {}

impl<T> EthBlockClient for T where T: BlockClient<Block = reth_ethereum_primitives::Block> {}
