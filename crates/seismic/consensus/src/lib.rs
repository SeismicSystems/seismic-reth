//! Optimism Consensus implementation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, sync::Arc};
use alloy_consensus::{BlockHeader as _, EMPTY_OMMER_ROOT_HASH};
use alloy_primitives::{B64, U256};
use core::fmt::Debug;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_hash_number, validate_against_parent_timestamp,
    validate_body_against_header, validate_cancun_gas, validate_header_base_fee,
    validate_header_extra_data, validate_header_gas,
};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{
    Block, BlockBody, BlockHeader, GotExpected, NodePrimitives, RecoveredBlock, SealedBlock,
    SealedHeader,
};

pub mod error;
pub use error::OpConsensusError;
