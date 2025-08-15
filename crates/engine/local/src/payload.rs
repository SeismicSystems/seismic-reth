//! The implementation of the [`PayloadAttributesBuilder`] for the
//! [`LocalEngineService`](super::service::LocalEngineService).

use alloy_primitives::{Address, B256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use std::sync::Arc;

/// The attributes builder for local Ethereum payload.
#[derive(Debug)]
#[non_exhaustive]
pub struct LocalPayloadAttributesBuilder<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> LocalPayloadAttributesBuilder<ChainSpec> {
    /// Creates a new instance of the builder.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes>
    for LocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    // timestamp is in milliseconds when passed into here,  will store it as milliseconds in payload attributes (similar to payload attributes emitted from consensus layer)
    // use timestamp in seconds for is_shanghai_active_at_timestamp and is_cancun_active_at_timestamp

    fn build(&self, timestamp: u64) -> EthPayloadAttributes {

        let timestamp_seconds = if cfg!(feature = "timestamp-in-seconds") { timestamp } else { timestamp / 1000 };  

        EthPayloadAttributes {
            timestamp: timestamp,
            prev_randao: B256::random(),
            suggested_fee_recipient: Address::random(),
            withdrawals: self
                .chain_spec
                .is_shanghai_active_at_timestamp(timestamp_seconds)
                .then(Default::default),
            parent_beacon_block_root: self
                .chain_spec
                .is_cancun_active_at_timestamp(timestamp_seconds)
                .then(B256::random),
        }
    }
}

#[cfg(feature = "op")]
impl<ChainSpec> PayloadAttributesBuilder<op_alloy_rpc_types_engine::OpPayloadAttributes>
    for LocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> op_alloy_rpc_types_engine::OpPayloadAttributes {
        op_alloy_rpc_types_engine::OpPayloadAttributes {
            payload_attributes: self.build(timestamp),
            // Add dummy system transaction
            transactions: Some(vec![
                reth_optimism_chainspec::constants::TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056
                    .into(),
            ]),
            no_tx_pool: None,
            gas_limit: None,
            eip_1559_params: None,
        }
    }
}

/// A temporary workaround to support local payload engine launcher for arbitrary payload
/// attributes.
// TODO(mattsse): This should be reworked so that LocalPayloadAttributesBuilder can be implemented
// for any
pub trait UnsupportedLocalAttributes: Send + Sync + 'static {}

impl<T, ChainSpec> PayloadAttributesBuilder<T> for LocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + 'static,
    T: UnsupportedLocalAttributes,
{
    fn build(&self, _: u64) -> T {
        panic!("Unsupported payload attributes")
    }
}
