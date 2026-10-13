//! Seismic next-block attributes.
//!
//! Wraps the stock Ethereum attributes and adds the sub-second component of the block timestamp,
//! which the block environment ([`alloy_seismic_evm::SeismicBlockEnv`]) and the assembler (via
//! the header's `extra_data`) need.

use reth_evm::NextBlockEnvAttributes;

/// Attributes for the next block's environment.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicNextBlockEnvAttributes {
    /// The stock attributes. `timestamp` is in Unix seconds.
    #[deref]
    pub inner: NextBlockEnvAttributes,
    /// Sub-second (milliseconds) component of the block timestamp, `0..1000`.
    pub timestamp_millis_part: u64,
}

impl SeismicNextBlockEnvAttributes {
    /// Returns the block time in Unix milliseconds.
    pub const fn timestamp_millis(&self) -> u64 {
        reth_seismic_primitives::header::join_timestamp_millis(
            self.inner.timestamp,
            self.timestamp_millis_part,
        )
    }
}

impl From<NextBlockEnvAttributes> for SeismicNextBlockEnvAttributes {
    /// Wraps stock attributes with a zero sub-second component.
    fn from(inner: NextBlockEnvAttributes) -> Self {
        Self { inner, timestamp_millis_part: 0 }
    }
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<alloy_consensus::Header>
    for SeismicNextBlockEnvAttributes
{
    fn build_pending_env(
        parent: &reth_primitives_traits::SealedHeader<alloy_consensus::Header>,
    ) -> Self {
        use reth_seismic_primitives::SeismicBlockHeader;
        // The stock builder advances the parent's seconds timestamp by one slot; the pending
        // block keeps the parent's sub-second component.
        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent),
            timestamp_millis_part: parent.timestamp_millis_part(),
        }
    }
}
