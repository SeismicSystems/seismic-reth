//! Loads Seismic pending block for a RPC response.

use crate::{SeismicEthApi, SeismicEthApiError};
use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_evm::NextBlockEnvAttributes;
use reth_primitives_traits::SealedHeader;
use reth_rpc_eth_api::{helpers::LoadPendingBlock, FromEvmError, RpcConvert, RpcNodeCore};
use reth_rpc_eth_types::PendingBlock;
use reth_storage_api::ProviderHeader;

impl<N, Rpc> LoadPendingBlock for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    SeismicEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives>,
{
    #[inline]
    fn pending_block(&self) -> &tokio::sync::Mutex<Option<PendingBlock<Self::Primitives>>> {
        self.inner.pending_block()
    }

    #[inline]
    fn pending_env_builder(
        &self,
    ) -> &dyn reth_rpc_eth_api::helpers::pending_block::PendingEnvBuilder<Self::Evm> {
        self.inner.eth_api.pending_env_builder()
    }

    #[inline]
    fn pending_block_kind(&self) -> reth_rpc_eth_types::builder::config::PendingBlockKind {
        self.inner.eth_api.pending_block_kind()
    }

    fn next_env_attributes(
        &self,
        parent: &SealedHeader<ProviderHeader<Self::Provider>>,
    ) -> Result<<Self::Evm as reth_evm::ConfigureEvm>::NextBlockEnvCtx, Self::Error> {
        Ok(NextBlockEnvAttributes {
            timestamp: parent.timestamp().saturating_add(12),
            suggested_fee_recipient: parent.beneficiary(),
            prev_randao: B256::random(),
            gas_limit: parent.gas_limit(),
            parent_beacon_block_root: parent.parent_beacon_block_root(),
            withdrawals: None,
        })
    }
}
