//! Loads Seismic pending block for a RPC response.

use crate::SeismicEthApi;
use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_node_api::NodePrimitives;
use reth_primitives_traits::SealedHeader;
use reth_rpc_eth_api::{
    helpers::{LoadPendingBlock, SpawnBlocking}, types::RpcTypes, EthApiTypes, FromEvmError, RpcConvert, RpcNodeCore
};
use reth_rpc_eth_types::{EthApiError, PendingBlock};
use reth_seismic_primitives::{SeismicBlock, SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{
    BlockReaderIdExt, ProviderBlock, ProviderHeader, ProviderReceipt, ProviderTx,
    StateProviderFactory,
};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use seismic_alloy_network::SeismicReth;

impl<N, Rpc> LoadPendingBlock for SeismicEthApi<N, Rpc>
where
    // Self: SpawnBlocking
    //     + EthApiTypes<
    //         NetworkTypes: RpcTypes<
    //             Header = alloy_rpc_types_eth::Header<ProviderHeader<Self::Provider>>,
    //         >,
    //         Error = EthApiError,
    //     >,
    N: RpcNodeCore,
    // <
    //     Provider: BlockReaderIdExt<
    //         Transaction = SeismicTransactionSigned,
    //         Block = SeismicBlock,
    //         Receipt = SeismicReceipt,
    //         Header = alloy_consensus::Header,
    //     > + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
    //                   + StateProviderFactory,
    //     Pool: TransactionPool<Transaction: PoolTransaction<Consensus = ProviderTx<N::Provider>>>,
    //     Evm: ConfigureEvm<
    //         Primitives: NodePrimitives<
    //             SignedTx = ProviderTx<Self::Provider>,
    //             BlockHeader = ProviderHeader<Self::Provider>,
    //             Receipt = ProviderReceipt<Self::Provider>,
    //             Block = ProviderBlock<Self::Provider>,
    //         >,
    //         NextBlockEnvCtx = NextBlockEnvAttributes,
    //     >,
    // >,
    EthApiError: FromEvmError<Self::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Network = SeismicReth>,
{
    #[inline]
    fn pending_block(&self) -> &tokio::sync::Mutex<Option<PendingBlock<Self::Primitives>>> {
        self.inner.pending_block()
    }

    #[inline]
    fn pending_env_builder(&self) -> &dyn reth_rpc_eth_api::helpers::pending_block::PendingEnvBuilder<Self::Evm> {
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
