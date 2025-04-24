//! Loads OP pending block for a RPC response.

use crate::SeismicEthApi;
use alloy_consensus::BlockHeader;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::B256;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use reth_rpc::EthApi;
use reth_rpc_eth_api::{
    helpers::{LoadPendingBlock, SpawnBlocking},
    types::RpcTypes,
    EthApiTypes, FromEthApiError, FromEvmError, FullEthApiTypes, RpcNodeCore,
};
use reth_rpc_eth_types::{EthApiError, PendingBlock};
use reth_seismic_primitives::{SeismicBlock, SeismicReceipt, SeismicTransactionSigned};
use reth_storage_api::{
    BlockReader, BlockReaderIdExt, HeaderProvider, ProviderBlock, ProviderHeader, ProviderReceipt,
    ProviderTx, ReceiptProvider, StateProviderFactory,
};
use reth_transaction_pool::{PoolTransaction, TransactionPool};

impl<N> LoadPendingBlock for SeismicEthApi<N>
where
    Self: SpawnBlocking
        + EthApiTypes<
            NetworkTypes: RpcTypes<
                Header = alloy_rpc_types_eth::Header<ProviderHeader<Self::Provider>>,
            >,
            Error = EthApiError,
        >,
    N: RpcNodeCore<
        Provider: BlockReaderIdExt<
            Transaction = SeismicTransactionSigned,
            Block = SeismicBlock,
            Receipt = SeismicReceipt,
            Header = alloy_consensus::Header,
        > + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
        Pool: TransactionPool<Transaction: PoolTransaction<Consensus = ProviderTx<N::Provider>>>,
        Evm: ConfigureEvm<
            Primitives: NodePrimitives<
                SignedTx = ProviderTx<Self::Provider>,
                BlockHeader = ProviderHeader<Self::Provider>,
                Receipt = ProviderReceipt<Self::Provider>,
                Block = ProviderBlock<Self::Provider>,
            >,
            NextBlockEnvCtx = NextBlockEnvAttributes,
        >,
    >,
    EthApi<N::Provider, N::Pool, N::Network, N::Evm>: LoadPendingBlock
        + FullEthApiTypes<Error = EthApiError>
        + RpcNodeCore<
            Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
            Provider: BlockReaderIdExt<
                Transaction = ProviderTx<Self::Provider>,
                Block = ProviderBlock<Self::Provider>,
                Receipt = ProviderReceipt<Self::Provider>,
                Header = alloy_consensus::Header,
            >,
        >,
    EthApiError: FromEvmError<Self::Evm>,
{
    #[inline]
    fn pending_block(
        &self,
    ) -> &tokio::sync::Mutex<
        Option<PendingBlock<ProviderBlock<Self::Provider>, ProviderReceipt<Self::Provider>>>,
    > {
        self.0.pending_block()
    }

    fn next_env_attributes(
        &self,
        parent: &SealedHeader<ProviderHeader<Self::Provider>>,
    ) -> Result<<Self::Evm as reth_evm::ConfigureEvm>::NextBlockEnvCtx, Self::Error> {
        self.0.next_env_attributes(parent)
    }
}
