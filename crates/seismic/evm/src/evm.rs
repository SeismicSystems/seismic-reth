//! This example shows how to implement a node with a custom EVM

#![warn(unused_crate_dependencies)]

use alloy_consensus::{EthereumTxEnvelope, SignableTransaction, Signed, TxLegacy};
use alloy_evm::{eth::EthEvmContext, Evm, EvmFactory};
use alloy_genesis::Genesis;
use alloy_primitives::{address, keccak256, Address, Bytes, Signature, TxHash};
use derive_more::{AsRef, Deref};
use reth::{
    builder::{
        components::{BasicPayloadServiceBuilder, ExecutorBuilder, PayloadBuilderBuilder},
        BuilderContext, NodeBuilder,
    },
    payload::{EthBuiltPayload, EthPayloadBuilderAttributes},
    revm::{
        context::{result::ResultAndState, BlockEnv, Cfg, Context, TxEnv},
        context_interface::{
            result::{EVMError, HaltReason},
            ContextTr,
        },
        handler::{EthPrecompiles, PrecompileProvider},
        inspector::{Inspector, NoOpInspector},
        interpreter::{interpreter::EthInterpreter, InterpreterResult},
        precompile::{PrecompileFn, PrecompileOutput, PrecompileResult, Precompiles},
        primitives::hardfork::SpecId,
        MainBuilder, MainContext,
    },
    rpc::types::{engine::PayloadAttributes, Block},
    tasks::TaskManager,
    transaction_pool::{PoolTransaction, TransactionPool},
};
use reth_chainspec::{Chain, ChainSpec};
use reth_evm::{execute::BasicBlockExecutorProvider, Database, EvmEnv, IntoTxEnv};
use reth_evm_ethereum::{EthEvm, EthEvmConfig};
use reth_node_api::{FullNodeTypes, NodeTypes, NodeTypesWithEngine, PayloadTypes};
use reth_primitives::{
    recover_signer_unchecked, transaction::recover_signer, BlockBody, EthPrimitives,
    TransactionSigned,
};
use reth_primitives_traits::{transaction::signed::RecoveryError, BlockHeader, SignedTransaction};
use reth_tracing::{RethTracer, Tracer};
use std::sync::OnceLock;

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SeismicExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SeismicExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = EthEvmConfig<SeismicEvmFactory>;
    type Executor = BasicBlockExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config =
            EthEvmConfig::new_with_evm_factory(ctx.chain_spec(), SeismicEvmFactory::default());
        Ok((evm_config.clone(), BasicBlockExecutorProvider::new(evm_config)))
    }
}

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SeismicPayloadBuilder {
    inner: EthereumPayloadBuilder,
}

impl<Types, Node, Pool> PayloadBuilderBuilder<Node, Pool> for SeismicPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Types::Payload: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = PayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    type PayloadBuilder = reth_ethereum_payload_builder::EthereumPayloadBuilder<
        Pool,
        Node::Provider,
        EthEvmConfig<SeismicEvmFactory>,
    >;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let evm_config =
            EthEvmConfig::new_with_evm_factory(ctx.chain_spec(), SeismicEvmFactory::default());
        self.inner.build(evm_config, ctx, pool)
    }
}

pub use alloy_seismic_evm::{SeismicEvmFactory, SeismicEvm};
