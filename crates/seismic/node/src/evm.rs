//! Ethereum EVM support

#[doc(inline)]
pub use reth_evm::execute::BasicBlockExecutorProvider;
#[doc(inline)]
pub use reth_evm_ethereum::execute::EthExecutorProvider;
#[doc(inline)]
pub use reth_evm_ethereum::{EthEvm, SeismicEvmConfig};
