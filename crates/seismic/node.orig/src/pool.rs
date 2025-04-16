//! OP-Reth Transaction pool.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use reth_transaction_pool::{
    validate::EthTransactionValidator, CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor,
};
use seismic_primitives::serde_bincode_compat::SeismicTransactionSigned;

/// Type alias for default optimism transaction pool
pub type SeismicTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<Client, SeismicTransactionSigned>>,
    CoinbaseTipOrdering<SeismicTransactionSigned>,
    S,
>;
