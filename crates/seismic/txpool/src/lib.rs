//! OP-Reth Transaction pool.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod conditional;
mod error;
pub mod interop;
pub mod maintain;
pub mod supervisor;
pub use error::InvalidCrossTx;

use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};

/// Type alias for default optimism transaction pool
pub type SeismicTransactionPool<Client, S, T = EthPooledTransaction<SeismicTransactionSigned>> =
    Pool<
        TransactionValidationTaskExecutor<EthTransactionValidator<Client, T>>,
        CoinbaseTipOrdering<T>,
        S,
    >;
