//! Seismic-Reth Transaction pool.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};

mod maintain;
mod recent_block_cache;
mod transaction;
pub mod usdc;
mod validator;

pub use maintain::SeismicBalanceHook;
pub use recent_block_cache::{RecentBlockCache, SEISMIC_TX_RECENT_BLOCK_LOOKBACK};
pub use transaction::SeismicPooledTransaction;
pub use validator::SeismicTransactionValidator;

/// Type alias for default seismic transaction pool
pub type SeismicTransactionPool<Client, S, T = SeismicPooledTransaction> = Pool<
    TransactionValidationTaskExecutor<SeismicTransactionValidator<Client, T>>,
    CoinbaseTipOrdering<T>,
    S,
>;
