//! Seismic-Reth Transaction pool.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use futures_util::future::Either;
use reth_transaction_pool::{CoinbaseTipOrdering, Pool, TransactionValidationTaskExecutor};

mod recent_block_cache;
pub mod screening;
mod transaction;
mod validator;

pub use recent_block_cache::{RecentBlockCache, SEISMIC_TX_RECENT_BLOCK_LOOKBACK};
pub use screening::ScreeningTransactionValidator;
pub use transaction::SeismicPooledTransaction;
pub use validator::SeismicTransactionValidator;

/// Type alias for default seismic transaction pool.
///
/// Uses `Either` to transparently support optional address screening:
/// - `Left` = `SeismicTransactionValidator` (no screening)
/// - `Right` = `ScreeningTransactionValidator<SeismicTransactionValidator>` (with screening)
pub type SeismicTransactionPool<Client, S, T = SeismicPooledTransaction> = Pool<
    TransactionValidationTaskExecutor<
        Either<
            SeismicTransactionValidator<Client, T>,
            ScreeningTransactionValidator<SeismicTransactionValidator<Client, T>>,
        >,
    >,
    CoinbaseTipOrdering<T>,
    S,
>;
