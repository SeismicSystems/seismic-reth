//! Token-only pool demotion and promotion driven by real balance changes on a real node.
//!
//! A native-less holder queues a three-transaction nonce sequence paid in SUSDC. An admin
//! burn mined ahead of it drains the balance: the builder skips the now-unpayable sequence,
//! maintenance demotes all of it, and a partial refund promotes exactly as many
//! transactions as the cumulative maximum cost allows, one nonce at a time, until a full
//! refund drains the queue. No transaction is ever resubmitted.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_signer_local::PrivateKeySigner;
use common::gas_tokens::{TokenKind, TokenTestContext, GAS_PRICE};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use reth_provider::StateProviderFactory;
use reth_seismic_node::utils::test_utils::get_nonce;
use reth_seismic_primitives::SeismicBlock;
use reth_transaction_pool::TransactionPool;
use seismic_alloy_consensus::GasPayment;

fn mined_hashes(block: &SealedBlock<SeismicBlock>) -> Vec<B256> {
    block.body().transactions().map(|tx| *tx.tx_hash()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn token_balance_changes_demote_and_promote_a_pending_nonce_sequence() -> eyre::Result<()> {
    let kind = TokenKind::Susdc;
    let mut context = TokenTestContext::new(false).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let susdc = context.bootstrap(kind, holder, false).await?;
    // Maximum cost of one fixture transaction, in SUSDC base units (ceil of 6e6 * 20 gwei).
    let max_cost = {
        let wei = U256::from(6_000_000u64) * U256::from(GAS_PRICE);
        let divisor = U256::from(10).pow(U256::from(18 - kind.decimals()));
        wei.div_ceil(divisor)
    };
    assert_eq!(max_cost, U256::from(120_000));

    // Three pending transactions mixing explicit and Auto selection; all can only pay in SUSDC.
    let mut hashes = Vec::new();
    for (nonce, payment) in
        [GasPayment::Token(susdc.token), GasPayment::Auto, GasPayment::Token(susdc.token)]
            .into_iter()
            .enumerate()
    {
        let tx = context
            .signed_seismic_transaction_at(
                &signer,
                nonce as u64,
                Address::random(),
                Bytes::new(),
                payment,
            )
            .await?;
        hashes.push(context.submit(tx.encoded_2718().into()).await?);
    }
    context.wait_for_pool_split(&hashes, 3, "admission").await?;

    // 1. The admin burn is ordered first and leaves one base unit: the builder must skip the whole
    //    dependent sequence rather than fail, and maintenance demotes all of it.
    let burn = context
        .signed_susdc_burn(&susdc, holder, susdc.funded_amount - U256::from(1), GAS_PRICE * 2)
        .await?;
    let burn_hash = context.submit(burn).await?;
    let block = context.advance().await?;
    assert_eq!(mined_hashes(&block), vec![burn_hash], "only the burn may be mined");
    context.receipt(burn_hash).await?;
    assert_eq!(context.token_balance(&susdc, holder)?, (U256::from(1), true));
    assert_eq!(get_nonce(&context.client, holder).await, 0);
    context.wait_for_pool_split(&hashes, 0, "after burn").await?;
    assert!(mined_hashes(&context.advance().await?).is_empty(), "queued txs are not retried");
    assert!(hashes.iter().all(|hash| context.node.inner.pool.contains(hash)));

    // 2. Refund enough for one maximum cost but not two: only nonce 0 is promoted. The mint block
    //    itself mines only the mint, because promotion follows the canonical update.
    let partial = max_cost * U256::from(2) - U256::from(2);
    context.fund(&susdc, holder, partial).await?;
    assert_eq!(context.token_balance(&susdc, holder)?.0, partial + U256::from(1));
    context.wait_for_pool_split(&hashes, 1, "after partial refund").await?;

    // 3. Each mined transaction charges far less than its maximum, so the next nonce becomes
    //    affordable and is promoted only once its predecessor is canonical.
    let mut balance = partial + U256::from(1);
    for (index, hash) in hashes.iter().enumerate() {
        let block = context.advance().await?;
        assert_eq!(mined_hashes(&block), vec![*hash], "nonce {index} must mine alone");
        let receipt = context.receipt(*hash).await?;
        balance -= susdc.fee_units(&receipt);
        assert_eq!(context.token_balance(&susdc, holder)?, (balance, true));
        assert_eq!(get_nonce(&context.client, holder).await, index as u64 + 1);
        let remaining = hashes.get(index + 1..).unwrap_or_default();
        context
            .wait_for_pool_split(remaining, usize::from(!remaining.is_empty()), "promotion")
            .await?;
    }

    assert!(hashes.iter().all(|hash| !context.node.inner.pool.contains(hash)));
    let state = context.node.inner.provider.latest()?;
    assert!(state.basic_account(&holder)?.is_some_and(|account| account.balance.is_zero()));
    Ok(())
}
