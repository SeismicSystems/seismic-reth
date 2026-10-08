//! Registry change and dependent token payment in the same block on a real node.
//!
//! A holder's explicit `Token(SUSDC)` transaction is admitted while the entry is active.
//! The owner's `deactivateToken` is ordered ahead of it in the next block, so the builder
//! must skip the token payment as deterministic invalidity (not fail the block), pool
//! maintenance must demote the now-unpayable transaction instead of retrying it every
//! block, and reactivation must promote and mine it without resubmission.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::gas_tokens::{deactivateTokenCall, TokenKind, TokenTestContext, GAS_PRICE};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use reth_provider::StateProviderFactory;
use reth_seismic_node::utils::test_utils::get_nonce;
use reth_seismic_primitives::SeismicBlock;
use reth_transaction_pool::TransactionPool;
use seismic_alloy_consensus::GasPayment;
use seismic_revm::gas_token_registry::GAS_TOKEN_REGISTRY;
use std::time::Duration;

fn mined_hashes(block: &SealedBlock<SeismicBlock>) -> Vec<B256> {
    block.body().transactions().map(|tx| *tx.tx_hash()).collect()
}

/// Pool maintenance reacts to canonical-state notifications asynchronously; poll briefly.
async fn wait_for_pool_state(
    context: &TokenTestContext,
    hash: B256,
    pending: bool,
    what: &str,
) -> eyre::Result<()> {
    let pool = &context.node.inner.pool;
    for _ in 0..100 {
        let is_pending = pool.pending_transactions().iter().any(|tx| *tx.hash() == hash);
        let is_queued = pool.queued_transactions().iter().any(|tx| *tx.hash() == hash);
        if is_pending == pending && is_queued != pending {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eyre::bail!("{what}: transaction {hash} did not reach pending={pending} in the pool")
}

#[tokio::test(flavor = "multi_thread")]
async fn same_block_deactivation_skips_then_demotes_and_reactivation_promotes() -> eyre::Result<()>
{
    let mut context = TokenTestContext::new(false).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let susdc = context.bootstrap(TokenKind::Susdc, holder, false).await?;
    let funded = context.token_balance(&susdc, holder)?;

    // Admitted while SUSDC is active: pending, explicit, no fallback asset.
    let token_tx = context
        .signed_seismic_transaction(
            &signer,
            Address::random(),
            Bytes::new(),
            GasPayment::Token(susdc.token),
        )
        .await?;
    let token_hash = *token_tx.tx_hash();
    assert_eq!(context.submit(token_tx.encoded_2718().into()).await?, token_hash);
    wait_for_pool_state(&context, token_hash, true, "admission").await?;

    // The owner's deactivation outbids the holder so the builder orders it first.
    let deactivation = context
        .signed_native_transaction(
            TxKind::Call(GAS_TOKEN_REGISTRY),
            deactivateTokenCall { token: susdc.token }.abi_encode().into(),
            GAS_PRICE * 2,
        )
        .await?;
    let deactivation_hash = context.submit(deactivation).await?;

    let block = context.advance().await?;
    assert_eq!(
        mined_hashes(&block),
        vec![deactivation_hash],
        "the block must contain only the deactivation; the token payment is skipped, not fatal"
    );
    context.receipt(deactivation_hash).await?;
    assert_eq!(get_nonce(&context.client, holder).await, 0, "the skipped tx consumed no nonce");
    assert_eq!(context.token_balance(&susdc, holder)?, funded, "and charged no fee");

    // Maintenance sees the registry write and demotes the holder's transaction: it stays in
    // the pool but is no longer offered to the builder.
    wait_for_pool_state(&context, token_hash, false, "after deactivation").await?;
    let block = context.advance().await?;
    assert!(mined_hashes(&block).is_empty(), "a demoted token payment must not be retried");
    assert!(context.node.inner.pool.contains(&token_hash));

    // Reactivation promotes the same transaction, which then mines and pays in SUSDC.
    context.set_token_active(susdc.token, true).await?;
    wait_for_pool_state(&context, token_hash, true, "after reactivation").await?;
    let block = context.advance().await?;
    assert_eq!(mined_hashes(&block), vec![token_hash]);
    let receipt = context.receipt(token_hash).await?;
    assert_eq!(get_nonce(&context.client, holder).await, 1);
    assert_eq!(
        context.token_balance(&susdc, holder)?,
        (funded.0 - susdc.fee_units(&receipt), true)
    );
    assert!(!context.node.inner.pool.contains(&token_hash));
    let state = context.node.inner.provider.latest()?;
    assert!(
        state.basic_account(&holder)?.is_some_and(|account| account.balance == U256::ZERO),
        "the holder paid only in SUSDC"
    );
    Ok(())
}
