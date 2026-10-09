//! Engine reorgs that revert a token balance change or a registry deactivation on a real
//! node. Pool maintenance must re-derive every token-only sender's payability from the new
//! canonical tip, re-promoting transactions that the orphaned branch had demoted, and the
//! orphaned registry/admin transactions must return to the pool like any reverted transaction.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_consensus::BlockHeader;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::gas_tokens::{deactivateTokenCall, TokenKind, TokenTestContext, GAS_PRICE};
use reth_primitives_traits::{SealedBlock, SignedTransaction};
use reth_provider::StateProviderFactory;
use reth_seismic_engine_types::SeismicBuiltPayload;
use reth_seismic_node::utils::test_utils::get_nonce;
use reth_seismic_primitives::SeismicBlock;
use reth_transaction_pool::TransactionPool;
use seismic_alloy_consensus::GasPayment;
use seismic_revm::gas_token_registry::{token_metadata_slot, GAS_TOKEN_REGISTRY};

fn mined_hashes(block: &SealedBlock<SeismicBlock>) -> Vec<B256> {
    block.body().transactions().map(|tx| *tx.tx_hash()).collect()
}

fn head_hash(context: &TokenTestContext) -> eyre::Result<B256> {
    use reth_provider::{BlockHashReader, BlockNumReader};
    let provider = &context.node.inner.provider;
    Ok(provider.block_hash(provider.best_block_number()?)?.unwrap())
}

fn entry_active(context: &TokenTestContext, index: u8) -> eyre::Result<bool> {
    let word = context
        .node
        .inner
        .provider
        .latest()?
        .storage(GAS_TOKEN_REGISTRY, B256::from(token_metadata_slot(index).to_be_bytes::<32>()))?
        .map_or(U256::ZERO, |word| word.value)
        .to_le_bytes::<32>();
    Ok(word.get(20) == Some(&1))
}

/// Shared skeleton: given an empty sibling `replacement` prebuilt on the current head, build
/// an orphan on the same parent carrying `orphan_tx` (which makes the holder's pending
/// transactions unpayable), make the orphan canonical, then reorg back to the sibling.
/// Returns the orphaned transaction hash.
async fn reorg_out(
    context: &mut TokenTestContext,
    replacement: &SeismicBuiltPayload,
    holder_hashes: &[B256],
    orphan_tx: Bytes,
    what: &str,
) -> eyre::Result<B256> {
    let parent = head_hash(context)?;
    assert!(mined_hashes(replacement.block()).is_empty(), "{what}: sibling must be empty");

    let orphan_hash = context.submit(orphan_tx).await?;
    let orphan = context.build_payload().await?;
    assert_eq!(
        mined_hashes(orphan.block()),
        vec![orphan_hash],
        "{what}: the orphan must carry only the reverting transaction; holder txs are skipped"
    );
    assert_ne!(orphan.block().hash(), replacement.block().hash());
    assert_eq!(orphan.block().parent_hash(), parent);
    assert_eq!(replacement.block().parent_hash(), parent);

    context.make_canonical(&orphan).await?;
    assert_eq!(head_hash(context)?, orphan.block().hash());
    context.wait_for_pool_split(holder_hashes, 0, &format!("{what}: orphan canonical")).await?;
    assert!(!context.node.inner.pool.contains(&orphan_hash));

    context.make_canonical(replacement).await?;
    assert_eq!(head_hash(context)?, replacement.block().hash());
    Ok(orphan_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_reverting_a_token_burn_repromotes_the_pending_sequence() -> eyre::Result<()> {
    let mut context = TokenTestContext::new(false).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let susdc = context.bootstrap(TokenKind::Susdc, holder, false).await?;
    let funded = context.token_balance(&susdc, holder)?;
    // The empty sibling must predate the holder's submissions or it would include them.
    let replacement = context.build_payload().await?;

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

    let burn = context
        .signed_susdc_burn(&susdc, holder, susdc.funded_amount - U256::from(1), GAS_PRICE * 2)
        .await?;
    let burn_hash = reorg_out(&mut context, &replacement, &hashes, burn, "burn").await?;

    // The burn is gone from canonical state: the balance is restored, the sequence must be
    // promoted again, and the reverted burn is back in the pool.
    assert_eq!(context.token_balance(&susdc, holder)?, funded);
    context.wait_for_pool_split(&hashes, 3, "after reorg").await?;
    assert!(context.node.inner.pool.contains(&burn_hash), "reverted txs return to the pool");

    // Without the reinjected burn competing for the block, the whole sequence mines at the
    // new tip and settles in SUSDC.
    context.node.inner.pool.remove_transactions(vec![burn_hash]);
    let block = context.advance().await?;
    assert_eq!(mined_hashes(&block), hashes);
    let mut balance = funded.0;
    for hash in &hashes {
        balance -= susdc.fee_units(&context.receipt(*hash).await?);
    }
    assert_eq!(context.token_balance(&susdc, holder)?, (balance, true));
    assert_eq!(get_nonce(&context.client, holder).await, 3);
    assert!(context.node.inner.pool.pooled_transactions().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reorg_reverting_a_deactivation_repromotes_the_explicit_payment() -> eyre::Result<()> {
    let mut context = TokenTestContext::new(false).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let susdc = context.bootstrap(TokenKind::Susdc, holder, false).await?;
    let funded = context.token_balance(&susdc, holder)?;
    let replacement = context.build_payload().await?;

    let tx = context
        .signed_seismic_transaction(
            &signer,
            Address::random(),
            Bytes::new(),
            GasPayment::Token(susdc.token),
        )
        .await?;
    let hashes = vec![context.submit(tx.encoded_2718().into()).await?];
    context.wait_for_pool_split(&hashes, 1, "admission").await?;

    let deactivation = context
        .signed_native_transaction(
            TxKind::Call(GAS_TOKEN_REGISTRY),
            deactivateTokenCall { token: susdc.token }.abi_encode().into(),
            GAS_PRICE * 2,
        )
        .await?;
    let deactivation_hash =
        reorg_out(&mut context, &replacement, &hashes, deactivation, "deactivation").await?;

    // The entry is active again at the new tip; the explicit payment is promoted without
    // resubmission and the orphaned owner transaction waits in the pool.
    assert!(entry_active(&context, 0)?);
    context.wait_for_pool_split(&hashes, 1, "after reorg").await?;
    assert!(context.node.inner.pool.contains(&deactivation_hash));

    // Let the reinjected deactivation re-apply on the new branch: ordered first again, it
    // deactivates the entry and the holder's payment is skipped and demoted exactly as it
    // was on the orphaned branch, proving the pool state is derived from the tip, not history.
    let block = context.advance().await?;
    assert_eq!(mined_hashes(&block), vec![deactivation_hash]);
    assert!(!entry_active(&context, 0)?);
    context.wait_for_pool_split(&hashes, 0, "re-applied deactivation").await?;
    assert_eq!(context.token_balance(&susdc, holder)?, funded);
    assert_eq!(get_nonce(&context.client, holder).await, 0);

    // And reactivation on this branch still promotes and mines it.
    context.set_token_active(susdc.token, true).await?;
    context.wait_for_pool_split(&hashes, 1, "reactivation").await?;
    let block = context.advance().await?;
    assert_eq!(mined_hashes(&block), hashes);
    let receipt = context.receipt(*hashes.first().unwrap()).await?;
    assert_eq!(
        context.token_balance(&susdc, holder)?,
        (funded.0 - susdc.fee_units(&receipt), true)
    );
    assert_eq!(get_nonce(&context.client, holder).await, 1);
    Ok(())
}
