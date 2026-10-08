//! Consensus-import coverage for gas-token fees.
//!
//! Locally built payloads are inserted into the builder node's engine tree as already
//! executed blocks, so the dev-mining tests never make the engine *execute* a token-paying
//! block on import. These tests run a second node that only receives blocks through
//! `engine_newPayload`: it must execute real SUSDC/`HypERC20` fee settlement itself and
//! reach the same state, and it must answer `INVALID` (not fail) for a block whose token
//! payment is deterministically unaffordable or unregistered.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_consensus::{proofs::calculate_transaction_root, BlockHeader};
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types_engine::PayloadStatusEnum;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::gas_tokens::{transferCall, TokenFixture, TokenKind, TokenTestContext};
use reth_primitives_traits::SealedBlock;
use reth_provider::{BlockHashReader, BlockNumReader, StateProviderFactory};
use reth_seismic_node::utils::e2e::SeismicTestNode;
use reth_seismic_primitives::{SeismicBlock, SeismicTransactionSigned};
use seismic_alloy_consensus::GasPayment;

fn head(node: &SeismicTestNode) -> eyre::Result<(u64, alloy_primitives::B256)> {
    // The canonical in-memory head, not the lagging persisted height.
    let number = node.inner.provider.best_block_number()?;
    Ok((number, node.inner.provider.block_hash(number)?.unwrap()))
}

fn assert_token_state_agrees(
    context: &TokenTestContext,
    fixture: &TokenFixture,
    accounts: &[Address],
) -> eyre::Result<()> {
    let importer = context.importer.as_ref().unwrap();
    assert_eq!(head(&context.node)?, head(importer)?, "builder and importer heads must agree");
    for account in accounts {
        assert_eq!(
            fixture.balance_at(importer, *account)?,
            context.token_balance(fixture, *account)?,
            "token balance of {account} must match after consensus import"
        );
    }
    Ok(())
}

/// Every bootstrap, mint/funding, registration, and fee-paying block is executed by the
/// importer through `engine_newPayload`; the harness requires `VALID` for each of them.
async fn assert_imported_token_fees_match_builder(kind: TokenKind) -> eyre::Result<()> {
    let mut context = TokenTestContext::new_with_importer(false, true).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let fixture = context.bootstrap(kind, holder, false).await?;
    assert_token_state_agrees(&context, &fixture, &[holder])?;

    let recipient = Address::random();
    let transferred = U256::from(10).pow(U256::from(kind.decimals()));
    let transfer = transferCall { to: recipient, amount: transferred }.abi_encode();
    let explicit = context
        .seismic_transaction(
            &signer,
            fixture.token,
            transfer.into(),
            GasPayment::Token(fixture.token),
        )
        .await?;
    let auto = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;

    let importer = context.importer.as_ref().unwrap();
    let expected = fixture.funded_amount -
        transferred -
        fixture.fee_units(&explicit) -
        fixture.fee_units(&auto);
    assert_eq!(fixture.balance_at(importer, holder)?, (expected, kind.is_private()));
    assert_eq!(fixture.balance_at(importer, recipient)?, (transferred, kind.is_private()));
    let (reward, reward_private) = fixture.balance_at(importer, Address::ZERO)?;
    assert!(reward > U256::ZERO, "imported execution must credit the beneficiary in tokens");
    assert_eq!(reward_private, kind.is_private());
    let state = importer.inner.provider.latest()?;
    assert!(
        state.basic_account(&holder)?.is_some_and(|account| account.balance.is_zero()),
        "token fees must never be charged natively on import"
    );
    assert_token_state_agrees(&context, &fixture, &[holder, recipient, Address::ZERO])
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_blocks_settle_shielded_susdc_fees_like_the_builder() -> eyre::Result<()> {
    assert_imported_token_fees_match_builder(TokenKind::Susdc).await
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_blocks_settle_public_hyperlane_fees_like_the_builder() -> eyre::Result<()> {
    assert_imported_token_fees_match_builder(TokenKind::HypErc20).await
}

/// Splice `tx` into an otherwise valid empty block template and re-seal it so only the
/// transaction itself can be the reason for rejection.
fn block_with(template: &SeismicBlock, tx: SeismicTransactionSigned) -> SealedBlock<SeismicBlock> {
    let mut block = template.clone();
    block.body.transactions.push(tx);
    block.header.transactions_root = calculate_transaction_root(&block.body.transactions);
    SealedBlock::seal_slow(block)
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_block_with_invalid_token_payment_is_invalid_not_fatal() -> eyre::Result<()> {
    let kind = TokenKind::Susdc;
    let mut context = TokenTestContext::new_with_importer(false, true).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let fixture = context.bootstrap(kind, holder, false).await?;
    let funded = context.token_balance(&fixture, holder)?;

    // A valid empty successor built by the builder node but not submitted to the importer;
    // its header is internally consistent, so only the spliced transaction differs.
    let template: SeismicBlock = context.node.new_payload().await?.block().clone().into_block();
    let importer = context.importer.as_ref().unwrap();
    let before = head(importer)?;
    assert_eq!(template.header.parent_hash(), before.1);

    let pauper = PrivateKeySigner::random();
    let cases = [
        (
            "unaffordable registered token",
            context
                .signed_seismic_transaction(
                    &pauper,
                    Address::random(),
                    Bytes::new(),
                    GasPayment::Token(fixture.token),
                )
                .await?,
            "lack of funds",
        ),
        (
            "unregistered explicit token",
            context
                .signed_seismic_transaction(
                    &signer,
                    Address::random(),
                    Bytes::new(),
                    GasPayment::Token(Address::random()),
                )
                .await?,
            "is not registered",
        ),
        (
            "strict native without native funds",
            context
                .signed_seismic_transaction(
                    &signer,
                    Address::random(),
                    Bytes::new(),
                    GasPayment::Native,
                )
                .await?,
            "lack of funds",
        ),
    ];

    for (name, tx, expected) in cases {
        let status = TokenTestContext::import_block(importer, block_with(&template, tx)).await?;
        let PayloadStatusEnum::Invalid { validation_error } = &status.status else {
            eyre::bail!("{name}: engine_newPayload must return INVALID, got {status:?}");
        };
        assert!(
            validation_error.to_lowercase().contains(expected),
            "{name}: expected a typed payment rejection containing {expected:?}, got {validation_error}"
        );
        assert_eq!(head(importer)?, before, "{name}: an invalid payload must not move the head");
        assert_eq!(
            fixture.balance_at(importer, holder)?,
            funded,
            "{name}: a rejected block must not charge any token fee"
        );
    }

    // The rejections are deterministic invalidity, not internal failures: the same engine
    // keeps importing valid token-paying blocks on the same parent afterwards.
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    let importer = context.importer.as_ref().unwrap();
    assert_eq!(head(importer)?.0, before.0 + 1);
    assert_eq!(
        fixture.balance_at(importer, holder)?,
        (funded.0 - fixture.fee_units(&receipt), kind.is_private())
    );
    assert_token_state_agrees(&context, &fixture, &[holder, Address::ZERO])
}
