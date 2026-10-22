//! Registry lifecycle on a real node: ordered Auto fallback across two registered real
//! tokens, pool rejection of unaffordable or inactive explicit selections, and owner
//! deactivation/reactivation observed through actual fee settlement.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::gas_tokens::{transferCall, TokenFixture, TokenKind, TokenTestContext};
use reth_provider::StateProviderFactory;
use seismic_alloy_consensus::GasPayment;
use seismic_revm::gas_token_registry::{token_metadata_slot, GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT};

fn registry_word(context: &TokenTestContext, slot: U256) -> eyre::Result<U256> {
    let state = context.node.inner.provider.latest()?;
    Ok(state
        .storage(GAS_TOKEN_REGISTRY, B256::from(slot.to_be_bytes::<32>()))?
        .map_or(U256::ZERO, |word| word.value))
}

fn assert_entry_active(context: &TokenTestContext, index: u8, active: bool) -> eyre::Result<()> {
    let word = registry_word(context, token_metadata_slot(index))?.to_le_bytes::<32>();
    assert_eq!(word.get(20), Some(&u8::from(active)), "entry {index} active flag");
    Ok(())
}

struct Holdings {
    susdc: U256,
    hyp: U256,
}

impl Holdings {
    fn assert(
        &self,
        context: &TokenTestContext,
        susdc: &TokenFixture,
        hyp: &TokenFixture,
        holder: Address,
        step: &str,
    ) -> eyre::Result<()> {
        assert_eq!(context.token_balance(susdc, holder)?, (self.susdc, true), "{step}: SUSDC");
        assert_eq!(context.token_balance(hyp, holder)?, (self.hyp, false), "{step}: HypERC20");
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_order_fallback_and_activation_on_a_real_node() -> eyre::Result<()> {
    let mut context = TokenTestContext::new(false).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    let susdc = context.bootstrap(TokenKind::Susdc, holder, false).await?;
    let hyp = context.bootstrap(TokenKind::HypErc20, holder, false).await?;
    assert_eq!(registry_word(&context, TOKEN_COUNT_SLOT)?, U256::from(2));
    assert_entry_active(&context, 0, true)?;
    assert_entry_active(&context, 1, true)?;
    let mut held = Holdings { susdc: susdc.funded_amount, hyp: hyp.funded_amount };
    held.assert(&context, &susdc, &hyp, holder, "bootstrap")?;

    // 1. Auto pays with the first active entry in insertion order (SUSDC, index 0), even though the
    //    HypERC20 balance is vastly larger in base units.
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    held.susdc -= susdc.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "auto prefers index 0")?;

    // 2. Drain SUSDC down to one base unit, paying that transfer explicitly in HypERC20 so the
    //    SUSDC balance moves only by the transferred amount.
    let drained = held.susdc - U256::from(1);
    let receipt = context
        .seismic_transaction(
            &signer,
            susdc.token,
            transferCall { to: Address::random(), amount: drained }.abi_encode().into(),
            GasPayment::Token(hyp.token),
        )
        .await?;
    held.susdc = U256::from(1);
    held.hyp -= hyp.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "explicit HypERC20 drain")?;

    // 3. An explicit SUSDC selection is now rejected at admission without fallback, while Auto
    //    skips the unaffordable first entry and settles in HypERC20.
    let raw = context
        .signed_seismic_transaction(
            &signer,
            Address::random(),
            Bytes::new(),
            GasPayment::Token(susdc.token),
        )
        .await?
        .encoded_2718();
    let error = context.submit_expect_rejected(raw.into()).await?;
    assert!(
        error.contains("sender does not have enough funds for the selected gas payment"),
        "unaffordable explicit token must be a typed rejection: {error}"
    );
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    held.hyp -= hyp.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "auto falls back to index 1")?;

    // 4. Deactivate SUSDC and refund the holder: an inactive entry is rejected explicitly and
    //    skipped by Auto regardless of balance, and the registry keeps its order.
    context.set_token_active(susdc.token, false).await?;
    assert_entry_active(&context, 0, false)?;
    assert_entry_active(&context, 1, true)?;
    assert_eq!(registry_word(&context, TOKEN_COUNT_SLOT)?, U256::from(2));
    context.fund(&susdc, holder, susdc.funded_amount).await?;
    held.susdc += susdc.funded_amount;
    held.assert(&context, &susdc, &hyp, holder, "refund while inactive")?;
    let raw = context
        .signed_seismic_transaction(
            &signer,
            Address::random(),
            Bytes::new(),
            GasPayment::Token(susdc.token),
        )
        .await?
        .encoded_2718();
    let error = context.submit_expect_rejected(raw.into()).await?;
    assert!(error.contains("is inactive"), "inactive explicit token must be typed: {error}");
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    held.hyp -= hyp.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "auto skips inactive index 0")?;

    // 5. Reactivation restores both explicit selection and Auto priority for index 0.
    context.set_token_active(susdc.token, true).await?;
    assert_entry_active(&context, 0, true)?;
    let receipt = context
        .seismic_transaction(
            &signer,
            Address::random(),
            Bytes::new(),
            GasPayment::Token(susdc.token),
        )
        .await?;
    held.susdc -= susdc.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "explicit SUSDC after reactivation")?;
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    held.susdc -= susdc.fee_units(&receipt);
    held.assert(&context, &susdc, &hyp, holder, "auto returns to index 0")?;

    // Fees were only ever charged in tokens: the holder never received native funds, and
    // the beneficiary was paid in both assets.
    let state = context.node.inner.provider.latest()?;
    assert!(state.basic_account(&holder)?.unwrap().balance.is_zero());
    assert!(context.token_balance(&susdc, Address::ZERO)?.0 > U256::ZERO);
    assert!(context.token_balance(&hyp, Address::ZERO)?.0 > U256::ZERO);
    Ok(())
}
