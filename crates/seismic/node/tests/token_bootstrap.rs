//! Real-contract gas-token bootstrap, including the proxy already present in dev genesis.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::gas_tokens::{
    transferCall, TokenKind, TokenTestContext, IMPLEMENTATION_SLOT, PROXY_ADMIN, TOKEN_PROXY,
};
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_provider::StateProviderFactory;
use reth_seismic_chainspec::SEISMIC_DEV;
use seismic_alloy_consensus::GasPayment;
use seismic_revm::gas_token_registry::{token_metadata_slot, GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT};

async fn assert_bootstrap_and_fee_execution(kind: TokenKind, proxy: bool) -> eyre::Result<()> {
    let original_admin = SEISMIC_DEV.genesis.alloc.get(&PROXY_ADMIN).unwrap().storage.clone();
    let mut context = TokenTestContext::new(proxy).await?;
    let signer = PrivateKeySigner::random();
    let holder = signer.address();
    {
        let state = context.node.inner.provider.latest()?;
        assert!(state
            .storage(GAS_TOKEN_REGISTRY, B256::from(TOKEN_COUNT_SLOT.to_be_bytes::<32>()))?
            .is_none_or(|word| word.value.is_zero() && !word.is_private()));
        assert!(state.basic_account(&holder)?.is_none());
        if proxy {
            // No implementation or token state is preseeded by the test genesis.
            assert!(state
                .storage(TOKEN_PROXY, IMPLEMENTATION_SLOT)?
                .is_none_or(|word| word.value.is_zero()));
            assert_eq!(
                state.storage(PROXY_ADMIN, B256::ZERO)?.unwrap().value.to_be_bytes::<32>(),
                context.wallet.inner.address().into_word().0
            );
        }
    }
    let fixture = context.bootstrap(kind, holder, proxy).await?;
    {
        let state = context.node.inner.provider.latest()?;
        assert!(
            state.basic_account(&holder)?.is_none_or(|account| account.balance.is_zero()),
            "mint/funding transactions must not grant the sender native funds"
        );
        let count = state
            .storage(GAS_TOKEN_REGISTRY, B256::from(TOKEN_COUNT_SLOT.to_be_bytes::<32>()))?
            .unwrap();
        assert_eq!(count.value, U256::from(1));
        assert!(!count.is_private());
        let entry = state.storage(GAS_TOKEN_REGISTRY, B256::from(token_metadata_slot(0)))?.unwrap();
        let bytes = entry.value.to_be_bytes::<32>();
        assert_eq!(Address::from_slice(bytes.get(12..).unwrap()), fixture.token);
        let bytes = entry.value.to_le_bytes::<32>();
        assert_eq!(bytes.get(20), Some(&1), "entry must be active");
        assert_eq!(bytes.get(21), Some(&u8::from(!kind.is_private())));
        assert_eq!(bytes.get(22), Some(&kind.decimals()));
        assert!(!entry.is_private());
        let slot = state
            .storage(
                GAS_TOKEN_REGISTRY,
                B256::from(token_metadata_slot(0).wrapping_add(U256::from(1))),
            )?
            .unwrap();
        assert_eq!(slot.value, kind.balance_slot());
        assert!(!slot.is_private());
        if proxy {
            assert_eq!(fixture.token, TOKEN_PROXY);
            assert_ne!(fixture.token, fixture.implementation);
            let implementation = state.storage(TOKEN_PROXY, IMPLEMENTATION_SLOT)?.unwrap();
            assert_eq!(
                implementation.value.to_be_bytes::<32>(),
                fixture.implementation.into_word().0
            );
            assert!(!implementation.is_private());
            assert!(state
                .storage(fixture.implementation, fixture.balance_key(holder))?
                .is_none_or(|word| word.value.is_zero()));
        }
    }

    let native: U256 =
        context.client.request("eth_getBalance", rpc_params![holder, "latest", true]).await?;
    assert!(
        native.is_zero(),
        "opt-in native balance RPC must not fold token holdings into native funds"
    );

    let recipient = Address::random();
    let transferred = U256::from(10).pow(U256::from(kind.decimals()));
    let transfer = transferCall { to: recipient, amount: transferred }.abi_encode();
    let receipt = context
        .seismic_transaction(
            &signer,
            fixture.token,
            transfer.into(),
            GasPayment::Token(fixture.token),
        )
        .await?;
    assert!(receipt.gas_used > U256::from(21_000), "the real token body must execute");
    let expected = fixture.funded_amount - transferred - fixture.fee_units(&receipt);
    assert_eq!(
        context.token_balance(&fixture, holder)?,
        (expected, kind.is_private()),
        "both the application transfer and actual token gas charge must commit"
    );
    assert_eq!(context.token_balance(&fixture, recipient)?, (transferred, kind.is_private()));

    // Auto must also select the registered token for a sender with zero native balance.
    let receipt = context
        .seismic_transaction(&signer, Address::random(), Bytes::new(), GasPayment::Auto)
        .await?;
    assert_eq!(
        context.token_balance(&fixture, holder)?,
        (expected - fixture.fee_units(&receipt), kind.is_private())
    );
    let (reward, reward_private) = context.token_balance(&fixture, Address::ZERO)?;
    assert!(reward > U256::ZERO, "the block beneficiary must receive token tips");
    assert_eq!(reward_private, kind.is_private());
    let state = context.node.inner.provider.latest()?;
    assert!(state.basic_account(&holder)?.unwrap().balance.is_zero());
    if proxy {
        for account in [holder, recipient, Address::ZERO] {
            assert!(
                state
                    .storage(fixture.implementation, fixture.balance_key(account))?
                    .is_none_or(|word| word.value.is_zero()),
                "transfers and fee settlement must never touch implementation balances"
            );
        }
    }
    assert_eq!(
        SEISMIC_DEV.genesis.alloc.get(&PROXY_ADMIN).unwrap().storage,
        original_admin,
        "the proxy test must not mutate the shared dev administrator"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_susdc_bootstrap_and_shielded_token_fees() -> eyre::Result<()> {
    assert_bootstrap_and_fee_execution(TokenKind::Susdc, false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_hyperlane_erc20_bootstrap_and_public_token_fees() -> eyre::Result<()> {
    assert_bootstrap_and_fee_execution(TokenKind::HypErc20, false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn genesis_proxy_susdc_bootstrap_and_shielded_token_fees() -> eyre::Result<()> {
    assert_bootstrap_and_fee_execution(TokenKind::Susdc, true).await
}
