use alloy_consensus::{TxEnvelope, TxSeismic};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::engine::PayloadAttributes;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_tee::{
    mock::{MockTeeServer, MockWallet},
    WalletAPI,
};
use reth_tracing::tracing::*;
use secp256k1::SecretKey;
use tokio::task;

pub async fn start_mock_tee_server() {
    let _ = task::spawn(async {
        let tee_server = MockTeeServer::new("127.0.0.1:7878");
        tee_server.run().await.map_err(|_| eyre::Error::msg("tee server failed"))
    });
}

/// Helper function to create a new eth payload attributes
pub fn seismic_payload_attributes(timestamp: u64) -> EthPayloadBuilderAttributes {
    let attributes = PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
        target_blobs_per_block: None,
        max_blobs_per_block: None,
    };
    EthPayloadBuilderAttributes::new(B256::ZERO, attributes)
}

/// Create a seismic transaction
pub async fn seismic_tx(
    sk_wallet: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    decrypted_input: Bytes,
) -> Bytes {
    let sk = SecretKey::from_slice(&sk_wallet.credential().to_bytes())
        .expect("32 bytes, within curve order");
    let tee_wallet = MockWallet {};

    let encrypted_input =
        <MockWallet as WalletAPI>::encrypt(&tee_wallet, decrypted_input.to_vec(), nonce, &sk)
            .unwrap();

    debug!(target: "e2e:seismic_tx", "encrypted_input: {:?}", encrypted_input.clone());
    debug!(target: "e2e:seismic_tx", "encrypted_input: {:?}", Bytes::from(encrypted_input.clone()));

    let tx = TransactionRequest {
        nonce: Some(nonce),
        value: Some(U256::from(0)),
        to: Some(to),
        gas: Some(600000),
        gas_price: Some(20e9 as u128),
        max_fee_per_gas: Some(20e9 as u128),
        max_priority_fee_per_gas: Some(20e9 as u128),
        chain_id: Some(chain_id),
        input: TransactionInput { input: Some(Bytes::from(encrypted_input)), data: None },
        transaction_type: Some(TxSeismic::TX_TYPE),
        ..Default::default()
    };

    let signed = TransactionTestContext::sign_tx(sk_wallet.clone(), tx).await;
    debug!(target: "e2e:seismic_tx", "signed: {:?}", signed.clone());
    <TxEnvelope as Encodable2718>::encoded_2718(&signed).into()
}

// pub struct SeismicTransactionTestContext;
// impl SeismicTransactionTestContext {
//     /// Creates an arbitrary and signs it, returning bytes

//     /// Creates a static transfer and signs it, returning bytes
//     pub async fn deploy_tx_bytes(chain_id: u64, wallet: PrivateKeySigner, nonce: u64) -> Bytes {
//         // Source code of the contract deployed:
//         // pragma solidity ^0.8.0;

//         // contract NoOpContract {
//         //     // A function that does nothing and has no return value.
//         //     function noop() external pure {
//         //         // This function is intentionally left blank.
//         //     }
//         // }

//         let contract_deploy =
// Bytes::from_static(&hex!("
// 6080604052348015600e575f5ffd5b50606a80601a5f395ff3fe6080604052348015600e575f5ffd5b50600436106026575f3560e01c80635dfc2e4a14602a575b5f5ffd5b60306032565b005b56fea2646970667358221220e809544020cceb1476f64dbe65da32b56bf6da2cf6da4aabbd286bf9905380c764736f6c634300081c0033"
// ));
//         let tx = seismic_tx(&wallet, chain_id, contract_deploy, nonce, TxKind::Create);
//         let tx_signed = Self::sign_tx(&wallet, tx).await;
//         tx_signed.envelope_encoded().into()
//     }

//     /// Creates a static transfer and signs it, returning bytes
//     pub async fn call_seismic_tx_bytes(
//         chain_id: u64,
//         wallet: PrivateKeySigner,
//         nonce: u64,
//         address: Address,
//         data: Bytes,
//     ) -> Bytes {
//         let selector = Bytes::from("5dfc2e4a");
//         let tx_input = [selector, data].concat();

//         let tx = seismic_tx(&wallet, chain_id, tx_input.into(), nonce, TxKind::Call(address));
//         let tx_signed = Self::sign_tx(&wallet, tx).await;
//         tx_signed.envelope_encoded().into()
//     }

//     /// Creates a static transfer and signs it, returning bytes
//     pub async fn call_legacy_tx_bytes(
//         chain_id: u64,
//         wallet: PrivateKeySigner,
//         nonce: u64,
//         address: Address,
//         data: Bytes,
//     ) -> Bytes {
//         let selector = Bytes::from("5dfc2e4a");
//         let tx_input = [selector, data].concat();

//         let tx = legacy_tx(chain_id, tx_input.into(), nonce, TxKind::Call(address));
//         let tx_signed = Self::sign_tx(&wallet, tx).await;
//         tx_signed.envelope_encoded().into()
//     }

// }

// /// Creates a type 2 transaction
// pub fn legacy_tx(chain_id: u64, input: Bytes, nonce: u64, to: TxKind) -> Transaction {
//     Transaction::Legacy(TxLegacy {
//         chain_id: Some(chain_id),
//         nonce,
//         gas_price: 20e9 as u128,
//         gas_limit: 600000,
//         to,
//         value: U256::from(1000),
//         input,
//     })
// }
