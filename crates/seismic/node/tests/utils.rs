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
