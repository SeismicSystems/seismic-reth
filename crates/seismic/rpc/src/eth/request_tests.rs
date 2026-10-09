#![allow(clippy::unwrap_used)]

use super::{transaction::SeismicSimTxConverter, SignableSeismicTransactionRequest};
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::TransactionRequest;
use reth_rpc_convert::transaction::{SimTxConverter, TryIntoTxEnv};
use revm::context::{BlockEnv, CfgEnv};
use seismic_alloy_consensus::{GasPayment, TxSeismic, TxSeismicElements, SEISMIC_TX_TYPE_ID};
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use seismic_revm::{transaction::abstraction::SeismicTxTr, SeismicSpecId};

fn cfg() -> CfgEnv<SeismicSpecId> {
    CfgEnv::default()
}

#[test]
fn selector_and_signed_read_survive_request_and_simulated_transaction_conversion() {
    for selector in
        [GasPayment::Auto, GasPayment::Native, GasPayment::Token(Address::repeat_byte(0x44))]
    {
        let request: SeismicTransactionRequest = TxSeismic {
            gas_payment: selector,
            seismic_elements: TxSeismicElements { signed_read: true, ..Default::default() },
            ..Default::default()
        }
        .into();
        let env = SignableSeismicTransactionRequest::from(request.clone())
            .try_into_tx_env(&cfg(), &BlockEnv::default())
            .unwrap();
        assert_eq!(env.gas_payment(), reth_evm::tx::gas_payment_to_env(selector));
        assert!(env.signed_read());
        assert_eq!(env.base.tx_type, SEISMIC_TX_TYPE_ID);
        let simulated = SeismicSimTxConverter::new()
            .convert_sim_tx(SignableSeismicTransactionRequest::from(request))
            .unwrap();
        let seismic_alloy_consensus::SeismicTypedTransaction::Seismic(transaction) =
            simulated.transaction()
        else {
            panic!("simulation must retain the Seismic transaction type");
        };
        assert_eq!(transaction.gas_payment, selector);
        assert!(transaction.seismic_elements.signed_read);
    }
}

#[test]
fn standard_request_types_remain_auto_without_signed_read_privileges() {
    for transaction_type in 0..=4u8 {
        let mut request =
            TransactionRequest { transaction_type: Some(transaction_type), ..Default::default() };
        match transaction_type {
            0 => request.gas_price = Some(1),
            1 => {
                request.gas_price = Some(1);
                request.access_list = Some(Default::default());
            }
            2 => {
                request.max_fee_per_gas = Some(3);
                request.max_priority_fee_per_gas = Some(1);
            }
            3 => {
                request.max_fee_per_gas = Some(3);
                request.blob_versioned_hashes = Some(vec![alloy_primitives::B256::repeat_byte(1)]);
                request.max_fee_per_blob_gas = Some(1);
            }
            _ => {
                request.max_fee_per_gas = Some(3);
                request.authorization_list = Some(vec![]);
            }
        }
        let env = SignableSeismicTransactionRequest::from(request)
            .try_into_tx_env(&cfg(), &BlockEnv::default())
            .unwrap();
        assert_eq!(env.base.tx_type, transaction_type);
        assert_eq!(env.gas_payment(), seismic_revm::GasPayment::Auto);
        assert!(!env.signed_read());
    }
}

#[test]
fn request_conversion_rejects_standard_explicit_and_zero_token_selection() {
    for selector in [
        GasPayment::Native,
        GasPayment::Token(Address::repeat_byte(0x44)),
        GasPayment::Token(Address::ZERO),
    ] {
        let request = SeismicTransactionRequest { gas_payment: selector, ..Default::default() };
        assert!(SignableSeismicTransactionRequest::from(request.clone())
            .try_into_tx_env(&cfg(), &BlockEnv::default())
            .is_err());
        assert!(SeismicSimTxConverter::new()
            .convert_sim_tx(SignableSeismicTransactionRequest::from(request))
            .is_err());
    }
    let request: SeismicTransactionRequest =
        TxSeismic { gas_payment: GasPayment::Token(Address::ZERO), ..Default::default() }.into();
    assert!(SignableSeismicTransactionRequest::from(request)
        .try_into_tx_env(&cfg(), &BlockEnv::default())
        .is_err());
}

#[test]
fn unauthenticated_write_request_cannot_supply_explicit_simulation_selection() {
    let request: SeismicTransactionRequest =
        TxSeismic { gas_payment: GasPayment::Native, ..Default::default() }.into();
    assert!(SignableSeismicTransactionRequest::from(request)
        .try_into_tx_env(&cfg(), &BlockEnv::default())
        .is_err());
}

#[test]
fn dynamic_fee_maximum_is_retained_while_effective_execution_price_is_normalized() {
    use revm::context_interface::Transaction;
    let request = TransactionRequest {
        max_fee_per_gas: Some(100),
        max_priority_fee_per_gas: Some(2),
        gas: Some(30_000),
        ..Default::default()
    };
    let block = BlockEnv { basefee: 10, ..Default::default() };
    let env =
        SignableSeismicTransactionRequest::from(request).try_into_tx_env(&cfg(), &block).unwrap();
    assert_eq!(env.max_fee_per_gas(), 100);
    assert_eq!(env.effective_gas_price(10), 12);
    assert_eq!(env.max_balance_spending().unwrap(), U256::from(3_000_000));
    let omitted_priority = TransactionRequest { max_fee_per_gas: Some(100), ..Default::default() };
    let env = SignableSeismicTransactionRequest::from(omitted_priority)
        .try_into_tx_env(&cfg(), &block)
        .unwrap();
    assert_eq!(env.max_fee_per_gas(), 100);
    assert_eq!(env.effective_gas_price(10), 10);
    let bad =
        TransactionRequest { gas_price: Some(1), max_fee_per_gas: Some(100), ..Default::default() };
    assert!(SignableSeismicTransactionRequest::from(bad).try_into_tx_env(&cfg(), &block).is_err());
}
