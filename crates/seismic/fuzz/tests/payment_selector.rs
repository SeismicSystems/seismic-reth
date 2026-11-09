//! Structured fuzz input must not invent signed payment metadata for standard types.
use alloy_primitives::Address;
use reth_seismic_fuzz::tx_gen::FuzzSeismicTx;
use seismic_revm::GasPayment;

const fn input(tx_type_selector: u8, gas_payment_selector: u8) -> FuzzSeismicTx {
    FuzzSeismicTx {
        caller: [0x42; 20],
        to_create: false,
        to_address: [0x43; 20],
        value_low: 0,
        data: Vec::new(),
        gas_limit: 100_000,
        gas_price: 1,
        nonce: 0,
        tx_type_selector,
        gas_payment_selector,
        gas_payment_token: [0x44; 20],
        rng_mode_execution: false,
        blob_hash_count: 1,
        blob_hash_seed: [0; 32],
        max_fee_per_blob_gas: 1,
    }
}

#[test]
fn generator_covers_every_seismic_payment_selector() {
    for (selector, expected) in
        [GasPayment::Auto, GasPayment::Native, GasPayment::Token(Address::from([0x44; 20]))]
            .into_iter()
            .enumerate()
    {
        let tx = input(4, selector as u8).into_seismic_tx();
        assert_eq!(tx.base.tx_type, 0x4a);
        assert_eq!(tx.gas_payment, expected);
        assert!(!tx.signed_read);
    }
}

#[test]
fn standard_and_differential_inputs_always_use_auto() {
    for selector in 0..=255 {
        for tx_type in 0..4 {
            let tx = input(tx_type, selector).into_seismic_tx();
            assert_eq!(tx.gas_payment, GasPayment::Auto);
        }
        let tx = input(4, selector).into_eth_compatible_tx();
        assert_ne!(tx.base.tx_type, 0x4a);
        assert_eq!(tx.gas_payment, GasPayment::Auto);
    }
}
