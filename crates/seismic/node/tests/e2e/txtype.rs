//! End-to-end coverage for tx-type RPC classification on the seismic node (precompile variant).
//!
//! The node must run an authenticated signed read as a Seismic tx (type 74) and a plain `eth_call`
//! as standard. The probe reads the type via `staticcall` to the 0x6A tx-info precompile; its
//! `requireSeismic()` reverts unless the type is 74, so success-vs-revert is a **74-specific**
//! signal (no other type passes) that needs no response decryption and exercises the `eth_call`
//! and `estimateGas` handlers directly (reth tags those two handlers independently).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test file.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex::FromHex, Bytes, TxKind};
use alloy_rpc_types::{Block, TransactionInput, TransactionRequest};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_seismic_node::utils::{
    e2e::{ensure_mock_purpose_keys, setup},
    test_utils::get_signed_seismic_tx_typed_data,
};
use reth_seismic_primitives::test_utils::sign_tx;
use reth_seismic_rpc::ext::EthApiOverrideClient;
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};

// TxTypeProbe (stock solc): isSeismic() [02ce8088] / requireSeismic() [c6d819f6] read the tx type
// by staticcall to the 0x6A tx-type precompile. Source + reproduce command: fixtures/TxTypeProbe.sol.
const TXTYPE_PROBE_DEPLOY: &str = "6080604052348015600e575f5ffd5b506103058061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c806302ce808814610038578063c6d819f614610056575b5f5ffd5b610040610060565b60405161004d9190610171565b60405180910390f35b61005e610071565b005b5f604a61006b610086565b14905090565b604a61007b610086565b14610084575f5ffd5b565b5f5f5f606a73ffffffffffffffffffffffffffffffffffffffff166040516100ad906101b7565b5f60405180830381855afa9150503d805f81146100e5576040519150601f19603f3d011682016040523d82523d5f602084013e6100ea565b606091505b50915091508180156100fd575060208151145b61013c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161013390610225565b60405180910390fd5b80806020019051810190610150919061027a565b9250505090565b5f8115159050919050565b61016b81610157565b82525050565b5f6020820190506101845f830184610162565b92915050565b5f81905092915050565b50565b5f6101a25f8361018a565b91506101ad82610194565b5f82019050919050565b5f6101c182610197565b9150819050919050565b5f82825260208201905092915050565b7f54585f494e464f000000000000000000000000000000000000000000000000005f82015250565b5f61020f6007836101cb565b915061021a826101db565b602082019050919050565b5f6020820190508181035f83015261023c81610203565b9050919050565b5f5ffd5b5f819050919050565b61025981610247565b8114610263575f5ffd5b50565b5f8151905061027481610250565b92915050565b5f6020828403121561028f5761028e610243565b5b5f61029c84828501610266565b9150509291505056fea26469706673582212204924f4189084c792361d86e18baf71dcadcfd5b6f8088b4caf833e2180d75aff64736f6c63782c302e382e33312d646576656c6f702e323032362e372e32302b636f6d6d69742e66643566333839632e6d6f64005d";

const REQUIRE_SEISMIC_SELECTOR: &str = "c6d819f6";

/// Plain standard `SeismicTransactionRequest` (no signature, no seismic elements) to `contract`.
fn plain_call(contract: alloy_primitives::Address, calldata: Bytes) -> SeismicTransactionRequest {
    SeismicTransactionRequest {
        inner: TransactionRequest {
            to: Some(TxKind::Call(contract)),
            input: TransactionInput { input: Some(calldata), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    }
}

/// The `eth_call` handler must classify a signed read as Seismic (`txtype()==74`) and a plain call
/// as standard: `requireSeismic()` succeeds for the signed read and reverts for the plain call.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_eth_call_classifies_signed_read() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;
    let recent = node.advance_block().await.unwrap().block().hash();
    let selector = Bytes::from_hex(REQUIRE_SEISMIC_SELECTOR).unwrap();

    // Signed read -> txtype()==74 -> requireSeismic() succeeds.
    let signed = get_signed_seismic_tx_typed_data(
        &signer,
        1,
        TxKind::Call(contract),
        chain_id,
        selector.clone(),
        recent,
    )
    .await;
    let signed_res = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicCallRequest::TypedData(signed),
        None,
        None,
        None,
    )
    .await;
    assert!(
        signed_res.is_ok(),
        "signed eth_call to requireSeismic() should succeed (txtype()==74), got {signed_res:?}"
    );

    // Plain eth_call -> txtype()!=74 -> requireSeismic() reverts.
    let plain_res = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicCallRequest::TransactionRequest(plain_call(contract, selector)),
        None,
        None,
        None,
    )
    .await;
    assert!(
        plain_res.is_err(),
        "plain eth_call to requireSeismic() should revert (txtype()!=74), but it succeeded"
    );
}

/// The `estimateGas` handler must classify a signed read as Seismic independently of `eth_call`:
/// estimating `requireSeismic()` succeeds for the signed read and reverts for the plain call.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_estimate_gas_classifies_signed_read() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;
    let recent = node.advance_block().await.unwrap().block().hash();
    let selector = Bytes::from_hex(REQUIRE_SEISMIC_SELECTOR).unwrap();

    let signed = get_signed_seismic_tx_typed_data(
        &signer,
        1,
        TxKind::Call(contract),
        chain_id,
        selector.clone(),
        recent,
    )
    .await;
    let signed_res = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TypedData(signed),
        None,
        None,
    )
    .await;
    assert!(
        signed_res.is_ok(),
        "signed estimateGas of requireSeismic() should succeed (txtype()==74), got {signed_res:?}"
    );

    let plain_res = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TransactionRequest(plain_call(contract, selector)),
        None,
        None,
    )
    .await;
    assert!(
        plain_res.is_err(),
        "plain estimateGas of requireSeismic() should revert (txtype()!=74), but it succeeded"
    );
}

/// Deploy the probe as a standard tx via the signer's account (nonce 0) and return its address.
async fn deploy_probe(
    client: &jsonrpsee::http_client::HttpClient,
    node: &mut reth_seismic_node::utils::e2e::SeismicTestNode,
    signer: &alloy_signer_local::PrivateKeySigner,
    from: alloy_primitives::Address,
    chain_id: u64,
) -> alloy_primitives::Address {
    let deploy_code = Bytes::from_hex(TXTYPE_PROBE_DEPLOY).unwrap();
    let deploy = SeismicTransactionRequest {
        inner: TransactionRequest {
            from: Some(from),
            nonce: Some(0),
            to: Some(TxKind::Create),
            gas: Some(1_000_000),
            max_fee_per_gas: Some(20e9 as u128),
            max_priority_fee_per_gas: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(deploy_code), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };
    let signed = sign_tx(signer.clone(), deploy).await;
    let raw: Bytes = signed.encoded_2718().into();
    EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await.unwrap();
    node.advance_block().await.unwrap();
    from.create(0)
}
