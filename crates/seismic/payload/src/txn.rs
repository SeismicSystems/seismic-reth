//use alloy_consensus::{EthereumTxEnvelope, TxEip4844Variant};
use alloy_network::{EthereumWallet, TransactionBuilder as _};
use alloy_primitives::{hex, Address, U256};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_macro::sol;
use alloy_sol_types::SolCall as _;
use rand::thread_rng;
use rand_distr::{Distribution as _, Normal};
use reth_ethereum_primitives::TransactionSigned;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{error::Error, fs};

static KEY_COUNTER: AtomicUsize = AtomicUsize::new(0);
static NONCE_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Define the contract interface using alloy's sol! macro
sol! {
    interface IGasConsumer {
        function consumeGas(uint256 targetGas) external;
    }
}

/// Builds and signs a transaction to call consumeGas(uint256) on contract at 0x69
///
/// # Arguments
/// * `target_gas` - The gas amount to pass to the consumeGas function
/// * `signer` - The signer to sign the transaction with
/// * `provider` - The Ethereum provider for chain information
///
/// # Returns
/// * `Result<Bytes, Box<dyn Error>>` - The signed transaction bytes
pub async fn build_consume_gas_transaction(
    target_gas: u64,
) -> Result<TransactionSigned, Box<dyn Error>> {
    // Contract address
    let contract_address =
        Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x69]);

    let signer = get_signer().unwrap();
    // Encode the function call using the sol! generated interface
    let call = IGasConsumer::consumeGasCall { targetGas: U256::from(target_gas) };
    let calldata = call.abi_encode();

    let nonce = NONCE_COUNTER.load(Ordering::Relaxed);

    let eip1559_request = TransactionRequest {
        to: Some(alloy_primitives::TxKind::Call(contract_address)),
        max_fee_per_gas: Some(50_000_000_000),
        max_priority_fee_per_gas: Some(2_000_000_000),
        nonce: Some(nonce as u64),
        gas: Some(target_gas + 30_000),
        input: calldata.into(),
        chain_id: Some(5124),
        ..Default::default()
    };

    // Get nonce and gas price from provider
    // let gas_price = target_gas + 100_000;

    // Create wallet and sign the transaction
    let wallet = EthereumWallet::from(signer);

    let maybe_eip1559_tx = eip1559_request.build(&wallet).await?;

    Ok(maybe_eip1559_tx.into())
}

// Or if you prefer a const that you manually change:
// const KEY_INDEX: usize = 0;

/// Reads a private key from the private_keys.txt file at the specified index
/// and returns an Alloy PrivateKeySigner
///
/// # Returns
/// * `Result<PrivateKeySigner, Box<dyn Error>>` - The signer for the private key at the index
///
/// # Errors
/// * If the file cannot be read
/// * If the line at the index doesn't exist
/// * If the private key format is invalid
pub fn get_signer() -> Result<PrivateKeySigner, Box<dyn Error>> {
    // Read the file
    let contents = include_str!("../../../../private_keys.txt");
    // Get the current index from the atomic counter
    let mut index = KEY_COUNTER.load(Ordering::SeqCst);

    // Or use a const:
    // let index = KEY_INDEX;

    // Parse lines and get the one at the index
    let lines: Vec<&str> = contents.lines().collect();

    if index >= lines.len() {
        index = 0;
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    }

    let line = lines[index];

    // Split by comma to get private key and address
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid format at line {}. Expected 'private_key,address'",
            index + 1
        )
        .into());
    }

    let private_key_str = parts[0].trim();
    let _address = parts[1].trim(); // Address for verification if needed

    // Remove "0x" prefix if present
    let private_key_hex = if private_key_str.starts_with("0x") || private_key_str.starts_with("0X")
    {
        &private_key_str[2..]
    } else {
        private_key_str
    };

    // Decode hex string to bytes
    let private_key_bytes = hex::decode(private_key_hex)?;

    // Create the signer from bytes
    let signer = PrivateKeySigner::from_slice(&private_key_bytes)?;

    KEY_COUNTER.swap(index + 1, Ordering::Relaxed);

    Ok(signer)
}

/// Loads all signers from the file
pub fn get_all_signers() -> Result<Vec<PrivateKeySigner>, Box<dyn Error>> {
    let contents = fs::read_to_string("private_keys.txt")?;
    let mut signers = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 2 {
            eprintln!("Skipping invalid line {}: {}", i + 1, line);
            continue;
        }

        let private_key_str = parts[0].trim();
        let private_key_hex =
            if private_key_str.starts_with("0x") || private_key_str.starts_with("0X") {
                &private_key_str[2..]
            } else {
                private_key_str
            };

        match hex::decode(private_key_hex) {
            Ok(bytes) => match PrivateKeySigner::from_slice(&bytes) {
                Ok(signer) => signers.push(signer),
                Err(e) => eprintln!("Failed to create signer for line {}: {}", i + 1, e),
            },
            Err(e) => eprintln!("Failed to decode hex for line {}: {}", i + 1, e),
        }
    }

    Ok(signers)
}

/// Loads all signers from the file
pub fn get_all_pubkeys() -> Result<Vec<Address>, Box<dyn Error>> {
    let contents = fs::read_to_string("private_keys.txt")?;
    let mut pub_keys = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 2 {
            eprintln!("Skipping invalid line {}: {}", i + 1, line);
            continue;
        }

        let pub_key_str = parts[1].trim();
        let pub_key_hex = if pub_key_str.starts_with("0x") || pub_key_str.starts_with("0X") {
            &pub_key_str[2..]
        } else {
            pub_key_str
        };

        match hex::decode(pub_key_hex) {
            Ok(bytes) => pub_keys.push(Address::from_slice(&bytes)),
            Err(e) => eprintln!("Failed to decode hex for line {}: {}", i + 1, e),
        }
    }

    Ok(pub_keys)
}

/// Method 1: Normal Distribution (Bell Curve)
pub fn calculate_gas_distribution(target_gas: u64, std_dev: u64, txn_count: u64) -> Vec<u64> {
    let normal = Normal::new(target_gas as f64, std_dev as f64).unwrap();
    let mut rng = thread_rng();

    let numbers: Vec<u64> =
        (0..txn_count).map(|_| normal.sample(&mut rng).round() as u64).collect();

    numbers
}

#[test]
fn test() {
    futures::executor::block_on(build_consume_gas_transaction(100000)).unwrap();
}
