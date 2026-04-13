//! Utilities for reading USDC balances from contract storage.
//!
//! The Seismic USDC predeploy stores its `_balances` mapping at storage slot 3.
//! We read balances directly from storage
//! (cheap) rather than executing an EVM `balanceOf` call (expensive).

use alloy_primitives::{keccak256, Address, B256, U256};
use reth_provider::StateProvider;

/// USDC predeploy address on Seismic.
pub const USDC_CONTRACT: Address =
    alloy_primitives::address!("215dfD51D1e6C05C1f7e322c0f9ddc607300e053");

/// Scale factor to convert USDC (6 decimals) to 18 decimals: 10^12.
pub const USDC_DECIMAL_SCALE: U256 = U256::from_limbs([1_000_000_000_000u64, 0, 0, 0]);

/// Storage slot of the `_balances` mapping in the USDC predeploy contract.
const BALANCES_MAPPING_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Computes the storage key for `_balances[address]`.
///
/// For a Solidity `mapping(address => uint256)` at slot `s`, the value for key
/// `k` is stored at `keccak256(abi.encode(k, s))` — i.e. `k` left-padded to 32
/// bytes concatenated with `s` as a 32-byte big-endian integer.
fn usdc_balance_storage_key(address: &Address) -> B256 {
    let mut buf = [0u8; 64];
    // address is 20 bytes, right-aligned in the first 32-byte word
    buf[12..32].copy_from_slice(address.as_slice());
    // second 32-byte word: slot number (0) — already zeroed
    #[allow(clippy::indexing_slicing)]
    BALANCES_MAPPING_SLOT.to_be_bytes::<32>().iter().enumerate().for_each(|(i, &b)| {
        buf[32 + i] = b;
    });
    keccak256(buf)
}

/// Reads the USDC balance for `address` from contract storage and scales it to
/// 18 decimals.  Returns `U256::ZERO` on any error (missing account, missing
/// slot, provider failure).
pub fn read_usdc_balance(state: &dyn StateProvider, address: &Address) -> U256 {
    let key = usdc_balance_storage_key(address);
    match state.storage(USDC_CONTRACT, key) {
        Ok(Some(flagged)) => flagged.value.saturating_mul(USDC_DECIMAL_SCALE),
        _ => U256::ZERO,
    }
}

/// Returns the *effective* balance: `max(native_balance, usdc_balance_scaled)`.
///
/// This is used as the balance for transaction pool ordering and demotion
/// decisions so that accounts paying gas in USDC are treated equivalently to
/// accounts paying in native token.
pub fn effective_balance(
    state: &dyn StateProvider,
    address: &Address,
    native_balance: U256,
) -> U256 {
    let usdc = read_usdc_balance(state, address);
    std::cmp::max(native_balance, usdc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_is_deterministic() {
        let addr = alloy_primitives::address!("0000000000000000000000000000000000000001");
        let k1 = usdc_balance_storage_key(&addr);
        let k2 = usdc_balance_storage_key(&addr);
        assert_eq!(k1, k2);
    }

    #[test]
    fn storage_key_differs_per_address() {
        let a = alloy_primitives::address!("0000000000000000000000000000000000000001");
        let b = alloy_primitives::address!("0000000000000000000000000000000000000002");
        assert_ne!(usdc_balance_storage_key(&a), usdc_balance_storage_key(&b));
    }
}
