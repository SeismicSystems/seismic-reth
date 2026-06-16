//! Utilities for reading USDC balances from contract storage.
//!
//! The Seismic USDC predeploy stores its `_balances` mapping at storage slot 3.
//! We read balances directly from storage
//! (cheap) rather than executing an EVM `balanceOf` call (expensive).

use alloy_primitives::{keccak256, Address, B256, U256};
use reth_provider::StateProvider;

/// USDC predeploy address on Seismic.
pub const USDC_CONTRACT: Address =
    alloy_primitives::address!("0x790701048922E265105fd6a4467a2901c2201C43");

/// Scale factor to convert USDC (6 decimals) to 18 decimals: 10^12.
pub const USDC_DECIMAL_SCALE: U256 = U256::from_limbs([1_000_000_000_000u64, 0, 0, 0]);

/// Storage slot of the `_balances` mapping in the USDC predeploy contract.
const BALANCES_MAPPING_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Computes the storage key for `_balances[address]`.
///
/// For a Solidity `mapping(address => uint256)` at slot `s`, the value for key
/// `k` is stored at `keccak256(abi.encode(k, s))` — i.e. `k` left-padded to 32
/// bytes concatenated with `s` as a 32-byte big-endian integer.
pub fn usdc_balance_storage_key(address: &Address) -> B256 {
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

/// Returns `true` if a sender with the given balances can afford a transaction
/// transferring `value` native tokens with a maximum gas cost of `gas_cost`
/// (including blob fees, in 18-decimal wei units).
///
/// On Seismic, gas can be paid in native token *or* USDC, but `tx.value` is
/// always a native-token transfer. The two requirements must therefore be
/// checked component-wise rather than against a single combined balance:
/// - `value` can only come out of the native balance: `native >= value`.
/// - gas is paid from a single token, either what remains of the native balance after the transfer
///   (`native - value >= gas_cost`) or USDC (`usdc >= gas_cost`); it cannot be split across both.
///
/// `usdc` must already be scaled to 18 decimals (see [`read_usdc_balance`]).
pub fn can_afford(native: U256, usdc: U256, gas_cost: U256, value: U256) -> bool {
    match native.checked_sub(value) {
        Some(remaining_native) => remaining_native >= gas_cost || usdc >= gas_cost,
        // Native balance cannot cover the value transfer; USDC cannot stand in
        // for it, so the transaction is unaffordable regardless of `usdc`.
        None => false,
    }
}

/// Returns the maximum number of gas units a sender can pay for, mirroring the
/// component-wise rule of [`can_afford`]: `value` must come out of the native
/// balance, and gas is paid from whichever single balance — remaining native or
/// USDC — is larger.
///
/// Returns zero when the native balance cannot cover `value` (no amount of gas
/// makes the transfer executable) or when `gas_price` is zero.
///
/// `usdc` must already be scaled to 18 decimals (see [`read_usdc_balance`]).
pub fn gas_allowance(native: U256, usdc: U256, value: U256, gas_price: U256) -> U256 {
    let Some(remaining_native) = native.checked_sub(value) else { return U256::ZERO };
    std::cmp::max(remaining_native, usdc).checked_div(gas_price).unwrap_or_default()
}

/// Returns the *display* balance reported by `eth_getBalance`:
/// `max(native_balance, usdc_balance_scaled)`, so wallets holding only USDC
/// still see a non-zero spendable balance.
///
/// This is a display convention only — it is **not** an affordability check.
/// `max` conflates the two balances, while value transfers can only be paid in
/// native token and gas in either token: use [`can_afford`] /
/// [`gas_allowance`] for any decision about whether a transaction can be paid
/// for.
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

    #[test]
    fn can_afford_native_only() {
        // native covers gas + value with room to spare, no USDC
        assert!(can_afford(U256::from(200), U256::ZERO, U256::from(50), U256::from(100)));
        // exact boundary: native == gas + value
        assert!(can_afford(U256::from(150), U256::ZERO, U256::from(50), U256::from(100)));
        // native one short of gas + value
        assert!(!can_afford(U256::from(149), U256::ZERO, U256::from(50), U256::from(100)));
    }

    #[test]
    fn can_afford_split_balances() {
        // native covers value exactly, USDC covers gas exactly; neither alone
        // covers gas + value
        assert!(can_afford(U256::from(100), U256::from(50), U256::from(50), U256::from(100)));
        // USDC one short of gas while remaining native is zero
        assert!(!can_afford(U256::from(100), U256::from(49), U256::from(50), U256::from(100)));
    }

    #[test]
    fn can_afford_value_exceeds_native() {
        // USDC can never pay for the value transfer
        assert!(!can_afford(U256::from(99), U256::MAX, U256::ZERO, U256::from(100)));
        assert!(!can_afford(U256::ZERO, U256::MAX, U256::MAX, U256::from(1)));
    }

    #[test]
    fn can_afford_gas_cannot_be_split_across_tokens() {
        // remaining native (40) + USDC (40) would cover gas (50), but gas is
        // paid from a single token
        assert!(!can_afford(U256::from(140), U256::from(40), U256::from(50), U256::from(100)));
    }

    #[test]
    fn can_afford_usdc_gas_zero_native() {
        // the common USDC-gas case: no native balance, no value transfer
        assert!(can_afford(U256::ZERO, U256::from(50), U256::from(50), U256::ZERO));
        assert!(!can_afford(U256::ZERO, U256::from(49), U256::from(50), U256::ZERO));
    }

    #[test]
    fn can_afford_zero_cost() {
        assert!(can_afford(U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO));
    }

    #[test]
    fn gas_allowance_value_exceeds_native() {
        assert_eq!(
            gas_allowance(U256::from(99), U256::MAX, U256::from(100), U256::from(1)),
            U256::ZERO
        );
    }

    #[test]
    fn gas_allowance_zero_gas_price() {
        assert_eq!(
            gas_allowance(U256::from(100), U256::from(100), U256::ZERO, U256::ZERO),
            U256::ZERO
        );
    }

    #[test]
    fn gas_allowance_uses_larger_of_remaining_native_and_usdc() {
        // remaining native (100) > usdc (60)
        assert_eq!(
            gas_allowance(U256::from(200), U256::from(60), U256::from(100), U256::from(2)),
            U256::from(50)
        );
        // usdc (300) > remaining native (100)
        assert_eq!(
            gas_allowance(U256::from(200), U256::from(300), U256::from(100), U256::from(2)),
            U256::from(150)
        );
        // native == value: gas can still be paid in USDC
        assert_eq!(
            gas_allowance(U256::from(100), U256::from(300), U256::from(100), U256::from(2)),
            U256::from(150)
        );
    }

    /// Replicates the seismic-revm `erc_address_storage` computation byte-for-byte
    /// to confirm we read the same slot the EVM writes to.
    #[test]
    fn storage_key_matches_seismic_revm() {
        let addr = alloy_primitives::address!("0123456789abcdef0123456789abcdef01234567");

        // seismic-revm erc_address_storage(addr):
        //   buf[12..32] = addr
        //   buf[63] = 3
        //   keccak256(buf)
        let mut expected_buf = [0u8; 64];
        expected_buf[12..32].copy_from_slice(addr.as_slice());
        expected_buf[63] = 3;
        let expected = keccak256(expected_buf);

        assert_eq!(usdc_balance_storage_key(&addr), expected);
    }
}
