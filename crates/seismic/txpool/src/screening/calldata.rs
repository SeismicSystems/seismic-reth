//! Address extraction from transactions for screening.
//!
//! Extracts all addresses relevant to compliance screening from a transaction:
//! sender, recipient, EIP-7702 authorizations, access list entries, and
//! addresses embedded in ERC-20/ERC-721/ERC-1155 token transfer calldata.

use alloy_primitives::{Address, Bytes};
use reth_transaction_pool::PoolTransaction;

// ──── ERC-20 selectors ─────────────────────────────────────────────────────
/// `transfer(address,uint256)`
const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `approve(address,uint256)`
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
/// `transferFrom(address,address,uint256)` — shared with ERC-721
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

// ──── ERC-721 selectors ────────────────────────────────────────────────────
/// `safeTransferFrom(address,address,uint256)`
const SAFE_TRANSFER_FROM: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e];
/// `safeTransferFrom(address,address,uint256,bytes)`
const SAFE_TRANSFER_FROM_DATA: [u8; 4] = [0xb8, 0x8d, 0x4f, 0xde];

// ──── ERC-1155 selectors ───────────────────────────────────────────────────
/// `safeTransferFrom(address,address,uint256,uint256,bytes)`
const ERC1155_SAFE_TRANSFER_FROM: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a];
/// `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)`
const ERC1155_SAFE_BATCH_TRANSFER_FROM: [u8; 4] = [0x2e, 0xb2, 0xc2, 0xd6];

/// Extracts all screenable addresses from a pool transaction.
///
/// Sources:
/// 1. Transaction sender
/// 2. Transaction recipient (`to` address)
/// 3. EIP-7702 authorization list addresses
/// 4. Access list addresses
/// 5. ERC-20/ERC-721/ERC-1155 calldata addresses
///
/// Returns a deduplicated, sorted vector of addresses.
pub fn extract_addresses<T: PoolTransaction>(tx: &T) -> Vec<Address>
where
    T: alloy_consensus::Transaction,
{
    let mut addrs = Vec::new();

    // 1. Sender
    addrs.push(tx.sender());

    // 2. Recipient
    if let Some(&to) = tx.kind().to() {
        addrs.push(to);
    }

    // 3. EIP-7702 authorization addresses
    if let Some(auths) = tx.authorization_list() {
        for auth in auths {
            addrs.push(auth.address);
        }
    }

    // 4. Access list addresses
    if let Some(al) = tx.access_list() {
        for item in al.iter() {
            addrs.push(item.address);
        }
    }

    // 5. ERC-20/ERC-721/ERC-1155 calldata addresses
    extract_calldata_addresses(tx.input(), &mut addrs);

    // Deduplicate
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// Parses known ERC-20/ERC-721/ERC-1155 function selectors from calldata and
/// extracts embedded addresses.
///
/// Each ABI-encoded address occupies a 32-byte word (left-padded with zeros).
/// We validate that the upper 12 bytes are zero before decoding.
pub fn extract_calldata_addresses(input: &Bytes, addrs: &mut Vec<Address>) {
    // Need at least 4 bytes for the selector
    if input.len() < 4 {
        return;
    }

    #[allow(clippy::expect_used)]
    let selector: [u8; 4] = input[..4].try_into().expect("checked length");
    let params = &input[4..];

    match selector {
        // transfer(address,uint256) — 1 address at word 0
        // approve(address,uint256) — 1 address at word 0
        TRANSFER | APPROVE => {
            if let Some(addr) = decode_address_word(params, 0) {
                addrs.push(addr);
            }
        }
        // transferFrom(address,address,uint256) — 2 addresses at words 0,1
        // safeTransferFrom(address,address,uint256) — 2 addresses at words 0,1
        // safeTransferFrom(address,address,uint256,bytes) — 2 addresses at words 0,1
        // ERC-1155 safeTransferFrom(address,address,uint256,uint256,bytes) — 2 addresses at words
        // 0,1 ERC-1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) — 2
        // addresses at words 0,1
        TRANSFER_FROM |
        SAFE_TRANSFER_FROM |
        SAFE_TRANSFER_FROM_DATA |
        ERC1155_SAFE_TRANSFER_FROM |
        ERC1155_SAFE_BATCH_TRANSFER_FROM => {
            if let Some(addr) = decode_address_word(params, 0) {
                addrs.push(addr);
            }
            if let Some(addr) = decode_address_word(params, 1) {
                addrs.push(addr);
            }
        }
        _ => {}
    }
}

/// Decodes an ABI-encoded address from the given word index (each word = 32 bytes).
///
/// Returns `None` if the data is too short or the upper 12 bytes are not zero
/// (malformed ABI encoding).
fn decode_address_word(data: &[u8], word_index: usize) -> Option<Address> {
    let start = word_index * 32;
    let end = start + 32;
    if data.len() < end {
        return None;
    }

    let word = &data[start..end];
    // Upper 12 bytes must be zero for a valid ABI-encoded address
    if word[..12] != [0u8; 12] {
        return None;
    }

    Some(Address::from_slice(&word[12..32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    /// Helper: build ABI-encoded calldata with selector + address words.
    fn encode_call(selector: [u8; 4], addresses: &[Address], extra_words: usize) -> Bytes {
        let mut data = Vec::with_capacity(4 + (addresses.len() + extra_words) * 32);
        data.extend_from_slice(&selector);
        for addr in addresses {
            // Left-pad address to 32 bytes
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(addr.as_slice());
        }
        // Extra zero words (e.g., uint256 params)
        for _ in 0..extra_words {
            data.extend_from_slice(&[0u8; 32]);
        }
        Bytes::from(data)
    }

    fn encode_u256_word(val: U256) -> [u8; 32] {
        val.to_be_bytes::<32>()
    }

    #[test]
    fn erc20_transfer_extracts_to() {
        let to = Address::random();
        let input = encode_call(TRANSFER, &[to], 1); // transfer(to, amount)
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![to]);
    }

    #[test]
    fn erc20_approve_extracts_spender() {
        let spender = Address::random();
        let input = encode_call(APPROVE, &[spender], 1); // approve(spender, amount)
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![spender]);
    }

    #[test]
    fn erc20_transfer_from_extracts_both() {
        let from = Address::random();
        let to = Address::random();
        let input = encode_call(TRANSFER_FROM, &[from, to], 1); // transferFrom(from, to, amount)
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![from, to]);
    }

    #[test]
    fn erc721_safe_transfer_from_extracts_both() {
        let from = Address::random();
        let to = Address::random();
        let input = encode_call(SAFE_TRANSFER_FROM, &[from, to], 1);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![from, to]);
    }

    #[test]
    fn erc721_safe_transfer_from_with_data_extracts_both() {
        let from = Address::random();
        let to = Address::random();
        // safeTransferFrom(from, to, tokenId, data) — addresses are still at words 0,1
        let input = encode_call(SAFE_TRANSFER_FROM_DATA, &[from, to], 2);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![from, to]);
    }

    #[test]
    fn erc1155_safe_transfer_from_extracts_both() {
        let from = Address::random();
        let to = Address::random();
        let input = encode_call(ERC1155_SAFE_TRANSFER_FROM, &[from, to], 3);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![from, to]);
    }

    #[test]
    fn erc1155_safe_batch_transfer_from_extracts_both() {
        let from = Address::random();
        let to = Address::random();
        let input = encode_call(ERC1155_SAFE_BATCH_TRANSFER_FROM, &[from, to], 3);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert_eq!(addrs, vec![from, to]);
    }

    #[test]
    fn unknown_selector_extracts_nothing() {
        let input = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn empty_input_extracts_nothing() {
        let input = Bytes::new();
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn truncated_calldata_extracts_nothing() {
        // Valid selector but not enough data for address word
        let input = Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x01]);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn malformed_address_word_rejected() {
        // Address word with non-zero upper 12 bytes
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
        data.extend_from_slice(&[0xff; 12]); // non-zero padding
        data.extend_from_slice(Address::random().as_slice());
        data.extend_from_slice(&encode_u256_word(U256::from(1000)));

        let input = Bytes::from(data);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn transfer_from_with_one_truncated_address() {
        // transferFrom but only 1 address word (not enough for second)
        let from = Address::random();
        let mut data = Vec::new();
        data.extend_from_slice(&TRANSFER_FROM);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(from.as_slice());
        // Missing second address word

        let input = Bytes::from(data);
        let mut addrs = Vec::new();
        extract_calldata_addresses(&input, &mut addrs);
        // Should extract the first address but not the second
        assert_eq!(addrs, vec![from]);
    }
}
