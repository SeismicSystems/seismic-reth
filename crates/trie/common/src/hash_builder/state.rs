use crate::TrieMask;
use alloc::vec::Vec;
use alloy_trie::{hash_builder::HashBuilderValue, nodes::RlpNode, HashBuilder};
use nybbles::Nibbles;

/// The hash builder state for storing in the database.
/// Check the `reth-trie` crate for more info on hash builder.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(any(test, feature = "serde"), derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    reth_codecs::add_arbitrary_tests(compact)
)]
pub struct HashBuilderState {
    /// The current key.
    pub key: Vec<u8>,
    /// The current node value.
    pub value: HashBuilderValue,
    /// Whether the state value is private.
    pub is_private: Option<bool>,
    /// The builder stack.
    pub stack: Vec<RlpNode>,

    /// Group masks.
    pub groups: Vec<TrieMask>,
    /// Tree masks.
    pub tree_masks: Vec<TrieMask>,
    /// Hash masks.
    pub hash_masks: Vec<TrieMask>,

    /// Flag indicating if the current node is stored in the database.
    pub stored_in_database: bool,
}

impl From<HashBuilderState> for HashBuilder {
    fn from(state: HashBuilderState) -> Self {
        Self {
            key: Nibbles::from_nibbles_unchecked(state.key),
            stack: state.stack,
            value: state.value,
            is_private: state.is_private,
            state_masks: state.groups,
            tree_masks: state.tree_masks,
            hash_masks: state.hash_masks,
            stored_in_database: state.stored_in_database,
            updated_branch_nodes: None,
            proof_retainer: None,
            rlp_buf: Vec::with_capacity(32),
        }
    }
}

impl From<HashBuilder> for HashBuilderState {
    fn from(state: HashBuilder) -> Self {
        Self {
            key: state.key.into(),
            stack: state.stack,
            value: state.value,
            is_private: state.is_private,
            groups: state.state_masks,
            tree_masks: state.tree_masks,
            hash_masks: state.hash_masks,
            stored_in_database: state.stored_in_database,
        }
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for HashBuilderState {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut len = 0;

        len += self.key.to_compact(buf);

        buf.put_u16(self.stack.len() as u16);
        len += 2;
        for item in &self.stack {
            buf.put_u16(item.len() as u16);
            buf.put_slice(&item[..]);
            len += 2 + item.len();
        }

        len += self.value.to_compact(buf);

        buf.put_u16(self.groups.len() as u16);
        len += 2;
        for item in &self.groups {
            len += (*item).to_compact(buf);
        }

        buf.put_u16(self.tree_masks.len() as u16);
        len += 2;
        for item in &self.tree_masks {
            len += (*item).to_compact(buf);
        }

        buf.put_u16(self.hash_masks.len() as u16);
        len += 2;
        for item in &self.hash_masks {
            len += (*item).to_compact(buf);
        }

        // Serialize Seismic-specific `is_private: Option<bool>`
        let private_byte = match self.is_private {
            None => 0u8,
            Some(false) => 1u8,
            Some(true) => 2u8,
        };
        buf.put_u8(private_byte);
        len += 1;

        buf.put_u8(self.stored_in_database as u8);
        len += 1;

        len
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use bytes::Buf;

        let (key, mut buf) = Vec::from_compact(buf, 0);

        let stack_len = buf.get_u16() as usize;
        let mut stack = Vec::with_capacity(stack_len);
        for _ in 0..stack_len {
            let item_len = buf.get_u16() as usize;
            stack.push(RlpNode::from_raw(&buf[..item_len]).unwrap());
            buf.advance(item_len);
        }

        let (value, mut buf) = HashBuilderValue::from_compact(buf, 0);

        let groups_len = buf.get_u16() as usize;
        let mut groups = Vec::with_capacity(groups_len);
        for _ in 0..groups_len {
            let (item, rest) = TrieMask::from_compact(buf, 0);
            groups.push(item);
            buf = rest;
        }

        let tree_masks_len = buf.get_u16() as usize;
        let mut tree_masks = Vec::with_capacity(tree_masks_len);
        for _ in 0..tree_masks_len {
            let (item, rest) = TrieMask::from_compact(buf, 0);
            tree_masks.push(item);
            buf = rest;
        }

        let hash_masks_len = buf.get_u16() as usize;
        let mut hash_masks = Vec::with_capacity(hash_masks_len);
        for _ in 0..hash_masks_len {
            let (item, rest) = TrieMask::from_compact(buf, 0);
            hash_masks.push(item);
            buf = rest;
        }

        // Deserialize Seismic-specific `is_private`
        let private_byte = buf.get_u8();
        let is_private = match private_byte {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => panic!("Invalid byte for Option<bool>: {}", private_byte),
        };

        let stored_in_database = buf.get_u8() != 0;

        (
            Self {
                key,
                stack,
                value,
                is_private,
                groups,
                tree_masks,
                hash_masks,
                stored_in_database,
            },
            buf,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_codecs::Compact;

    #[test]
    fn hash_builder_state_regression() {
        let mut state = HashBuilderState::default();
        state.stack.push(Default::default());
        let mut buf = vec![];
        let len = state.clone().to_compact(&mut buf);
        let (decoded, _) = HashBuilderState::from_compact(&buf, len);
        assert_eq!(state, decoded);
    }

    #[test]
    fn hash_builder_state_regression_with_private() {
        let mut state = HashBuilderState::default();
        state.is_private = Some(true);
        state.stack.push(Default::default());
        let mut buf = vec![];
        let len = state.clone().to_compact(&mut buf);
        let (decoded, _) = HashBuilderState::from_compact(&buf, len);
        assert_eq!(state, decoded);
    }

    #[cfg(feature = "arbitrary")]
    proptest::proptest! {
        #[test]
        fn hash_builder_state_roundtrip(state in proptest_arbitrary_interop::arb::<HashBuilderState>()) {
            let mut buf = vec![];
            let len = state.to_compact(&mut buf);
            let (decoded, _) = HashBuilderState::from_compact(&buf, len);
            assert_eq!(state, decoded);
        }
    }
}
