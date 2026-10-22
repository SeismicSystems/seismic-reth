//! Access to standard block fields without discarding chain-specific environment data.

use core::fmt::Debug;
use revm::{context::BlockEnv, context_interface::Block};
use seismic_revm::SeismicBlockEnv;

/// A block environment whose standard Ethereum fields can be read and overridden.
///
/// Generic RPC helpers use this view while retaining the full environment for execution.
pub trait BlockEnvAccess: Block + Clone + Debug + Send + Sync + 'static {
    /// Returns the standard environment. Its timestamp is Unix seconds.
    fn as_block_env(&self) -> &BlockEnv;

    /// Returns the standard environment without replacing chain-specific fields.
    fn as_block_env_mut(&mut self) -> &mut BlockEnv;
}

impl BlockEnvAccess for BlockEnv {
    fn as_block_env(&self) -> &BlockEnv {
        self
    }

    fn as_block_env_mut(&mut self) -> &mut BlockEnv {
        self
    }
}

impl BlockEnvAccess for SeismicBlockEnv {
    fn as_block_env(&self) -> &BlockEnv {
        &self.inner
    }

    fn as_block_env_mut(&mut self) -> &mut BlockEnv {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::U256;

    #[test]
    fn standard_overrides_preserve_the_seismic_millisecond_part() {
        let mut env = SeismicBlockEnv {
            inner: BlockEnv { timestamp: U256::from(1_800_000_000u64), ..Default::default() },
            timestamp_millis_part: 321,
        };
        env.as_block_env_mut().timestamp += U256::from(12);
        env.as_block_env_mut().basefee = 42;
        assert_eq!(env.as_block_env().timestamp, U256::from(1_800_000_012u64));
        assert_eq!(env.as_block_env().basefee, 42);
        assert_eq!(env.timestamp_millis_part, 321);
        assert_eq!(env.timestamp_millis(), U256::from(1_800_000_012_321u64));
    }
}
