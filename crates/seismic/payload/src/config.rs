/// Settings for the OP builder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeismicBuilderConfig {
    pub desired_gas_limit: u64,
    pub await_payload_on_missing: bool,
    // gas_limit: Option<u64>,
}

impl SeismicBuilderConfig {
    /// Create new payload builder config.
    pub const fn new() -> Self {
        Self { desired_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M, await_payload_on_missing: true }
    }

    /// Returns the gas limit for the next block based
    /// on parent and desired gas limits.
    pub fn gas_limit(&self, parent_gas_limit: u64) -> u64 {
        calculate_block_gas_limit(parent_gas_limit, self.desired_gas_limit)
    }

    /// Set desired gas limit.
    pub const fn with_gas_limit(mut self, desired_gas_limit: u64) -> Self {
        self.desired_gas_limit = desired_gas_limit;
        self
    }
}

/// Calculate the gas limit for the next block based on parent and desired gas limits.
/// Ref: <https://github.com/ethereum/go-ethereum/blob/88cbfab332c96edfbe99d161d9df6a40721bd786/core/block_validator.go#L166>
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit - delta;
    let max_gas_limit = parent_gas_limit + delta;
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}

/// The bound divisor of the gas limit, used in update calculations.
pub const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;
/// The default Ethereum block gas limit: 30M
pub const ETHEREUM_BLOCK_GAS_LIMIT_30M: u64 = 30_000_000;