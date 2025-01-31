//! Kernels that provide RNG functionality and ephemeral keypairs for
//! simulating calls or bridging with TEE services.
use reth_revm::seismic::{kernel::{kernel_interface::{KernelKeys, KernelRng}}, rng::{LeafRng, RootRng, SchnorrkelKeypair}, Kernel};
use revm::seismic::RngContainer;
use std::fmt;

/// A `Kernel` variant used for simulating calls. The main difference is adding
/// append_local_entropy, meaning each call will have its own RNG output
/// Holds an internal RNG container and ephemeral Schnorrkel keypair.
pub struct CallKernel {
    rng_container: RngContainer,
}

impl fmt::Debug for CallKernel {
    /// Formats a `CallKernel` instance as `Kernel { ... }`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We can’t easily peek into the trait object, so just say "Kernel { ... }"
        write!(f, "Kernel {{ ... }}")
    }
}

impl KernelRng for CallKernel {
    /// Resets the `RootRng` to a new instance derived from the `root_vrf_key`.
    fn reset_rng(&mut self) {
        self.rng_container.reset_rng();
    }

    /// Returns a reference to the underlying `RootRng`.
    fn root_rng_ref(&self) -> &RootRng {
        self.rng_container.root_rng_ref()
    }

    /// Returns a mutable reference to the underlying `RootRng`.
    fn root_rng_mut_ref(&mut self) -> &mut RootRng {
        self.rng_container.root_rng_mut_ref()
    }

    /// Returns a mutable reference to the optional `LeafRng`.
    fn leaf_rng_mut_ref(&mut self) -> &mut Option<LeafRng> {
        self.rng_container.leaf_rng_mut_ref()
    }

    /// Optionally appends additional local entropy to the `RootRng`.
    fn maybe_append_entropy(&mut self) {
        let rng = self.root_rng_mut_ref();
        rng.append_local_entropy();
    }
}

impl KernelKeys for CallKernel {
    /// Returns a clone of the ephemeral Schnorrkel keypair for RNG usage.
    fn get_root_vrf_key(&self) -> SchnorrkelKeypair {
        self.root_rng_ref().get_root_vrf_key()
    }

}

impl From<CallKernel> for Kernel {
    /// Converts a `CallKernel` into a boxed trait object `Kernel`.
    fn from(val: CallKernel) -> Self {
        Kernel::from_boxed(Box::new(val))
    }
}

/// `CallKernel::clone()` does not clone the `leaf_rng`
/// because cloning `merlin::TranscriptRng` is intentionally difficult
/// by the underlying `merlin` crate. The `leaf_rng` is intended
/// for a single usage per call simulation and should not be
/// cloned mid-simulation.
impl Clone for CallKernel {
    fn clone(&self) -> Self {
        Self {
            rng_container: self.rng_container.clone(),
        }
    }
}

impl Default for CallKernel {
    /// Creates a default `CallKernel` with a default `RngContainer`
    /// and a sample Schnorrkel keypair.
    fn default() -> Self {
        Self {
            rng_container: RngContainer::default(),
        }
    }
}

impl CallKernel {
    /// Creates a new `CallKernel` from a given `root_vrf_key` and ephemeral keypair.
    pub fn new(root_vrf_key: SchnorrkelKeypair) -> Self {
        Self {
            rng_container: RngContainer::new(root_vrf_key),
        }
    }
}

/// A `Kernel` variant intended for mainnet usage with TEE integration.
/// Currently, it uses the same pattern as `CallKernel` but is intended
/// for real-world bridging rather than local simulation.
pub struct SeismicKernel {
    rng_container: RngContainer,
}

impl fmt::Debug for SeismicKernel {
    /// Formats a `SeismicKernel` instance as `Kernel { ... }`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We can’t easily peek into the trait object, so just say "Kernel { ... }"
        write!(f, "Kernel {{ ... }}")
    }
}

impl KernelRng for SeismicKernel {
    /// Resets the `RootRng` to a new instance derived from the `root_vrf_key`.
    fn reset_rng(&mut self) {
        self.rng_container.reset_rng()
    }

    /// Returns a reference to the underlying `RootRng`.
    fn root_rng_ref(&self) -> &RootRng {
        self.rng_container.root_rng_ref()
    }


    /// Returns a mutable reference to the underlying `RootRng`.
    fn root_rng_mut_ref(&mut self) -> &mut RootRng {
        self.rng_container.root_rng_mut_ref()
    }

    /// Returns a mutable reference to the optional `LeafRng`.
    fn leaf_rng_mut_ref(&mut self) -> &mut Option<LeafRng> {
        self.rng_container.leaf_rng_mut_ref()
    }

    /// Currently does no-op for additional entropy.
    fn maybe_append_entropy(&mut self) {
        // no-op
    }
}

impl KernelKeys for SeismicKernel {
    /// Returns a clone of the ephemeral Schnorrkel keypair for RNG usage.
    fn get_root_vrf_key(&self) -> SchnorrkelKeypair {
        self.root_rng_ref().get_root_vrf_key()
    }
}

impl From<SeismicKernel> for Kernel {
    /// Converts a `SeismicKernel` into a boxed trait object `Kernel`.
    fn from(val: SeismicKernel) -> Self {
        Kernel::from_boxed(Box::new(val))
    }
}

/// `SeismicKernel::clone()` does not clone the `leaf_rng`
/// because cloning `merlin::TranscriptRng` is intentionally difficult
/// by the underlying `merlin` crate. The `leaf_rng` is meant
/// to be used once per call simulation and should not be
/// cloned mid-simulation.
impl Clone for SeismicKernel {
    fn clone(&self) -> Self {
        Self {
            rng_container: self.rng_container.clone(),
        }
    }
}

impl Default for SeismicKernel {
    /// Creates a default `SeismicKernel` with a default `RngContainer`
    /// and a sample Schnorrkel keypair.
    fn default() -> Self {
        Self {
            rng_container: RngContainer::default(),
        }
    }
}

impl SeismicKernel {
    /// Creates a new `SeismicKernel` from a given `root_vrf_key` and ephemeral keypair.
    pub fn new(root_vrf_key: SchnorrkelKeypair) -> Self {
        Self {
            rng_container: RngContainer::new(root_vrf_key),
        }
    }
}

