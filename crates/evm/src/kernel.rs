use reth_revm::seismic::{kernel::{get_sample_schnorrkel_keypair, kernel_interface::{KernelKeys, KernelRng}}, rng::{LeafRng, RootRng, SchnorrkelKeypair}, Kernel, precompiles::SecretKey};
use revm::seismic::RngContainer;
use tee_service_api::get_sample_secp256k1_sk;
use std::fmt;

pub struct CallKernel {
    rng_container: RngContainer,
    secret_key: SecretKey,
    eph_rng_keypair: SchnorrkelKeypair,
}

impl fmt::Debug for CallKernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We can’t easily peek into the trait object, so just say "Kernel { ... }"
        write!(f, "Kernel {{ ... }}")
    }
}

impl KernelRng for CallKernel {
    fn reset_rng(&mut self, root_vrf_key: SchnorrkelKeypair) {
        self.rng_container.reset_rng(root_vrf_key);
    }

    fn root_rng_mut_ref(&mut self) -> &mut RootRng {
        self.rng_container.root_rng_mut_ref()
    }

    fn leaf_rng_mut_ref(&mut self) -> &mut Option<LeafRng> {
        self.rng_container.leaf_rng_mut_ref()
    }

    fn maybe_append_entropy(&mut self) {
        let rng = self.root_rng_mut_ref();
        rng.append_local_entropy();
    }
}

impl KernelKeys for CallKernel {
    fn get_io_key(&self) -> SecretKey {
        self.secret_key
    }
    fn get_eph_rng_keypair(&self) -> SchnorrkelKeypair {
        self.eph_rng_keypair.clone()
    }
}

impl From<CallKernel> for Kernel {
    fn from(val: CallKernel) -> Self {
        Kernel::from_boxed(Box::new(val))
    }
}

/// CallKernel::clone() does not clone the leaf_rng
/// becayse cloning merlin::TranscriptRng is intentionally difficult
/// by the underlying merlin crate
/// leaf_rng is meant to be used once per call simulation, so
/// it should not be cloned mid-simulation
impl Clone for CallKernel {
    fn clone(&self) -> Self {
        Self {
            rng_container: self.rng_container.clone(),
            secret_key: self.secret_key,
            eph_rng_keypair: self.eph_rng_keypair.clone(),
        }
    }
}

impl Default for CallKernel {
    fn default() -> Self {
        Self {
            rng_container: RngContainer::default(),
            secret_key: get_sample_secp256k1_sk(),
            eph_rng_keypair: get_sample_schnorrkel_keypair(),
        }
    }
}

impl CallKernel {
    pub fn new(root_vrf_key: SchnorrkelKeypair, secret_key: SecretKey, eph_rng_keypair: SchnorrkelKeypair) -> Self {
        Self {
            rng_container: RngContainer::new(root_vrf_key),
            secret_key,
            eph_rng_keypair,
        }
    }
}


// TODO: Wire this to mainnet actual TEE_service
pub struct SeismicKernel {
    rng_container: RngContainer,
    secret_key: SecretKey,
    eph_rng_keypair: SchnorrkelKeypair,
}

impl fmt::Debug for SeismicKernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We can’t easily peek into the trait object, so just say "Kernel { ... }"
        write!(f, "Kernel {{ ... }}")
    }
}

impl KernelRng for SeismicKernel {
    fn reset_rng(&mut self, root_vrf_key: SchnorrkelKeypair) {
        self.rng_container.reset_rng(root_vrf_key);
    }

    fn root_rng_mut_ref(&mut self) -> &mut RootRng {
        self.rng_container.root_rng_mut_ref()
    }

    fn leaf_rng_mut_ref(&mut self) -> &mut Option<LeafRng> {
        self.rng_container.leaf_rng_mut_ref()
    }

    fn maybe_append_entropy(&mut self) {
        // no-op
    }
}

impl KernelKeys for SeismicKernel {
    fn get_io_key(&self) -> SecretKey {
        self.secret_key
    }
    fn get_eph_rng_keypair(&self) -> SchnorrkelKeypair {
        self.eph_rng_keypair.clone()
    }
}

impl From<SeismicKernel> for Kernel {
    fn from(val: SeismicKernel) -> Self {
        Kernel::from_boxed(Box::new(val))
    }
}

/// SeismicKernel::clone() does not clone the leaf_rng
/// becayse cloning merlin::TranscriptRng is intentionally difficult
/// by the underlying merlin crate
/// leaf_rng is meant to be used once per call simulation, so
/// it should not be cloned mid-simulation
impl Clone for SeismicKernel {
    fn clone(&self) -> Self {
        Self {
            rng_container: self.rng_container.clone(),
            secret_key: self.secret_key,
            eph_rng_keypair: self.eph_rng_keypair.clone(),
        }
    }
}

impl Default for SeismicKernel {
    fn default() -> Self {
        Self {
            rng_container: RngContainer::default(),
            secret_key: get_sample_secp256k1_sk(),
            eph_rng_keypair: get_sample_schnorrkel_keypair(),
        }
    }
}

impl SeismicKernel {
    pub fn new(root_vrf_key: SchnorrkelKeypair, secret_key: SecretKey, eph_rng_keypair: SchnorrkelKeypair) -> Self {
        Self {
            rng_container: RngContainer::new(root_vrf_key),
            secret_key,
            eph_rng_keypair,
        }
    }
}


