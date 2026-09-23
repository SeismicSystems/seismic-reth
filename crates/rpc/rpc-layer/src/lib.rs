//! Layer implementations used in RPC

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use http::HeaderMap;
use jsonrpsee_http_client::HttpResponse;

mod auth_client_layer;
mod auth_layer;
mod compression_layer;
mod jwt_validator;
/// Single-signature authentication middleware using secp256k1 / Ethereum addresses.
pub mod signature_auth_layer;

pub use auth_layer::{AuthService, ResponseFuture};
pub use compression_layer::CompressionLayer;
pub use signature_auth_layer::{
    eip712_signing_hash, CurrentBlockFn, OpsWhitelistTxAuth, SignatureAuthConfig,
    SignatureAuthLayer, SignatureAuthService, Whitelist, EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION,
    NONCE_HEADER, OPS_AUTH_CONTRACT, OPS_AUTH_SLOT, SIGNATURE_HEADER, WHITELIST_TX_SENTINEL,
};

// Export alloy JWT types
pub use alloy_rpc_types_engine::{Claims, JwtError, JwtSecret};

pub use auth_client_layer::{secret_to_bearer_header, AuthClientLayer, AuthClientService};
pub use auth_layer::AuthLayer;
pub use jwt_validator::JwtAuthValidator;

/// General purpose trait to validate Http Authorization headers. It's supposed to be integrated as
/// a validator trait into an [`AuthLayer`].
pub trait AuthValidator {
    /// This function is invoked by the [`AuthLayer`] to perform validation on Http headers.
    /// The result conveys validation errors in the form of an Http response.
    #[expect(clippy::result_large_err)]
    fn validate(&self, headers: &HeaderMap) -> Result<(), HttpResponse>;
}
