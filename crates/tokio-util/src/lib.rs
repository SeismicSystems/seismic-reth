//! Event listeners

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod event_sender;
mod event_stream;
pub use event_sender::EventSender;
pub use event_stream::EventStream;

#[cfg(feature = "time")]
pub mod ratelimit;
