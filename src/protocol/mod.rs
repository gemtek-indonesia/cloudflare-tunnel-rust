//! Cloudflare edge wire contracts, pinned to cloudflared 18cdfe0.

#[allow(clippy::all, unused_parens)]
pub mod tunnelrpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/tunnelrpc_capnp.rs"));
}
#[allow(clippy::all, unused_parens)]
pub mod quic_metadata_protocol_capnp {
    include!(concat!(env!("OUT_DIR"), "/quic_metadata_protocol_capnp.rs"));
}

pub mod callbacks;
pub mod datagram;
pub mod headers;
pub mod metadata;
pub mod registration;

pub fn reader_options() -> capnp::message::ReaderOptions {
    capnp::message::ReaderOptions::default()
}
