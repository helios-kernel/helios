/// The guest vsock port `inspector-host` listens on for inspector RPC.
///
/// Both ends need the same number and neither can discover it: the guest
/// binds it before anything is listening for it, and the host connects
/// to it before the guest can announce anything. It lives here because
/// this crate is the one both ends already share.
pub const VSOCK_RPC_PORT: u32 = 1024;

#[cfg(feature = "auth")]
pub mod auth;
pub mod error;
pub mod mux;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transport;
pub mod wire;

pub use error::TransportError;
pub use error::WireError;
