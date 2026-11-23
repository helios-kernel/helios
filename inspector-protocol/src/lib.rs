/// The guest vsock port the debugger serves inspector RPC on.
///
/// Both ends need the same number and neither can discover it: the guest
/// binds it before anything is listening for it, and the host connects
/// to it before the guest can announce anything. It lives here because
/// this crate is the one both ends already share.
pub const VSOCK_RPC_PORT: u32 = 1024;

#[cfg(feature = "system")]
pub mod debugger;
pub mod error;
pub mod mux;
#[cfg(feature = "system")]
pub mod system;
pub mod transport;
pub mod wire;

#[cfg(feature = "system")]
pub use error::DispatchError;
#[cfg(feature = "system")]
pub use error::RpcError;
pub use error::TransportError;
pub use error::WireError;
