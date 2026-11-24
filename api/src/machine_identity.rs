//! Domain-separated Ed25519 challenge signing with this boot's machine
//! identity key (`helios:system/machine-identity`).

use crate::bindings::helios::system::machine_identity as raw;
pub use crate::bindings::helios::system::machine_identity::SignError;

/// Returns this machine's 32-byte Ed25519 identity public key.
///
/// Refused with [`SignError::Denied`] unless the calling instance holds
/// `machine-right.identity`.
pub fn public_key() -> Result<Vec<u8>, SignError> {
    raw::public_key()
}

/// Signs `challenge` under the non-empty `domain` label with this machine's
/// Ed25519 identity key.
pub fn sign(domain: &str, challenge: &[u8]) -> Result<Vec<u8>, SignError> {
    raw::sign(domain, challenge)
}
