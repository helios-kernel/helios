//! `helios:system/machine-identity` for the component host.
//!
//! Exposes this boot's HKDF-derived Ed25519 machine identity public key and
//! domain-separated challenge signing to instances holding
//! [`crate::MachineIdentityCap`].

use alloc::string::String;
use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use wasmtime::component::{HasSelf, Linker};

use crate::wasmtime_adapter::bindings::machine_identity::bindings::helios::system::machine_identity as identity_wit;
use crate::{ComponentHostNetwork, MachineIdentitySignError};

use super::StoreData;

pub(super) fn add_machine_identity_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    identity_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )
}

impl<CpuImpl, Net, StorageImpl> identity_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn public_key(&mut self) -> wasmtime::Result<Result<Vec<u8>, identity_wit::SignError>> {
        let Ok(_cap) = self.process_authority().derive_machine_identity_cap() else {
            return Ok(Err(identity_wit::SignError::Denied));
        };
        let key = self.runtime_state.machine_identity_key().ok_or_else(|| {
            wasmtime::Error::msg("machine identity key was queried before bring-up installed it")
        })?;
        Ok(Ok(key.public_key().to_vec()))
    }

    fn sign(
        &mut self,
        domain: String,
        challenge: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, identity_wit::SignError>> {
        let Ok(_cap) = self.process_authority().derive_machine_identity_cap() else {
            return Ok(Err(identity_wit::SignError::Denied));
        };
        let key = self.runtime_state.machine_identity_key().ok_or_else(|| {
            wasmtime::Error::msg("machine identity key was used before bring-up installed it")
        })?;
        Ok(key
            .sign(&domain, &challenge)
            .map(|signature| signature.to_vec())
            .map_err(map_sign_error))
    }
}

fn map_sign_error(error: MachineIdentitySignError) -> identity_wit::SignError {
    match error {
        MachineIdentitySignError::InvalidDomain => identity_wit::SignError::InvalidDomain,
        MachineIdentitySignError::ChallengeTooLarge { limit } => {
            identity_wit::SignError::ChallengeTooLarge(limit)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;
    use futures_lite::future::block_on;

    use super::identity_wit::{self, Host as _};
    use crate::test_support::test_root_entropy;
    use crate::wasmtime_adapter::component_host::service::test_store::store_data_authorized;
    use crate::{
        MAX_MACHINE_IDENTITY_CHALLENGE_BYTES, MachineAuthorityRights, MachineIdentityKey,
        NoMeasuredBoot, ProcessAuthority, settle_signing_key,
    };

    fn settled_identity_key() -> MachineIdentityKey {
        let entropy = test_root_entropy();
        let mut tpm: Option<NoMeasuredBoot> = None;
        block_on(settle_signing_key(tpm.as_mut(), &[0x42; 32], &entropy))
            .expect("ephemeral bring-up key settlement succeeds")
            .machine_identity
    }

    #[test]
    fn machine_identity_host_enforces_identity_capability_separately_from_machine_control() {
        let mut control_only = ProcessAuthority::empty();
        control_only.grant_machine_rights(MachineAuthorityRights::CONTROL);
        let mut store = store_data_authorized(control_only, |state| {
            state.install_machine_identity_key(settled_identity_key());
        });

        assert_eq!(
            store.public_key().unwrap(),
            Err(identity_wit::SignError::Denied)
        );
        assert_eq!(
            store
                .sign(String::from("ssh.host.v1"), b"challenge".to_vec())
                .unwrap(),
            Err(identity_wit::SignError::Denied)
        );
    }

    #[test]
    fn machine_identity_host_signs_domain_separated_challenges_and_validates_bounds() {
        let mut identity_auth = ProcessAuthority::empty();
        identity_auth.grant_machine_rights(MachineAuthorityRights::IDENTITY);
        let mut store = store_data_authorized(identity_auth, |state| {
            state.install_machine_identity_key(settled_identity_key());
        });

        let pubkey_vec = store
            .public_key()
            .unwrap()
            .expect("identity cap permits public_key");
        let pubkey: [u8; 32] = pubkey_vec
            .try_into()
            .expect("Ed25519 public key is 32 bytes");
        let installed = store
            .runtime_state
            .machine_identity_key()
            .expect("test installed machine identity key");
        assert_eq!(pubkey, installed.public_key());

        let challenge = "挑战・チャレンジ・챌린지".as_bytes().to_vec();
        let sig_vec = store
            .sign(
                String::from("helios.host-agent.handshake.v1"),
                challenge.clone(),
            )
            .unwrap()
            .expect("valid domain and challenge sign cleanly");
        let sig: [u8; 64] = sig_vec.try_into().expect("Ed25519 signature is 64 bytes");

        let installed = store
            .runtime_state
            .machine_identity_key()
            .expect("test installed machine identity key");
        installed
            .verify("helios.host-agent.handshake.v1", &challenge, &sig)
            .expect("signature must verify under matching domain");
        assert!(
            installed
                .verify("helios.other-protocol.v1", &challenge, &sig)
                .is_err(),
            "cross-domain signature replay must fail"
        );

        assert_eq!(
            store.sign(String::new(), b"abc".to_vec()).unwrap(),
            Err(identity_wit::SignError::InvalidDomain)
        );
        let oversized = vec![0u8; MAX_MACHINE_IDENTITY_CHALLENGE_BYTES + 1];
        assert_eq!(
            store
                .sign(String::from("helios.host-agent.handshake.v1"), oversized)
                .unwrap(),
            Err(identity_wit::SignError::ChallengeTooLarge(
                MAX_MACHINE_IDENTITY_CHALLENGE_BYTES as u32
            ))
        );
    }
}
