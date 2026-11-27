//! Host-side Touch ID / FIDO2 login broker for `helios vm --gui`.
//!
//! While a `--gui` session is open, this module polls the guest's
//! `/instances/` inspect tree for an active [`ConsoleLoginChallenge`] published
//! by `/console-session` under `/instances/<id>/console-auth/challenge`, verifies
//! the guest's authenticated `MachineIdentity` public key, signs the challenge
//! with the matching host operator account (triggering macOS Touch ID or FIDO2
//! touch on the host), and writes a postcard-encoded [`ConsoleLoginAuthReply`]
//! to `/run/console-auth/reply.postcard` over the existing authenticated
//! `RpcClient`.

use std::path::Path;
use std::time::Duration;

use helios_inspector_protocol::auth::{
    AuthProof, CONSOLE_AUTH_REPLY_PATH, ConsoleLoginAuthReply, ConsoleLoginChallenge,
    ConsoleLoginProof, console_login_signing_message,
};
use helios_ops::AccountError;
use helios_ops::account::{AccountStore, OperatorAccount};
#[cfg(test)]
use helios_ops::account::{Fido2Provider, TouchIdProvider};
use helios_wit_rpc::inspector::helios::system::inspect as proto_inspect;
use helios_wit_rpc::inspector_fs;

use crate::diagnostics::CliTheme;
use crate::serial::RpcClient;

/// Poll interval for both QEMU window exit and guest VT2 login challenges.
pub(super) const GUI_BROKER_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Maximum inspect entries scanned when looking for pending console login challenges.
const CONSOLE_AUTH_INSPECT_LIMIT: u32 = 256;

/// Extracts the first pending [`ConsoleLoginChallenge`] published by
/// `/console-session` whose `request_id` is newer than `last_handled_request_id`.
pub(super) fn extract_pending_console_challenge(
    snapshot: &proto_inspect::SnapshotResult,
    last_handled_request_id: u64,
) -> Option<ConsoleLoginChallenge> {
    for entry in &snapshot.entries {
        if !entry.path.starts_with("/instances/")
            || !entry.path.ends_with("/console-auth/challenge")
        {
            continue;
        }
        let proto_inspect::Value::Blob(bytes) = &entry.value else {
            continue;
        };
        let Ok(challenge) = ConsoleLoginChallenge::decode_postcard(bytes) else {
            continue;
        };
        if challenge.request_id > last_handled_request_id {
            return Some(challenge);
        }
    }
    None
}

fn process_challenge_with_signer<F>(
    challenge: &ConsoleLoginChallenge,
    expected_machine_key: Option<[u8; 32]>,
    store: &AccountStore,
    sign: F,
) -> ConsoleLoginAuthReply
where
    F: FnOnce(&OperatorAccount, &str, &[u8]) -> Result<AuthProof, AccountError>,
{
    if let Some(expected) = expected_machine_key
        && challenge.machine_public_key != expected
    {
        return ConsoleLoginAuthReply::Rejected {
            request_id: challenge.request_id,
            reason: "guest machine identity public key mismatch".to_owned(),
        };
    }

    let account = match store.load(&challenge.username) {
        Ok(account) => account,
        Err(err) => {
            return ConsoleLoginAuthReply::Rejected {
                request_id: challenge.request_id,
                reason: err.to_string(),
            };
        }
    };
    let public_key = match account.public_key() {
        Ok(pk) => pk,
        Err(err) => {
            return ConsoleLoginAuthReply::Rejected {
                request_id: challenge.request_id,
                reason: err.to_string(),
            };
        }
    };
    let message = match console_login_signing_message(challenge) {
        Ok(msg) => msg,
        Err(err) => {
            return ConsoleLoginAuthReply::Rejected {
                request_id: challenge.request_id,
                reason: err.to_string(),
            };
        }
    };
    let reason = format!("Log in to Helios console as '{}'", challenge.username);
    match sign(&account, &reason, &message) {
        Ok(proof) => ConsoleLoginAuthReply::Approved(ConsoleLoginProof {
            request_id: challenge.request_id,
            username: challenge.username.clone(),
            public_key,
            proof,
        }),
        Err(err) => ConsoleLoginAuthReply::Rejected {
            request_id: challenge.request_id,
            reason: err.to_string(),
        },
    }
}

/// Evaluates `challenge` using the host's default Touch ID and FIDO2 providers.
pub(super) fn process_console_login_challenge_default(
    challenge: &ConsoleLoginChallenge,
    expected_machine_key: Option<[u8; 32]>,
    store: &AccountStore,
) -> ConsoleLoginAuthReply {
    process_challenge_with_signer(
        challenge,
        expected_machine_key,
        store,
        |account, reason, message| account.sign_message(reason, message),
    )
}

/// Evaluates `challenge` using injected Touch ID and FIDO2 providers (for
/// deterministic unit tests without invoking live OS biometric prompts).
#[cfg(test)]
pub(super) fn process_console_login_challenge_with(
    challenge: &ConsoleLoginChallenge,
    expected_machine_key: Option<[u8; 32]>,
    store: &AccountStore,
    touch_id: &dyn TouchIdProvider,
    fido2: &dyn Fido2Provider,
) -> ConsoleLoginAuthReply {
    process_challenge_with_signer(
        challenge,
        expected_machine_key,
        store,
        |account, reason, message| account.sign_message_with(reason, message, touch_id, fido2),
    )
}

/// Performs one non-fatal poll cycle against the guest's inspect tree,
/// brokering any new VT2 login challenge on a worker thread and writing the
/// signed reply back to [`CONSOLE_AUTH_REPLY_PATH`].
pub(super) async fn poll_and_broker_once(client: &RpcClient, last_handled_request_id: &mut u64) {
    let inspect_client = proto_inspect::RpcClient::new(client.peer());
    let query = proto_inspect::Query {
        prefixes: vec!["/instances/".to_owned()],
    };
    let snapshot = match inspect_client
        .snapshot(query, CONSOLE_AUTH_INSPECT_LIMIT)
        .await
    {
        Ok(Ok(snap)) => snap,
        _ => return,
    };

    let Some(challenge) = extract_pending_console_challenge(&snapshot, *last_handled_request_id)
    else {
        return;
    };
    *last_handled_request_id = challenge.request_id;
    let expected_machine_key = client.server_public_key();
    let theme = CliTheme::stderr();
    eprintln!(
        "{} VT2 login challenge for {} {} — confirm Touch ID or FIDO2 key if prompted...",
        theme.bold_cyan("auth"),
        theme.bold(&challenge.username),
        theme.dim(format!("(request #{})", challenge.request_id)),
    );

    let (reply_tx, reply_rx) = async_channel::bounded(1);
    let challenge_for_thread = challenge.clone();
    std::thread::spawn(move || {
        let store = AccountStore::default_store();
        let reply = process_console_login_challenge_default(
            &challenge_for_thread,
            expected_machine_key,
            &store,
        );
        let _ = reply_tx.send_blocking(reply);
    });

    let Ok(reply) = reply_rx.recv().await else {
        return;
    };
    let encoded = match reply.encode_postcard() {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!(
                "{} failed to encode console auth reply: {err}",
                theme.bold_red("auth")
            );
            return;
        }
    };

    let peer = client.peer();
    if let Some(parent) = Path::new(CONSOLE_AUTH_REPLY_PATH).parent()
        && let Some(parent_str) = parent.to_str()
    {
        let _ = inspector_fs::mkdir(&peer, parent_str).await;
    }
    if let Err(err) =
        inspector_fs::write_file(&peer, CONSOLE_AUTH_REPLY_PATH, &encoded, false).await
    {
        eprintln!(
            "{} failed to deliver console auth reply to `{CONSOLE_AUTH_REPLY_PATH}`: {err}",
            theme.bold_red("auth")
        );
        return;
    }

    match &reply {
        ConsoleLoginAuthReply::Approved(_) => {
            eprintln!(
                "{} authenticated VT2 login for {} {}",
                theme.check(),
                theme.bold(&challenge.username),
                theme.dim(format!("(request #{})", challenge.request_id)),
            );
        }
        ConsoleLoginAuthReply::Rejected { reason, .. } => {
            eprintln!(
                "{} VT2 login rejected for {} {}: {reason}",
                theme.bold_red("auth"),
                theme.bold(&challenge.username),
                theme.dim(format!("(request #{})", challenge.request_id)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use helios_inspector_protocol::auth::verify_console_login;
    use helios_ops::account::{AccountAuthenticatorChoice, CreateAccountRequest, Fido2Enrollment};

    use super::*;

    struct MockTouchId {
        approve: bool,
        secrets: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl MockTouchId {
        fn new(approve: bool) -> Self {
            Self {
                approve,
                secrets: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl TouchIdProvider for MockTouchId {
        fn authenticate(&self, _reason: &str) -> Result<(), AccountError> {
            if self.approve {
                Ok(())
            } else {
                Err(AccountError::TouchIdFailed {
                    detail: "user cancelled Touch ID".to_owned(),
                })
            }
        }

        fn store_secret(
            &self,
            service: &str,
            account: &str,
            secret: &[u8],
        ) -> Result<(), AccountError> {
            self.secrets
                .lock()
                .expect("lock mock keychain")
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
            Ok(())
        }

        fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, AccountError> {
            self.secrets
                .lock()
                .expect("lock mock keychain")
                .get(&(service.to_owned(), account.to_owned()))
                .cloned()
                .ok_or_else(|| AccountError::Keychain {
                    operation: "load mock secret",
                    detail: "not found".to_owned(),
                })
        }

        fn delete_secret(&self, service: &str, account: &str) -> Result<(), AccountError> {
            self.secrets
                .lock()
                .expect("lock mock keychain")
                .remove(&(service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    struct UnusedFido2;

    impl Fido2Provider for UnusedFido2 {
        fn enroll(
            &self,
            _key_handle_path: &Path,
            _application: &str,
            _require_uv: bool,
            _comment: &str,
        ) -> Result<Fido2Enrollment, AccountError> {
            unreachable!("not used in Touch ID mock test")
        }

        fn sign(
            &self,
            _key_handle_path: &Path,
            _namespace: &str,
            _message: &[u8],
        ) -> Result<String, AccountError> {
            unreachable!("not used in Touch ID mock test")
        }
    }

    #[test]
    fn broker_approves_valid_touch_id_challenge_and_verifies_against_policy() {
        let dir = tempfile::tempdir().expect("temp accounts dir");
        let store = AccountStore::new(dir.path());
        let touch_id = MockTouchId::new(true);
        let fido2 = UnusedFido2;

        let created = store
            .create_with(
                CreateAccountRequest::new("lexo", AccountAuthenticatorChoice::TouchId),
                &touch_id,
                &fido2,
            )
            .expect("create mock Touch ID account");
        let policy = store.export_account_policy().expect("export policy");

        let machine_key = [0x42; 32];
        let challenge = ConsoleLoginChallenge {
            request_id: 7,
            username: "lexo".to_owned(),
            machine_public_key: machine_key,
            challenge_nonce: [0x99; 32],
            issued_at_unix: 1_700_000_123,
        };

        let reply = process_console_login_challenge_with(
            &challenge,
            Some(machine_key),
            &store,
            &touch_id,
            &fido2,
        );
        let ConsoleLoginAuthReply::Approved(proof) = reply else {
            panic!("expected Approved reply, got {reply:?}");
        };
        let verified = verify_console_login(&policy.accounts, &challenge, &proof)
            .expect("brokered Touch ID proof must verify against guest AccountPolicy");
        assert_eq!(verified.username, created.username);
        assert_eq!(verified.grants, created.grants);
    }

    #[test]
    fn broker_rejects_cancelled_touch_id_machine_mismatch_and_unknown_user() {
        let dir = tempfile::tempdir().expect("temp accounts dir");
        let store = AccountStore::new(dir.path());
        let enroll_touch_id = MockTouchId::new(true);
        let fido2 = UnusedFido2;

        store
            .create_with(
                CreateAccountRequest::new("lexo", AccountAuthenticatorChoice::TouchId),
                &enroll_touch_id,
                &fido2,
            )
            .expect("create account");

        let machine_key = [0x11; 32];
        let challenge = ConsoleLoginChallenge {
            request_id: 3,
            username: "lexo".to_owned(),
            machine_public_key: machine_key,
            challenge_nonce: [0x22; 32],
            issued_at_unix: 1_700_000_500,
        };

        // 1. Machine identity public key mismatch -> rejected.
        let mismatch = process_console_login_challenge_with(
            &challenge,
            Some([0xAA; 32]),
            &store,
            &enroll_touch_id,
            &fido2,
        );
        assert!(matches!(
            mismatch,
            ConsoleLoginAuthReply::Rejected { request_id: 3, .. }
        ));

        // 2. Cancelled biometric prompt -> rejected.
        let cancel_touch_id = MockTouchId::new(false);
        let cancelled = process_console_login_challenge_with(
            &challenge,
            Some(machine_key),
            &store,
            &cancel_touch_id,
            &fido2,
        );
        assert!(matches!(
            cancelled,
            ConsoleLoginAuthReply::Rejected { request_id: 3, .. }
        ));

        // 3. Unknown username -> rejected.
        let unknown_challenge = ConsoleLoginChallenge {
            username: "ghost".to_owned(),
            ..challenge
        };
        let unknown = process_console_login_challenge_with(
            &unknown_challenge,
            Some(machine_key),
            &store,
            &enroll_touch_id,
            &fido2,
        );
        assert!(matches!(
            unknown,
            ConsoleLoginAuthReply::Rejected { request_id: 3, .. }
        ));
    }

    #[test]
    fn extract_pending_challenge_decodes_and_deduplicates_by_request_id() {
        let challenge = ConsoleLoginChallenge {
            request_id: 4,
            username: "lexo".to_owned(),
            machine_public_key: [0x55; 32],
            challenge_nonce: [0x66; 32],
            issued_at_unix: 1_700_000_000,
        };
        let snapshot = proto_inspect::SnapshotResult {
            timestamp: 100,
            truncated: false,
            publications: Vec::new(),
            entries: vec![proto_inspect::Entry {
                path: "/instances/12/console-auth/challenge".to_owned(),
                value: proto_inspect::Value::Blob(
                    challenge.encode_postcard().expect("encode challenge"),
                ),
            }],
        };
        assert_eq!(
            extract_pending_console_challenge(&snapshot, 3),
            Some(challenge)
        );
        assert_eq!(extract_pending_console_challenge(&snapshot, 4), None);
    }
}
