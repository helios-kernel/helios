//! Hardware-backed and software operator accounts (`~/.config/helios/accounts/<username>.toml`).
//!
//! Supports:
//! - macOS Touch ID (`LocalAuthentication.framework` `LAContext` biometric prompt +
//!   macOS Keychain-sealed NIST P-256 signing key via `security-framework`; zero
//!   plaintext secret on disk)
//! - Cross-platform FIDO2 hardware security keys via OpenSSH (`ssh-keygen -t ed25519-sk`
//!   with automatic `ecdsa-sk` P-256 fallback and `ssh-keygen -Y sign` `SSHSIG` parsing)
//! - Software NIST P-256 and Ed25519 keys for deterministic CI/headless environments

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use helios_inspector_protocol::auth::{
    AccountPolicy, AuthError as ProtocolAuthError, AuthProof, AuthPublicKey, AuthorizedAccount,
    ClientIdentity, ConsoleLoginChallenge, ConsoleLoginProof, DEFAULT_FIDO2_APPLICATION,
    DirectoryRightsMask, DirectoryRule, FIDO2_SSHSIG_NAMESPACE, Fido2MessageMode,
    NetworkRightsMask, ProcessRightsMask, ScopeRule, SessionGrants, SshSigHashAlg,
    TerminalRightsMask, TransportMask, VerifiedAccountSession, console_login_signing_message,
    p256_public_key_sec1, random_32, sign_p256_scalar, verify_console_login,
};
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::AccountError;
use crate::target::{Attenuation, GrantRight, TargetStore, normalize_scope};

/// macOS Keychain generic-password service name for Touch ID operator accounts.
pub const TOUCH_ID_KEYCHAIN_SERVICE: &str = "cool.lexo.helios.touch-id";

/// Supported FIDO2 security-key algorithms enrolled through OpenSSH `-sk` keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fido2Alg {
    Ed25519,
    P256,
}

impl Fido2Alg {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "fido2-ed25519",
            Self::P256 => "fido2-p256",
        }
    }
}

/// Persisted authenticator specification inside `<username>.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuthenticatorSpec {
    /// macOS Touch ID biometric prompt gating a P-256 signing scalar stored in
    /// the user's macOS Keychain. Only the compressed 33-byte SEC1 public key
    /// is written to disk.
    TouchId {
        keychain_service: String,
        keychain_account: String,
        public_key_sec1_hex: String,
    },
    /// FIDO2 security key backed by an OpenSSH `-sk` encrypted key handle file
    /// (the private key never leaves the hardware token).
    Fido2 {
        key_type: Fido2Alg,
        application: String,
        require_uv: bool,
        public_key_hex: String,
        key_handle_path: PathBuf,
    },
    /// Software NIST P-256 key stored in a `0600` TOML file (for headless / CI use).
    SoftwareP256 {
        secret_scalar_hex: String,
        public_key_sec1_hex: String,
    },
    /// Software Ed25519 key stored in a `0600` TOML file (for headless / CI use).
    SoftwareEd25519 {
        secret_seed_hex: String,
        public_key_hex: String,
    },
}

impl AuthenticatorSpec {
    /// Short human-readable authenticator kind label.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::TouchId { .. } => "touch-id",
            Self::Fido2 { .. } => "fido2",
            Self::SoftwareP256 { .. } => "p256",
            Self::SoftwareEd25519 { .. } => "ed25519",
        }
    }
}

/// Requested authenticator kind when enrolling a new operator account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAuthenticatorChoice {
    TouchId,
    Fido2,
    SoftwareP256,
    SoftwareEd25519,
}

impl AccountAuthenticatorChoice {
    /// Platform default when no explicit authenticator flag is passed:
    /// Touch ID on macOS, FIDO2 on other operating systems.
    #[must_use]
    pub const fn platform_default() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::TouchId
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::Fido2
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TouchId => "touch-id",
            Self::Fido2 => "fido2",
            Self::SoftwareP256 => "p256",
            Self::SoftwareEd25519 => "ed25519",
        }
    }
}

/// Parameters for [`AccountStore::create`] / [`AccountStore::create_with`].
#[derive(Debug, Clone)]
pub struct CreateAccountRequest {
    pub username: String,
    pub authenticator: AccountAuthenticatorChoice,
    pub require_uv: bool,
    pub application: String,
    pub grants: SessionGrants,
    pub allowed_transports: TransportMask,
    pub replace: bool,
}

impl CreateAccountRequest {
    #[must_use]
    pub fn new(username: impl Into<String>, authenticator: AccountAuthenticatorChoice) -> Self {
        Self {
            username: username.into(),
            authenticator,
            require_uv: false,
            application: DEFAULT_FIDO2_APPLICATION.to_owned(),
            grants: SessionGrants::full_worker_ceiling(),
            allowed_transports: TransportMask::ALL,
            replace: false,
        }
    }
}

/// Persisted operator account stored at `~/.config/helios/accounts/<username>.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAccount {
    pub username: String,
    pub authenticator: AuthenticatorSpec,
    pub grants: SessionGrants,
    #[serde(default = "default_allowed_transports")]
    pub allowed_transports: TransportMask,
    pub created_at_unix: u64,
}

const fn default_allowed_transports() -> TransportMask {
    TransportMask::ALL
}

impl OperatorAccount {
    /// Decodes the account's wire [`AuthPublicKey`] and validates its encoding.
    pub fn public_key(&self) -> Result<AuthPublicKey, AccountError> {
        let key = match &self.authenticator {
            AuthenticatorSpec::TouchId {
                public_key_sec1_hex,
                ..
            }
            | AuthenticatorSpec::SoftwareP256 {
                public_key_sec1_hex,
                ..
            } => AuthPublicKey::P256(decode_hex_33(public_key_sec1_hex).map_err(|detail| {
                AccountError::InvalidAccount {
                    username: self.username.clone(),
                    detail,
                }
            })?),
            AuthenticatorSpec::SoftwareEd25519 { public_key_hex, .. } => {
                AuthPublicKey::Ed25519(decode_hex_32(public_key_hex).map_err(|detail| {
                    AccountError::InvalidAccount {
                        username: self.username.clone(),
                        detail,
                    }
                })?)
            }
            AuthenticatorSpec::Fido2 {
                key_type,
                application,
                require_uv,
                public_key_hex,
                ..
            } => match key_type {
                Fido2Alg::Ed25519 => AuthPublicKey::Fido2Ed25519 {
                    public_key: decode_hex_32(public_key_hex).map_err(|detail| {
                        AccountError::InvalidAccount {
                            username: self.username.clone(),
                            detail,
                        }
                    })?,
                    application: application.clone(),
                    require_uv: *require_uv,
                },
                Fido2Alg::P256 => AuthPublicKey::Fido2P256 {
                    public_key: decode_hex_33(public_key_hex).map_err(|detail| {
                        AccountError::InvalidAccount {
                            username: self.username.clone(),
                            detail,
                        }
                    })?,
                    application: application.clone(),
                    require_uv: *require_uv,
                },
            },
        };
        key.validate()?;
        Ok(key)
    }

    /// Converts this host account record into an [`AuthorizedAccount`] suitable
    /// for staging into `/etc/helios/accounts.postcard`.
    pub fn to_authorized_account(&self) -> Result<AuthorizedAccount, AccountError> {
        let account = AuthorizedAccount {
            username: self.username.clone(),
            public_key: self.public_key()?,
            grants: self.grants.clone(),
            allowed_transports: self.allowed_transports,
        };
        account.validate()?;
        Ok(account)
    }

    /// Signs `message` using the account's configured host authenticator.
    pub fn sign_message(&self, reason: &str, message: &[u8]) -> Result<AuthProof, AccountError> {
        let touch_id = default_touch_id_provider();
        let fido2 = OpenSshFido2Provider;
        self.sign_message_with(reason, message, &touch_id, &fido2)
    }

    /// Signs `message` using injected Touch ID and FIDO2 providers (used for
    /// deterministic unit tests without invoking system dialogs or hardware keys).
    pub fn sign_message_with(
        &self,
        reason: &str,
        message: &[u8],
        touch_id: &dyn TouchIdProvider,
        fido2: &dyn Fido2Provider,
    ) -> Result<AuthProof, AccountError> {
        match &self.authenticator {
            AuthenticatorSpec::TouchId {
                keychain_service,
                keychain_account,
                ..
            } => {
                // Always gate Keychain access behind biometric evaluation first.
                touch_id.authenticate(reason)?;
                let secret =
                    Zeroizing::new(touch_id.load_secret(keychain_service, keychain_account)?);
                let mut scalar = Zeroizing::new([0u8; 32]);
                if secret.len() != 32 {
                    return Err(AccountError::Keychain {
                        operation: "load Touch ID P-256 scalar",
                        detail: format!("expected 32-byte scalar, got {} bytes", secret.len()),
                    });
                }
                scalar.copy_from_slice(&secret);
                let sig = sign_p256_scalar(&scalar, message)?;
                Ok(AuthProof::P256(sig))
            }
            AuthenticatorSpec::Fido2 {
                key_handle_path, ..
            } => {
                let armored = fido2.sign(key_handle_path, FIDO2_SSHSIG_NAMESPACE, message)?;
                parse_sshsig_fido2_proof(&armored, FIDO2_SSHSIG_NAMESPACE)
            }
            AuthenticatorSpec::SoftwareP256 {
                secret_scalar_hex, ..
            } => {
                let scalar =
                    Zeroizing::new(decode_hex_32(secret_scalar_hex).map_err(|detail| {
                        AccountError::InvalidAccount {
                            username: self.username.clone(),
                            detail,
                        }
                    })?);
                let sig = sign_p256_scalar(&scalar, message)?;
                Ok(AuthProof::P256(sig))
            }
            AuthenticatorSpec::SoftwareEd25519 {
                secret_seed_hex, ..
            } => {
                let seed = Zeroizing::new(decode_hex_32(secret_seed_hex).map_err(|detail| {
                    AccountError::InvalidAccount {
                        username: self.username.clone(),
                        detail,
                    }
                })?);
                let signing_key = Ed25519SigningKey::from_bytes(&seed);
                Ok(AuthProof::Ed25519(signing_key.sign(message).to_bytes()))
            }
        }
    }

    /// Converts this operator account into a wire [`ClientIdentity`] that signs
    /// inspector challenges on demand.
    pub fn to_client_identity(&self) -> Result<ClientIdentity, AccountError> {
        let public_key = self.public_key()?;
        let cloned = self.clone();
        let reason = format!("Sign in to Helios as '{}'", self.username);
        Ok(ClientIdentity::from_account_signer(
            self.username.clone(),
            public_key,
            None,
            Arc::new(move |msg| {
                cloned
                    .sign_message(&reason, msg)
                    .map_err(|err| ProtocolAuthError::SigningFailed {
                        detail: err.to_string(),
                    })
            }),
        ))
    }

    /// Performs a local challenge-response self-test using
    /// [`verify_console_login`] against this account's public key.
    pub fn verify_self(&self) -> Result<VerifiedAccountSession, AccountError> {
        let touch_id = default_touch_id_provider();
        let fido2 = OpenSshFido2Provider;
        self.verify_self_with(&touch_id, &fido2)
    }

    /// Performs a local challenge-response self-test using injected providers.
    pub fn verify_self_with(
        &self,
        touch_id: &dyn TouchIdProvider,
        fido2: &dyn Fido2Provider,
    ) -> Result<VerifiedAccountSession, AccountError> {
        let authorized = self.to_authorized_account()?;
        let challenge = ConsoleLoginChallenge {
            request_id: 1,
            username: self.username.clone(),
            machine_public_key: random_32()?,
            challenge_nonce: random_32()?,
            issued_at_unix: unix_now_secs(),
        };
        let message = console_login_signing_message(&challenge)?;
        let reason = format!("Verify Helios account '{}'", self.username);
        let proof = self.sign_message_with(&reason, &message, touch_id, fido2)?;
        let response = ConsoleLoginProof {
            request_id: challenge.request_id,
            username: self.username.clone(),
            public_key: authorized.public_key.clone(),
            proof,
        };
        Ok(verify_console_login(&[authorized], &challenge, &response)?)
    }
}

/// Persistent host directory of enrolled operator accounts.
#[derive(Debug, Clone)]
pub struct AccountStore {
    dir: PathBuf,
}

impl AccountStore {
    /// Default accounts directory (`<config_dir>/accounts`).
    #[must_use]
    pub fn default_dir() -> PathBuf {
        TargetStore::default_config_dir().join("accounts")
    }

    /// Opens the default operator account store.
    #[must_use]
    pub fn default_store() -> Self {
        Self {
            dir: Self::default_dir(),
        }
    }

    /// Opens an account store backed by `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Root directory of this account store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path to `<username>.toml` within this store.
    #[must_use]
    pub fn path_for(&self, username: &str) -> PathBuf {
        self.dir.join(format!("{username}.toml"))
    }

    /// Validates `username` and checks whether an account can be created in
    /// this store without invoking any hardware authenticator.
    pub fn check_creatable(&self, username: &str, replace: bool) -> Result<(), AccountError> {
        validate_username(username)?;
        if !replace {
            let path = self.path_for(username);
            if path.exists() {
                return Err(AccountError::AlreadyExists {
                    username: username.to_owned(),
                    path,
                });
            }
        }
        Ok(())
    }

    /// Enrolls a new operator account using the host's default Touch ID and
    /// FIDO2 providers.
    pub fn create(&self, req: CreateAccountRequest) -> Result<OperatorAccount, AccountError> {
        let touch_id = default_touch_id_provider();
        let fido2 = OpenSshFido2Provider;
        self.create_with(req, &touch_id, &fido2)
    }

    /// Enrolls a new operator account using injected providers.
    pub fn create_with(
        &self,
        req: CreateAccountRequest,
        touch_id: &dyn TouchIdProvider,
        fido2: &dyn Fido2Provider,
    ) -> Result<OperatorAccount, AccountError> {
        self.check_creatable(&req.username, req.replace)?;
        req.grants.validate()?;
        if req.authenticator == AccountAuthenticatorChoice::Fido2 && req.application.is_empty() {
            return Err(AccountError::InvalidAccount {
                username: req.username,
                detail: "FIDO2 application string must not be empty".to_owned(),
            });
        }

        let account_path = self.path_for(&req.username);
        let existing = if req.replace && account_path.exists() {
            match Self::load_from_path(&account_path, &req.username) {
                Ok(acct) => Some(acct),
                Err(AccountError::NotFound { .. }) => None,
                Err(err) => {
                    tracing::warn!(
                        username = %req.username,
                        path = %account_path.display(),
                        error = %err,
                        "ignoring unreadable existing account during replace"
                    );
                    None
                }
            }
        } else {
            None
        };

        fs::create_dir_all(&self.dir).map_err(|source| AccountError::WriteAccount {
            path: account_path.clone(),
            source,
        })?;

        let mut fido2_staging: Option<StagedFido2Handle> = None;
        let authenticator = match req.authenticator {
            AccountAuthenticatorChoice::TouchId => {
                let reason = format!("Create Helios account '{}'", req.username);
                touch_id.authenticate(&reason)?;
                let (scalar, pub_sec1) = generate_p256_keypair()?;
                let fp_hex = encode_hex(&AuthPublicKey::P256(pub_sec1).fingerprint_sha256());
                let keychain_account = format!("{}-{}", req.username, &fp_hex[..12]);
                touch_id.store_secret(TOUCH_ID_KEYCHAIN_SERVICE, &keychain_account, &*scalar)?;
                AuthenticatorSpec::TouchId {
                    keychain_service: TOUCH_ID_KEYCHAIN_SERVICE.to_owned(),
                    keychain_account,
                    public_key_sec1_hex: encode_hex(&pub_sec1),
                }
            }
            AccountAuthenticatorChoice::Fido2 => {
                let staging_dir = tempfile::Builder::new()
                    .prefix(&format!(".{}.fido2-staging-", req.username))
                    .tempdir_in(&self.dir)
                    .map_err(|source| AccountError::WriteAccount {
                        path: account_path.clone(),
                        source,
                    })?;
                let staged_key_handle_path = staging_dir.path().join("id_sk");
                let final_key_handle_path = self.dir.join(format!("{}.fido2_sk", req.username));
                let comment = format!("helios:{}", req.username);
                let enrolled = fido2.enroll(
                    &staged_key_handle_path,
                    &req.application,
                    req.require_uv,
                    &comment,
                )?;
                fido2_staging = Some(StagedFido2Handle {
                    _staging_dir: staging_dir,
                    staged_path: staged_key_handle_path,
                    final_path: final_key_handle_path.clone(),
                });
                AuthenticatorSpec::Fido2 {
                    key_type: enrolled.key_type,
                    application: enrolled.application,
                    require_uv: req.require_uv,
                    public_key_hex: encode_hex(&enrolled.public_key_bytes),
                    key_handle_path: final_key_handle_path,
                }
            }
            AccountAuthenticatorChoice::SoftwareP256 => {
                let (scalar, pub_sec1) = generate_p256_keypair()?;
                AuthenticatorSpec::SoftwareP256 {
                    secret_scalar_hex: encode_hex(&*scalar),
                    public_key_sec1_hex: encode_hex(&pub_sec1),
                }
            }
            AccountAuthenticatorChoice::SoftwareEd25519 => {
                let seed = Zeroizing::new(random_32()?);
                let pub_bytes = Ed25519SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes();
                AuthenticatorSpec::SoftwareEd25519 {
                    secret_seed_hex: encode_hex(&*seed),
                    public_key_hex: encode_hex(&pub_bytes),
                }
            }
        };

        let account = OperatorAccount {
            username: req.username,
            authenticator,
            grants: req.grants,
            allowed_transports: req.allowed_transports,
            created_at_unix: unix_now_secs(),
        };
        let encoded = match toml::to_string_pretty(&account) {
            Ok(encoded) => encoded,
            Err(source) => {
                rollback_new_touch_id(&account.authenticator, touch_id);
                return Err(AccountError::SerializeAccount { source });
            }
        };
        let staged_toml = match stage_private_file(&self.dir, encoded.as_bytes()) {
            Ok(tmp) => tmp,
            Err(source) => {
                rollback_new_touch_id(&account.authenticator, touch_id);
                return Err(AccountError::WriteAccount {
                    path: account_path,
                    source,
                });
            }
        };

        if let Some(staged) = fido2_staging {
            install_staged_fido2_handle(&staged).map_err(|source| AccountError::WriteAccount {
                path: staged.final_path.clone(),
                source,
            })?;
        }

        if let Err(err) = staged_toml.persist(&account_path) {
            rollback_new_touch_id(&account.authenticator, touch_id);
            return Err(AccountError::WriteAccount {
                path: account_path,
                source: err.error,
            });
        }

        if let Some(old) = existing {
            cleanup_superseded_credential(&old.authenticator, &account.authenticator, touch_id);
        }

        Ok(account)
    }

    /// Loads an operator account by username from `<dir>/<username>.toml`.
    pub fn load(&self, username: &str) -> Result<OperatorAccount, AccountError> {
        validate_username(username)?;
        let path = self.path_for(username);
        Self::load_from_path(&path, username)
    }

    /// Loads an operator account from an explicit TOML file path.
    pub fn load_file(path: &Path) -> Result<OperatorAccount, AccountError> {
        let fallback_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>");
        Self::load_from_path(path, fallback_name)
    }

    fn load_from_path(path: &Path, username: &str) -> Result<OperatorAccount, AccountError> {
        let content = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(AccountError::NotFound {
                    username: username.to_owned(),
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(AccountError::ReadAccount {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let account: OperatorAccount =
            toml::from_str(&content).map_err(|source| AccountError::ParseAccount {
                path: path.to_path_buf(),
                source,
            })?;
        validate_username(&account.username)?;
        account.public_key()?;
        account.grants.validate()?;
        Ok(account)
    }

    /// Lists all enrolled operator accounts sorted by username.
    pub fn list(&self) -> Result<Vec<OperatorAccount>, AccountError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(AccountError::ReadAccount {
                    path: self.dir.clone(),
                    source,
                });
            }
        };
        let mut accounts = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| AccountError::ReadAccount {
                path: self.dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            accounts.push(Self::load_file(&path)?);
        }
        accounts.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(accounts)
    }

    /// Removes an operator account and cleans up any associated Keychain item
    /// or FIDO2 key-handle files.
    pub fn remove(&self, username: &str) -> Result<OperatorAccount, AccountError> {
        let touch_id = default_touch_id_provider();
        self.remove_with(username, &touch_id)
    }

    /// Removes an operator account using an injected Touch ID provider.
    pub fn remove_with(
        &self,
        username: &str,
        touch_id: &dyn TouchIdProvider,
    ) -> Result<OperatorAccount, AccountError> {
        let account = self.load(username)?;
        let path = self.path_for(username);
        match &account.authenticator {
            AuthenticatorSpec::TouchId {
                keychain_service,
                keychain_account,
                ..
            } => {
                touch_id.delete_secret(keychain_service, keychain_account)?;
            }
            AuthenticatorSpec::Fido2 {
                key_handle_path, ..
            } => {
                remove_if_exists(key_handle_path)?;
                let mut pub_path = key_handle_path.as_os_str().to_os_string();
                pub_path.push(".pub");
                remove_if_exists(Path::new(&pub_path))?;
            }
            AuthenticatorSpec::SoftwareP256 { .. } | AuthenticatorSpec::SoftwareEd25519 { .. } => {}
        }
        fs::remove_file(&path).map_err(|source| AccountError::RemoveAccount { path, source })?;
        Ok(account)
    }

    /// Exports all enrolled accounts in this store as an [`AccountPolicy`]
    /// ready to encode to `/etc/helios/accounts.postcard`.
    pub fn export_account_policy(&self) -> Result<AccountPolicy, AccountError> {
        let mut accounts = Vec::new();
        for account in self.list()? {
            accounts.push(account.to_authorized_account()?);
        }
        Ok(AccountPolicy {
            version: helios_inspector_protocol::auth::AUTH_PROTOCOL_VERSION,
            accounts,
        })
    }
}

/// Validates a POSIX-safe operator username matching `[a-z_][a-z0-9_-]{0,31}`.
pub fn validate_username(username: &str) -> Result<(), AccountError> {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(AccountError::InvalidUsername {
            username: username.to_owned(),
        });
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0] == b'_';
    let rest_ok = bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if !first_ok || !rest_ok {
        return Err(AccountError::InvalidUsername {
            username: username.to_owned(),
        });
    }
    Ok(())
}

/// Builds a wire [`SessionGrants`] from CLI `--scope` / `--only` [`Attenuation`].
pub fn session_grants_from_attenuation(
    attenuation: &Attenuation,
) -> Result<SessionGrants, AccountError> {
    let scope_rule = match attenuation.scope.as_deref() {
        None => ScopeRule::Machine,
        Some(raw) => {
            let norm = normalize_scope(raw);
            if norm == "/" {
                ScopeRule::Machine
            } else {
                ScopeRule::Subtree(norm)
            }
        }
    };

    let grants = if attenuation.only.is_empty() {
        let mut full = SessionGrants::full_worker_ceiling();
        if scope_rule != ScopeRule::Machine {
            full.inspect_read = Some(scope_rule.clone());
            full.trace_read = Some(scope_rule.clone());
            full.profile_read = Some(scope_rule.clone());
            full.instance_control = Some(scope_rule.clone());
            full.component_control = Some(scope_rule);
        }
        full
    } else {
        let mut grants = SessionGrants::empty();
        let mut dir_rights = DirectoryRightsMask::EMPTY;
        for right in &attenuation.only {
            match right {
                GrantRight::Inspect | GrantRight::InstanceRead => {
                    grants.inspect_read = Some(scope_rule.clone());
                }
                GrantRight::Trace => {
                    grants.trace_read = Some(scope_rule.clone());
                    grants.diagnostics_control = true;
                }
                GrantRight::Profile => {
                    grants.profile_read = Some(scope_rule.clone());
                }
                GrantRight::InstanceControl => {
                    grants.instance_control = Some(scope_rule.clone());
                    grants.component_control = Some(scope_rule.clone());
                    grants.process = grants.process.union(ProcessRightsMask::SIGNAL);
                }
                GrantRight::Exec => {
                    grants.process = ProcessRightsMask::ALL;
                    grants.terminal = TerminalRightsMask::ALL;
                }
                GrantRight::FilesystemRead => {
                    dir_rights = dir_rights.union(DirectoryRightsMask::READ);
                }
                GrantRight::FilesystemWrite => {
                    dir_rights = dir_rights
                        .union(DirectoryRightsMask::READ)
                        .union(DirectoryRightsMask::WRITE)
                        .union(DirectoryRightsMask::MUTATE_DIRECTORY);
                }
                GrantRight::Snapshot | GrantRight::Processors => {
                    grants.machine_control = true;
                }
                GrantRight::Net | GrantRight::Http => {
                    grants.network = NetworkRightsMask::ALL;
                }
                GrantRight::Virtualize => {
                    grants.virtualize = true;
                }
            }
        }
        if !dir_rights.is_empty() {
            grants
                .directories
                .push(DirectoryRule::new("/", "/", dir_rights));
        }
        grants
    };
    grants.validate()?;
    Ok(grants)
}

/// Platform abstraction for macOS Touch ID biometric evaluation and Keychain
/// secret storage, injectable for deterministic non-GUI unit tests.
pub trait TouchIdProvider: Send + Sync {
    /// Evaluates biometric authentication with the localized user prompt `reason`.
    fn authenticate(&self, reason: &str) -> Result<(), AccountError>;
    /// Stores `secret` in the Keychain under `(service, account)`.
    fn store_secret(&self, service: &str, account: &str, secret: &[u8])
    -> Result<(), AccountError>;
    /// Loads the secret stored under `(service, account)`.
    fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, AccountError>;
    /// Deletes the secret stored under `(service, account)` if present.
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), AccountError>;
}

/// Result of enrolling a FIDO2 hardware key via `ssh-keygen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Enrollment {
    pub key_type: Fido2Alg,
    pub application: String,
    pub public_key_bytes: Vec<u8>,
}

/// Platform abstraction for FIDO2 hardware security-key enrollment and signing,
/// injectable for deterministic unit tests.
pub trait Fido2Provider: Send + Sync {
    /// Enrolls a FIDO2 security key handle at `key_handle_path`.
    fn enroll(
        &self,
        key_handle_path: &Path,
        application: &str,
        require_uv: bool,
        comment: &str,
    ) -> Result<Fido2Enrollment, AccountError>;

    /// Signs `message` with the enrolled key handle at `key_handle_path` under
    /// `namespace`, returning an OpenSSH armored `-----BEGIN SSH SIGNATURE-----`.
    fn sign(
        &self,
        key_handle_path: &Path,
        namespace: &str,
        message: &[u8],
    ) -> Result<String, AccountError>;
}

/// Cross-platform FIDO2 provider delegating to OpenSSH's `ssh-keygen`
/// (`-t ed25519-sk` with automatic `-t ecdsa-sk` fallback, and `-Y sign`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenSshFido2Provider;

impl Fido2Provider for OpenSshFido2Provider {
    fn enroll(
        &self,
        key_handle_path: &Path,
        application: &str,
        require_uv: bool,
        comment: &str,
    ) -> Result<Fido2Enrollment, AccountError> {
        let parent = key_handle_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let staging_dir = tempfile::Builder::new()
            .prefix(".helios-fido2-")
            .tempdir_in(parent)
            .map_err(|err| AccountError::Fido2 {
                operation: "create FIDO2 staging directory",
                detail: err.to_string(),
            })?;
        let staged_key_path = staging_dir.path().join("id_sk");
        let staged_pub_path = append_pub_ext(&staged_key_path);

        let mut last_err = None;
        for key_type in ["ed25519-sk", "ecdsa-sk"] {
            let mut cmd = Command::new("ssh-keygen");
            cmd.arg("-q")
                .arg("-t")
                .arg(key_type)
                .arg("-O")
                .arg(format!("application={application}"));
            if require_uv {
                cmd.arg("-O").arg("verify-required");
            }
            cmd.arg("-N")
                .arg("")
                .arg("-f")
                .arg(&staged_key_path)
                .arg("-C")
                .arg(comment);

            let output = cmd.output().map_err(|err| AccountError::Fido2 {
                operation: "run ssh-keygen",
                detail: format!("failed to launch ssh-keygen: {err}"),
            })?;
            if output.status.success() {
                let pub_text =
                    fs::read_to_string(&staged_pub_path).map_err(|err| AccountError::Fido2 {
                        operation: "read generated FIDO2 public key",
                        detail: err.to_string(),
                    })?;
                let enrolled = parse_openssh_sk_public_key(&pub_text)?;
                let final_pub_path = append_pub_ext(key_handle_path);
                fs::rename(&staged_key_path, key_handle_path).map_err(|err| {
                    AccountError::Fido2 {
                        operation: "install FIDO2 key handle",
                        detail: err.to_string(),
                    }
                })?;
                if let Err(err) = fs::rename(&staged_pub_path, &final_pub_path) {
                    let _ = remove_if_exists(key_handle_path);
                    return Err(AccountError::Fido2 {
                        operation: "install FIDO2 public key",
                        detail: err.to_string(),
                    });
                }
                return Ok(enrolled);
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let _ = remove_if_exists(&staged_key_path);
            let _ = remove_if_exists(&staged_pub_path);
            last_err = Some(format!("ssh-keygen -t {key_type} failed: {stderr}"));
        }

        Err(AccountError::Fido2 {
            operation: "enroll FIDO2 security key",
            detail: last_err.unwrap_or_else(|| "no supported FIDO2 key type".to_owned()),
        })
    }

    fn sign(
        &self,
        key_handle_path: &Path,
        namespace: &str,
        message: &[u8],
    ) -> Result<String, AccountError> {
        let mut child = Command::new("ssh-keygen")
            .arg("-Y")
            .arg("sign")
            .arg("-f")
            .arg(key_handle_path)
            .arg("-n")
            .arg(namespace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| AccountError::Fido2 {
                operation: "spawn ssh-keygen -Y sign",
                detail: err.to_string(),
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(message)
                .map_err(|err| AccountError::Fido2 {
                    operation: "write challenge to ssh-keygen stdin",
                    detail: err.to_string(),
                })?;
        }
        let output = child
            .wait_with_output()
            .map_err(|err| AccountError::Fido2 {
                operation: "wait for ssh-keygen -Y sign",
                detail: err.to_string(),
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(AccountError::Fido2 {
                operation: "ssh-keygen -Y sign",
                detail: stderr,
            });
        }
        String::from_utf8(output.stdout).map_err(|err| AccountError::Fido2 {
            operation: "decode SSHSIG output",
            detail: err.to_string(),
        })
    }
}

/// Parses an OpenSSH security-key `.pub` line (`sk-ssh-ed25519@openssh.com` or
/// `sk-ecdsa-sha2-nistp256@openssh.com`) into a [`Fido2Enrollment`].
pub fn parse_openssh_sk_public_key(pub_line: &str) -> Result<Fido2Enrollment, AccountError> {
    let mut parts = pub_line.split_whitespace();
    let alg = parts.next().ok_or_else(|| AccountError::Fido2 {
        operation: "parse OpenSSH public key",
        detail: "empty public key line".to_owned(),
    })?;
    let b64 = parts.next().ok_or_else(|| AccountError::Fido2 {
        operation: "parse OpenSSH public key",
        detail: "missing base64 public key blob".to_owned(),
    })?;
    let blob = BASE64_STANDARD
        .decode(b64)
        .map_err(|err| AccountError::Fido2 {
            operation: "decode OpenSSH public key base64",
            detail: err.to_string(),
        })?;
    let mut cursor = SshReader::new(&blob);
    let wire_alg = cursor.read_str("key type")?;
    if wire_alg != alg {
        return Err(AccountError::Fido2 {
            operation: "parse OpenSSH public key",
            detail: format!("key type mismatch: header `{alg}` vs wire `{wire_alg}`"),
        });
    }
    match wire_alg {
        "sk-ssh-ed25519@openssh.com" => {
            let pk = cursor.read_bytes("ed25519 public key")?;
            if pk.len() != 32 {
                return Err(AccountError::Fido2 {
                    operation: "parse OpenSSH public key",
                    detail: format!("expected 32-byte Ed25519 key, got {}", pk.len()),
                });
            }
            let application = cursor.read_str("application")?.to_owned();
            cursor.ensure_eof("sk-ssh-ed25519 public key")?;
            Ok(Fido2Enrollment {
                key_type: Fido2Alg::Ed25519,
                application,
                public_key_bytes: pk.to_vec(),
            })
        }
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let curve = cursor.read_str("ecdsa curve name")?;
            if curve != "nistp256" {
                return Err(AccountError::Fido2 {
                    operation: "parse OpenSSH public key",
                    detail: format!("unsupported ECDSA curve `{curve}`, expected `nistp256`"),
                });
            }
            let sec1 = cursor.read_bytes("nistp256 point")?;
            let vk =
                P256VerifyingKey::from_sec1_bytes(sec1).map_err(|err| AccountError::Fido2 {
                    operation: "parse NIST P-256 public key",
                    detail: err.to_string(),
                })?;
            let compressed = vk.to_sec1_point(true);
            let application = cursor.read_str("application")?.to_owned();
            cursor.ensure_eof("sk-ecdsa-sha2-nistp256 public key")?;
            Ok(Fido2Enrollment {
                key_type: Fido2Alg::P256,
                application,
                public_key_bytes: compressed.as_bytes().to_vec(),
            })
        }
        other => Err(AccountError::Fido2 {
            operation: "parse OpenSSH public key",
            detail: format!("unsupported FIDO2 key type `{other}`"),
        }),
    }
}

/// Parses an armored OpenSSH `-----BEGIN SSH SIGNATURE-----` (`PROTOCOL.sshsig`)
/// produced by a FIDO2 `-sk` key into an [`AuthProof`].
pub fn parse_sshsig_fido2_proof(
    armored: &str,
    expected_namespace: &str,
) -> Result<AuthProof, AccountError> {
    const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
    const END: &str = "-----END SSH SIGNATURE-----";

    let mut in_body = false;
    let mut b64 = String::new();
    let mut saw_end = false;
    for raw_line in armored.lines() {
        let line = raw_line.trim();
        if line == BEGIN {
            in_body = true;
            continue;
        }
        if line == END {
            saw_end = true;
            break;
        }
        if in_body && !line.is_empty() {
            b64.push_str(line);
        }
    }
    if !in_body || !saw_end || b64.is_empty() {
        return Err(AccountError::Fido2 {
            operation: "parse SSHSIG armor",
            detail: "missing BEGIN/END SSH SIGNATURE armor boundaries".to_owned(),
        });
    }

    let blob = BASE64_STANDARD
        .decode(&b64)
        .map_err(|err| AccountError::Fido2 {
            operation: "decode SSHSIG base64",
            detail: err.to_string(),
        })?;
    let mut cursor = SshReader::new(&blob);
    let magic = cursor.read_fixed::<6>("SSHSIG magic")?;
    if &magic != b"SSHSIG" {
        return Err(AccountError::Fido2 {
            operation: "parse SSHSIG header",
            detail: "invalid SSHSIG magic preamble".to_owned(),
        });
    }
    let version = cursor.read_u32("SSHSIG version")?;
    if version != 1 {
        return Err(AccountError::Fido2 {
            operation: "parse SSHSIG header",
            detail: format!("unsupported SSHSIG version {version}"),
        });
    }
    let _public_key_blob = cursor.read_bytes("SSHSIG publickey")?;
    let namespace = cursor.read_str("SSHSIG namespace")?;
    if namespace != expected_namespace {
        return Err(AccountError::Fido2 {
            operation: "parse SSHSIG namespace",
            detail: format!("expected namespace `{expected_namespace}`, got `{namespace}`"),
        });
    }
    let _reserved = cursor.read_bytes("SSHSIG reserved")?;
    let hash_alg = match cursor.read_str("SSHSIG hash_algorithm")? {
        "sha512" => SshSigHashAlg::Sha512,
        "sha256" => SshSigHashAlg::Sha256,
        other => {
            return Err(AccountError::Fido2 {
                operation: "parse SSHSIG hash algorithm",
                detail: format!("unsupported hash algorithm `{other}`"),
            });
        }
    };
    let sig_blob = cursor.read_bytes("SSHSIG signature")?;
    cursor.ensure_eof("SSHSIG envelope")?;

    let mut sig_cursor = SshReader::new(sig_blob);
    let sig_alg = sig_cursor.read_str("signature algorithm")?;
    let mode = Fido2MessageMode::SshSig { hash_alg };
    match sig_alg {
        "sk-ssh-ed25519@openssh.com" => {
            let raw_sig = sig_cursor.read_bytes("sk-ssh-ed25519 signature")?;
            let signature: [u8; 64] = raw_sig.try_into().map_err(|_| AccountError::Fido2 {
                operation: "parse sk-ssh-ed25519 signature",
                detail: format!("expected 64-byte signature, got {} bytes", raw_sig.len()),
            })?;
            let flags = sig_cursor.read_u8("sk flags")?;
            let counter = sig_cursor.read_u32("sk counter")?;
            sig_cursor.ensure_eof("sk-ssh-ed25519 signature blob")?;
            Ok(AuthProof::Fido2Ed25519 {
                flags,
                counter,
                signature,
                mode,
            })
        }
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let ecdsa_inner = sig_cursor.read_bytes("sk-ecdsa signature pair")?;
            let flags = sig_cursor.read_u8("sk flags")?;
            let counter = sig_cursor.read_u32("sk counter")?;
            sig_cursor.ensure_eof("sk-ecdsa-sha2-nistp256 signature blob")?;

            let mut pair = SshReader::new(ecdsa_inner);
            let r = mpint_to_fixed_32(pair.read_bytes("ecdsa r")?)?;
            let s = mpint_to_fixed_32(pair.read_bytes("ecdsa s")?)?;
            pair.ensure_eof("sk-ecdsa signature pair")?;
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r);
            signature[32..].copy_from_slice(&s);
            Ok(AuthProof::Fido2P256 {
                flags,
                counter,
                signature,
                mode,
            })
        }
        other => Err(AccountError::Fido2 {
            operation: "parse SSHSIG signature algorithm",
            detail: format!("expected FIDO2 -sk signature algorithm, got `{other}`"),
        }),
    }
}

fn mpint_to_fixed_32(mpint: &[u8]) -> Result<[u8; 32], AccountError> {
    let trimmed = if mpint.first() == Some(&0x00) && mpint.len() > 1 {
        &mpint[1..]
    } else {
        mpint
    };
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err(AccountError::Fido2 {
            operation: "decode ECDSA mpint scalar",
            detail: format!(
                "invalid P-256 signature scalar length {} bytes",
                trimmed.len()
            ),
        });
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

struct SshReader<'a> {
    buf: &'a [u8],
}

impl<'a> SshReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn read_fixed<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], AccountError> {
        if self.buf.len() < N {
            return Err(AccountError::Fido2 {
                operation: "parse SSH wire format",
                detail: format!("unexpected EOF reading {field}"),
            });
        }
        let (head, tail) = self.buf.split_at(N);
        self.buf = tail;
        let mut out = [0u8; N];
        out.copy_from_slice(head);
        Ok(out)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, AccountError> {
        Ok(self.read_fixed::<1>(field)?[0])
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, AccountError> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>(field)?))
    }

    fn read_bytes(&mut self, field: &'static str) -> Result<&'a [u8], AccountError> {
        let len = self.read_u32(field)? as usize;
        if self.buf.len() < len {
            return Err(AccountError::Fido2 {
                operation: "parse SSH wire format",
                detail: format!("truncated SSH string reading {field}"),
            });
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    fn read_str(&mut self, field: &'static str) -> Result<&'a str, AccountError> {
        let bytes = self.read_bytes(field)?;
        std::str::from_utf8(bytes).map_err(|err| AccountError::Fido2 {
            operation: "parse SSH UTF-8 string",
            detail: format!("invalid UTF-8 in {field}: {err}"),
        })
    }

    fn ensure_eof(&self, context: &'static str) -> Result<(), AccountError> {
        if !self.buf.is_empty() {
            return Err(AccountError::Fido2 {
                operation: "parse SSH wire format",
                detail: format!("{} trailing byte(s) after {context}", self.buf.len()),
            });
        }
        Ok(())
    }
}

fn generate_p256_keypair() -> Result<(Zeroizing<[u8; 32]>, [u8; 33]), AccountError> {
    // Reject the astronomically unlikely all-zero or >= group-order draw.
    for _ in 0..8 {
        let candidate = Zeroizing::new(random_32()?);
        if let Ok(sec1) = p256_public_key_sec1(&candidate) {
            return Ok((candidate, sec1));
        }
    }
    Err(AccountError::Protocol {
        source: ProtocolAuthError::Malformed {
            detail: "failed to generate a valid NIST P-256 scalar".to_owned(),
        },
    })
}

fn remove_if_exists(path: &Path) -> Result<(), AccountError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AccountError::RemoveAccount {
            path: path.to_path_buf(),
            source,
        }),
    }
}

struct StagedFido2Handle {
    _staging_dir: tempfile::TempDir,
    staged_path: PathBuf,
    final_path: PathBuf,
}

fn append_pub_ext(path: &Path) -> PathBuf {
    let mut pub_path = path.as_os_str().to_os_string();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

fn install_staged_fido2_handle(staged: &StagedFido2Handle) -> std::io::Result<()> {
    let moved_handle = staged.staged_path.exists();
    if moved_handle {
        fs::rename(&staged.staged_path, &staged.final_path)?;
    }
    let staged_pub = append_pub_ext(&staged.staged_path);
    let final_pub = append_pub_ext(&staged.final_path);
    if staged_pub.exists() {
        fs::rename(&staged_pub, &final_pub)?;
    } else if moved_handle {
        let _ = remove_if_exists(&final_pub);
    }
    Ok(())
}

fn rollback_new_touch_id(spec: &AuthenticatorSpec, touch_id: &dyn TouchIdProvider) {
    if let AuthenticatorSpec::TouchId {
        keychain_service,
        keychain_account,
        ..
    } = spec
    {
        let _ = touch_id.delete_secret(keychain_service, keychain_account);
    }
}

fn cleanup_superseded_credential(
    old: &AuthenticatorSpec,
    new: &AuthenticatorSpec,
    touch_id: &dyn TouchIdProvider,
) {
    match old {
        AuthenticatorSpec::TouchId {
            keychain_service: old_service,
            keychain_account: old_account,
            ..
        } => {
            let same = matches!(
                new,
                AuthenticatorSpec::TouchId {
                    keychain_service: new_service,
                    keychain_account: new_account,
                    ..
                } if new_service == old_service && new_account == old_account
            );
            if !same {
                let _ = touch_id.delete_secret(old_service, old_account);
            }
        }
        AuthenticatorSpec::Fido2 {
            key_handle_path: old_path,
            ..
        } => {
            let same = matches!(
                new,
                AuthenticatorSpec::Fido2 {
                    key_handle_path: new_path,
                    ..
                } if new_path == old_path
            );
            if !same {
                let _ = remove_if_exists(old_path);
                let _ = remove_if_exists(&append_pub_ext(old_path));
            }
        }
        AuthenticatorSpec::SoftwareP256 { .. } | AuthenticatorSpec::SoftwareEd25519 { .. } => {}
    }
}

fn stage_private_file(dir: &Path, bytes: &[u8]) -> std::io::Result<tempfile::NamedTempFile> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".helios-account-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Encodes `bytes` as lowercase hex.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_owned());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().as_chunks::<2>().0 {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_owned())?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_owned())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn decode_hex_32(raw: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(raw)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32-byte key, got {} bytes", v.len()))
}

fn decode_hex_33(raw: &str) -> Result<[u8; 33], String> {
    let bytes = decode_hex(raw)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 33-byte SEC1 key, got {} bytes", v.len()))
}

#[cfg(target_os = "macos")]
fn default_touch_id_provider() -> macos_touch_id::MacOsTouchIdProvider {
    macos_touch_id::MacOsTouchIdProvider
}

#[cfg(not(target_os = "macos"))]
fn default_touch_id_provider() -> UnsupportedTouchIdProvider {
    UnsupportedTouchIdProvider
}

#[cfg(not(target_os = "macos"))]
struct UnsupportedTouchIdProvider;

#[cfg(not(target_os = "macos"))]
impl TouchIdProvider for UnsupportedTouchIdProvider {
    fn authenticate(&self, _reason: &str) -> Result<(), AccountError> {
        Err(AccountError::TouchIdUnsupported)
    }

    fn store_secret(
        &self,
        _service: &str,
        _account: &str,
        _secret: &[u8],
    ) -> Result<(), AccountError> {
        Err(AccountError::TouchIdUnsupported)
    }

    fn load_secret(&self, _service: &str, _account: &str) -> Result<Vec<u8>, AccountError> {
        Err(AccountError::TouchIdUnsupported)
    }

    fn delete_secret(&self, _service: &str, _account: &str) -> Result<(), AccountError> {
        Err(AccountError::TouchIdUnsupported)
    }
}

#[cfg(target_os = "macos")]
mod macos_touch_id {
    use std::ffi::c_void;
    use std::sync::{Arc, Condvar, Mutex};

    use objc2::msg_send;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2_foundation::{NSError, NSString};
    use security_framework::passwords::{
        PasswordOptions, delete_generic_password, generic_password, set_generic_password,
    };

    use super::TouchIdProvider;
    use crate::error::AccountError;

    // `kLAPolicyDeviceOwnerAuthenticationWithBiometrics = 1` from
    // `LocalAuthentication.framework/Headers/LAPublicDefines.h`.
    const LA_POLICY_DEVICE_OWNER_AUTH_WITH_BIOMETRICS: isize = 1;

    // `BLOCK_HAS_COPY_DISPOSE = 1 << 25` from the Clang Block ABI specification.
    const BLOCK_HAS_COPY_DISPOSE: i32 = 1 << 25;

    // `errSecItemNotFound = -25300` from `Security.framework/Headers/SecBase.h`.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    unsafe extern "C" {
        static _NSConcreteStackBlock: c_void;
    }

    struct EvalState {
        result: Mutex<Option<Result<(), String>>>,
        condvar: Condvar,
    }

    #[repr(C)]
    struct BlockDescriptor {
        reserved: usize,
        size: usize,
        copy_helper: unsafe extern "C" fn(*mut c_void, *const c_void),
        dispose_helper: unsafe extern "C" fn(*mut c_void),
    }

    #[repr(C)]
    struct EvalReplyBlock {
        isa: *const c_void,
        flags: i32,
        reserved: i32,
        invoke: unsafe extern "C" fn(*mut EvalReplyBlock, Bool, *mut NSError),
        descriptor: *const BlockDescriptor,
        state: *const EvalState,
    }

    static BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<EvalReplyBlock>(),
        copy_helper: block_copy_helper,
        dispose_helper: block_dispose_helper,
    };

    /// # Safety
    /// Called exclusively by Apple's libclosure `Block_copy` when promoting an
    /// [`EvalReplyBlock`] to the heap; `dst` and `src` must point to valid
    /// [`EvalReplyBlock`] structures.
    unsafe extern "C" fn block_copy_helper(dst: *mut c_void, src: *const c_void) {
        // SAFETY: `src` is a valid `EvalReplyBlock` passed by `Block_copy`.
        let src_state = unsafe { (*src.cast::<EvalReplyBlock>()).state };
        // SAFETY: `dst` is writable storage allocated by `Block_copy` for `EvalReplyBlock`.
        unsafe { (*dst.cast::<EvalReplyBlock>()).state = src_state };
        // SAFETY: `src_state` was produced by `Arc::into_raw` and remains live during copy.
        unsafe { Arc::increment_strong_count(src_state) };
    }

    /// # Safety
    /// Called exclusively by Apple's libclosure `Block_release` when freeing a
    /// heap-copied [`EvalReplyBlock`]; `block` must point to a live block.
    unsafe extern "C" fn block_dispose_helper(block: *mut c_void) {
        // SAFETY: `block` is a valid `EvalReplyBlock` being disposed by `Block_release`.
        let state = unsafe { (*block.cast::<EvalReplyBlock>()).state };
        // SAFETY: Matches the strong count incremented in `block_copy_helper`.
        unsafe { Arc::decrement_strong_count(state) };
    }

    /// # Safety
    /// Invoked by `LocalAuthentication` upon completion of
    /// `evaluatePolicy:localizedReason:reply:`; `block` must point to a valid
    /// [`EvalReplyBlock`] and `error` must be null or a valid `NSError`.
    unsafe extern "C" fn eval_reply_invoke(
        block: *mut EvalReplyBlock,
        success: Bool,
        error: *mut NSError,
    ) {
        // SAFETY: `block` is a live `EvalReplyBlock` owning a strong ref to `EvalState`.
        let state_ptr = unsafe { (*block).state };
        // SAFETY: `state_ptr` remains valid for the duration of the block invocation.
        let state = unsafe { &*state_ptr };
        let outcome = if success.as_bool() {
            Ok(())
        } else {
            Err(describe_ns_error(error))
        };
        if let Ok(mut guard) = state.result.lock() {
            *guard = Some(outcome);
            state.condvar.notify_all();
        }
    }

    fn describe_ns_error(error: *mut NSError) -> String {
        if error.is_null() {
            return "biometric authentication cancelled or rejected".to_owned();
        }
        // SAFETY: Caller passed a non-null `NSError` pointer from LocalAuthentication.
        let err_ref = unsafe { &*error };
        err_ref.localizedDescription().to_string()
    }

    /// macOS Touch ID provider using `LocalAuthentication.framework` and the
    /// user's login Keychain (`security-framework`).
    pub struct MacOsTouchIdProvider;

    impl TouchIdProvider for MacOsTouchIdProvider {
        fn authenticate(&self, reason: &str) -> Result<(), AccountError> {
            let Some(la_class) = AnyClass::get(c"LAContext") else {
                return Err(AccountError::TouchIdFailed {
                    detail: "LocalAuthentication.framework LAContext class is unavailable"
                        .to_owned(),
                });
            };
            // SAFETY: `la_class` is the registered Objective-C `LAContext` class.
            let allocated: *mut AnyObject = unsafe { msg_send![la_class, alloc] };
            // SAFETY: `allocated` is a freshly allocated `LAContext` receiver for `init`;
            // Objective-C `init` returns a +1 owned `LAContext*` or null on failure.
            let raw_ctx: *mut AnyObject = unsafe { msg_send![allocated, init] };
            // SAFETY: `raw_ctx` is either null or the +1 owned `LAContext` returned by `init`.
            let ctx: Option<Retained<AnyObject>> = unsafe { Retained::from_raw(raw_ctx) };
            let ctx = ctx.ok_or_else(|| AccountError::TouchIdFailed {
                detail: "failed to initialize LAContext".to_owned(),
            })?;

            let mut check_error: *mut NSError = std::ptr::null_mut();
            // SAFETY: `ctx` is an initialized `LAContext`; `canEvaluatePolicy:error:` writes an
            // autoreleased `NSError*` into `check_error` on failure.
            let can_evaluate: Bool = unsafe {
                msg_send![
                    &*ctx,
                    canEvaluatePolicy: LA_POLICY_DEVICE_OWNER_AUTH_WITH_BIOMETRICS,
                    error: &mut check_error
                ]
            };
            if !can_evaluate.as_bool() {
                return Err(AccountError::TouchIdFailed {
                    detail: describe_ns_error(check_error),
                });
            }

            let state = Arc::new(EvalState {
                result: Mutex::new(None),
                condvar: Condvar::new(),
            });
            let state_ptr = Arc::into_raw(Arc::clone(&state));
            let isa = std::ptr::addr_of!(_NSConcreteStackBlock);
            let block = EvalReplyBlock {
                isa,
                flags: BLOCK_HAS_COPY_DISPOSE,
                reserved: 0,
                invoke: eval_reply_invoke,
                descriptor: &BLOCK_DESCRIPTOR,
                state: state_ptr,
            };
            let ns_reason = NSString::from_str(reason);
            let block_ptr = std::ptr::addr_of!(block).cast::<c_void>();
            // SAFETY: `ctx` is an initialized `LAContext`, `ns_reason` is a valid `NSString`,
            // and `block_ptr` conforms to Apple's Objective-C block ABI with copy/dispose helpers.
            let (): () = unsafe {
                msg_send![
                    &*ctx,
                    evaluatePolicy: LA_POLICY_DEVICE_OWNER_AUTH_WITH_BIOMETRICS,
                    localizedReason: &*ns_reason,
                    reply: block_ptr
                ]
            };
            // Release the stack block's own Arc reference; any heap copy made by
            // `evaluatePolicy:localizedReason:reply:` holds its own strong reference.
            // SAFETY: Matches the `Arc::into_raw` created for `block.state` above.
            let _ = unsafe { Arc::from_raw(state_ptr) };

            let mut guard = state
                .result
                .lock()
                .map_err(|_| AccountError::TouchIdFailed {
                    detail: "Touch ID completion lock poisoned".to_owned(),
                })?;
            while guard.is_none() {
                guard = state
                    .condvar
                    .wait(guard)
                    .map_err(|_| AccountError::TouchIdFailed {
                        detail: "Touch ID completion wait poisoned".to_owned(),
                    })?;
            }
            match guard.take() {
                Some(Ok(())) => Ok(()),
                Some(Err(detail)) => Err(AccountError::TouchIdFailed { detail }),
                None => Err(AccountError::TouchIdFailed {
                    detail: "Touch ID evaluation ended without result".to_owned(),
                }),
            }
        }

        fn store_secret(
            &self,
            service: &str,
            account: &str,
            secret: &[u8],
        ) -> Result<(), AccountError> {
            set_generic_password(service, account, secret).map_err(|err| AccountError::Keychain {
                operation: "set_generic_password",
                detail: err.to_string(),
            })
        }

        fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, AccountError> {
            generic_password(PasswordOptions::new_generic_password(service, account)).map_err(
                |err| AccountError::Keychain {
                    operation: "generic_password",
                    detail: err.to_string(),
                },
            )
        }

        fn delete_secret(&self, service: &str, account: &str) -> Result<(), AccountError> {
            match delete_generic_password(service, account) {
                Ok(()) => Ok(()),
                Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                Err(err) => Err(AccountError::Keychain {
                    operation: "delete_generic_password",
                    detail: err.to_string(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    use helios_inspector_protocol::auth::{
        FIDO2_FLAG_UP, FIDO2_FLAG_UV, fido2_assertion_transcript,
    };
    use p256::ecdsa::SigningKey as P256SigningKey;
    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct MockTouchId {
        allow_auth: bool,
        auth_calls: Mutex<Vec<String>>,
        secrets: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl MockTouchId {
        fn allowing() -> Self {
            Self {
                allow_auth: true,
                auth_calls: Mutex::new(Vec::new()),
                secrets: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl TouchIdProvider for MockTouchId {
        fn authenticate(&self, reason: &str) -> Result<(), AccountError> {
            self.auth_calls
                .lock()
                .expect("lock auth calls")
                .push(reason.to_owned());
            if self.allow_auth {
                Ok(())
            } else {
                Err(AccountError::TouchIdFailed {
                    detail: "user cancelled".to_owned(),
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
                .expect("lock secrets")
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
            Ok(())
        }

        fn load_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, AccountError> {
            self.secrets
                .lock()
                .expect("lock secrets")
                .get(&(service.to_owned(), account.to_owned()))
                .cloned()
                .ok_or_else(|| AccountError::Keychain {
                    operation: "mock_load",
                    detail: "item not found".to_owned(),
                })
        }

        fn delete_secret(&self, service: &str, account: &str) -> Result<(), AccountError> {
            self.secrets
                .lock()
                .expect("lock secrets")
                .remove(&(service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    enum MockFido2Key {
        Ed25519([u8; 32]),
        P256([u8; 32]),
    }

    struct MockFido2 {
        key: MockFido2Key,
        flags: u8,
        counter: u32,
        hash_alg: SshSigHashAlg,
    }

    impl Fido2Provider for MockFido2 {
        fn enroll(
            &self,
            key_handle_path: &Path,
            application: &str,
            _require_uv: bool,
            comment: &str,
        ) -> Result<Fido2Enrollment, AccountError> {
            let pub_line = match self.key {
                MockFido2Key::Ed25519(seed) => {
                    let pk = Ed25519SigningKey::from_bytes(&seed)
                        .verifying_key()
                        .to_bytes();
                    let mut blob = Vec::new();
                    push_ssh_str(&mut blob, b"sk-ssh-ed25519@openssh.com");
                    push_ssh_str(&mut blob, &pk);
                    push_ssh_str(&mut blob, application.as_bytes());
                    format!(
                        "sk-ssh-ed25519@openssh.com {} {comment}\n",
                        BASE64_STANDARD.encode(&blob)
                    )
                }
                MockFido2Key::P256(scalar) => {
                    let sk = P256SigningKey::from_slice(&scalar).expect("p256 sk");
                    let uncompressed = sk.verifying_key().to_sec1_point(false);
                    let mut blob = Vec::new();
                    push_ssh_str(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
                    push_ssh_str(&mut blob, b"nistp256");
                    push_ssh_str(&mut blob, uncompressed.as_bytes());
                    push_ssh_str(&mut blob, application.as_bytes());
                    format!(
                        "sk-ecdsa-sha2-nistp256@openssh.com {} {comment}\n",
                        BASE64_STANDARD.encode(&blob)
                    )
                }
            };
            fs::write(key_handle_path, b"mock-fido2-key-handle").expect("write key handle");
            let mut pub_path = key_handle_path.as_os_str().to_os_string();
            pub_path.push(".pub");
            fs::write(pub_path, &pub_line).expect("write pub");
            parse_openssh_sk_public_key(&pub_line)
        }

        fn sign(
            &self,
            _key_handle_path: &Path,
            namespace: &str,
            message: &[u8],
        ) -> Result<String, AccountError> {
            let mode = Fido2MessageMode::SshSig {
                hash_alg: self.hash_alg,
            };
            let transcript = fido2_assertion_transcript(
                DEFAULT_FIDO2_APPLICATION,
                self.flags,
                self.counter,
                mode,
                message,
            );
            let mut sig_blob = Vec::new();
            let mut pub_blob = Vec::new();
            match self.key {
                MockFido2Key::Ed25519(seed) => {
                    let sk = Ed25519SigningKey::from_bytes(&seed);
                    let sig = sk.sign(&transcript).to_bytes();
                    push_ssh_str(&mut pub_blob, b"sk-ssh-ed25519@openssh.com");
                    push_ssh_str(&mut pub_blob, &sk.verifying_key().to_bytes());
                    push_ssh_str(&mut pub_blob, DEFAULT_FIDO2_APPLICATION.as_bytes());

                    push_ssh_str(&mut sig_blob, b"sk-ssh-ed25519@openssh.com");
                    push_ssh_str(&mut sig_blob, &sig);
                    sig_blob.push(self.flags);
                    sig_blob.extend_from_slice(&self.counter.to_be_bytes());
                }
                MockFido2Key::P256(scalar) => {
                    let sk = P256SigningKey::from_slice(&scalar).expect("p256 sk");
                    let sig = sign_p256_scalar(&scalar, &transcript).expect("sign p256");
                    push_ssh_str(&mut pub_blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
                    push_ssh_str(&mut pub_blob, b"nistp256");
                    push_ssh_str(
                        &mut pub_blob,
                        sk.verifying_key().to_sec1_point(false).as_bytes(),
                    );
                    push_ssh_str(&mut pub_blob, DEFAULT_FIDO2_APPLICATION.as_bytes());

                    let mut ecdsa_pair = Vec::new();
                    push_ssh_mpint(&mut ecdsa_pair, &sig[..32]);
                    push_ssh_mpint(&mut ecdsa_pair, &sig[32..]);

                    push_ssh_str(&mut sig_blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
                    push_ssh_str(&mut sig_blob, &ecdsa_pair);
                    sig_blob.push(self.flags);
                    sig_blob.extend_from_slice(&self.counter.to_be_bytes());
                }
            }

            let mut sshsig = Vec::new();
            sshsig.extend_from_slice(b"SSHSIG");
            sshsig.extend_from_slice(&1u32.to_be_bytes());
            push_ssh_str(&mut sshsig, &pub_blob);
            push_ssh_str(&mut sshsig, namespace.as_bytes());
            push_ssh_str(&mut sshsig, b"");
            push_ssh_str(&mut sshsig, self.hash_alg.as_str().as_bytes());
            push_ssh_str(&mut sshsig, &sig_blob);
            Ok(format!(
                "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
                BASE64_STANDARD.encode(&sshsig)
            ))
        }
    }

    fn push_ssh_str(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn push_ssh_mpint(buf: &mut Vec<u8>, be_unsigned: &[u8]) {
        let first_nz = be_unsigned
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(be_unsigned.len());
        let trimmed = &be_unsigned[first_nz..];
        let mut encoded = Vec::with_capacity(trimmed.len() + 1);
        if trimmed.first().is_some_and(|b| (b & 0x80) != 0) {
            encoded.push(0x00);
        }
        encoded.extend_from_slice(trimmed);
        push_ssh_str(buf, &encoded);
    }

    #[test]
    fn validates_posix_usernames() {
        for ok in ["lexo", "_admin", "ops_1-prod", "a"] {
            validate_username(ok).unwrap_or_else(|e| panic!("expected `{ok}` valid: {e}"));
        }
        for bad in [
            "",
            "Lexo",
            "1user",
            "../etc",
            "a/b",
            "user name",
            &"a".repeat(33),
        ] {
            assert!(
                validate_username(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn account_store_lifecycle_software_touch_id_and_fido2_sshsig() {
        let dir = TempDir::new().expect("tempdir");
        let store = AccountStore::new(dir.path().join("accounts"));
        let touch_id = MockTouchId::allowing();
        let fido_ed = MockFido2 {
            key: MockFido2Key::Ed25519([0x61; 32]),
            flags: FIDO2_FLAG_UP | FIDO2_FLAG_UV,
            counter: 17,
            hash_alg: SshSigHashAlg::Sha512,
        };
        let fido_p256 = MockFido2 {
            key: MockFido2Key::P256([0x62; 32]),
            flags: FIDO2_FLAG_UP,
            counter: 3,
            hash_alg: SshSigHashAlg::Sha256,
        };

        // 1. Software P-256 with --scope and --only attenuation.
        let mut only = BTreeSet::new();
        only.insert(GrantRight::Inspect);
        only.insert(GrantRight::Trace);
        let grants = session_grants_from_attenuation(&Attenuation {
            scope: Some("/core/http".to_owned()),
            only,
        })
        .expect("grants from attenuation");
        assert_eq!(
            grants.inspect_read,
            Some(ScopeRule::Subtree("/core/http".to_owned()))
        );
        assert_eq!(
            grants.trace_read,
            Some(ScopeRule::Subtree("/core/http".to_owned()))
        );
        assert!(grants.diagnostics_control);
        assert!(!grants.virtualize);
        assert!(grants.directories.is_empty());

        let mut req =
            CreateAccountRequest::new("soft_p256", AccountAuthenticatorChoice::SoftwareP256);
        req.grants = grants.clone();
        let created = store
            .create_with(req, &touch_id, &fido_ed)
            .expect("create soft_p256");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(store.path_for("soft_p256"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let verified = created
            .verify_self_with(&touch_id, &fido_ed)
            .expect("verify soft_p256");
        assert_eq!(verified.username, "soft_p256");
        assert_eq!(verified.grants, grants);

        // 2. Software Ed25519.
        let soft_ed = store
            .create_with(
                CreateAccountRequest::new("soft_ed", AccountAuthenticatorChoice::SoftwareEd25519),
                &touch_id,
                &fido_ed,
            )
            .expect("create soft_ed");
        soft_ed
            .verify_self_with(&touch_id, &fido_ed)
            .expect("verify soft_ed");

        // 3. Touch ID (mocked, zero GUI popups) — secret never lands in TOML on disk.
        let touch_acct = store
            .create_with(
                CreateAccountRequest::new("touch_user", AccountAuthenticatorChoice::TouchId),
                &touch_id,
                &fido_ed,
            )
            .expect("create touch_user");
        let on_disk = fs::read_to_string(store.path_for("touch_user")).expect("read toml");
        assert!(!on_disk.contains("secret_scalar_hex"));
        touch_acct
            .verify_self_with(&touch_id, &fido_ed)
            .expect("verify touch_user");
        assert_eq!(touch_id.auth_calls.lock().expect("calls").len(), 2);

        // Touch ID rejection blocks signing before reading Keychain.
        let denying = MockTouchId::default();
        assert!(matches!(
            touch_acct.verify_self_with(&denying, &fido_ed),
            Err(AccountError::TouchIdFailed { .. })
        ));

        // 4. FIDO2 Ed25519 (SSHSIG SHA-512, require_uv = true).
        let mut fido_ed_req = CreateAccountRequest::new("yk_ed", AccountAuthenticatorChoice::Fido2);
        fido_ed_req.require_uv = true;
        let yk_ed = store
            .create_with(fido_ed_req, &touch_id, &fido_ed)
            .expect("create yk_ed");
        yk_ed
            .verify_self_with(&touch_id, &fido_ed)
            .expect("verify yk_ed");

        // 5. FIDO2 P-256 (SSHSIG SHA-256 + mpint conversion).
        let yk_p256 = store
            .create_with(
                CreateAccountRequest::new("yk_p256", AccountAuthenticatorChoice::Fido2),
                &touch_id,
                &fido_p256,
            )
            .expect("create yk_p256");
        yk_p256
            .verify_self_with(&touch_id, &fido_p256)
            .expect("verify yk_p256");

        // List & AccountPolicy export.
        let listed = store.list().expect("list accounts");
        let names: Vec<&str> = listed.iter().map(|a| a.username.as_str()).collect();
        assert_eq!(
            names,
            vec!["soft_ed", "soft_p256", "touch_user", "yk_ed", "yk_p256"]
        );
        let policy = store.export_account_policy().expect("export policy");
        let encoded = policy.encode_postcard().expect("encode postcard");
        let decoded = AccountPolicy::decode_postcard(&encoded).expect("decode postcard");
        assert_eq!(decoded.accounts.len(), 5);

        // Remove cleans up Keychain and FIDO2 key handles.
        let touch_keychain_account = match &touch_acct.authenticator {
            AuthenticatorSpec::TouchId {
                keychain_account, ..
            } => keychain_account.clone(),
            other => panic!("expected TouchId authenticator, got {other:?}"),
        };
        store
            .remove_with("touch_user", &touch_id)
            .expect("remove touch_user");
        assert!(
            touch_id
                .load_secret(TOUCH_ID_KEYCHAIN_SERVICE, &touch_keychain_account)
                .is_err()
        );
        store.remove_with("yk_ed", &touch_id).expect("remove yk_ed");
        assert!(!dir.path().join("accounts/yk_ed.fido2_sk").exists());
        assert!(!dir.path().join("accounts/yk_ed.fido2_sk.pub").exists());
    }

    struct FailingFido2 {
        enroll_calls: Mutex<usize>,
        write_junk_before_error: bool,
    }

    impl FailingFido2 {
        fn new(write_junk_before_error: bool) -> Self {
            Self {
                enroll_calls: Mutex::new(0),
                write_junk_before_error,
            }
        }
    }

    impl Fido2Provider for FailingFido2 {
        fn enroll(
            &self,
            key_handle_path: &Path,
            _application: &str,
            _require_uv: bool,
            _comment: &str,
        ) -> Result<Fido2Enrollment, AccountError> {
            *self.enroll_calls.lock().expect("lock enroll calls") += 1;
            if self.write_junk_before_error {
                let _ = fs::write(key_handle_path, b"corrupted-partial-handle");
            }
            Err(AccountError::Fido2 {
                operation: "enroll FIDO2 security key",
                detail: "security key unplugged".to_owned(),
            })
        }

        fn sign(
            &self,
            _key_handle_path: &Path,
            _namespace: &str,
            _message: &[u8],
        ) -> Result<String, AccountError> {
            Err(AccountError::Fido2 {
                operation: "sign",
                detail: "security key unplugged".to_owned(),
            })
        }
    }

    #[test]
    fn check_creatable_validates_before_invoking_providers() {
        let dir = TempDir::new().expect("tempdir");
        let store = AccountStore::new(dir.path().join("accounts"));
        let touch_id = MockTouchId::allowing();
        let fido2 = FailingFido2::new(false);

        // Invalid usernames are rejected regardless of `replace`.
        assert!(matches!(
            store.check_creatable("BadUser", false),
            Err(AccountError::InvalidUsername { .. })
        ));
        assert!(matches!(
            store.check_creatable("../escape", true),
            Err(AccountError::InvalidUsername { .. })
        ));

        // Non-existent valid username is creatable for both replace=false and replace=true.
        store
            .check_creatable("alice", false)
            .expect("new account should be creatable");
        store
            .check_creatable("alice", true)
            .expect("new account should be creatable with replace");

        // Create `alice` with software key so the file exists.
        store
            .create_with(
                CreateAccountRequest::new("alice", AccountAuthenticatorChoice::SoftwareEd25519),
                &touch_id,
                &fido2,
            )
            .expect("create initial alice");

        // check_creatable rejects existing account when replace=false and accepts when replace=true.
        assert!(matches!(
            store.check_creatable("alice", false),
            Err(AccountError::AlreadyExists { ref username, .. }) if username == "alice"
        ));
        store
            .check_creatable("alice", true)
            .expect("existing account should be creatable with replace=true");

        // create_with with replace=false must fail BEFORE invoking Touch ID or FIDO2 providers.
        assert!(matches!(
            store.create_with(
                CreateAccountRequest::new("alice", AccountAuthenticatorChoice::TouchId),
                &touch_id,
                &fido2,
            ),
            Err(AccountError::AlreadyExists { ref username, .. }) if username == "alice"
        ));
        assert!(matches!(
            store.create_with(
                CreateAccountRequest::new("alice", AccountAuthenticatorChoice::Fido2),
                &touch_id,
                &fido2,
            ),
            Err(AccountError::AlreadyExists { ref username, .. }) if username == "alice"
        ));
        assert!(
            touch_id.auth_calls.lock().expect("auth calls").is_empty(),
            "Touch ID provider must not be called when account already exists"
        );
        assert_eq!(
            *fido2.enroll_calls.lock().expect("enroll calls"),
            0,
            "FIDO2 provider must not be called when account already exists"
        );
    }

    #[test]
    fn replace_transitions_and_preserves_original_on_failure() {
        let dir = TempDir::new().expect("tempdir");
        let store = AccountStore::new(dir.path().join("accounts"));
        let touch_id = MockTouchId::allowing();
        let fido_ed = MockFido2 {
            key: MockFido2Key::Ed25519([0x41; 32]),
            flags: FIDO2_FLAG_UP | FIDO2_FLAG_UV,
            counter: 5,
            hash_alg: SshSigHashAlg::Sha512,
        };
        let fido_p256 = MockFido2 {
            key: MockFido2Key::P256([0x42; 32]),
            flags: FIDO2_FLAG_UP,
            counter: 9,
            hash_alg: SshSigHashAlg::Sha256,
        };

        // 1. Initial Touch ID enrollment.
        let initial = store
            .create_with(
                CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::TouchId),
                &touch_id,
                &fido_ed,
            )
            .expect("create initial Touch ID");
        let old_touch_account = match &initial.authenticator {
            AuthenticatorSpec::TouchId {
                keychain_account, ..
            } => keychain_account.clone(),
            other => panic!("expected TouchId, got {other:?}"),
        };
        assert!(
            touch_id
                .load_secret(TOUCH_ID_KEYCHAIN_SERVICE, &old_touch_account)
                .is_ok()
        );

        // 2. Cancelled Touch ID replacement leaves original TOML & Keychain intact.
        let denying_touch = MockTouchId::default();
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::TouchId);
        req.replace = true;
        assert!(matches!(
            store.create_with(req, &denying_touch, &fido_ed),
            Err(AccountError::TouchIdFailed { .. })
        ));
        let loaded = store.load("ops_admin").expect("original account intact");
        assert_eq!(loaded.authenticator, initial.authenticator);
        loaded
            .verify_self_with(&touch_id, &fido_ed)
            .expect("original Touch ID still verifies after failed replace");

        // 3. Touch ID -> Touch ID replacement allocates a new keychain_account and deletes the old one.
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::TouchId);
        req.replace = true;
        let replaced_touch = store
            .create_with(req, &touch_id, &fido_ed)
            .expect("replace Touch ID -> Touch ID");
        let new_touch_account = match &replaced_touch.authenticator {
            AuthenticatorSpec::TouchId {
                keychain_account, ..
            } => keychain_account.clone(),
            other => panic!("expected TouchId, got {other:?}"),
        };
        assert_ne!(
            old_touch_account, new_touch_account,
            "Touch ID replacement must use a fresh keychain_account"
        );
        assert!(
            touch_id
                .load_secret(TOUCH_ID_KEYCHAIN_SERVICE, &old_touch_account)
                .is_err(),
            "old Touch ID keychain secret must be deleted after replacement"
        );
        assert!(
            touch_id
                .load_secret(TOUCH_ID_KEYCHAIN_SERVICE, &new_touch_account)
                .is_ok(),
            "new Touch ID keychain secret must be present"
        );
        replaced_touch
            .verify_self_with(&touch_id, &fido_ed)
            .expect("replaced Touch ID verifies");

        // 4. Touch ID -> FIDO2 replacement removes the old Touch ID keychain secret.
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::Fido2);
        req.replace = true;
        let replaced_fido = store
            .create_with(req, &touch_id, &fido_ed)
            .expect("replace Touch ID -> FIDO2");
        assert!(
            touch_id
                .load_secret(TOUCH_ID_KEYCHAIN_SERVICE, &new_touch_account)
                .is_err(),
            "superseded Touch ID secret must be deleted when switching to FIDO2"
        );
        let handle_path = match &replaced_fido.authenticator {
            AuthenticatorSpec::Fido2 {
                key_handle_path, ..
            } => key_handle_path.clone(),
            other => panic!("expected Fido2, got {other:?}"),
        };
        assert!(handle_path.exists());
        let original_handle_bytes = fs::read(&handle_path).expect("read original fido2 handle");
        let original_toml_bytes = fs::read(store.path_for("ops_admin")).expect("read toml");
        replaced_fido
            .verify_self_with(&touch_id, &fido_ed)
            .expect("FIDO2 account verifies");

        // 5. Failed FIDO2 -> FIDO2 replacement must NOT clobber existing key handle or TOML.
        let failing_fido = FailingFido2::new(true);
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::Fido2);
        req.replace = true;
        assert!(matches!(
            store.create_with(req, &touch_id, &failing_fido),
            Err(AccountError::Fido2 { .. })
        ));
        assert_eq!(
            fs::read(&handle_path).expect("read handle after failed replace"),
            original_handle_bytes,
            "existing FIDO2 key handle must remain untouched when replacement fails"
        );
        assert_eq!(
            fs::read(store.path_for("ops_admin")).expect("read toml after failed replace"),
            original_toml_bytes,
            "existing account TOML must remain untouched when replacement fails"
        );
        store
            .load("ops_admin")
            .expect("reload after failed FIDO2 replace")
            .verify_self_with(&touch_id, &fido_ed)
            .expect("original FIDO2 account still verifies");

        // 6. Successful FIDO2 -> FIDO2 replacement swaps in the new key cleanly.
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::Fido2);
        req.replace = true;
        let replaced_fido_p256 = store
            .create_with(req, &touch_id, &fido_p256)
            .expect("replace FIDO2 Ed25519 -> FIDO2 P-256");
        replaced_fido_p256
            .verify_self_with(&touch_id, &fido_p256)
            .expect("replaced FIDO2 P-256 account verifies");

        // 7. FIDO2 -> Touch ID replacement removes old FIDO2 key handle and .pub file.
        let mut req = CreateAccountRequest::new("ops_admin", AccountAuthenticatorChoice::TouchId);
        req.replace = true;
        let back_to_touch = store
            .create_with(req, &touch_id, &fido_p256)
            .expect("replace FIDO2 -> Touch ID");
        assert!(
            !handle_path.exists(),
            "old FIDO2 key handle must be removed when switching to Touch ID"
        );
        assert!(
            !append_pub_ext(&handle_path).exists(),
            "old FIDO2 .pub file must be removed when switching to Touch ID"
        );
        back_to_touch
            .verify_self_with(&touch_id, &fido_p256)
            .expect("back-to-Touch-ID account verifies");
    }
}
