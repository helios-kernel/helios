//! Pure-Rust TLS 1.3 transport (`rustls` + `rustls-pure`) with RFC 8446
//! `tls-exporter` channel binding for `inspector-tls` (`wasm32-wasip3`) and
//! host `helios://` clients.
//!
//! No X.509 CA PKI or client-certificate parsing is performed:
//! - The server (`inspector-tls`) generates an ephemeral Ed25519 key pair and
//!   minimal self-signed DER certificate in memory with zero capabilities.
//! - The client verifies the TLS 1.3 `CertificateVerify` handshake signature via
//!   `rustls-pure`, extracts the 32-byte RFC 8446 `tls-exporter` channel binding
//!   and leaf certificate SHA-256, and then verifies `ServerHello.machine_signature`
//!   (signed by `helios:system/machine-identity`) before sending any credentials.

use std::io::{self, Read as _, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ed25519_dalek::{Signer as _, SigningKey};
use futures_io::{AsyncRead, AsyncWrite};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, ServerConfig,
    ServerConnection, SideData, SignatureScheme,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::auth::{AuthError, TLS_EXPORTER_LABEL, random_32};

/// TLS 1.3 handshake metadata used to bind the transport to `MachineIdentity`
/// and `ClientAuth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsBinding {
    /// 32-byte RFC 8446 `tls-exporter` keying material under [`TLS_EXPORTER_LABEL`].
    pub channel_binding: [u8; 32],
    /// SHA-256 digest of the server's ephemeral TLS leaf certificate DER bytes.
    pub peer_cert_sha256: [u8; 32],
}

/// Errors produced during pure-Rust TLS 1.3 setup, handshake, or I/O.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to generate ephemeral TLS key: {0}")]
    Random(#[from] AuthError),
    #[error("rustls configuration or protocol error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("peer presented no TLS server certificate")]
    MissingServerCertificate,
    #[error("TLS transport I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Builds a TLS 1.3-only `ServerConfig` backed by `rustls-pure` and a fresh
/// ephemeral Ed25519 key pair + minimal self-signed DER certificate.
///
/// Returns `(ServerConfig, leaf_cert_sha256)`.
pub fn build_ephemeral_server_config() -> Result<(Arc<ServerConfig>, [u8; 32]), TlsError> {
    let seed = random_32()?;
    let (cert_der, pkcs8_der) = generate_ephemeral_ed25519_cert(seed);
    let cert_sha256 = sha256_bytes(&cert_der);
    let provider = Arc::new(rustls_pure::provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der)),
        )?;
    Ok((Arc::new(config), cert_sha256))
}

/// Builds a TLS 1.3-only `ClientConfig` backed by `rustls-pure`.
///
/// Certificate chain trust is intentionally delegated to the post-handshake
/// `MachineIdentity` signature over `(tls-exporter, peer_cert_sha256)` in
/// [`crate::auth::verify_server_hello`]; TLS 1.3 `CertificateVerify` signature
/// verification is still strictly enforced by `rustls-pure`.
pub fn build_client_config() -> Result<Arc<ClientConfig>, TlsError> {
    let provider = Arc::new(rustls_pure::provider());
    let verifier = Arc::new(EphemeralLeafVerifier {
        provider: Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Async TLS 1.3 server stream over any `futures_io::AsyncRead + AsyncWrite`.
pub struct TlsServerStream<R, W> {
    io: TlsIo<R, W, ServerConnection>,
    binding: TlsBinding,
}

impl<R, W> TlsServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Completes a TLS 1.3 server handshake over `(read, write)` using `config`
    /// and exports the RFC 8446 `tls-exporter` channel binding.
    pub async fn accept(
        read: R,
        write: W,
        config: Arc<ServerConfig>,
        leaf_cert_sha256: [u8; 32],
    ) -> Result<Self, TlsError> {
        let conn = ServerConnection::new(config)?;
        let mut io = TlsIo::new(read, write, conn);
        io.complete_handshake().await?;
        let mut channel_binding = [0u8; 32];
        io.conn
            .export_keying_material(&mut channel_binding, TLS_EXPORTER_LABEL, None)?;
        Ok(Self {
            io,
            binding: TlsBinding {
                channel_binding,
                peer_cert_sha256: leaf_cert_sha256,
            },
        })
    }

    #[must_use]
    pub const fn binding(&self) -> TlsBinding {
        self.binding
    }
}

impl<R, W> AsyncRead for TlsServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.io.poll_read_plaintext(cx, buf)
    }
}

impl<R, W> AsyncWrite for TlsServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io.poll_write_plaintext(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_flush_tls(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_close_tls(cx)
    }
}

/// Async TLS 1.3 client stream over any `futures_io::AsyncRead + AsyncWrite`.
pub struct TlsClientStream<R, W> {
    io: TlsIo<R, W, ClientConnection>,
    binding: TlsBinding,
}

impl<R, W> TlsClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Completes a TLS 1.3 client handshake over `(read, write)` using `config`
    /// and returns the stream along with its RFC 8446 `tls-exporter` binding
    /// and peer leaf certificate digest.
    pub async fn connect(
        read: R,
        write: W,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<Self, TlsError> {
        let sni = ServerName::try_from(server_name.to_owned())
            .unwrap_or_else(|_| ServerName::try_from("helios.local").expect("valid static SNI"));
        let conn = ClientConnection::new(config, sni)?;
        let mut io = TlsIo::new(read, write, conn);
        io.complete_handshake().await?;
        let peer_cert_sha256 = io
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| sha256_bytes(cert.as_ref()))
            .ok_or(TlsError::MissingServerCertificate)?;
        let mut channel_binding = [0u8; 32];
        io.conn
            .export_keying_material(&mut channel_binding, TLS_EXPORTER_LABEL, None)?;
        Ok(Self {
            io,
            binding: TlsBinding {
                channel_binding,
                peer_cert_sha256,
            },
        })
    }

    #[must_use]
    pub const fn binding(&self) -> TlsBinding {
        self.binding
    }
}

impl<R, W> AsyncRead for TlsClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.io.poll_read_plaintext(cx, buf)
    }
}

impl<R, W> AsyncWrite for TlsClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io.poll_write_plaintext(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_flush_tls(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_close_tls(cx)
    }
}

/// Shared non-blocking `rustls::ConnectionCommon` I/O adapter over split
/// `AsyncRead + AsyncWrite` halves.
struct TlsIo<R, W, C> {
    read: R,
    write: W,
    conn: C,
    pending_ciphertext: Vec<u8>,
    pending_offset: usize,
    /// `true` while an `AsyncWrite` call (`poll_write`/`poll_flush`/`poll_close`)
    /// returned `Poll::Pending` on `self.write` so `poll_read_plaintext` never
    /// polls `self.write` with the reader's `Context` and overwrites the writer
    /// task's registered waker.
    writer_waiting: bool,
    read_eof: bool,
    scratch: [u8; 16 * 1024],
    rx_cipher_offset: usize,
    rx_cipher_len: usize,
}

enum CipherReadStep {
    Progress,
    Eof,
}

impl<R, W, S, C> TlsIo<R, W, C>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: SideData,
    C: std::ops::DerefMut<Target = ConnectionCommon<S>> + Unpin,
{
    fn new(read: R, write: W, conn: C) -> Self {
        Self {
            read,
            write,
            conn,
            pending_ciphertext: Vec::new(),
            pending_offset: 0,
            writer_waiting: false,
            read_eof: false,
            scratch: [0u8; 16 * 1024],
            rx_cipher_offset: 0,
            rx_cipher_len: 0,
        }
    }

    async fn complete_handshake(&mut self) -> Result<(), TlsError> {
        std::future::poll_fn(|cx| self.poll_handshake(cx)).await
    }

    fn drain_tls_outbox(&mut self) {
        if self.pending_offset >= self.pending_ciphertext.len() {
            self.pending_ciphertext.clear();
            self.pending_offset = 0;
        }
        while self.conn.wants_write() {
            let _ = self.conn.write_tls(&mut self.pending_ciphertext);
        }
    }

    fn poll_flush_ciphertext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain_tls_outbox();
        while self.pending_offset < self.pending_ciphertext.len() {
            let slice = &self.pending_ciphertext[self.pending_offset..];
            match Pin::new(&mut self.write).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS ciphertext writer returned zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_offset += n;
                    if self.pending_offset == self.pending_ciphertext.len() {
                        self.pending_ciphertext.clear();
                        self.pending_offset = 0;
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn feed_buffered_ciphertext(&mut self) -> io::Result<usize> {
        let mut total_consumed = 0usize;
        while self.rx_cipher_offset < self.rx_cipher_len {
            let mut cursor = &self.scratch[self.rx_cipher_offset..self.rx_cipher_len];
            let consumed = self.conn.read_tls(&mut cursor)?;
            if consumed == 0 {
                break;
            }
            self.rx_cipher_offset += consumed;
            total_consumed += consumed;
            self.conn
                .process_new_packets()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        }
        if self.rx_cipher_offset >= self.rx_cipher_len {
            self.rx_cipher_offset = 0;
            self.rx_cipher_len = 0;
        }
        Ok(total_consumed)
    }

    fn poll_read_ciphertext_step(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<CipherReadStep>> {
        if self.rx_cipher_offset < self.rx_cipher_len {
            let consumed = match self.feed_buffered_ciphertext() {
                Ok(n) => n,
                Err(err) => return Poll::Ready(Err(err)),
            };
            if consumed > 0 {
                return Poll::Ready(Ok(CipherReadStep::Progress));
            }
            let io_state = match self.conn.process_new_packets() {
                Ok(state) => state,
                Err(err) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
                }
            };
            if io_state.plaintext_bytes_to_read() > 0 {
                return Poll::Ready(Ok(CipherReadStep::Progress));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS deframer stalled with unconsumed ciphertext buffered",
            )));
        }

        match Pin::new(&mut self.read).poll_read(cx, &mut self.scratch) {
            Poll::Ready(Ok(0)) => {
                self.read_eof = true;
                Poll::Ready(Ok(CipherReadStep::Eof))
            }
            Poll::Ready(Ok(n)) => {
                self.rx_cipher_offset = 0;
                self.rx_cipher_len = n;
                match self.feed_buffered_ciphertext() {
                    Ok(consumed) if consumed > 0 => Poll::Ready(Ok(CipherReadStep::Progress)),
                    Ok(_) => match self.conn.process_new_packets() {
                        Ok(io_state) if io_state.plaintext_bytes_to_read() > 0 => {
                            Poll::Ready(Ok(CipherReadStep::Progress))
                        }
                        Ok(_) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TLS deframer rejected newly read ciphertext without making progress",
                        ))),
                        Err(err) => {
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)))
                        }
                    },
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsError>> {
        loop {
            if self.conn.wants_write() || self.pending_offset < self.pending_ciphertext.len() {
                match self.poll_flush_ciphertext(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(TlsError::Io(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if !self.conn.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            if self.conn.wants_read() || self.rx_cipher_offset < self.rx_cipher_len {
                match self.poll_read_ciphertext_step(cx) {
                    Poll::Ready(Ok(CipherReadStep::Eof)) => {
                        return Poll::Ready(Err(TlsError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF during TLS 1.3 handshake",
                        ))));
                    }
                    Poll::Ready(Ok(CipherReadStep::Progress)) => continue,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(TlsError::Io(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            return Poll::Pending;
        }
    }

    fn poll_read_plaintext(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            // Queue any TLS post-handshake control messages (e.g. KeyUpdate /
            // alert). Only flush through `self.write` when no split writer task
            // is parked on `self.write`, so we never overwrite the writer's waker.
            if self.writer_waiting {
                if self.conn.wants_write() {
                    self.drain_tls_outbox();
                }
            } else if (self.conn.wants_write()
                || self.pending_offset < self.pending_ciphertext.len())
                && let Poll::Ready(Err(err)) = self.poll_flush_ciphertext(cx)
            {
                return Poll::Ready(Err(err));
            }
            match self.conn.reader().read(buf) {
                Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
                Ok(_) => return Poll::Ready(Ok(0)),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if self.rx_cipher_offset == self.rx_cipher_len && self.read_eof {
                        return Poll::Ready(Ok(0));
                    }
                    match self.poll_read_ciphertext_step(cx) {
                        Poll::Ready(Ok(CipherReadStep::Eof)) => return Poll::Ready(Ok(0)),
                        Poll::Ready(Ok(CipherReadStep::Progress)) => continue,
                        Poll::Ready(Err(io_err)) => return Poll::Ready(Err(io_err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn poll_write_plaintext(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            self.writer_waiting = false;
            return Poll::Ready(Ok(0));
        }
        if self.pending_offset < self.pending_ciphertext.len() {
            match self.poll_flush_ciphertext(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    self.writer_waiting = false;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {
                    self.writer_waiting = true;
                    return Poll::Pending;
                }
            }
        }
        let written = self.conn.writer().write(buf)?;
        self.drain_tls_outbox();
        match self.poll_flush_ciphertext(cx) {
            Poll::Ready(Ok(())) => {
                self.writer_waiting = false;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                self.writer_waiting = false;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                self.writer_waiting = false;
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.writer().flush()?;
        match self.poll_flush_ciphertext(cx) {
            Poll::Ready(res) => {
                self.writer_waiting = false;
                Poll::Ready(res)
            }
            Poll::Pending => {
                self.writer_waiting = true;
                Poll::Pending
            }
        }
    }

    fn poll_close_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.send_close_notify();
        match self.poll_flush_ciphertext(cx) {
            Poll::Ready(Ok(())) => match Pin::new(&mut self.write).poll_close(cx) {
                Poll::Ready(res) => {
                    self.writer_waiting = false;
                    Poll::Ready(res)
                }
                Poll::Pending => {
                    self.writer_waiting = true;
                    Poll::Pending
                }
            },
            Poll::Ready(Err(err)) => {
                self.writer_waiting = false;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                self.writer_waiting = true;
                Poll::Pending
            }
        }
    }
}

/// Custom TLS 1.3 verifier that strictly checks the TLS 1.3 handshake signature
/// via `rustls-pure` while deferring node-identity trust to `ServerHello`'s
/// `MachineIdentity` signature over `(tls-exporter, peer_cert_sha256)`.
#[derive(Debug)]
struct EphemeralLeafVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for EphemeralLeafVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Generates an ephemeral Ed25519 PKCS#8 private key (RFC 8410) and minimal
/// self-signed X.509 v3 DER certificate in pure Rust with zero external cert
/// generator dependencies.
fn generate_ephemeral_ed25519_cert(seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key().to_bytes();

    // RFC 8410 Ed25519 PKCS#8 PrivateKeyInfo (48 bytes).
    const PKCS8_ED25519_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&PKCS8_ED25519_PREFIX);
    pkcs8.extend_from_slice(&seed);

    // AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 (id-Ed25519) }
    const ED25519_ALG_ID: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    // Name: CN=helios-inspector
    let cn_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    let cn_val = der_tlv(0x0c, b"helios-inspector");
    let mut atv_body = Vec::with_capacity(cn_oid.len() + cn_val.len());
    atv_body.extend_from_slice(&cn_oid);
    atv_body.extend_from_slice(&cn_val);
    let rdn = der_tlv(0x31, &der_tlv(0x30, &atv_body));
    let name = der_tlv(0x30, &rdn);

    // Validity: 2020-01-01T00:00:00Z .. 2099-12-31T23:59:59Z
    let not_before = der_tlv(0x17, b"200101000000Z");
    let not_after = der_tlv(0x18, b"20991231235959Z");
    let mut validity_body = Vec::with_capacity(not_before.len() + not_after.len());
    validity_body.extend_from_slice(&not_before);
    validity_body.extend_from_slice(&not_after);
    let validity = der_tlv(0x30, &validity_body);

    // SubjectPublicKeyInfo (RFC 8410 Ed25519)
    let mut spki_bit_string = Vec::with_capacity(33);
    spki_bit_string.push(0x00);
    spki_bit_string.extend_from_slice(&verifying_key);
    let spki_bits = der_tlv(0x03, &spki_bit_string);
    let mut spki_body = Vec::with_capacity(ED25519_ALG_ID.len() + spki_bits.len());
    spki_body.extend_from_slice(&ED25519_ALG_ID);
    spki_body.extend_from_slice(&spki_bits);
    let spki = der_tlv(0x30, &spki_body);

    // TBSCertificate
    let mut tbs_body = Vec::with_capacity(192);
    // version [0] EXPLICIT INTEGER v3 (2)
    tbs_body.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    // serialNumber INTEGER 1
    tbs_body.extend_from_slice(&[0x02, 0x01, 0x01]);
    // signature AlgorithmIdentifier
    tbs_body.extend_from_slice(&ED25519_ALG_ID);
    // issuer
    tbs_body.extend_from_slice(&name);
    // validity
    tbs_body.extend_from_slice(&validity);
    // subject
    tbs_body.extend_from_slice(&name);
    // subjectPublicKeyInfo
    tbs_body.extend_from_slice(&spki);
    let tbs = der_tlv(0x30, &tbs_body);

    let sig = signing_key.sign(&tbs).to_bytes();
    let mut sig_bit_string = Vec::with_capacity(65);
    sig_bit_string.push(0x00);
    sig_bit_string.extend_from_slice(&sig);
    let sig_bits = der_tlv(0x03, &sig_bit_string);

    let mut cert_body = Vec::with_capacity(tbs.len() + ED25519_ALG_ID.len() + sig_bits.len());
    cert_body.extend_from_slice(&tbs);
    cert_body.extend_from_slice(&ED25519_ALG_ID);
    cert_body.extend_from_slice(&sig_bits);
    let cert_der = der_tlv(0x30, &cert_body);

    (cert_der, pkcs8)
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use async_io::Async;
    use futures_lite::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::auth::{
        AUTH_PROTOCOL_VERSION, AuthPolicy, ClientIdentity, MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
        SessionGrants, TransportKind, client_handshake, server_handshake,
        sign_machine_identity_message,
    };

    #[test]
    fn tls13_pure_rust_handshake_exports_matching_channel_binding_and_authenticates() {
        futures_lite::future::block_on(async {
            let (client_sock, server_sock) = UnixStream::pair().expect("unix pair");
            client_sock.set_nonblocking(true).expect("client nb");
            server_sock.set_nonblocking(true).expect("server nb");

            let client_r = Async::new(client_sock.try_clone().expect("clone c")).expect("c r");
            let client_w = Async::new(client_sock).expect("c w");
            let server_r = Async::new(server_sock.try_clone().expect("clone s")).expect("s r");
            let server_w = Async::new(server_sock).expect("s w");

            let (server_cfg, leaf_sha) =
                build_ephemeral_server_config().expect("build ephemeral server config");
            let client_cfg = build_client_config().expect("build client config");

            let machine_key = SigningKey::from_bytes(&[0x51; 32]);
            let machine_pub = machine_key.verifying_key().to_bytes();
            let client_seed = [0x62; 32];
            let client_pub = SigningKey::from_bytes(&client_seed)
                .verifying_key()
                .to_bytes();
            let policy = AuthPolicy::single_static_key("tls-test", client_pub);
            let identity = ClientIdentity::from_static_seed(client_seed);

            let server_fut = async move {
                let tls = TlsServerStream::accept(server_r, server_w, server_cfg, leaf_sha)
                    .await
                    .expect("server TLS 1.3 accept");
                let binding = tls.binding();
                let mut reader_writer = tls;
                let (mut r, mut w) = futures_util::AsyncReadExt::split(&mut reader_writer);
                let verified = server_handshake(
                    &mut r,
                    &mut w,
                    TransportKind::TcpTls,
                    &policy,
                    &SessionGrants::full_worker_ceiling(),
                    machine_pub,
                    1_700_000_000,
                    7,
                    Some(binding.channel_binding),
                    Some(binding.peer_cert_sha256),
                    |challenge| {
                        Ok(sign_machine_identity_message(
                            &machine_key,
                            MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                            challenge,
                        ))
                    },
                )
                .await
                .expect("server auth");
                let mut echo = [0u8; 5];
                r.read_exact(&mut echo).await.expect("read ping");
                w.write_all(&echo).await.expect("write pong");
                w.flush().await.expect("flush pong");
                (binding, verified)
            };

            let client_fut = async move {
                let mut tls =
                    TlsClientStream::connect(client_r, client_w, client_cfg, "helios.local")
                        .await
                        .expect("client TLS 1.3 connect");
                let binding = tls.binding();
                let (mut r, mut w) = futures_util::AsyncReadExt::split(&mut tls);
                let (hello, grants, session_id) = client_handshake(
                    &mut r,
                    &mut w,
                    TransportKind::TcpTls,
                    &identity,
                    Some(machine_pub),
                    Some(binding.channel_binding),
                    Some(binding.peer_cert_sha256),
                )
                .await
                .expect("client auth");
                assert_eq!(hello.protocol_version, AUTH_PROTOCOL_VERSION);
                assert_eq!(session_id, 7);
                w.write_all(b"hello").await.expect("write hello");
                w.flush().await.expect("flush hello");
                let mut reply = [0u8; 5];
                r.read_exact(&mut reply).await.expect("read echo");
                assert_eq!(&reply, b"hello");
                (binding, grants)
            };

            let ((s_bind, verified), (c_bind, grants)) =
                futures_lite::future::zip(server_fut, client_fut).await;
            assert_eq!(
                s_bind, c_bind,
                "RFC 8446 tls-exporter and cert digest must match"
            );
            assert_eq!(verified.principal, "tls-test");
            assert_eq!(verified.granted, grants);
        });
    }

    #[test]
    fn tls_control_handshake_drops_host_control_channel_before_data_plane_relay() {
        use crate::auth::{
            ClientAuth, ClientHello, ServerAuthResult, ServerHello, TlsControlRequest,
            TlsControlResponse, compute_handshake_challenge, read_auth_message, verify_client_auth,
            write_auth_message,
        };

        futures_lite::future::block_on(async {
            // Wire pairs:
            //   client <-> inspector-tls (TLS 1.3 socket)
            //   inspector-tls <-> inspector-host (control IPC channel, dropped after auth!)
            //   inspector-tls <-> inspector-worker (data IPC channel, active after host exits!)
            let (client_sock, tls_net_sock) = UnixStream::pair().expect("net pair");
            let (tls_ctrl_sock, host_ctrl_sock) = UnixStream::pair().expect("ctrl pair");
            let (tls_data_sock, worker_data_sock) = UnixStream::pair().expect("data pair");
            for s in [
                &client_sock,
                &tls_net_sock,
                &tls_ctrl_sock,
                &host_ctrl_sock,
                &tls_data_sock,
                &worker_data_sock,
            ] {
                s.set_nonblocking(true).expect("set_nonblocking");
            }

            let client_r = Async::new(client_sock.try_clone().expect("clone")).expect("c r");
            let client_w = Async::new(client_sock).expect("c w");
            let tls_net_r = Async::new(tls_net_sock.try_clone().expect("clone")).expect("tn r");
            let tls_net_w = Async::new(tls_net_sock).expect("tn w");
            let mut tls_ctrl_r =
                Async::new(tls_ctrl_sock.try_clone().expect("clone")).expect("tc r");
            let mut tls_ctrl_w = Async::new(tls_ctrl_sock).expect("tc w");
            let mut host_ctrl_r =
                Async::new(host_ctrl_sock.try_clone().expect("clone")).expect("hc r");
            let mut host_ctrl_w = Async::new(host_ctrl_sock).expect("hc w");
            let mut tls_data_r =
                Async::new(tls_data_sock.try_clone().expect("clone")).expect("td r");
            let mut tls_data_w = Async::new(tls_data_sock).expect("td w");
            let mut worker_data_r =
                Async::new(worker_data_sock.try_clone().expect("clone")).expect("wd r");
            let mut worker_data_w = Async::new(worker_data_sock).expect("wd w");

            let (server_cfg, leaf_sha) =
                build_ephemeral_server_config().expect("ephemeral TLS 1.3 server config");
            let client_cfg = build_client_config().expect("TLS 1.3 client config");

            // Only inspector-host holds machine_key and policy.
            let machine_key = SigningKey::from_bytes(&[0x77; 32]);
            let machine_pub = machine_key.verifying_key().to_bytes();
            let client_seed = [0x88; 32];
            let client_pub = SigningKey::from_bytes(&client_seed)
                .verifying_key()
                .to_bytes();
            let policy = AuthPolicy::single_static_key("ops-tls", client_pub);
            let identity = ClientIdentity::from_static_seed(client_seed);

            // 1. inspector-host: handles ONLY SignHandshake + Authenticate, then exits and drops control.
            let host_fut = async move {
                let sign_req: TlsControlRequest = read_auth_message(&mut host_ctrl_r)
                    .await
                    .expect("host read SignHandshake");
                let (channel_binding, tls_spki_sha256) = match sign_req {
                    TlsControlRequest::SignHandshake {
                        channel_binding,
                        tls_spki_sha256,
                    } => (channel_binding, tls_spki_sha256),
                    other => panic!("unexpected first control request: {other:?}"),
                };
                // Host generates server_nonce itself (never supplied by inspector-tls).
                let server_nonce = random_32().expect("host server_nonce");
                let now_unix = 1_700_000_000;
                let challenge = compute_handshake_challenge(
                    AUTH_PROTOCOL_VERSION,
                    TransportKind::TcpTls,
                    server_nonce,
                    now_unix,
                    Some(channel_binding),
                    Some(tls_spki_sha256),
                );
                let hello = ServerHello {
                    protocol_version: AUTH_PROTOCOL_VERSION,
                    transport: TransportKind::TcpTls,
                    machine_public_key: machine_pub,
                    server_nonce,
                    server_unix_time: now_unix,
                    tls_binding_required: true,
                    machine_signature: sign_machine_identity_message(
                        &machine_key,
                        MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                        &challenge,
                    ),
                };
                write_auth_message(
                    &mut host_ctrl_w,
                    &TlsControlResponse::HandshakeSigned(hello),
                )
                .await
                .expect("host write HandshakeSigned");

                let auth_req: TlsControlRequest = read_auth_message(&mut host_ctrl_r)
                    .await
                    .expect("host read Authenticate");
                let (server_hello, cb, client_auth) = match auth_req {
                    TlsControlRequest::Authenticate {
                        server_hello,
                        channel_binding,
                        client_auth,
                    } => (server_hello, channel_binding, client_auth),
                    other => panic!("unexpected second control request: {other:?}"),
                };
                assert_eq!(
                    server_hello.server_nonce, server_nonce,
                    "authenticated ServerHello must carry host-generated server_nonce"
                );
                let verified = verify_client_auth(
                    &policy,
                    &SessionGrants::full_worker_ceiling(),
                    &server_hello,
                    Some(cb),
                    &client_auth,
                    now_unix,
                )
                .expect("verify client auth");
                write_auth_message(
                    &mut host_ctrl_w,
                    &TlsControlResponse::AuthDecision(ServerAuthResult::Accepted {
                        granted: verified.granted.clone(),
                        session_id: 99,
                    }),
                )
                .await
                .expect("host write AuthDecision");
                // inspector-host now exits the session completely!
                drop(host_ctrl_r);
                drop(host_ctrl_w);
                (verified, server_nonce)
            };

            // 2. inspector-tls: ZERO policy, ZERO machine key. Relays handshake via control,
            // drops control, then splices TLS plaintext <-> data directly to inspector-worker.
            let tls_fut = async move {
                let mut tls = TlsServerStream::accept(tls_net_r, tls_net_w, server_cfg, leaf_sha)
                    .await
                    .expect("tls accept");
                let binding = tls.binding();
                let (mut net_r, mut net_w) = futures_util::AsyncReadExt::split(&mut tls);

                let client_hello: ClientHello = read_auth_message(&mut net_r)
                    .await
                    .expect("tls read ClientHello");
                assert_eq!(client_hello.protocol_version, AUTH_PROTOCOL_VERSION);

                write_auth_message(
                    &mut tls_ctrl_w,
                    &TlsControlRequest::SignHandshake {
                        channel_binding: binding.channel_binding,
                        tls_spki_sha256: binding.peer_cert_sha256,
                    },
                )
                .await
                .expect("tls request SignHandshake");
                let server_hello = match read_auth_message::<_, TlsControlResponse>(&mut tls_ctrl_r)
                    .await
                    .expect("tls read HandshakeSigned")
                {
                    TlsControlResponse::HandshakeSigned(hello) => hello,
                    other => panic!("unexpected SignHandshake reply: {other:?}"),
                };
                write_auth_message(&mut net_w, &server_hello)
                    .await
                    .expect("tls send ServerHello");

                let client_auth: ClientAuth = read_auth_message(&mut net_r)
                    .await
                    .expect("tls read ClientAuth");
                write_auth_message(
                    &mut tls_ctrl_w,
                    &TlsControlRequest::Authenticate {
                        server_hello,
                        channel_binding: binding.channel_binding,
                        client_auth: Box::new(client_auth),
                    },
                )
                .await
                .expect("tls send Authenticate");
                let decision = match read_auth_message::<_, TlsControlResponse>(&mut tls_ctrl_r)
                    .await
                    .expect("tls read AuthDecision")
                {
                    TlsControlResponse::AuthDecision(d) => d,
                    other => panic!("unexpected AuthDecision reply: {other:?}"),
                };
                write_auth_message(&mut net_w, &decision)
                    .await
                    .expect("tls send ServerAuthResult");
                assert!(matches!(decision, ServerAuthResult::Accepted { .. }));

                // Control channel is closed and dropped; host is out of the data plane.
                let mut eof = [0u8; 1];
                assert_eq!(
                    tls_ctrl_r.read(&mut eof).await.expect("control eof"),
                    0,
                    "inspector-host must close control channel after handshake"
                );
                drop(tls_ctrl_r);
                drop(tls_ctrl_w);

                // Bidirectional plaintext splice between client TLS and worker data pipe.
                let mut req = [0u8; 10];
                net_r.read_exact(&mut req).await.expect("tls read payload");
                tls_data_w
                    .write_all(&req)
                    .await
                    .expect("tls forward to worker");
                tls_data_w.flush().await.expect("flush worker");

                let mut resp = [0u8; 10];
                tls_data_r
                    .read_exact(&mut resp)
                    .await
                    .expect("tls read worker reply");
                net_w
                    .write_all(&resp)
                    .await
                    .expect("tls write reply to client");
                net_w.flush().await.expect("flush client");
            };

            // 3. inspector-worker: receives decrypted RPC bytes directly from inspector-tls.
            let worker_fut = async move {
                let mut buf = [0u8; 10];
                worker_data_r
                    .read_exact(&mut buf)
                    .await
                    .expect("worker read data");
                assert_eq!(&buf, b"rpc-frame1");
                worker_data_w
                    .write_all(b"rpc-reply1")
                    .await
                    .expect("worker write reply");
                worker_data_w.flush().await.expect("worker flush");
            };

            // 4. Client over TLS 1.3.
            let client_fut = async move {
                let mut tls =
                    TlsClientStream::connect(client_r, client_w, client_cfg, "helios.local")
                        .await
                        .expect("client TLS connect");
                let binding = tls.binding();
                let (mut r, mut w) = futures_util::AsyncReadExt::split(&mut tls);
                let (hello, grants, session_id) = client_handshake(
                    &mut r,
                    &mut w,
                    TransportKind::TcpTls,
                    &identity,
                    Some(machine_pub),
                    Some(binding.channel_binding),
                    Some(binding.peer_cert_sha256),
                )
                .await
                .expect("client handshake");
                assert_eq!(session_id, 99);
                w.write_all(b"rpc-frame1").await.expect("client send data");
                w.flush().await.expect("client flush");
                let mut reply = [0u8; 10];
                r.read_exact(&mut reply).await.expect("client read reply");
                assert_eq!(&reply, b"rpc-reply1");
                (hello.server_nonce, grants)
            };

            let (((verified, host_nonce), ()), ((), (client_nonce, grants))) =
                futures_lite::future::zip(
                    futures_lite::future::zip(host_fut, tls_fut),
                    futures_lite::future::zip(worker_fut, client_fut),
                )
                .await;
            assert_eq!(verified.principal, "ops-tls");
            assert_eq!(verified.granted, grants);
            assert_eq!(
                client_nonce, host_nonce,
                "client must observe the server_nonce generated by inspector-host"
            );
        });
    }

    #[test]
    fn tls_io_retains_unconsumed_ciphertext_across_lagging_bursts() {
        futures_lite::future::block_on(async {
            let (server_cfg, leaf_sha) =
                build_ephemeral_server_config().expect("build ephemeral server config");
            let client_cfg = build_client_config().expect("build client config");

            // Use an in-memory bounded channel pair so the sender can fill the
            // wire with >128 KiB of TLS ciphertext (many records) before the
            // receiver begins draining plaintext slowly in tiny chunks, forcing
            // rustls's deframer buffer to fill (`read_tls == 0`) mid-`scratch`.
            let (c2s_tx, c2s_rx) = async_channel::bounded::<Vec<u8>>(64);
            let (s2c_tx, s2c_rx) = async_channel::bounded::<Vec<u8>>(64);

            struct ChanReader {
                rx: Pin<Box<async_channel::Receiver<Vec<u8>>>>,
                buf: Vec<u8>,
                pos: usize,
            }
            impl AsyncRead for ChanReader {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    out: &mut [u8],
                ) -> Poll<io::Result<usize>> {
                    if out.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    loop {
                        if self.pos < self.buf.len() {
                            let n = (self.buf.len() - self.pos).min(out.len());
                            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                            self.pos += n;
                            if self.pos == self.buf.len() {
                                self.buf.clear();
                                self.pos = 0;
                            }
                            return Poll::Ready(Ok(n));
                        }
                        match futures_core::Stream::poll_next(self.rx.as_mut(), cx) {
                            Poll::Ready(Some(chunk)) => {
                                if !chunk.is_empty() {
                                    self.buf = chunk;
                                    self.pos = 0;
                                }
                            }
                            Poll::Ready(None) => return Poll::Ready(Ok(0)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
            }

            struct ChanWriter {
                tx: async_channel::Sender<Vec<u8>>,
            }
            impl AsyncWrite for ChanWriter {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    match self.tx.try_send(buf.to_vec()) {
                        Ok(()) => Poll::Ready(Ok(buf.len())),
                        Err(async_channel::TrySendError::Full(_)) => Poll::Pending,
                        Err(async_channel::TrySendError::Closed(_)) => {
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")))
                        }
                    }
                }
                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
                fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    self.tx.close();
                    Poll::Ready(Ok(()))
                }
            }

            let client_r = ChanReader {
                rx: Box::pin(s2c_rx),
                buf: Vec::new(),
                pos: 0,
            };
            let client_w = ChanWriter { tx: c2s_tx };
            let server_r = ChanReader {
                rx: Box::pin(c2s_rx),
                buf: Vec::new(),
                pos: 0,
            };
            let server_w = ChanWriter { tx: s2c_tx };

            let (mut server_tls, mut client_tls) = futures_lite::future::zip(
                async {
                    TlsServerStream::accept(server_r, server_w, server_cfg, leaf_sha)
                        .await
                        .expect("server accept")
                },
                async {
                    TlsClientStream::connect(client_r, client_w, client_cfg, "helios.local")
                        .await
                        .expect("client connect")
                },
            )
            .await;

            // Burst 160 KiB of deterministic non-trivial payload (including CJK
            // UTF-8 bytes) into TLS records BEFORE the server drains any plaintext.
            let mut payload = Vec::with_capacity(160 * 1024);
            let pattern = "中文日本語한국어-tls-burst-".as_bytes();
            while payload.len() < 160 * 1024 {
                let remaining = (160 * 1024) - payload.len();
                let take = remaining.min(pattern.len());
                payload.extend_from_slice(&pattern[..take]);
            }

            // Write 20 x 8 KiB chunks (160 KiB total) so multiple TLS records
            // coalesce inside a single 16 KiB `TlsIo::scratch` read and force
            // `conn.read_tls` to return `0` when rustls's deframer fills.
            for chunk in payload.chunks(8 * 1024) {
                client_tls
                    .write_all(chunk)
                    .await
                    .expect("client write burst");
            }
            client_tls.flush().await.expect("client flush burst");
            client_tls.close().await.expect("client close");

            // Drain plaintext in small 257-byte reads so rustls's plaintext buffer
            // stays populated across multiple `poll_read` iterations.
            let mut received = Vec::with_capacity(payload.len());
            let mut small_buf = [0u8; 257];
            loop {
                let n = server_tls
                    .read(&mut small_buf)
                    .await
                    .expect("server read lagged burst");
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&small_buf[..n]);
            }
            assert_eq!(received.len(), payload.len());
            assert_eq!(received, payload);
        });
    }

    #[test]
    fn tls_io_split_read_never_steals_parked_writer_waker() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountingWake(AtomicUsize);
        impl Wake for CountingWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        struct GatedWriter {
            inner: Vec<u8>,
            blocked: Arc<AtomicBool>,
            saved_waker: Arc<std::sync::Mutex<Option<Waker>>>,
        }
        impl AsyncWrite for GatedWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.blocked.load(Ordering::Acquire) {
                    *self.saved_waker.lock().expect("waker lock") = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                self.inner.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        struct PendingReader;
        impl AsyncRead for PendingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }

        let (server_cfg, _leaf_sha) = build_ephemeral_server_config().expect("server config");
        let conn = ServerConnection::new(server_cfg).expect("server conn");
        let blocked = Arc::new(AtomicBool::new(true));
        let saved_waker = Arc::new(std::sync::Mutex::new(None::<Waker>));
        let mut io = TlsIo::new(
            PendingReader,
            GatedWriter {
                inner: Vec::new(),
                blocked: Arc::clone(&blocked),
                saved_waker: Arc::clone(&saved_waker),
            },
            conn,
        );

        // Seed pending ciphertext so flush parks the writer task on GatedWriter.
        io.pending_ciphertext.extend_from_slice(b"ciphertext-bytes");
        let writer_wake_state = Arc::new(CountingWake(AtomicUsize::new(0)));
        let reader_wake_state = Arc::new(CountingWake(AtomicUsize::new(0)));
        let writer_waker = Waker::from(Arc::clone(&writer_wake_state));
        let reader_waker = Waker::from(Arc::clone(&reader_wake_state));
        let mut writer_cx = Context::from_waker(&writer_waker);
        let mut reader_cx = Context::from_waker(&reader_waker);

        // Writer parks on flush.
        assert!(matches!(io.poll_flush_tls(&mut writer_cx), Poll::Pending));
        assert!(io.writer_waiting);

        // Reader polls while writer is parked: MUST NOT overwrite GatedWriter's saved waker.
        let mut read_buf = [0u8; 64];
        assert!(matches!(
            io.poll_read_plaintext(&mut reader_cx, &mut read_buf),
            Poll::Pending
        ));

        // Unblock writer and fire saved waker: MUST wake writer, NOT reader!
        blocked.store(false, Ordering::Release);
        saved_waker
            .lock()
            .expect("waker lock")
            .take()
            .expect("writer waker must be stored")
            .wake();
        assert_eq!(writer_wake_state.0.load(Ordering::Acquire), 1);
        assert_eq!(
            reader_wake_state.0.load(Ordering::Acquire),
            0,
            "poll_read_plaintext must not steal the parked writer's waker"
        );

        // Writer resumes and flushes cleanly.
        assert!(matches!(
            io.poll_flush_tls(&mut writer_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(!io.writer_waiting);
    }
}
