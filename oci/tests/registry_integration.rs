//! End-to-end integration tests for `helios-oci` against a real loopback HTTP OCI
//! Distribution Spec v2 registry driven by `zenwave`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_net::TcpListener;
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_lite::io::{AsyncReadExt as _, AsyncWriteExt as _};
use helios_btrfs::write::stream_referenced_sources;
use helios_oci::{
    Arch, DefaultImageStore, Descriptor, Digest, DirectoryBackend, ImageConfig, ImageIndex,
    ImageManifest, ImageReference, ImageRuntimeConfig, ImageStore, NodeKind, OciError, Platform,
    RegistryAuth, RegistryClient, RootFs, SubvolumeBackend, SubvolumeError, SubvolumeMeta,
    UserDefaultImage, media_type,
};
use tempfile::TempDir;

#[derive(Clone, Debug)]
enum MockAuthMode {
    Basic {
        expected_header: String,
    },
    Bearer {
        token: String,
        expected_basic: Option<String>,
    },
}

#[derive(Default)]
struct RegistryState {
    auth: Option<MockAuthMode>,
    manifests: BTreeMap<String, (String, Vec<u8>)>,
    blobs: BTreeMap<String, Vec<u8>>,
    blob_hits: BTreeMap<String, usize>,
}

struct MockRegistry {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<RegistryState>>,
    stop_tx: async_channel::Sender<()>,
}

impl MockRegistry {
    async fn start(state: RegistryState) -> (Self, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        let state = Arc::new(Mutex::new(state));
        let state_bg = Arc::clone(&state);
        let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);

        let handle = std::thread::spawn(move || {
            futures_lite::future::block_on(async move {
                loop {
                    let accept_or_stop =
                        futures_lite::future::or(async { Some(listener.accept().await) }, async {
                            let _ = stop_rx.recv().await;
                            None
                        })
                        .await;
                    let Some(Ok((mut stream, _))) = accept_or_stop else {
                        break;
                    };
                    let state_conn = Arc::clone(&state_bg);
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut req_bytes = Vec::new();
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                req_bytes.extend_from_slice(&buf[..n]);
                                if req_bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let req_text = String::from_utf8_lossy(&req_bytes);
                    let mut lines = req_text.lines();
                    let request_line = lines.next().unwrap_or("");
                    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
                    let mut auth_header = None;
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':')
                            && k.trim().eq_ignore_ascii_case("authorization")
                        {
                            auth_header = Some(v.trim().to_owned());
                        }
                    }

                    let (status, content_type, extra_header, body) =
                        handle_request(&state_conn, addr, path, auth_header.as_deref());

                    let mut resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    if let Some((hk, hv)) = extra_header {
                        resp.push_str(&format!("{hk}: {hv}\r\n"));
                    }
                    resp.push_str("\r\n");
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.flush().await;
                }
            });
        });

        (
            Self {
                addr,
                state,
                stop_tx,
            },
            handle,
        )
    }

    fn host_port(&self) -> String {
        self.addr.to_string()
    }

    fn blob_hits(&self, digest: &Digest) -> usize {
        self.state
            .lock()
            .unwrap()
            .blob_hits
            .get(&digest.as_str())
            .copied()
            .unwrap_or(0)
    }

    fn shutdown(self, handle: std::thread::JoinHandle<()>) {
        let _ = self.stop_tx.try_send(());
        let _ = handle.join();
    }
}

fn handle_request(
    state: &Arc<Mutex<RegistryState>>,
    addr: std::net::SocketAddr,
    path: &str,
    auth_header: Option<&str>,
) -> (
    &'static str,
    String,
    Option<(&'static str, String)>,
    Vec<u8>,
) {
    let mut guard = state.lock().unwrap();

    // Token endpoint for Bearer auth flow.
    if path.starts_with("/token")
        && let Some(MockAuthMode::Bearer {
            token,
            expected_basic,
        }) = &guard.auth
    {
        if let Some(expected) = expected_basic
            && auth_header != Some(expected.as_str())
        {
            return (
                "401 Unauthorized",
                "application/json".to_owned(),
                None,
                br#"{"error":"invalid_basic_creds"}"#.to_vec(),
            );
        }
        let body = format!(r#"{{"token":"{token}"}}"#).into_bytes();
        return ("200 OK", "application/json".to_owned(), None, body);
    }

    // Check registry auth challenge.
    if let Some(mode) = guard.auth.clone() {
        match mode {
            MockAuthMode::Basic { expected_header } => {
                if auth_header != Some(expected_header.as_str()) {
                    return (
                        "401 Unauthorized",
                        "application/json".to_owned(),
                        Some((
                            "WWW-Authenticate",
                            r#"Basic realm="Helios Test""#.to_owned(),
                        )),
                        br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#.to_vec(),
                    );
                }
            }
            MockAuthMode::Bearer { token, .. } => {
                let want = format!("Bearer {token}");
                if auth_header != Some(want.as_str()) {
                    let challenge = format!(
                        r#"Bearer realm="http://{addr}/token",service="helios-test",scope="repository:demo/app:pull""#
                    );
                    return (
                        "401 Unauthorized",
                        "application/json".to_owned(),
                        Some(("WWW-Authenticate", challenge)),
                        br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#.to_vec(),
                    );
                }
            }
        }
    }

    if let Some((_, rest)) = path.split_once("/manifests/") {
        if let Some((ct, bytes)) = guard.manifests.get(rest) {
            return ("200 OK", ct.clone(), None, bytes.clone());
        }
        return (
            "404 Not Found",
            "application/json".to_owned(),
            None,
            br#"{"errors":[{"code":"MANIFEST_UNKNOWN"}]}"#.to_vec(),
        );
    }

    if let Some((_, digest)) = path.split_once("/blobs/") {
        if let Some(bytes) = guard.blobs.get(digest).cloned() {
            *guard.blob_hits.entry(digest.to_owned()).or_insert(0) += 1;
            return ("200 OK", "application/octet-stream".to_owned(), None, bytes);
        }
        return (
            "404 Not Found",
            "application/json".to_owned(),
            None,
            br#"{"errors":[{"code":"BLOB_UNKNOWN"}]}"#.to_vec(),
        );
    }

    (
        "404 Not Found",
        "text/plain".to_owned(),
        None,
        b"not found".to_vec(),
    )
}

fn append_pax_file(
    builder: &mut tar::Builder<Vec<u8>>,
    path: &str,
    data: &[u8],
    mode: u32,
    uid: u64,
    gid: u64,
    xattrs: &[(&str, &[u8])],
) {
    if !xattrs.is_empty() {
        let mut pax = Vec::new();
        for (key, value) in xattrs {
            let full_key = format!("SCHILY.xattr.{key}");
            let mut record_len = full_key.len() + 1 + value.len() + 2;
            loop {
                let digits = record_len.to_string().len();
                let total = digits + 1 + full_key.len() + 1 + value.len() + 1;
                if total == record_len {
                    break;
                }
                record_len = total;
            }
            write!(&mut pax, "{record_len} {full_key}=").unwrap();
            pax.extend_from_slice(value);
            pax.push(b'\n');
        }
        let mut pax_hdr = tar::Header::new_ustar();
        pax_hdr.set_entry_type(tar::EntryType::XHeader);
        pax_hdr.set_size(pax.len() as u64);
        pax_hdr.set_mode(0o644);
        pax_hdr.set_cksum();
        builder
            .append_data(&mut pax_hdr, format!("PaxHeaders/{path}"), pax.as_slice())
            .unwrap();
    }

    let mut hdr = tar::Header::new_gnu();
    hdr.set_entry_type(tar::EntryType::Regular);
    hdr.set_size(data.len() as u64);
    hdr.set_mode(mode);
    hdr.set_uid(uid);
    hdr.set_gid(gid);
    hdr.set_mtime(1_700_000_000);
    hdr.set_cksum();
    builder.append_data(&mut hdr, path, data).unwrap();
}

fn append_dir(builder: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32) {
    let mut hdr = tar::Header::new_gnu();
    hdr.set_entry_type(tar::EntryType::Directory);
    hdr.set_size(0);
    hdr.set_mode(mode);
    hdr.set_uid(0);
    hdr.set_gid(0);
    hdr.set_mtime(1_700_000_000);
    hdr.set_cksum();
    builder
        .append_data(&mut hdr, path, std::io::empty())
        .unwrap();
}

fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(raw).unwrap();
    enc.finish().unwrap()
}

fn build_layer0_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    append_dir(&mut builder, "etc", 0o755);
    append_dir(&mut builder, "usr", 0o755);
    append_dir(&mut builder, "usr/bin", 0o755);
    append_dir(&mut builder, "opt", 0o755);
    append_dir(&mut builder, "opt/old_dir", 0o755);
    append_dir(&mut builder, "opt/opaque", 0o755);

    append_pax_file(
        &mut builder,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:app:/app:/bin/sh\n",
        0o644,
        0,
        0,
        &[],
    );
    append_pax_file(
        &mut builder,
        "etc/keep.txt",
        b"from-layer-0",
        0o644,
        0,
        0,
        &[],
    );
    append_pax_file(
        &mut builder,
        "etc/obsolete.txt",
        b"to-be-whited-out",
        0o644,
        0,
        0,
        &[],
    );
    append_pax_file(
        &mut builder,
        "opt/opaque/stale.txt",
        b"removed-by-opaque-whiteout",
        0o644,
        0,
        0,
        &[],
    );
    // SUID + real 20-byte Linux `struct vfs_cap_data` (`VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE`,
    // `CAP_NET_RAW = 1 << 13`; `include/uapi/linux/capability.h`).
    let cap_bytes: [u8; 20] = [
        0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    append_pax_file(
        &mut builder,
        "usr/bin/ping",
        b"#!/bin/sh\necho pong\n",
        0o4755,
        0,
        0,
        &[("security.capability", &cap_bytes)],
    );
    // CJK files (Chinese, Japanese, Korean)
    append_pax_file(
        &mut builder,
        "opt/中文_日本語_한국어.txt",
        "你好・こんにちは・안녕하세요".as_bytes(),
        0o644,
        1000,
        1000,
        &[],
    );
    builder.into_inner().unwrap()
}

fn build_layer1_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    // Explicit whiteout of `etc/obsolete.txt`
    append_pax_file(&mut builder, "etc/.wh.obsolete.txt", b"", 0o644, 0, 0, &[]);
    // Opaque whiteout of `opt/opaque` + new sibling file in same layer
    append_pax_file(
        &mut builder,
        "opt/opaque/.wh..wh..opq",
        b"",
        0o644,
        0,
        0,
        &[],
    );
    append_pax_file(
        &mut builder,
        "opt/opaque/fresh.txt",
        b"created-in-layer-1",
        0o644,
        1000,
        1000,
        &[],
    );
    // SGID directory + new file
    append_dir(&mut builder, "app", 0o2755);
    append_pax_file(
        &mut builder,
        "app/service.sh",
        b"#!/bin/sh\necho ready\n",
        0o755,
        1000,
        1000,
        &[],
    );
    builder.into_inner().unwrap()
}

fn build_single_arch_manifest_and_config(
    arch: Arch,
    layers: &[(&str, &Vec<u8>, Digest)],
    state: &mut RegistryState,
) -> (Digest, Vec<u8>) {
    let mut diff_ids = Vec::new();
    let mut layer_descs = Vec::new();
    for (mt, compressed, diff_id) in layers {
        let blob_digest = Digest::sha256(compressed);
        state
            .blobs
            .insert(blob_digest.as_str(), (*compressed).clone());
        diff_ids.push(diff_id.clone());
        layer_descs.push(Descriptor {
            media_type: (*mt).to_owned(),
            digest: blob_digest,
            size: compressed.len() as u64,
            urls: Vec::new(),
            annotations: BTreeMap::new(),
            platform: None,
        });
    }

    let cfg = ImageConfig {
        architecture: arch.oci_arch().to_owned(),
        os: "linux".to_owned(),
        config: ImageRuntimeConfig {
            user: Some("app".to_owned()),
            env: vec![
                "PATH=/usr/bin:/bin".to_owned(),
                "HELIOS_IMAGE=demo".to_owned(),
            ],
            entrypoint: vec!["/bin/sh".to_owned()],
            cmd: vec!["/app/service.sh".to_owned()],
            working_dir: Some("/app".to_owned()),
            labels: BTreeMap::new(),
            stop_signal: None,
        },
        rootfs: RootFs {
            kind: "layers".to_owned(),
            diff_ids,
        },
    };
    let cfg_bytes = serde_json::to_vec(&cfg).unwrap();
    let cfg_digest = Digest::sha256(&cfg_bytes);
    state.blobs.insert(cfg_digest.as_str(), cfg_bytes.clone());

    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(media_type::OCI_MANIFEST.to_owned()),
        config: Descriptor {
            media_type: media_type::OCI_CONFIG.to_owned(),
            digest: cfg_digest,
            size: cfg_bytes.len() as u64,
            urls: Vec::new(),
            annotations: BTreeMap::new(),
            platform: None,
        },
        layers: layer_descs,
        annotations: BTreeMap::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_digest = Digest::sha256(&manifest_bytes);
    state.manifests.insert(
        manifest_digest.as_str(),
        (media_type::OCI_MANIFEST.to_owned(), manifest_bytes.clone()),
    );
    (manifest_digest, manifest_bytes)
}

#[test]
fn pulls_multi_arch_bearer_gzip_and_zstd_whiteouts_cjk_and_chain_id_cache() {
    futures_lite::future::block_on(async {
        let layer0_tar = build_layer0_tar();
        let layer0_diff_id = Digest::sha256(&layer0_tar);
        let layer0_gz = gzip_bytes(&layer0_tar);
        let layer0_gz_digest = Digest::sha256(&layer0_gz);

        let layer1_tar = build_layer1_tar();
        let layer1_diff_id = Digest::sha256(&layer1_tar);
        let layer1_zst = zrip_encode::compress(&layer1_tar, 1).unwrap();

        let mut state = RegistryState {
            auth: Some(MockAuthMode::Bearer {
                token: "jwt-helios-1199".to_owned(),
                expected_basic: Some(
                    RegistryAuth::Basic {
                        username: "alice".to_owned(),
                        password: "secret".to_owned(),
                    }
                    .basic_header_value()
                    .unwrap(),
                ),
            }),
            ..RegistryState::default()
        };

        let (amd64_digest, amd64_bytes) = build_single_arch_manifest_and_config(
            Arch::X86_64,
            &[
                (
                    media_type::OCI_LAYER_TAR_GZIP,
                    &layer0_gz,
                    layer0_diff_id.clone(),
                ),
                (
                    media_type::OCI_LAYER_TAR_ZSTD,
                    &layer1_zst,
                    layer1_diff_id.clone(),
                ),
            ],
            &mut state,
        );
        let (arm64_digest, arm64_bytes) = build_single_arch_manifest_and_config(
            Arch::Aarch64,
            &[(
                media_type::OCI_LAYER_TAR_GZIP,
                &layer0_gz,
                layer0_diff_id.clone(),
            )],
            &mut state,
        );

        let index = ImageIndex {
            schema_version: 2,
            media_type: Some(media_type::OCI_INDEX.to_owned()),
            manifests: vec![
                Descriptor {
                    media_type: media_type::OCI_MANIFEST.to_owned(),
                    digest: amd64_digest.clone(),
                    size: amd64_bytes.len() as u64,
                    urls: Vec::new(),
                    annotations: BTreeMap::new(),
                    platform: Some(Platform {
                        os: "linux".to_owned(),
                        architecture: "amd64".to_owned(),
                        variant: None,
                    }),
                },
                Descriptor {
                    media_type: media_type::OCI_MANIFEST.to_owned(),
                    digest: arm64_digest.clone(),
                    size: arm64_bytes.len() as u64,
                    urls: Vec::new(),
                    annotations: BTreeMap::new(),
                    platform: Some(Platform {
                        os: "linux".to_owned(),
                        architecture: "arm64".to_owned(),
                        variant: Some("v8".to_owned()),
                    }),
                },
            ],
            annotations: BTreeMap::new(),
        };
        let index_bytes = serde_json::to_vec(&index).unwrap();
        state.manifests.insert(
            "v1".to_owned(),
            (media_type::OCI_INDEX.to_owned(), index_bytes),
        );

        let (registry, handle) = MockRegistry::start(state).await;
        let tmp = TempDir::new().unwrap();
        let store = ImageStore::open(tmp.path(), DirectoryBackend).unwrap();

        let reference =
            ImageReference::parse(&format!("http://{}/demo/app:v1", registry.host_port())).unwrap();
        let mut client = RegistryClient::with_auth(RegistryAuth::Basic {
            username: "alice".to_owned(),
            password: "secret".to_owned(),
        });

        // 1. Pull amd64 (2 layers: gzip + zstd)
        let amd64 = store
            .pull(&mut client, &reference, Arch::X86_64)
            .await
            .expect("pull amd64");
        assert_eq!(amd64.manifest_digest, amd64_digest);
        assert_eq!(amd64.layer_chain_ids.len(), 2);
        assert!(!amd64.btrfs_backed);

        let root = amd64.rootfs_path();
        assert_eq!(
            std::fs::read(root.join("etc/keep.txt")).unwrap(),
            b"from-layer-0"
        );
        assert!(
            !root.join("etc/obsolete.txt").exists(),
            "explicit .wh.* whiteout failed"
        );
        assert!(
            !root.join("opt/opaque/stale.txt").exists(),
            "opaque .wh..wh..opq whiteout failed"
        );
        assert_eq!(
            std::fs::read(root.join("opt/opaque/fresh.txt")).unwrap(),
            b"created-in-layer-1"
        );
        assert_eq!(
            std::fs::read(root.join("opt/中文_日本語_한국어.txt")).unwrap(),
            "你好・こんにちは・안녕하세요".as_bytes()
        );
        assert_eq!(
            std::fs::read(root.join("app/service.sh")).unwrap(),
            b"#!/bin/sh\necho ready\n"
        );

        // Verify persisted full Unix metadata (suid, sgid, uid/gid, security.capability xattr)
        let top_meta = store
            .load_layer_metadata(amd64.top_chain_id().unwrap())
            .unwrap()
            .expect("top layer metadata");
        let ping = top_meta.entries.get("usr/bin/ping").expect("ping meta");
        assert_eq!(ping.kind, NodeKind::File);
        assert_eq!(ping.mode, 0o4755);
        assert_eq!(
            ping.xattrs.get("security.capability").map(Vec::as_slice),
            Some(
                &[
                    0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..]
            )
        );
        let app_dir = top_meta.entries.get("app").expect("app dir meta");
        assert_eq!(app_dir.mode, 0o2755);
        assert!(!top_meta.entries.contains_key("etc/obsolete.txt"));
        assert!(!top_meta.entries.contains_key("opt/opaque/stale.txt"));

        // 2. Pull arm64 (shares layer 0 by chain-id!): blob hit count for layer 0 MUST stay 1!
        assert_eq!(registry.blob_hits(&layer0_gz_digest), 1);
        let arm64 = store
            .pull(&mut client, &reference, Arch::Aarch64)
            .await
            .expect("pull arm64");
        assert_eq!(arm64.manifest_digest, arm64_digest);
        assert_eq!(arm64.layer_chain_ids.len(), 1);
        assert_eq!(arm64.layer_chain_ids[0], amd64.layer_chain_ids[0]);
        assert_eq!(
            registry.blob_hits(&layer0_gz_digest),
            1,
            "layer 0 should be reused from chain-id cache without re-downloading"
        );

        // 3. Per-user default image store keyed by login principal
        let mut prefs = store.default_image_store().unwrap();
        let pref = UserDefaultImage::from_pulled_image(&amd64).unwrap();
        assert_eq!(pref.credentials.uid, 1000);
        assert_eq!(pref.credentials.gid, 1000);
        prefs.set("alice@helios.internal", pref.clone()).unwrap();
        let reloaded = DefaultImageStore::load(prefs.path()).unwrap();
        assert_eq!(reloaded.get("alice@helios.internal").unwrap(), Some(&pref));

        registry.shutdown(handle);
    });
}

#[test]
fn basic_auth_and_sha256_digest_mismatch_are_enforced() {
    futures_lite::future::block_on(async {
        let layer0_tar = build_layer0_tar();
        let layer0_diff_id = Digest::sha256(&layer0_tar);
        let layer0_gz = gzip_bytes(&layer0_tar);
        let expected_blob_digest = Digest::sha256(&layer0_gz);

        let basic_auth = RegistryAuth::Basic {
            username: "builder".to_owned(),
            password: "pw".to_owned(),
        };

        let mut state = RegistryState {
            auth: Some(MockAuthMode::Basic {
                expected_header: basic_auth.basic_header_value().unwrap(),
            }),
            ..RegistryState::default()
        };

        let (_m_digest, m_bytes) = build_single_arch_manifest_and_config(
            Arch::X86_64,
            &[(media_type::OCI_LAYER_TAR_GZIP, &layer0_gz, layer0_diff_id)],
            &mut state,
        );
        state.manifests.insert(
            "tampered".to_owned(),
            (media_type::OCI_MANIFEST.to_owned(), m_bytes),
        );
        // Corrupt the stored blob bytes so SHA-256 verification MUST fail!
        state.blobs.insert(
            expected_blob_digest.as_str(),
            b"corrupted-gzip-stream".to_vec(),
        );

        let (registry, handle) = MockRegistry::start(state).await;
        let tmp = TempDir::new().unwrap();
        let store = ImageStore::open_directory(tmp.path()).unwrap();
        let reference = ImageReference::parse(&format!(
            "http://{}/demo/app:tampered",
            registry.host_port()
        ))
        .unwrap();

        // Anonymous client must fail Basic auth cleanly.
        let mut anon = RegistryClient::new();
        let auth_err = store
            .pull(&mut anon, &reference, Arch::X86_64)
            .await
            .unwrap_err();
        assert!(
            matches!(auth_err, OciError::Auth { .. }),
            "got {auth_err:?}"
        );

        // Authenticated client downloads blob and MUST reject SHA-256 mismatch.
        let mut authed = RegistryClient::with_auth(basic_auth);
        let mismatch = store
            .pull(&mut authed, &reference, Arch::X86_64)
            .await
            .unwrap_err();
        assert!(
            matches!(mismatch, OciError::DigestMismatch { .. }),
            "expected DigestMismatch, got {mismatch:?}"
        );

        registry.shutdown(handle);
    });
}

/// Recorded btrfs subvolume lifecycle backend exercising both:
/// 1. `create_subvolume` -> `snapshot_subvolume` -> whiteout extraction -> `set_subvolume_read_only(true)`
/// 2. `receive_subvolume` stream validation through `helios_btrfs::write::stream_referenced_sources`.
struct RecordingBtrfsBackend {
    use_receive_stream: bool,
    events: Mutex<Vec<String>>,
    subvolumes: Mutex<BTreeMap<PathBuf, SubvolumeMeta>>,
    received_streams: Mutex<Vec<Vec<u8>>>,
}

impl RecordingBtrfsBackend {
    fn new(use_receive_stream: bool) -> Self {
        Self {
            use_receive_stream,
            events: Mutex::new(Vec::new()),
            subvolumes: Mutex::new(BTreeMap::new()),
            received_streams: Mutex::new(Vec::new()),
        }
    }
}

impl SubvolumeBackend for RecordingBtrfsBackend {
    async fn create_subvolume(&self, path: &Path) -> Result<SubvolumeMeta, SubvolumeError> {
        std::fs::create_dir_all(path).map_err(|e| SubvolumeError::Backend {
            operation: "create_subvolume",
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;
        self.events.lock().unwrap().push(format!(
            "create:{}",
            path.file_name().unwrap().to_string_lossy()
        ));
        let meta = SubvolumeMeta {
            uuid: [0x11; 16],
            received_uuid: None,
            ctransid: 1,
            read_only: false,
        };
        self.subvolumes
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), meta.clone());
        Ok(meta)
    }

    async fn snapshot_subvolume(
        &self,
        source: &Path,
        destination: &Path,
        read_only: bool,
    ) -> Result<SubvolumeMeta, SubvolumeError> {
        helios_oci::unpack::copy_tree_recursive(source, destination).map_err(|e| {
            SubvolumeError::Backend {
                operation: "snapshot_subvolume",
                path: destination.to_path_buf(),
                detail: e.to_string(),
            }
        })?;
        self.events.lock().unwrap().push(format!(
            "snapshot:{}->{}",
            source.file_name().unwrap().to_string_lossy(),
            destination.file_name().unwrap().to_string_lossy()
        ));
        let meta = SubvolumeMeta {
            uuid: [0x22; 16],
            received_uuid: None,
            ctransid: 2,
            read_only,
        };
        self.subvolumes
            .lock()
            .unwrap()
            .insert(destination.to_path_buf(), meta.clone());
        Ok(meta)
    }

    async fn set_subvolume_read_only(
        &self,
        path: &Path,
        read_only: bool,
    ) -> Result<(), SubvolumeError> {
        self.events.lock().unwrap().push(format!(
            "set_ro:{}:{read_only}",
            path.file_name().unwrap().to_string_lossy()
        ));
        if let Some(meta) = self.subvolumes.lock().unwrap().get_mut(path) {
            meta.read_only = read_only;
        }
        Ok(())
    }

    async fn delete_subvolume(&self, path: &Path) -> Result<(), SubvolumeError> {
        self.subvolumes.lock().unwrap().remove(path);
        let _ = helios_oci::unpack::remove_path_recursive(path);
        Ok(())
    }

    async fn subvolume_info(&self, path: &Path) -> Result<Option<SubvolumeMeta>, SubvolumeError> {
        if path.file_name().and_then(|n| n.to_str()) == Some("layers") {
            return Err(SubvolumeError::NotSubvolume {
                path: path.to_path_buf(),
            });
        }
        Ok(self.subvolumes.lock().unwrap().get(path).cloned())
    }

    async fn receive_subvolume(
        &self,
        destination_parent: &Path,
        stream: Vec<u8>,
    ) -> Result<Option<SubvolumeMeta>, SubvolumeError> {
        if !self.use_receive_stream {
            return Ok(None);
        }
        // Verify CRC32C, magic, version, TLVs, and END via real `helios-btrfs` parser!
        stream_referenced_sources(&stream).map_err(|e| SubvolumeError::Backend {
            operation: "receive_subvolume",
            path: destination_parent.to_path_buf(),
            detail: e.to_string(),
        })?;
        // Parse subvol name (first TLV attr::PATH = 15) and uuid (attr::UUID = 1) from first command.
        let (name, uuid) = parse_first_cmd_name_and_uuid(&stream);
        self.received_streams.lock().unwrap().push(stream);
        let idx = self.received_streams.lock().unwrap().len() as u64;
        let meta = SubvolumeMeta {
            uuid,
            received_uuid: Some(uuid),
            ctransid: idx,
            read_only: true,
        };
        let subvol_path = destination_parent.join(name);
        let _ = std::fs::create_dir_all(&subvol_path);
        self.subvolumes
            .lock()
            .unwrap()
            .insert(subvol_path, meta.clone());
        Ok(Some(meta))
    }
}

fn parse_first_cmd_name_and_uuid(stream: &[u8]) -> (String, [u8; 16]) {
    let mut pos = 17 + 10; // 13 magic + 4 version + 10 cmd header
    let cmd_len = u32::from_le_bytes(stream[17..21].try_into().unwrap()) as usize;
    let end = pos + cmd_len;
    let mut name = String::new();
    let mut uuid = [0u8; 16];
    while pos + 4 <= end {
        let kind = u16::from_le_bytes(stream[pos..pos + 2].try_into().unwrap());
        let len = usize::from(u16::from_le_bytes(
            stream[pos + 2..pos + 4].try_into().unwrap(),
        ));
        let data = &stream[pos + 4..pos + 4 + len];
        if kind == 15 {
            name = String::from_utf8_lossy(data).into_owned();
        } else if kind == 1 && data.len() == 16 {
            uuid.copy_from_slice(data);
        }
        pos += 4 + len;
    }
    (name, uuid)
}

#[test]
fn materializes_multi_layer_oci_image_through_btrfs_subvolume_lifecycle_and_send_stream() {
    futures_lite::future::block_on(async {
        let layer0_tar = build_layer0_tar();
        let layer0_diff_id = Digest::sha256(&layer0_tar);
        let layer0_gz = gzip_bytes(&layer0_tar);

        let layer1_tar = build_layer1_tar();
        let layer1_diff_id = Digest::sha256(&layer1_tar);
        let layer1_zst = zrip_encode::compress(&layer1_tar, 1).unwrap();

        let mut state = RegistryState::default();
        let (_digest, manifest_bytes) = build_single_arch_manifest_and_config(
            Arch::X86_64,
            &[
                (media_type::OCI_LAYER_TAR_GZIP, &layer0_gz, layer0_diff_id),
                (media_type::OCI_LAYER_TAR_ZSTD, &layer1_zst, layer1_diff_id),
            ],
            &mut state,
        );
        state.manifests.insert(
            "latest".to_owned(),
            (media_type::OCI_MANIFEST.to_owned(), manifest_bytes),
        );

        let (registry, handle) = MockRegistry::start(state).await;
        let reference = ImageReference::parse(&format!(
            "http://{}/demo/btrfs:latest",
            registry.host_port()
        ))
        .unwrap();

        // 1. Direct `create_subvolume` -> `snapshot_subvolume` -> `set_subvolume_read_only(true)` path:
        let tmp_subvol = TempDir::new().unwrap();
        let store = ImageStore::open(tmp_subvol.path(), RecordingBtrfsBackend::new(false)).unwrap();
        let mut client = RegistryClient::new();
        let pulled = store
            .pull(&mut client, &reference, Arch::X86_64)
            .await
            .expect("pull via create/snapshot/set_ro");
        assert!(pulled.btrfs_backed);
        assert_eq!(pulled.layer_chain_ids.len(), 2);

        let events = store.backend().events.lock().unwrap().clone();
        assert_eq!(
            events.len(),
            4,
            "expected create, set_ro, snapshot, set_ro: {events:?}"
        );
        assert!(events[0].starts_with("create:"));
        assert!(events[1].ends_with(":true"));
        assert!(events[2].starts_with("snapshot:"));
        assert!(events[3].ends_with(":true"));
        assert!(!pulled.rootfs_path().join("etc/obsolete.txt").exists());
        assert!(!pulled.rootfs_path().join("opt/opaque/stale.txt").exists());
        assert!(pulled.rootfs_path().join("opt/opaque/fresh.txt").is_file());
        assert!(
            pulled
                .rootfs_path()
                .join("opt/中文_日本語_한국어.txt")
                .is_file()
        );

        // 2. `receive_subvolume` path validating CRC32C btrfs v1 send streams through `helios-btrfs`:
        let tmp_recv = TempDir::new().unwrap();
        let store_recv =
            ImageStore::open(tmp_recv.path(), RecordingBtrfsBackend::new(true)).unwrap();
        let pulled_recv = store_recv
            .pull(&mut client, &reference, Arch::X86_64)
            .await
            .expect("pull via receive_subvolume");
        assert!(pulled_recv.btrfs_backed);
        let streams = store_recv.backend().received_streams.lock().unwrap();
        assert_eq!(
            streams.len(),
            2,
            "both base and child layers should use btrfs v1 send streams"
        );
        assert!(stream_referenced_sources(&streams[0]).unwrap().is_empty());
        let child_refs = stream_referenced_sources(&streams[1]).unwrap();
        assert_eq!(
            child_refs.len(),
            1,
            "child snapshot stream must reference parent subvolume UUID"
        );
        assert_eq!(
            child_refs[0].0,
            pulled_recv.layer_chain_ids[0].to_uuid_bytes()
        );
        drop(streams);

        registry.shutdown(handle);
    });
}

#[test]
fn scratch_repull_preserves_btrfs_backed_and_concurrent_pulls_succeed() {
    futures_lite::future::block_on(async {
        let layer0_tar = build_layer0_tar();
        let layer0_diff_id = Digest::sha256(&layer0_tar);
        let layer0_gz = gzip_bytes(&layer0_tar);

        let mut state = RegistryState::default();
        let (_scratch_digest, scratch_manifest) =
            build_single_arch_manifest_and_config(Arch::X86_64, &[], &mut state);
        state.manifests.insert(
            "scratch".to_owned(),
            (media_type::OCI_MANIFEST.to_owned(), scratch_manifest),
        );

        let (_app_digest, app_manifest) = build_single_arch_manifest_and_config(
            Arch::X86_64,
            &[(media_type::OCI_LAYER_TAR_GZIP, &layer0_gz, layer0_diff_id)],
            &mut state,
        );
        state.manifests.insert(
            "app".to_owned(),
            (media_type::OCI_MANIFEST.to_owned(), app_manifest),
        );

        let (registry, handle) = MockRegistry::start(state).await;

        // 1. 0-layer scratch image re-pull preserves btrfs_backed = true when subvolume exists.
        let scratch_ref = ImageReference::parse(&format!(
            "http://{}/demo/empty:scratch",
            registry.host_port()
        ))
        .unwrap();
        let tmp_btrfs = TempDir::new().unwrap();
        let btrfs_store =
            ImageStore::open(tmp_btrfs.path(), RecordingBtrfsBackend::new(false)).unwrap();
        let mut client = RegistryClient::new();
        let first_scratch = btrfs_store
            .pull(&mut client, &scratch_ref, Arch::X86_64)
            .await
            .unwrap();
        assert!(first_scratch.btrfs_backed);
        let second_scratch = btrfs_store
            .pull(&mut client, &scratch_ref, Arch::X86_64)
            .await
            .unwrap();
        assert!(
            second_scratch.btrfs_backed,
            "0-layer scratch re-pull must preserve btrfs_backed = true"
        );

        // DirectoryBackend 0-layer pull & re-pull remain btrfs_backed = false.
        let tmp_dir = TempDir::new().unwrap();
        let dir_store = ImageStore::open_directory(tmp_dir.path()).unwrap();
        assert!(
            !dir_store
                .pull(&mut client, &scratch_ref, Arch::X86_64)
                .await
                .unwrap()
                .btrfs_backed
        );
        assert!(
            !dir_store
                .pull(&mut client, &scratch_ref, Arch::X86_64)
                .await
                .unwrap()
                .btrfs_backed
        );

        // 2. Concurrent pulls into the same directory ImageStore must not race on staging/.
        let app_ref =
            ImageReference::parse(&format!("http://{}/demo/app:app", registry.host_port()))
                .unwrap();
        let store_root = tmp_dir.path().to_path_buf();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let store_root = store_root.clone();
                let app_ref = app_ref.clone();
                scope.spawn(move || {
                    futures_lite::future::block_on(async move {
                        let store = ImageStore::open_directory(&store_root).unwrap();
                        let mut c = RegistryClient::new();
                        let pulled = store.pull(&mut c, &app_ref, Arch::X86_64).await.unwrap();
                        assert!(pulled.rootfs_path().join("etc/passwd").is_file());
                    });
                });
            }
        });
        let staging_leftovers: Vec<_> = std::fs::read_dir(tmp_dir.path().join("staging"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            staging_leftovers.is_empty(),
            "staging directory should have no leftovers: {staging_leftovers:?}"
        );

        registry.shutdown(handle);
    });
}

#[cfg(unix)]
#[test]
fn non_btrfs_multi_layer_pull_preserves_hardlinks_and_dir_modes() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    futures_lite::future::block_on(async {
        let mut l0 = tar::Builder::new(Vec::new());
        append_dir(&mut l0, "usr", 0o755);
        append_dir(&mut l0, "usr/bin", 0o755);
        append_dir(&mut l0, "opt", 0o755);
        append_dir(&mut l0, "opt/sgid", 0o2755);
        append_dir(&mut l0, "opt/ro", 0o555);
        append_pax_file(&mut l0, "usr/bin/busybox", b"busybox-bin", 0o755, 0, 0, &[]);
        let mut hl_hdr = tar::Header::new_gnu();
        hl_hdr.set_entry_type(tar::EntryType::Link);
        hl_hdr.set_size(0);
        hl_hdr.set_mode(0o755);
        hl_hdr.set_cksum();
        l0.append_link(&mut hl_hdr, "opt/sgid/sh", "usr/bin/busybox")
            .unwrap();
        let l0_tar = l0.into_inner().unwrap();
        let l0_diff = Digest::sha256(&l0_tar);
        let l0_gz = gzip_bytes(&l0_tar);

        let mut l1 = tar::Builder::new(Vec::new());
        append_pax_file(&mut l1, "top.txt", b"top-level", 0o644, 0, 0, &[]);
        append_pax_file(&mut l1, "opt/sgid/extra.txt", b"extra", 0o644, 0, 0, &[]);
        let l1_tar = l1.into_inner().unwrap();
        let l1_diff = Digest::sha256(&l1_tar);
        let l1_zst = zrip_encode::compress(&l1_tar, 1).unwrap();

        let mut state = RegistryState::default();
        let (_digest, manifest_bytes) = build_single_arch_manifest_and_config(
            Arch::X86_64,
            &[
                (media_type::OCI_LAYER_TAR_GZIP, &l0_gz, l0_diff),
                (media_type::OCI_LAYER_TAR_ZSTD, &l1_zst, l1_diff),
            ],
            &mut state,
        );
        state.manifests.insert(
            "latest".to_owned(),
            (media_type::OCI_MANIFEST.to_owned(), manifest_bytes),
        );

        let (registry, handle) = MockRegistry::start(state).await;
        let tmp = TempDir::new().unwrap();
        let store = ImageStore::open_directory(tmp.path()).unwrap();
        let reference = ImageReference::parse(&format!(
            "http://{}/demo/hardlink:latest",
            registry.host_port()
        ))
        .unwrap();
        let mut client = RegistryClient::new();
        let pulled = store
            .pull(&mut client, &reference, Arch::X86_64)
            .await
            .unwrap();
        let root = pulled.rootfs_path();

        let busybox_meta = std::fs::symlink_metadata(root.join("usr/bin/busybox")).unwrap();
        let sh_meta = std::fs::symlink_metadata(root.join("opt/sgid/sh")).unwrap();
        assert_eq!(busybox_meta.ino(), sh_meta.ino());
        assert_eq!(busybox_meta.nlink(), 2);

        let sgid_meta = std::fs::symlink_metadata(root.join("opt/sgid")).unwrap();
        assert_eq!(sgid_meta.permissions().mode() & 0o7777, 0o2555);
        let ro_meta = std::fs::symlink_metadata(root.join("opt/ro")).unwrap();
        assert_eq!(ro_meta.permissions().mode() & 0o7777, 0o555);
        assert_eq!(std::fs::read(root.join("top.txt")).unwrap(), b"top-level");
        assert_eq!(
            std::fs::read(root.join("opt/sgid/extra.txt")).unwrap(),
            b"extra"
        );

        registry.shutdown(handle);
    });
}
