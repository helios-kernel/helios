//! Integration test verifying that `helios_oci::OciVmRootfs` layers an ephemeral
//! writable overlay over a pulled read-only OCI image and configures `helios_vmm::MicroVm`
//! over `virtio-fs` alongside pass-through Helios host shares — while keeping `helios-vmm`
//! itself completely free of OCI concepts.

use helios_oci::{
    Arch, Digest, ImageConfig, ImageReference, ImageRuntimeConfig, OciVmRootfs, PulledImage, RootFs,
};
use helios_vmm::virtio::fs::VirtioFsShareConfig;
use helios_vmm::virtio::fs::backend::HostFsBackend;
use helios_vmm::virtio::fs::fuse::{
    FUSE_CREATE, FUSE_INIT, FUSE_LOOKUP, FUSE_OPEN, FUSE_READ, FUSE_ROOT_ID, FUSE_WRITE,
    FuseCreateIn, FuseEntryOut, FuseInHeader, FuseInitIn, FuseOpenIn, FuseOpenOut, FuseOutHeader,
    FuseReadIn, FuseSession, FuseWriteIn,
};
use helios_vmm::{MicroVm, ROOTFS_TAG};
use tempfile::TempDir;
use zerocopy::{FromBytes, IntoBytes};

fn build_req(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
    let len = (40 + body.len()) as u32;
    let hdr = FuseInHeader {
        len: len.to_le(),
        opcode: opcode.to_le(),
        unique: unique.to_le(),
        nodeid: nodeid.to_le(),
        uid: 0,
        gid: 0,
        pid: 1,
        padding: 0,
    };
    let mut buf = Vec::with_capacity(len as usize);
    buf.extend_from_slice(hdr.as_bytes());
    buf.extend_from_slice(body);
    buf
}

fn parse_reply(bytes: &[u8]) -> (FuseOutHeader, &[u8]) {
    let (hdr, rest) = FuseOutHeader::read_from_prefix(bytes).unwrap();
    (hdr, rest)
}

#[test]
fn oci_vm_rootfs_layers_ephemeral_overlay_and_wires_microvm_virtio_fs_shares() {
    futures_lite::future::block_on(async {
        let base_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(base_dir.path().join("etc")).unwrap();
        std::fs::write(
            base_dir.path().join("etc/os-release"),
            "NAME=\"Helios OCI Test 中文 日本語 한국어\"\n",
        )
        .unwrap();

        let host_share_dir = TempDir::new().unwrap();
        std::fs::write(host_share_dir.path().join("host.txt"), b"persistent-host").unwrap();

        let overlay_parent = TempDir::new().unwrap();
        let overlay_dir = overlay_parent.path().join("vm-overlay-1");

        let pulled = PulledImage {
            reference: ImageReference::parse("alpine:3.20").unwrap(),
            manifest_digest: Digest::sha256(b"manifest"),
            arch: Arch::Aarch64,
            config: ImageConfig {
                architecture: "arm64".to_owned(),
                os: "linux".to_owned(),
                config: ImageRuntimeConfig {
                    entrypoint: vec!["/sbin/init".to_owned()],
                    ..ImageRuntimeConfig::default()
                },
                rootfs: RootFs::default(),
            },
            layer_chain_ids: vec![Digest::sha256(b"layer0")],
            rootfs_path: base_dir.path().to_path_buf(),
            btrfs_backed: false,
        };

        let oci_rootfs = OciVmRootfs::prepare_directory(&pulled, &overlay_dir)
            .await
            .expect("prepare ephemeral overlay")
            .with_host_share(
                "workspace",
                host_share_dir.path().to_string_lossy().into_owned(),
                false,
            )
            .expect("attach host share");

        // Configure pure custom `MicroVm::builder()` via the thin user-space adapter.
        let builder = MicroVm::builder()
            .cpus(2)
            .memory_mib(256)
            .unwrap()
            .kernel("/boot/Image");

        #[derive(Debug)]
        enum BuildErr {
            Oci(helios_oci::OciError),
            Vmm(helios_vmm::Error),
        }
        impl core::fmt::Display for BuildErr {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::Oci(e) => write!(f, "oci: {e}"),
                    Self::Vmm(e) => write!(f, "vmm: {e}"),
                }
            }
        }
        impl From<helios_oci::OciError> for BuildErr {
            fn from(err: helios_oci::OciError) -> Self {
                Self::Oci(err)
            }
        }

        let builder = oci_rootfs
            .configure_builder(
                builder,
                |b, rootfs| b.rootfs_dir(rootfs).map_err(BuildErr::Vmm),
                |b, share| {
                    let cfg = VirtioFsShareConfig::new(&share.tag, &share.host_path)
                        .map_err(BuildErr::Vmm)?
                        .read_only(share.read_only);
                    Ok(b.virtio_fs(cfg))
                },
                |b, cmdline| b.cmdline(cmdline),
            )
            .unwrap_or_else(|err| panic!("configure MicroVmBuilder: {err}"));

        let vm = builder.build_vm().expect("build MicroVm");
        assert_eq!(vm.config().fs_shares.len(), 2);
        assert_eq!(vm.config().fs_shares[0].tag, ROOTFS_TAG);
        assert_eq!(
            vm.config().fs_shares[0].host_path,
            overlay_dir.to_string_lossy()
        );
        assert!(!vm.config().fs_shares[0].read_only);
        assert_eq!(vm.config().fs_shares[1].tag, "workspace");
        assert_eq!(
            vm.config().fs_shares[1].host_path,
            host_share_dir.path().to_string_lossy()
        );
        assert!(
            vm.config()
                .cmdline
                .contains("root=rootfs rootfstype=virtiofs rw")
        );
        assert!(vm.config().cmdline.contains("init=/sbin/init"));

        // Drive FUSE directly over the ephemeral OCI rootfs share: writes stay in overlay
        // and NEVER mutate the read-only OCI base layer!
        let backend = HostFsBackend::new(oci_rootfs.rootfs_path(), false).unwrap();
        let mut session = FuseSession::new(backend);
        let init = FuseInitIn {
            major: 7u32.to_le(),
            minor: 36u32.to_le(),
            max_readahead: 4096u32.to_le(),
            flags: 0,
        };
        let _ = session
            .handle_request(&build_req(FUSE_INIT, 1, 0, init.as_bytes()), 64 * 1024)
            .await
            .unwrap();

        let mut create_body = FuseCreateIn {
            flags: 2u32.to_le(),
            mode: 0o644u32.to_le(),
            umask: 0,
            open_flags: 0,
        }
        .as_bytes()
        .to_vec();
        create_body.extend_from_slice(b"ephemeral.txt\0");
        let reply = session
            .handle_request(
                &build_req(FUSE_CREATE, 2, FUSE_ROOT_ID, &create_body),
                64 * 1024,
            )
            .await
            .unwrap();
        let (hdr, body) = parse_reply(&reply);
        assert_eq!(i32::from_le(hdr.error), 0);
        let (entry, rest) = FuseEntryOut::read_from_prefix(body).unwrap();
        let (open_out, _) = FuseOpenOut::read_from_prefix(rest).unwrap();

        let payload = b"ephemeral-vm-write";
        let mut write_body = FuseWriteIn {
            fh: open_out.fh,
            offset: 0,
            size: (payload.len() as u32).to_le(),
            ..FuseWriteIn::default()
        }
        .as_bytes()
        .to_vec();
        write_body.extend_from_slice(payload);
        let reply = session
            .handle_request(
                &build_req(FUSE_WRITE, 3, u64::from_le(entry.nodeid), &write_body),
                64 * 1024,
            )
            .await
            .unwrap();
        assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);

        // Read back from overlay and verify read-only OCI base layer was untouched!
        assert_eq!(
            std::fs::read(overlay_dir.join("ephemeral.txt")).unwrap(),
            payload
        );
        assert!(
            !base_dir.path().join("ephemeral.txt").exists(),
            "read-only OCI image layer must never be mutated by VM writes"
        );

        // Drive FUSE against pass-through Helios host share ("workspace")
        let ws_backend = HostFsBackend::new(&vm.config().fs_shares[1].host_path, false).unwrap();
        let mut ws_session = FuseSession::new(ws_backend);
        let _ = ws_session
            .handle_request(&build_req(FUSE_INIT, 1, 0, init.as_bytes()), 64 * 1024)
            .await
            .unwrap();
        let lookup = ws_session
            .handle_request(
                &build_req(FUSE_LOOKUP, 2, FUSE_ROOT_ID, b"host.txt\0"),
                64 * 1024,
            )
            .await
            .unwrap();
        let (hdr, body) = parse_reply(&lookup);
        assert_eq!(i32::from_le(hdr.error), 0);
        let node = u64::from_le(FuseEntryOut::read_from_prefix(body).unwrap().0.nodeid);
        let opened = ws_session
            .handle_request(
                &build_req(FUSE_OPEN, 3, node, FuseOpenIn::default().as_bytes()),
                64 * 1024,
            )
            .await
            .unwrap();
        let fh = FuseOpenOut::read_from_prefix(parse_reply(&opened).1)
            .unwrap()
            .0
            .fh;
        let read_reply = ws_session
            .handle_request(
                &build_req(
                    FUSE_READ,
                    4,
                    node,
                    FuseReadIn {
                        fh,
                        offset: 0,
                        size: 64u32.to_le(),
                        ..FuseReadIn::default()
                    }
                    .as_bytes(),
                ),
                64 * 1024,
            )
            .await
            .unwrap();
        assert_eq!(parse_reply(&read_reply).1, b"persistent-host");

        // Cleanup drops the ephemeral overlay cleanly while preserving the base OCI layer.
        drop(session);
        drop(oci_rootfs);
        assert!(!overlay_dir.exists());
        assert!(base_dir.path().join("etc/os-release").exists());
    });
}
