//! Virtio 1.2 filesystem device (`VIRTIO_ID_FS = 26`, §5.11) carrying FUSE
//! requests over a hiprio queue (queue 0) and a request queue (queue 1).

pub mod backend;
pub mod fuse;

use helios_api::hv::{GuestMemory, IoWidth};

use super::{Queue, VERSION_1, VirtioMmio, VirtioModel, read_config_bytes};
use crate::boot::VirtioSlot;
use crate::error::{Error, Result};
use backend::FsBackend;
use fuse::FuseSession;

/// Maximum UTF-8 byte length of a `virtio-fs` mount tag (Virtio 1.2 §5.11.4).
pub const MAX_TAG_BYTES: usize = 36;

/// Default mount tag used when booting a directory tree via `--rootfs-dir`.
pub const ROOTFS_TAG: &str = "rootfs";

/// Configuration for one `virtio-fs` shared directory mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioFsShareConfig {
    pub tag: String,
    pub host_path: String,
    pub read_only: bool,
}

impl VirtioFsShareConfig {
    pub fn new(tag: impl Into<String>, host_path: impl Into<String>) -> Result<Self> {
        let tag = tag.into();
        let host_path = host_path.into();
        validate_tag(&tag)?;
        if host_path.is_empty() {
            return Err(Error::Config(
                "virtio-fs host directory path must not be empty",
            ));
        }
        Ok(Self {
            tag,
            host_path,
            read_only: false,
        })
    }

    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
}

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(Error::InvalidShareTag {
            tag: tag.to_owned(),
            reason: "tag must not be empty",
        });
    }
    if tag.len() > MAX_TAG_BYTES {
        return Err(Error::InvalidShareTag {
            tag: tag.to_owned(),
            reason: "tag exceeds 36-byte virtio-fs limit",
        });
    }
    if tag.contains('\0') || tag.contains('/') {
        return Err(Error::InvalidShareTag {
            tag: tag.to_owned(),
            reason: "tag must not contain NUL or '/'",
        });
    }
    Ok(())
}

/// Virtio-fs device model (queue 0 = hiprio, queue 1 = request queue 0).
pub struct FsModel<B: FsBackend> {
    queues: [Queue; 2],
    tag: [u8; MAX_TAG_BYTES],
    tag_name: String,
    session: FuseSession<B>,
}

impl<B: FsBackend> FsModel<B> {
    pub fn new(tag: &str, backend: B) -> Result<Self> {
        validate_tag(tag)?;
        let mut raw_tag = [0u8; MAX_TAG_BYTES];
        raw_tag[..tag.len()].copy_from_slice(tag.as_bytes());
        Ok(Self {
            queues: [Queue::default(), Queue::default()],
            tag: raw_tag,
            tag_name: tag.to_owned(),
            session: FuseSession::new(backend),
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag_name
    }

    pub fn session(&self) -> &FuseSession<B> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut FuseSession<B> {
        &mut self.session
    }
}

impl<B: FsBackend> VirtioModel for FsModel<B> {
    const ID: u32 = 26;
    const FEATURES: u64 = VERSION_1;
    const REQUIRED: u64 = VERSION_1;

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn configuration(&self, offset: u64, width: IoWidth) -> u64 {
        // struct virtio_fs_config { u8 tag[36]; le32 num_request_queues; }
        let mut config = [0u8; 40];
        config[..MAX_TAG_BYTES].copy_from_slice(&self.tag);
        config[MAX_TAG_BYTES..40].copy_from_slice(&1u32.to_le_bytes());
        read_config_bytes(&config, offset, width)
    }

    fn reset(&mut self) {
        for queue in &mut self.queues {
            queue.reset();
        }
        self.session.reset();
    }
}

pub type VirtioFs<B> = VirtioMmio<FsModel<B>>;

impl<B: FsBackend> VirtioFs<B> {
    pub fn fs(slot: VirtioSlot, tag: &str, backend: B) -> Result<Self> {
        Ok(Self::new(slot, FsModel::new(tag, backend)?))
    }

    /// Processes all pending FUSE requests on both the hiprio queue (0) and
    /// the request queue (1).
    pub async fn process_queues(&mut self, memory: &impl GuestMemory) -> Result<()> {
        self.process_queue(memory, 0).await?;
        self.process_queue(memory, 1).await?;
        Ok(())
    }

    /// Processes all pending FUSE requests on a single virtqueue (`0` = hiprio,
    /// `1` = request queue).
    pub async fn process_queue(
        &mut self,
        memory: &impl GuestMemory,
        queue_index: usize,
    ) -> Result<()> {
        if !self.driver_ok() {
            return Ok(());
        }
        if queue_index >= self.model.queues.len() {
            return Err(Error::Virtio("virtio-fs queue index out of range"));
        }
        while let Some(chain) = self.model.queues[queue_index].pop(memory)? {
            let mut request_bytes = Vec::new();
            let mut writable = Vec::new();
            let mut seen_writable = false;
            for desc in chain.descriptors {
                if desc.writable {
                    seen_writable = true;
                    writable.push(desc);
                } else {
                    if seen_writable {
                        return Err(Error::Virtio(
                            "readable descriptor after writable descriptor in virtio-fs chain",
                        ));
                    }
                    let chunk = memory.read_bytes(desc.address, desc.length as usize)?;
                    request_bytes.extend_from_slice(&chunk);
                }
            }

            let used_len = match self.model.session.handle_request(&request_bytes).await {
                None => 0u32,
                Some(reply) => {
                    let mut written = 0usize;
                    for desc in writable {
                        if written >= reply.len() {
                            break;
                        }
                        let take = (desc.length as usize).min(reply.len() - written);
                        memory.write_slice(desc.address, &reply[written..written + take])?;
                        written += take;
                    }
                    if written != reply.len() {
                        return Err(Error::Virtio(
                            "virtio-fs writable descriptor chain shorter than FUSE reply",
                        ));
                    }
                    written as u32
                }
            };

            if self.model.queues[queue_index].complete(memory, chain.head, used_len)? {
                self.interrupt |= 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::DRIVER_OK;
    use super::super::test_support::*;
    use super::backend::*;
    use super::fuse::*;
    use super::*;
    use helios_api::hv::GuestPhysAddr;
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
        assert_eq!(u32::from_le(hdr.len) as usize, bytes.len());
        (hdr, rest)
    }

    #[test]
    fn virtio_fs_config_space_and_virtqueue_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"from-host").unwrap();
        let backend = HostFsBackend::new(dir.path(), false).unwrap();
        let mut dev = VirtioFs::fs(VirtioSlot::at(4).unwrap(), "rootfs", backend).unwrap();

        // Check tag bytes and num_request_queues in config space.
        let mut tag_bytes = [0u8; 6];
        for (i, slot) in tag_bytes.iter_mut().enumerate() {
            *slot = dev.model.configuration(0x100 + i as u64, IoWidth::Byte) as u8;
        }
        assert_eq!(&tag_bytes, b"rootfs");
        assert_eq!(dev.model.configuration(0x106, IoWidth::Byte), 0);
        assert_eq!(dev.model.configuration(0x124, IoWidth::Dword), 1);

        // Drive FUSE_INIT and FUSE_LOOKUP through split virtqueue 1.
        let ram = test_ram(16 * 1024);
        dev.status = DRIVER_OK;
        dev.model.queues[0] = enable_queue(&ram, 0, 8);
        dev.model.queues[1] = enable_queue(&ram, 512, 8);

        let init_in = FuseInitIn {
            major: 7u32.to_le(),
            minor: 36u32.to_le(),
            max_readahead: 65536u32.to_le(),
            flags: (FUSE_DO_READDIRPLUS | FUSE_BIG_WRITES).to_le(),
        };
        let req = build_req(FUSE_INIT, 1, 0, init_in.as_bytes());
        ram.write_slice(GuestPhysAddr::new(4096), &req).unwrap();
        write_desc(&ram, &dev.model.queues[1], 0, 4096, req.len() as u32, 1, 1);
        write_desc(&ram, &dev.model.queues[1], 1, 8192, 512, 2, 0);
        push_avail(&ram, &dev.model.queues[1], 0, 0);

        futures_lite::future::block_on(dev.process_queue(&ram, 1)).unwrap();
        let used = used_len(&ram, &dev.model.queues[1], 0) as usize;
        let reply = ram.read_bytes(GuestPhysAddr::new(8192), used).unwrap();
        let (hdr, body) = parse_reply(&reply);
        assert_eq!(i32::from_le(hdr.error), 0);
        assert_eq!(u64::from_le(hdr.unique), 1);
        let (init_out, _) = FuseInitOut::read_from_prefix(body).unwrap();
        assert_eq!(u32::from_le(init_out.major), 7);
        assert_eq!(u32::from_le(init_out.minor), FUSE_KERNEL_MINOR_VERSION);
        assert_ne!(u32::from_le(init_out.flags) & FUSE_DO_READDIRPLUS, 0);
    }

    #[test]
    fn fuse_full_lifecycle_cjk_and_confinement() {
        let outside = tempfile::tempdir().unwrap();
        let secret_file = outside.path().join("secret.txt");
        std::fs::write(&secret_file, b"top-secret").unwrap();

        let dir = tempfile::tempdir().unwrap();
        // Plant a symlink inside share root pointing outside — must be blocked on open!
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret_file, dir.path().join("escape_link")).unwrap();

        let backend = HostFsBackend::new(dir.path(), false).unwrap();
        let mut session = FuseSession::new(backend);

        futures_lite::future::block_on(async {
            // 1. INIT
            let init_in = FuseInitIn {
                major: 7u32.to_le(),
                minor: 31u32.to_le(),
                max_readahead: 4096u32.to_le(),
                flags: FUSE_DO_READDIRPLUS.to_le(),
            };
            let reply = session
                .handle_request(&build_req(FUSE_INIT, 1, 0, init_in.as_bytes()))
                .await
                .unwrap();
            let (hdr, _) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);

            // 2. GETATTR on root
            let getattr_in = FuseGetattrIn::default();
            let reply = session
                .handle_request(&build_req(
                    FUSE_GETATTR,
                    2,
                    FUSE_ROOT_ID,
                    getattr_in.as_bytes(),
                ))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (attr_out, _) = FuseAttrOut::read_from_prefix(body).unwrap();
            assert_eq!(u32::from_le(attr_out.attr.mode) & S_IFMT, S_IFDIR);

            // 3. Confinement: path traversal attempts rejected with -EINVAL, symlink escape rejected with -EACCES
            for bad in ["..", ".", "a/b", "../secret.txt", ""] {
                let mut name = bad.as_bytes().to_vec();
                name.push(0);
                let reply = session
                    .handle_request(&build_req(FUSE_LOOKUP, 3, FUSE_ROOT_ID, &name))
                    .await
                    .unwrap();
                let (hdr, _) = parse_reply(&reply);
                assert_eq!(
                    i32::from_le(hdr.error),
                    -EINVAL,
                    "expected EINVAL for {bad:?}"
                );
            }
            #[cfg(unix)]
            {
                let reply = session
                    .handle_request(&build_req(FUSE_LOOKUP, 4, FUSE_ROOT_ID, b"escape_link\0"))
                    .await
                    .unwrap();
                let (hdr, body) = parse_reply(&reply);
                assert_eq!(i32::from_le(hdr.error), 0);
                let (entry, _) = FuseEntryOut::read_from_prefix(body).unwrap();
                let link_node = u64::from_le(entry.nodeid);
                let open_in = FuseOpenIn {
                    flags: 0,
                    open_flags: 0,
                };
                let reply = session
                    .handle_request(&build_req(FUSE_OPEN, 5, link_node, open_in.as_bytes()))
                    .await
                    .unwrap();
                let (hdr, _) = parse_reply(&reply);
                assert_eq!(i32::from_le(hdr.error), -EACCES);
            }

            // 4. MKDIR with CJK (Chinese, Japanese, Korean) directory name
            let cjk_dir = "目录_テスト_테스트";
            let mut mkdir_body = FuseMkdirIn {
                mode: 0o755u32.to_le(),
                umask: 0,
            }
            .as_bytes()
            .to_vec();
            mkdir_body.extend_from_slice(cjk_dir.as_bytes());
            mkdir_body.push(0);
            let reply = session
                .handle_request(&build_req(FUSE_MKDIR, 10, FUSE_ROOT_ID, &mkdir_body))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (dir_entry, _) = FuseEntryOut::read_from_prefix(body).unwrap();
            let sub_node = u64::from_le(dir_entry.nodeid);
            assert!(dir.path().join(cjk_dir).is_dir());

            // 5. CREATE + WRITE + FLUSH + READ + SETATTR(truncate) + RELEASE with CJK filename
            let cjk_file = "文件_ファイル_파일.txt";
            let mut create_body = FuseCreateIn {
                flags: 2u32.to_le(), // O_RDWR
                mode: 0o644u32.to_le(),
                umask: 0,
                open_flags: 0,
            }
            .as_bytes()
            .to_vec();
            create_body.extend_from_slice(cjk_file.as_bytes());
            create_body.push(0);
            let reply = session
                .handle_request(&build_req(FUSE_CREATE, 11, sub_node, &create_body))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (file_entry, rest) = FuseEntryOut::read_from_prefix(body).unwrap();
            let (open_out, _) = FuseOpenOut::read_from_prefix(rest).unwrap();
            let file_node = u64::from_le(file_entry.nodeid);
            let fh = u64::from_le(open_out.fh);

            // WRITE
            let payload = "你好世界・こんにちは・안녕하세요".as_bytes();
            let mut write_body = FuseWriteIn {
                fh: fh.to_le(),
                offset: 0,
                size: (payload.len() as u32).to_le(),
                ..FuseWriteIn::default()
            }
            .as_bytes()
            .to_vec();
            write_body.extend_from_slice(payload);
            let reply = session
                .handle_request(&build_req(FUSE_WRITE, 12, file_node, &write_body))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (write_out, _) = FuseWriteOut::read_from_prefix(body).unwrap();
            assert_eq!(u32::from_le(write_out.size) as usize, payload.len());

            // FLUSH
            let flush_in = FuseFlushIn {
                fh: fh.to_le(),
                ..FuseFlushIn::default()
            };
            let reply = session
                .handle_request(&build_req(FUSE_FLUSH, 13, file_node, flush_in.as_bytes()))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);

            // READ back
            let read_in = FuseReadIn {
                fh: fh.to_le(),
                offset: 0,
                size: 256u32.to_le(),
                ..FuseReadIn::default()
            };
            let reply = session
                .handle_request(&build_req(FUSE_READ, 14, file_node, read_in.as_bytes()))
                .await
                .unwrap();
            let (hdr, data) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            assert_eq!(data, payload);

            // SETATTR truncate to 6 bytes ("你好")
            let setattr_in = FuseSetattrIn {
                valid: (FATTR_SIZE | FATTR_FH).to_le(),
                fh: fh.to_le(),
                size: 6u64.to_le(),
                ..FuseSetattrIn::default()
            };
            let reply = session
                .handle_request(&build_req(
                    FUSE_SETATTR,
                    15,
                    file_node,
                    setattr_in.as_bytes(),
                ))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (attr, _) = FuseAttrOut::read_from_prefix(body).unwrap();
            assert_eq!(u64::from_le(attr.attr.size), 6);

            // RELEASE
            let release_in = FuseReleaseIn {
                fh: fh.to_le(),
                ..FuseReleaseIn::default()
            };
            let reply = session
                .handle_request(&build_req(
                    FUSE_RELEASE,
                    16,
                    file_node,
                    release_in.as_bytes(),
                ))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);

            // Verify persistence directly on host filesystem
            assert_eq!(
                std::fs::read(dir.path().join(cjk_dir).join(cjk_file)).unwrap(),
                "你好".as_bytes()
            );

            // 6. OPENDIR + READDIR + READDIRPLUS + RELEASEDIR
            let open_in = FuseOpenIn::default();
            let reply = session
                .handle_request(&build_req(FUSE_OPENDIR, 17, sub_node, open_in.as_bytes()))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let dir_fh = u64::from_le(FuseOpenOut::read_from_prefix(body).unwrap().0.fh);

            // READDIR with pagination (small buffer)
            let mut names = Vec::new();
            let mut offset = 0u64;
            loop {
                let rd = FuseReadIn {
                    fh: dir_fh.to_le(),
                    offset: offset.to_le(),
                    size: 64u32.to_le(),
                    ..FuseReadIn::default()
                };
                let reply = session
                    .handle_request(&build_req(FUSE_READDIR, 18, sub_node, rd.as_bytes()))
                    .await
                    .unwrap();
                let (hdr, mut buf) = parse_reply(&reply);
                assert_eq!(i32::from_le(hdr.error), 0);
                if buf.is_empty() {
                    break;
                }
                while !buf.is_empty() {
                    let (de, rest) = FuseDirent::read_from_prefix(buf).unwrap();
                    let nlen = u32::from_le(de.namelen) as usize;
                    names.push(core::str::from_utf8(&rest[..nlen]).unwrap().to_owned());
                    offset = u64::from_le(de.off);
                    let padded = (24 + nlen + 7) & !7;
                    buf = &buf[padded..];
                }
            }
            assert_eq!(names, vec![".", "..", cjk_file]);

            // READDIRPLUS from offset 0
            let rd_plus = FuseReadIn {
                fh: dir_fh.to_le(),
                offset: 0,
                size: 4096u32.to_le(),
                ..FuseReadIn::default()
            };
            let reply = session
                .handle_request(&build_req(
                    FUSE_READDIRPLUS,
                    19,
                    sub_node,
                    rd_plus.as_bytes(),
                ))
                .await
                .unwrap();
            let (hdr, mut buf) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let mut plus_entries = Vec::new();
            while !buf.is_empty() {
                let (ent, rest) = FuseEntryOut::read_from_prefix(buf).unwrap();
                let (de, rest) = FuseDirent::read_from_prefix(rest).unwrap();
                let nlen = u32::from_le(de.namelen) as usize;
                let name = core::str::from_utf8(&rest[..nlen]).unwrap().to_owned();
                plus_entries.push((name, u64::from_le(ent.nodeid)));
                let padded = (128 + 24 + nlen + 7) & !7;
                buf = &buf[padded..];
            }
            assert_eq!(plus_entries[0], (".".to_owned(), 0));
            assert_eq!(plus_entries[1], ("..".to_owned(), 0));
            assert_eq!(plus_entries[2], (cjk_file.to_owned(), file_node));

            let rel_dir = FuseReleaseIn {
                fh: dir_fh.to_le(),
                ..FuseReleaseIn::default()
            };
            let reply = session
                .handle_request(&build_req(
                    FUSE_RELEASEDIR,
                    20,
                    sub_node,
                    rel_dir.as_bytes(),
                ))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);

            // 7. RENAME file into root
            let mut rename_body = FuseRenameIn {
                newdir: FUSE_ROOT_ID.to_le(),
            }
            .as_bytes()
            .to_vec();
            rename_body.extend_from_slice(cjk_file.as_bytes());
            rename_body.push(0);
            rename_body.extend_from_slice(b"moved.txt\0");
            let reply = session
                .handle_request(&build_req(FUSE_RENAME, 21, sub_node, &rename_body))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);
            assert!(dir.path().join("moved.txt").is_file());

            // OPEN renamed inode by existing nodeid works because path table updated!
            let open_rd = FuseOpenIn {
                flags: 0,
                open_flags: 0,
            };
            let reply = session
                .handle_request(&build_req(FUSE_OPEN, 22, file_node, open_rd.as_bytes()))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let moved_fh = u64::from_le(FuseOpenOut::read_from_prefix(body).unwrap().0.fh);
            let reply = session
                .handle_request(&build_req(
                    FUSE_RELEASE,
                    23,
                    file_node,
                    FuseReleaseIn {
                        fh: moved_fh.to_le(),
                        ..FuseReleaseIn::default()
                    }
                    .as_bytes(),
                ))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);

            // 8. UNLINK + RMDIR
            let reply = session
                .handle_request(&build_req(FUSE_UNLINK, 24, FUSE_ROOT_ID, b"moved.txt\0"))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);
            assert!(!dir.path().join("moved.txt").exists());

            let mut rmdir_name = cjk_dir.as_bytes().to_vec();
            rmdir_name.push(0);
            let reply = session
                .handle_request(&build_req(FUSE_RMDIR, 25, FUSE_ROOT_ID, &rmdir_name))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), 0);
            assert!(!dir.path().join(cjk_dir).exists());

            // 9. FORGET evicts forgotten inodes (file_node had 2 lookups: CREATE + READDIRPLUS)
            let before = session.inode_count();
            assert!(
                session
                    .handle_request(&build_req(
                        FUSE_FORGET,
                        26,
                        file_node,
                        FuseForgetIn {
                            nlookup: 2u64.to_le()
                        }
                        .as_bytes(),
                    ))
                    .await
                    .is_none()
            );
            assert!(
                session
                    .handle_request(&build_req(
                        FUSE_FORGET,
                        27,
                        sub_node,
                        FuseForgetIn {
                            nlookup: 1u64.to_le()
                        }
                        .as_bytes(),
                    ))
                    .await
                    .is_none()
            );
            assert_eq!(session.inode_count(), before - 2);

            // 10. STATFS
            let reply = session
                .handle_request(&build_req(FUSE_STATFS, 28, FUSE_ROOT_ID, &[]))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let (st, _) = FuseKstatfs::read_from_prefix(body).unwrap();
            assert_eq!(u32::from_le(st.bsize), 4096);
            assert_eq!(u32::from_le(st.namelen), 255);
            assert!(u64::from_le(st.blocks) > 0);
        });
    }

    #[test]
    fn fuse_read_only_rename2_symlink_and_batch_forget() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"beta").unwrap();

        // Read-only share rejects mutations with -EROFS while permitting reads.
        let ro = HostFsBackend::new(dir.path(), true).unwrap();
        let mut ro_session = FuseSession::new(ro);
        futures_lite::future::block_on(async {
            let reply = ro_session
                .handle_request(&build_req(FUSE_LOOKUP, 1, FUSE_ROOT_ID, b"a.txt\0"))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let a_node = u64::from_le(FuseEntryOut::read_from_prefix(body).unwrap().0.nodeid);

            let open_wr = FuseOpenIn {
                flags: 1u32.to_le(), // O_WRONLY
                open_flags: 0,
            };
            let reply = ro_session
                .handle_request(&build_req(FUSE_OPEN, 2, a_node, open_wr.as_bytes()))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), -EROFS);

            let reply = ro_session
                .handle_request(&build_req(FUSE_UNLINK, 3, FUSE_ROOT_ID, b"a.txt\0"))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), -EROFS);
        });

        // Writable share: RENAME2(RENAME_NOREPLACE), SYMLINK/READLINK, BATCH_FORGET.
        let rw = HostFsBackend::new(dir.path(), false).unwrap();
        let mut session = FuseSession::new(rw);
        futures_lite::future::block_on(async {
            let a_reply = session
                .handle_request(&build_req(FUSE_LOOKUP, 1, FUSE_ROOT_ID, b"a.txt\0"))
                .await
                .unwrap();
            let a_node = u64::from_le(
                FuseEntryOut::read_from_prefix(parse_reply(&a_reply).1)
                    .unwrap()
                    .0
                    .nodeid,
            );
            let b_reply = session
                .handle_request(&build_req(FUSE_LOOKUP, 2, FUSE_ROOT_ID, b"b.txt\0"))
                .await
                .unwrap();
            let b_node = u64::from_le(
                FuseEntryOut::read_from_prefix(parse_reply(&b_reply).1)
                    .unwrap()
                    .0
                    .nodeid,
            );

            // RENAME2 with RENAME_NOREPLACE onto existing b.txt fails with -EEXIST.
            let mut r2 = FuseRename2In {
                newdir: FUSE_ROOT_ID.to_le(),
                flags: 1u32.to_le(), // RENAME_NOREPLACE
                padding: 0,
            }
            .as_bytes()
            .to_vec();
            r2.extend_from_slice(b"a.txt\0b.txt\0");
            let reply = session
                .handle_request(&build_req(FUSE_RENAME2, 3, FUSE_ROOT_ID, &r2))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), -EEXIST);

            // Absolute symlink target rejected with -EPERM; relative symlink + READLINK succeeds.
            let reply = session
                .handle_request(&build_req(
                    FUSE_SYMLINK,
                    4,
                    FUSE_ROOT_ID,
                    b"bad_link\0/etc/passwd\0",
                ))
                .await
                .unwrap();
            assert_eq!(i32::from_le(parse_reply(&reply).0.error), -EPERM);

            let reply = session
                .handle_request(&build_req(
                    FUSE_SYMLINK,
                    5,
                    FUSE_ROOT_ID,
                    b"good_link\0a.txt\0",
                ))
                .await
                .unwrap();
            let (hdr, body) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            let link_node = u64::from_le(FuseEntryOut::read_from_prefix(body).unwrap().0.nodeid);

            let reply = session
                .handle_request(&build_req(FUSE_READLINK, 6, link_node, &[]))
                .await
                .unwrap();
            let (hdr, target) = parse_reply(&reply);
            assert_eq!(i32::from_le(hdr.error), 0);
            assert_eq!(target, b"a.txt");

            // BATCH_FORGET evicts all three non-root inodes.
            let mut batch = FuseBatchForgetIn {
                count: 3u32.to_le(),
                dummy: 0,
            }
            .as_bytes()
            .to_vec();
            for id in [a_node, b_node, link_node] {
                batch.extend_from_slice(
                    FuseForgetOne {
                        nodeid: id.to_le(),
                        nlookup: 1u64.to_le(),
                    }
                    .as_bytes(),
                );
            }
            assert!(
                session
                    .handle_request(&build_req(FUSE_BATCH_FORGET, 7, 0, &batch))
                    .await
                    .is_none()
            );
            assert_eq!(session.inode_count(), 1); // only root remains
        });
    }
}
