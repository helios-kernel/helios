use crate::memory::GuestMemory;
use futures_lite::future::zip;
use helios_api::bindings::wasi::filesystem::{
    preopens,
    types::{Descriptor, DescriptorFlags, OpenFlags, PathFlags},
};

use crate::{
    Error, Result,
    memory::{Memory, TRANSFER},
};

pub struct File {
    descriptor: Descriptor,
    pub size: u64,
}

impl File {
    pub async fn open(path: &str, writable: bool) -> Result<Self> {
        let (root, _) = preopens::get_directories()
            .into_iter()
            .find(|(_, name)| name == "/")
            .ok_or(Error::Root)?;
        let descriptor = root
            .open_at(
                PathFlags::SYMLINK_FOLLOW,
                path.trim_start_matches('/').to_owned(),
                OpenFlags::empty(),
                if writable {
                    DescriptorFlags::READ | DescriptorFlags::WRITE
                } else {
                    DescriptorFlags::READ
                },
            )
            .await?;
        let size = descriptor.stat().await?.size;
        Ok(Self { descriptor, size })
    }

    /// Transfers are bounded independently of the file or RAM size.
    pub async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length > TRANSFER
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > self.size)
        {
            return Err(Error::FileRange(offset, length));
        }
        let (mut stream, completion) = self.descriptor.read_via_stream(offset);
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let (status, next) = stream.read(bytes).await;
            bytes = next;
            if helios_api::stream_closed(status) && bytes.len() < length {
                return Err(Error::ShortRead);
            }
        }
        drop(stream);
        // A bounded read intentionally closes the stream before file EOF.
        // Closing the reader cancels the unused suffix; no file mutation occurs.
        drop(completion);
        Ok(bytes)
    }

    pub async fn load(&self, memory: &Memory, address: u64) -> Result<()> {
        memory.offset(address, self.size)?;
        let (mut stream, completion) = self.descriptor.read_via_stream(0);
        let mut buffer = Vec::with_capacity(TRANSFER);
        let mut offset = 0;
        loop {
            let (status, mut bytes) = stream.read(buffer).await;
            let closed = helios_api::stream_closed(status);
            if offset + bytes.len() as u64 > self.size {
                return Err(Error::FileRange(offset, bytes.len()));
            }
            memory.write(address + offset, &bytes)?;
            offset += bytes.len() as u64;
            bytes.clear();
            buffer = bytes;
            if closed {
                break;
            }
        }
        completion.await?;
        if offset != self.size {
            return Err(Error::ShortRead);
        }
        memory.publish(address, self.size)
    }

    pub async fn write(&self, offset: u64, bytes: Vec<u8>) -> Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(Error::FileRange(offset, bytes.len()));
        }
        let (mut tx, rx) = helios_api::bindings::wit_stream::new();
        let (written, remainder) = zip(
            async { self.descriptor.write_via_stream(rx, offset).await },
            async move {
                let rest = tx.write_all(bytes).await;
                drop(tx);
                rest
            },
        )
        .await;
        written?;
        if !remainder.is_empty() {
            return Err(Error::ShortWrite);
        }
        Ok(())
    }
}
