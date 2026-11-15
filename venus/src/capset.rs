//! Venus capability set version zero (`virgl_renderer_capset_venus`).

use crate::RendererProtocol;
use crate::protocol::EXTENSIONS;

/// `VIRTIO_GPU_CAPSET_VENUS`, from the virtio GPU capability-set table.
pub const ID: u32 = 4;
pub const VERSION: u32 = 0;

/// The version-zero structure has five initial words, 32 extension-mask
/// words, and three capability words (`venus_hw.h`).
const WORDS: usize = 40;
const MASK_WORDS: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapsetError {
    #[error("Venus capset needs {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("Venus renderer speaks wire version {version}; this encoder speaks version 1")]
    WireVersion { version: u32 },
    #[error("Venus renderer does not support {capability}")]
    Missing { capability: &'static str },
}

#[derive(Debug)]
pub struct Capset {
    pub protocol: RendererProtocol,
    pub serialization_version: u32,
    pub venus_version: u32,
    pub allows_wait_syncs: bool,
    pub multiple_timelines: bool,
    pub guest_vram: bool,
}

impl Capset {
    /// Decode the fixed prefix. A newer renderer may append fields; they
    /// do not change the version-zero prefix that this driver consumes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CapsetError> {
        if bytes.len() < WORDS * 4 {
            return Err(CapsetError::Truncated {
                expected: WORDS * 4,
                actual: bytes.len(),
            });
        }
        let words: [u32; WORDS] = core::array::from_fn(|index| {
            u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
        });
        if words[0] != 1 {
            return Err(CapsetError::WireVersion { version: words[0] });
        }
        if words[4] == 0 {
            return Err(CapsetError::Missing {
                capability: "shared blob-id-0 memory",
            });
        }
        let mask = &words[5..5 + MASK_WORDS];
        let protocol = if mask[0] & 1 == 0 {
            RendererProtocol::with_all_extensions(words[1])
        } else {
            let mut protocol = RendererProtocol::without_extensions(words[1]);
            for extension in EXTENSIONS {
                let number = extension.number;
                if mask
                    .get(number as usize / 32)
                    .is_some_and(|word| word & (1 << (number % 32)) != 0)
                {
                    protocol.enable_extension(number);
                }
            }
            protocol
        };
        Ok(Self {
            protocol,
            serialization_version: words[2],
            venus_version: words[3],
            allows_wait_syncs: words[37] != 0,
            multiple_timelines: words[38] != 0,
            guest_vram: words[39] != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_version;

    fn bytes(mask: Option<u32>) -> Vec<u8> {
        let mut words = [0u32; WORDS];
        words[0] = 1;
        words[1] = api_version(1, 3);
        words[2] = 1;
        words[3] = 4;
        words[4] = 1;
        if let Some(number) = mask {
            words[5] = 1;
            words[5 + number as usize / 32] |= 1 << (number % 32);
        }
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }

    #[test]
    fn explicit_mask_enables_only_the_announced_extension() {
        let extension = EXTENSIONS
            .iter()
            .find(|extension| extension.number < 1024)
            .unwrap();
        let capset = Capset::decode(&bytes(Some(extension.number))).unwrap();
        assert_eq!(capset.protocol.api_version(), api_version(1, 3));
        for item in EXTENSIONS {
            assert_eq!(
                capset.protocol.has_extension(item.number),
                item.number == extension.number
            );
        }
    }

    #[test]
    fn unset_mask_marker_means_all_protocol_extensions() {
        let capset = Capset::decode(&bytes(None)).unwrap();
        assert!(
            EXTENSIONS
                .iter()
                .all(|item| capset.protocol.has_extension(item.number))
        );
    }

    #[test]
    fn truncated_or_incompatible_capsets_are_refused() {
        let mut bytes = bytes(None);
        assert!(matches!(
            Capset::decode(&bytes[..bytes.len() - 1]),
            Err(CapsetError::Truncated { .. })
        ));
        bytes[0] = 2;
        assert!(matches!(
            Capset::decode(&bytes),
            Err(CapsetError::WireVersion { version: 2 })
        ));
        bytes[0] = 1;
        bytes[16..20].fill(0);
        assert!(matches!(
            Capset::decode(&bytes),
            Err(CapsetError::Missing { .. })
        ));
    }
}
