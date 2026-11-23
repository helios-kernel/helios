//! A minimal RFB client that reads one frame of the guest's console.
//!
//! QEMU's QMP `screendump` refuses a console whose scanout is a GL or
//! dma-buf scanout (`no surface`), which is what a Venus session draws
//! into. QEMU's VNC server is fed from the console's 2D surface under
//! every display backend, `egl-headless` copying each GL frame into it,
//! so the inspector reads the screen over a VNC unix socket instead.
//!
//! Only what a capture needs is spoken, per RFC 6143: the RFB 3.8
//! handshake with security type None, a Raw-encoded full-screen
//! framebuffer update (plus the DesktopSize pseudo-encoding, so a guest
//! mode change during the capture is followed), and nothing of the input
//! side.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// How long one read or write on the VNC socket waits.
///
/// A framebuffer update of a large console is a few megabytes the server
/// has to produce first; the bound is for a server that has stopped
/// answering, so that the session says so rather than hanging.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// The ProtocolVersion this client speaks (RFC 6143 section 7.1.1).
const CLIENT_VERSION: &[u8; 12] = b"RFB 003.008\n";
/// The oldest ProtocolVersion a server may offer: the security
/// negotiation and the SecurityResult reason string this client reads
/// are those of 3.8 (RFC 6143 section 7.1.1, 7.1.3).
const MINIMUM_SERVER_VERSION: (u16, u16) = (3, 8);
/// Security type None (RFC 6143 section 7.1.2).
const SECURITY_NONE: u8 = 1;
/// SecurityResult OK (RFC 6143 section 7.1.3).
const SECURITY_RESULT_OK: u32 = 0;
/// ClientInit shared-flag: leave other clients connected (RFC 6143
/// section 7.3.1).
const CLIENT_INIT_SHARED: u8 = 1;

/// Client-to-server message types (RFC 6143 section 7.5).
const SET_PIXEL_FORMAT: u8 = 0;
const SET_ENCODINGS: u8 = 2;
const FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;

/// Server-to-client message types (RFC 6143 section 7.6).
const FRAMEBUFFER_UPDATE: u8 = 0;
const BELL: u8 = 2;
const SERVER_CUT_TEXT: u8 = 3;

/// Raw encoding (RFC 6143 section 7.7.1).
const ENCODING_RAW: i32 = 0;
/// DesktopSize pseudo-encoding (RFC 6143 section 7.8.2).
const ENCODING_DESKTOP_SIZE: i32 = -223;

/// The pixel format every capture asks for (RFC 6143 section 7.4):
/// 32 bits per pixel, depth 24, little-endian, true colour, 8 bits per
/// channel, red at bit 16, green at bit 8 and blue at bit 0. A pixel is
/// then the bytes blue, green, red, padding.
const PIXEL_FORMAT: [u8; 16] = [
    32, 24, 0, 1, // bits-per-pixel, depth, big-endian flag, true-colour flag
    0, 255, 0, 255, 0, 255, // red-max, green-max, blue-max, each a u16
    16, 8, 0, // red-shift, green-shift, blue-shift
    0, 0, 0, // padding
];
/// Bytes one pixel takes in [`PIXEL_FORMAT`].
const BYTES_PER_PIXEL: usize = 4;

/// Why a frame could not be read from the VNC server, or written out.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VncError {
    #[error("failed to connect to the VNC socket {socket}: {source}")]
    Connect {
        socket: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to set the {which} timeout of the VNC socket: {source}")]
    Timeout {
        which: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to read the {what} from the VNC server: {source}")]
    Read {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to send the {what} to the VNC server: {source}")]
    Write {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("the VNC server opened with {greeting:?} instead of an RFB ProtocolVersion")]
    MalformedVersion { greeting: String },
    #[error(
        "the VNC server offers {offered:?}; this client needs RFB {}.{} or newer",
        MINIMUM_SERVER_VERSION.0,
        MINIMUM_SERVER_VERSION.1
    )]
    UnsupportedVersion { offered: String },
    #[error("the VNC server refused the connection: {reason}")]
    ConnectionRefused { reason: String },
    #[error("the VNC server offers security types {offered:?} and none of them is None (1)")]
    NoSecurityNone { offered: Vec<u8> },
    #[error("the VNC server failed the security handshake: {reason}")]
    SecurityFailed { reason: String },
    #[error("the VNC server sent message type {message_type}, which this client does not handle")]
    UnexpectedMessage { message_type: u8 },
    #[error(
        "the VNC server sent a rectangle with encoding {encoding}, which this client did not ask for"
    )]
    UnsupportedEncoding { encoding: i32 },
    #[error(
        "the VNC server sent a {width}x{height} rectangle at ({x}, {y}) outside its \
         {frame_width}x{frame_height} framebuffer"
    )]
    RectangleOutOfBounds {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        frame_width: u16,
        frame_height: u16,
    },
    #[error("failed to encode the {width}x{height} capture as a PNG: {source}")]
    EncodePng {
        width: u16,
        height: u16,
        #[source]
        source: png::EncodingError,
    },
    #[error("failed to write the capture {path}: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// One captured frame: 8-bit RGB, row-major, no padding.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    width: u16,
    height: u16,
    rgb: Vec<u8>,
    /// Which pixels a Raw rectangle has written since the frame was
    /// allocated.
    covered: Vec<bool>,
    covered_count: usize,
}

impl Frame {
    fn blank(width: u16, height: u16) -> Self {
        let pixels = usize::from(width) * usize::from(height);
        Self {
            width,
            height,
            rgb: vec![0; pixels * 3],
            covered: vec![false; pixels],
            covered_count: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.covered_count == self.covered.len()
    }

    /// Stores a Raw rectangle in [`PIXEL_FORMAT`].
    fn paint(&mut self, rectangle: &Rectangle, pixels: &[u8]) -> Result<(), VncError> {
        let right = u32::from(rectangle.x) + u32::from(rectangle.width);
        let bottom = u32::from(rectangle.y) + u32::from(rectangle.height);
        if right > u32::from(self.width) || bottom > u32::from(self.height) {
            return Err(VncError::RectangleOutOfBounds {
                x: rectangle.x,
                y: rectangle.y,
                width: rectangle.width,
                height: rectangle.height,
                frame_width: self.width,
                frame_height: self.height,
            });
        }
        let frame_width = usize::from(self.width);
        let rectangle_width = usize::from(rectangle.width);
        for row in 0..usize::from(rectangle.height) {
            let source = &pixels[row * rectangle_width * BYTES_PER_PIXEL..]
                [..rectangle_width * BYTES_PER_PIXEL];
            let first = (usize::from(rectangle.y) + row) * frame_width + usize::from(rectangle.x);
            for (column, pixel) in source.as_chunks::<BYTES_PER_PIXEL>().0.iter().enumerate() {
                let index = first + column;
                // Bytes are blue, green, red, padding.
                self.rgb[index * 3..][..3].copy_from_slice(&[pixel[2], pixel[1], pixel[0]]);
                if !self.covered[index] {
                    self.covered[index] = true;
                    self.covered_count += 1;
                }
            }
        }
        Ok(())
    }
}

/// The header of one rectangle of a FramebufferUpdate (RFC 6143
/// section 7.6.1).
struct Rectangle {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    encoding: i32,
}

/// Reads the current screen of the VNC server on `socket` and writes it
/// to `path` as an 8-bit RGB PNG.
///
/// Each call is its own connection and its own non-incremental request,
/// so the file shows the screen as it is when the call is made.
pub(crate) fn capture(socket: &Path, path: &Path) -> Result<(), VncError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| VncError::Connect {
        socket: socket.display().to_string(),
        source,
    })?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|source| VncError::Timeout {
            which: "read",
            source,
        })?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|source| VncError::Timeout {
            which: "write",
            source,
        })?;
    let frame = read_frame(&mut stream)?;
    let png = encode_png(&frame)?;
    fs::write(path, png).map_err(|source| VncError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

fn encode_png(frame: &Frame) -> Result<Vec<u8>, VncError> {
    let fail = |source| VncError::EncodePng {
        width: frame.width,
        height: frame.height,
        source,
    };
    let mut encoded = Vec::new();
    let mut encoder = png::Encoder::new(
        &mut encoded,
        u32::from(frame.width),
        u32::from(frame.height),
    );
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(fail)?;
    writer.write_image_data(&frame.rgb).map_err(fail)?;
    writer.finish().map_err(fail)?;
    Ok(encoded)
}

/// Runs the handshake on `stream` and reads one complete frame.
fn read_frame<S: Read + Write>(stream: &mut S) -> Result<Frame, VncError> {
    handshake(stream)?;
    let width = read_u16(stream, "framebuffer width")?;
    let height = read_u16(stream, "framebuffer height")?;
    // The server's own pixel format and the desktop name are not used:
    // SetPixelFormat replaces the former.
    read_bytes(stream, 16, "server pixel format")?;
    let name_length = read_u32(stream, "desktop name length")?;
    read_text(stream, name_length, "desktop name")?;

    let mut message = vec![SET_PIXEL_FORMAT, 0, 0, 0];
    message.extend_from_slice(&PIXEL_FORMAT);
    write_all(stream, &message, "SetPixelFormat")?;

    let encodings = [ENCODING_RAW, ENCODING_DESKTOP_SIZE];
    let mut message = vec![SET_ENCODINGS, 0];
    message.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for encoding in encodings {
        message.extend_from_slice(&encoding.to_be_bytes());
    }
    write_all(stream, &message, "SetEncodings")?;

    let mut frame = Frame::blank(width, height);
    request_update(stream, &frame)?;
    while !frame.is_complete() {
        let message_type = read_u8(stream, "server message type")?;
        match message_type {
            FRAMEBUFFER_UPDATE => {
                let resized = read_update(stream, &mut frame)?;
                if resized && !frame.is_complete() {
                    request_update(stream, &frame)?;
                }
            }
            // Bell carries nothing (RFC 6143 section 7.6.3).
            BELL => {}
            // ServerCutText: padding, then a length-prefixed text
            // (RFC 6143 section 7.6.4).
            SERVER_CUT_TEXT => {
                read_bytes(stream, 3, "ServerCutText padding")?;
                let length = read_u32(stream, "ServerCutText length")?;
                read_text(stream, length, "ServerCutText text")?;
            }
            message_type => return Err(VncError::UnexpectedMessage { message_type }),
        }
    }
    Ok(frame)
}

/// RFB 3.8 version exchange, security type None, ClientInit
/// (RFC 6143 sections 7.1 and 7.3.1).
fn handshake<S: Read + Write>(stream: &mut S) -> Result<(), VncError> {
    let greeting = read_bytes(stream, CLIENT_VERSION.len(), "ProtocolVersion")?;
    let offered = String::from_utf8_lossy(&greeting).trim_end().to_owned();
    let version = parse_version(&greeting).ok_or(VncError::MalformedVersion {
        greeting: offered.clone(),
    })?;
    if version < MINIMUM_SERVER_VERSION {
        return Err(VncError::UnsupportedVersion { offered });
    }
    write_all(stream, CLIENT_VERSION, "ProtocolVersion")?;

    let count = read_u8(stream, "security type count")?;
    if count == 0 {
        let length = read_u32(stream, "refusal reason length")?;
        let reason = read_text(stream, length, "refusal reason")?;
        return Err(VncError::ConnectionRefused { reason });
    }
    let offered = read_bytes(stream, usize::from(count), "security types")?;
    if !offered.contains(&SECURITY_NONE) {
        return Err(VncError::NoSecurityNone { offered });
    }
    write_all(stream, &[SECURITY_NONE], "security type")?;
    let result = read_u32(stream, "SecurityResult")?;
    if result != SECURITY_RESULT_OK {
        let length = read_u32(stream, "SecurityResult reason length")?;
        let reason = read_text(stream, length, "SecurityResult reason")?;
        return Err(VncError::SecurityFailed { reason });
    }
    write_all(stream, &[CLIENT_INIT_SHARED], "ClientInit")
}

/// The `(major, minor)` of an `RFB xxx.yyy\n` ProtocolVersion.
fn parse_version(greeting: &[u8]) -> Option<(u16, u16)> {
    let text = core::str::from_utf8(greeting).ok()?;
    let (major, minor) = text
        .strip_prefix("RFB ")?
        .strip_suffix('\n')?
        .split_once('.')?;
    if major.len() != 3 || minor.len() != 3 {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// A non-incremental FramebufferUpdateRequest for the whole frame
/// (RFC 6143 section 7.5.3).
fn request_update<S: Write>(stream: &mut S, frame: &Frame) -> Result<(), VncError> {
    let mut message = vec![FRAMEBUFFER_UPDATE_REQUEST, 0, 0, 0, 0, 0];
    message.extend_from_slice(&frame.width.to_be_bytes());
    message.extend_from_slice(&frame.height.to_be_bytes());
    write_all(stream, &message, "FramebufferUpdateRequest")
}

/// Reads the rectangles of one FramebufferUpdate into `frame`, and says
/// whether one of them resized it (RFC 6143 section 7.6.1).
fn read_update<S: Read>(stream: &mut S, frame: &mut Frame) -> Result<bool, VncError> {
    read_bytes(stream, 1, "FramebufferUpdate padding")?;
    let rectangles = read_u16(stream, "FramebufferUpdate rectangle count")?;
    let mut resized = false;
    for _ in 0..rectangles {
        let rectangle = Rectangle {
            x: read_u16(stream, "rectangle x")?,
            y: read_u16(stream, "rectangle y")?,
            width: read_u16(stream, "rectangle width")?,
            height: read_u16(stream, "rectangle height")?,
            encoding: read_i32(stream, "rectangle encoding")?,
        };
        match rectangle.encoding {
            ENCODING_RAW => {
                let length =
                    usize::from(rectangle.width) * usize::from(rectangle.height) * BYTES_PER_PIXEL;
                let pixels = read_bytes(stream, length, "Raw rectangle")?;
                frame.paint(&rectangle, &pixels)?;
            }
            // The rectangle's width and height are the new size, and it
            // has no payload (RFC 6143 section 7.8.2).
            ENCODING_DESKTOP_SIZE => {
                *frame = Frame::blank(rectangle.width, rectangle.height);
                resized = true;
            }
            encoding => return Err(VncError::UnsupportedEncoding { encoding }),
        }
    }
    Ok(resized)
}

fn write_all<S: Write>(stream: &mut S, bytes: &[u8], what: &'static str) -> Result<(), VncError> {
    stream
        .write_all(bytes)
        .and_then(|()| stream.flush())
        .map_err(|source| VncError::Write { what, source })
}

/// Reads exactly `length` bytes, allocating only as they arrive, so a
/// length the server made up costs nothing until the bytes are there.
fn read_bytes<S: Read>(
    stream: &mut S,
    length: usize,
    what: &'static str,
) -> Result<Vec<u8>, VncError> {
    let mut bytes = Vec::new();
    stream
        .take(length as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| VncError::Read { what, source })?;
    if bytes.len() != length {
        return Err(VncError::Read {
            what,
            source: io::ErrorKind::UnexpectedEof.into(),
        });
    }
    Ok(bytes)
}

fn read_text<S: Read>(stream: &mut S, length: u32, what: &'static str) -> Result<String, VncError> {
    let bytes = read_bytes(stream, length as usize, what)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_array<S: Read, const N: usize>(
    stream: &mut S,
    what: &'static str,
) -> Result<[u8; N], VncError> {
    let mut bytes = [0; N];
    stream
        .read_exact(&mut bytes)
        .map_err(|source| VncError::Read { what, source })?;
    Ok(bytes)
}

fn read_u8<S: Read>(stream: &mut S, what: &'static str) -> Result<u8, VncError> {
    Ok(read_array::<_, 1>(stream, what)?[0])
}

fn read_u16<S: Read>(stream: &mut S, what: &'static str) -> Result<u16, VncError> {
    Ok(u16::from_be_bytes(read_array(stream, what)?))
}

fn read_u32<S: Read>(stream: &mut S, what: &'static str) -> Result<u32, VncError> {
    Ok(u32::from_be_bytes(read_array(stream, what)?))
}

fn read_i32<S: Read>(stream: &mut S, what: &'static str) -> Result<i32, VncError> {
    Ok(i32::from_be_bytes(read_array(stream, what)?))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::{Frame, VncError, encode_png, read_frame};

    /// What a test server announces about its framebuffer; the client
    /// replaces the pixel format, so the values are QEMU's own default.
    const SERVER_PIXEL_FORMAT: [u8; 16] = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    /// The SetPixelFormat message the client must send: type 0, three
    /// padding bytes, the 16-byte format of RFC 6143 section 7.4.
    const EXPECTED_SET_PIXEL_FORMAT: [u8; 20] = [
        0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
    ];
    /// SetEncodings: type 2, padding, two encodings, Raw (0) and
    /// DesktopSize (-223 as an i32).
    const EXPECTED_SET_ENCODINGS: [u8; 12] = [2, 0, 0, 2, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x21];

    fn expect<S: Read>(server: &mut S, expected: &[u8], what: &str) {
        let mut received = vec![0; expected.len()];
        server.read_exact(&mut received).expect(what);
        assert_eq!(received, expected, "{what}");
    }

    /// The server half of the handshake up to and including ServerInit.
    fn greet(server: &mut UnixStream, width: u16, height: u16) {
        server.write_all(b"RFB 003.008\n").unwrap();
        expect(server, b"RFB 003.008\n", "the client's ProtocolVersion");
        server.write_all(&[1, 1]).unwrap();
        expect(server, &[1], "the chosen security type");
        server.write_all(&0u32.to_be_bytes()).unwrap();
        expect(server, &[1], "the shared ClientInit");
        let name = "helios 中文 日本語 한국어";
        let mut init = Vec::new();
        init.extend_from_slice(&width.to_be_bytes());
        init.extend_from_slice(&height.to_be_bytes());
        init.extend_from_slice(&SERVER_PIXEL_FORMAT);
        init.extend_from_slice(&(name.len() as u32).to_be_bytes());
        init.extend_from_slice(name.as_bytes());
        server.write_all(&init).unwrap();
        expect(server, &EXPECTED_SET_PIXEL_FORMAT, "SetPixelFormat");
        expect(server, &EXPECTED_SET_ENCODINGS, "SetEncodings");
    }

    fn request(width: u16, height: u16) -> Vec<u8> {
        let mut message = vec![3, 0, 0, 0, 0, 0];
        message.extend_from_slice(&width.to_be_bytes());
        message.extend_from_slice(&height.to_be_bytes());
        message
    }

    /// One Raw rectangle a test server sends: its pixels as
    /// `(red, green, blue)`, row-major.
    struct Raw<'a> {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        pixels: &'a [(u8, u8, u8)],
    }

    /// A FramebufferUpdate of Raw rectangles, their pixels as the
    /// little-endian 32-bit values of the client's pixel format.
    fn raw_update(rectangles: &[Raw]) -> Vec<u8> {
        let mut message = vec![0, 0];
        message.extend_from_slice(&(rectangles.len() as u16).to_be_bytes());
        for Raw {
            x,
            y,
            width,
            height,
            pixels,
        } in rectangles
        {
            for field in [x, y, width, height] {
                message.extend_from_slice(&field.to_be_bytes());
            }
            message.extend_from_slice(&0i32.to_be_bytes());
            for (red, green, blue) in *pixels {
                let pixel = u32::from(*red) << 16 | u32::from(*green) << 8 | u32::from(*blue);
                message.extend_from_slice(&pixel.to_le_bytes());
            }
        }
        message
    }

    fn client_reads(
        script: impl FnOnce(UnixStream) + Send + 'static,
    ) -> (Result<Frame, VncError>, JoinHandle<()>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server = thread::spawn(move || script(server));
        (read_frame(&mut client), server)
    }

    #[test]
    fn a_frame_in_two_raw_rectangles_is_read_pixel_for_pixel() {
        let (frame, server) = client_reads(|mut server| {
            greet(&mut server, 3, 2);
            expect(&mut server, &request(3, 2), "the full-screen request");
            // A Bell and a ServerCutText ahead of the update are
            // skipped, not mistaken for it.
            server.write_all(&[2]).unwrap();
            let clipboard = "中文、日本語、한국어";
            let mut cut = vec![3, 0, 0, 0];
            cut.extend_from_slice(&(clipboard.len() as u32).to_be_bytes());
            cut.extend_from_slice(clipboard.as_bytes());
            server.write_all(&cut).unwrap();
            // One update, the bottom row first.
            server
                .write_all(&raw_update(&[
                    Raw {
                        x: 0,
                        y: 1,
                        width: 3,
                        height: 1,
                        pixels: &[(1, 2, 3), (250, 251, 252), (0x12, 0x34, 0x56)],
                    },
                    Raw {
                        x: 0,
                        y: 0,
                        width: 3,
                        height: 1,
                        pixels: &[(255, 0, 0), (0, 255, 0), (0, 0, 255)],
                    },
                ]))
                .unwrap();
        });
        let frame = frame.expect("the frame is read");
        server.join().unwrap();
        assert_eq!((frame.width, frame.height), (3, 2));
        assert_eq!(
            frame.rgb,
            [
                255, 0, 0, 0, 255, 0, 0, 0, 255, // top row
                1, 2, 3, 250, 251, 252, 0x12, 0x34, 0x56, // bottom row
            ]
        );
    }

    #[test]
    fn a_resize_is_followed_by_a_request_for_the_new_size() {
        let (frame, server) = client_reads(|mut server| {
            greet(&mut server, 2, 2);
            expect(&mut server, &request(2, 2), "the first request");
            // DesktopSize: one rectangle, the new size in its width and
            // height, encoding -223, no payload.
            let mut resize = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1];
            resize.extend_from_slice(&(-223i32).to_be_bytes());
            server.write_all(&resize).unwrap();
            expect(&mut server, &request(3, 1), "the request for the new size");
            server
                .write_all(&raw_update(&[Raw {
                    x: 0,
                    y: 0,
                    width: 3,
                    height: 1,
                    pixels: &[(10, 20, 30), (40, 50, 60), (70, 80, 90)],
                }]))
                .unwrap();
        });
        let frame = frame.expect("the resized frame is read");
        server.join().unwrap();
        assert_eq!((frame.width, frame.height), (3, 1));
        assert_eq!(frame.rgb, [10, 20, 30, 40, 50, 60, 70, 80, 90]);
    }

    #[test]
    fn a_server_older_than_rfb_3_8_is_refused() {
        let (frame, server) = client_reads(|mut server| {
            server.write_all(b"RFB 003.003\n").unwrap();
        });
        server.join().unwrap();
        match frame {
            Err(VncError::UnsupportedVersion { offered }) => assert_eq!(offered, "RFB 003.003"),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn the_encoded_capture_decodes_to_the_frame() {
        let mut frame = Frame::blank(2, 1);
        frame
            .paint(
                &super::Rectangle {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 1,
                    encoding: 0,
                },
                // Blue, green, red, padding: (9, 8, 7) and (200, 100, 50).
                &[7, 8, 9, 0, 50, 100, 200, 0],
            )
            .unwrap();
        let encoded = encode_png(&frame).unwrap();
        let mut reader = png::Decoder::new(std::io::Cursor::new(encoded))
            .read_info()
            .unwrap();
        let mut decoded = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut decoded).unwrap();
        assert_eq!((info.width, info.height), (2, 1));
        assert_eq!(info.color_type, png::ColorType::Rgb);
        assert_eq!(info.bit_depth, png::BitDepth::Eight);
        assert_eq!(decoded, [9, 8, 7, 200, 100, 50]);
    }
}
