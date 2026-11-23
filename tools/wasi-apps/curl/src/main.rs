use std::fs::File;
use std::io::{self, Write};

use futures_lite::StreamExt as _;
use helios_api::http::{BodyError, Client as _, DefaultClient, Error as HttpError, Transport};
use helios_curl_write_out::expand_write_out;
use thiserror::Error;

type Result<T> = core::result::Result<T, CurlError>;

const NULL_DEVICE_PATH: &str = "/dev/null";

const USER_AGENT: &str = "helios-curl/0.1";

#[derive(Debug, Error)]
enum CurlError {
    #[error("usage: curl <http-url>")]
    Usage,
    #[error("curl option `{0}` requires a value")]
    MissingOptionValue(String),
    #[error("unsupported curl option `{0}`")]
    UnsupportedOption(String),
    #[error("multiple URLs were provided")]
    MultipleUrls,
    #[error("http request failed: {0}")]
    Request(#[from] HttpError),
    #[error("failed to read response after {bytes_read} bytes: {source}")]
    ReadResponse {
        bytes_read: usize,
        #[source]
        source: BodyError,
    },
    #[error("failed to write response body")]
    WriteResponseBody(#[source] io::Error),
    #[error("failed to create output file `{path}`")]
    CreateOutputFile {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    UnsupportedWriteOut(#[from] helios_curl_write_out::Error),
}

struct CurlOptions {
    url: String,
    output: OutputTarget,
    write_out: Option<String>,
}

enum OutputTarget {
    Stdout,
    Discard,
    File(File),
}

impl OutputTarget {
    fn from_path(path: String) -> Result<Self> {
        if path == NULL_DEVICE_PATH {
            return Ok(Self::Discard);
        }
        let file =
            File::create(&path).map_err(|source| CurlError::CreateOutputFile { path, source })?;
        Ok(Self::File(file))
    }

    fn write_body(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Stdout => {
                let mut stdout = io::stdout();
                stdout
                    .write_all(bytes)
                    .map_err(CurlError::WriteResponseBody)?;
                stdout.flush().map_err(CurlError::WriteResponseBody)
            }
            Self::Discard => Ok(()),
            Self::File(file) => file.write_all(bytes).map_err(CurlError::WriteResponseBody),
        }
    }
}

fn parse_options() -> Result<CurlOptions> {
    let mut args = std::env::args().skip(1);
    let mut url = None;
    let mut output = OutputTarget::Stdout;
    let mut write_out = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" | "-o" => {
                let path = args
                    .next()
                    .ok_or_else(|| CurlError::MissingOptionValue(arg.clone()))?;
                output = OutputTarget::from_path(path)?;
            }
            "--write-out" | "-w" => {
                write_out = Some(
                    args.next()
                        .ok_or_else(|| CurlError::MissingOptionValue(arg.clone()))?,
                );
            }
            _ if arg.starts_with('-') => return Err(CurlError::UnsupportedOption(arg)),
            _ => {
                if url.replace(arg).is_some() {
                    return Err(CurlError::MultipleUrls);
                }
            }
        }
    }

    Ok(CurlOptions {
        url: url.ok_or(CurlError::Usage)?,
        output,
        write_out,
    })
}

fn write_out(template: &str, size_download: usize) -> Result<()> {
    let rendered = expand_write_out(template, size_download)?;
    let mut stdout = io::stdout();
    stdout
        .write_all(rendered.as_bytes())
        .map_err(CurlError::WriteResponseBody)?;
    stdout.flush().map_err(CurlError::WriteResponseBody)
}

async fn run() -> Result<()> {
    let mut options = parse_options()?;
    let mut client = DefaultClient::raw(Transport::system());
    let response = client
        .get(options.url.as_str())?
        .header("user-agent", USER_AGENT)?
        .await?;

    let mut body = response.into_body().into_data_stream();
    let mut size_download = 0_usize;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|source| CurlError::ReadResponse {
            bytes_read: size_download,
            source,
        })?;
        size_download += chunk.len();
        options.output.write_body(&chunk)?;
    }

    if let Some(template) = options.write_out.as_deref() {
        write_out(template, size_download)?;
    }
    Ok(())
}

#[helios_api::main]
async fn main() -> Result<()> {
    run().await
}
