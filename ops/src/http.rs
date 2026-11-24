//! Official HTTP client surface for `helios-ops`, powered by [`zenwave`].
//!
//! Symmetric with `helios-api` on WASI Preview 3, this module re-exports
//! `zenwave`'s core client types and provides typed async helpers for
//! Authority CA credential exchange (`helios login`) and OTLP/HTTP export
//! (`helios bridge --otlp-endpoint`).

use core::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use zenwave::{
    Client, DefaultClient, Error, Method, Request, Response, ResponseExt, StatusCode, Transport,
    header,
};

use crate::error::HttpError;

/// Construct a new default [`zenwave::DefaultClient`] backed by the system transport.
#[must_use]
pub fn client() -> DefaultClient {
    DefaultClient::new(Transport::system())
}

/// Perform an HTTP `GET` and decode the response body as JSON.
pub async fn get_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Option<Duration>,
) -> Result<T, HttpError> {
    let mut http = client();
    let mut builder = http.get(url).map_err(|err| HttpError::Request {
        method: "GET".to_owned(),
        url: url.to_owned(),
        detail: err.to_string(),
    })?;
    for &(name, value) in headers {
        builder = builder
            .header(name, value)
            .map_err(|err| HttpError::Request {
                method: "GET".to_owned(),
                url: url.to_owned(),
                detail: err.to_string(),
            })?;
    }
    if let Some(dur) = timeout {
        builder = builder.connect_timeout(dur).response_head_timeout(dur);
    }
    let response = builder.await.map_err(|err| HttpError::Request {
        method: "GET".to_owned(),
        url: url.to_owned(),
        detail: err.to_string(),
    })?;
    let status = response.status().as_u16();
    let bytes = response
        .into_bytes()
        .await
        .map_err(|err| HttpError::Request {
            method: "GET".to_owned(),
            url: url.to_owned(),
            detail: err.to_string(),
        })?;
    if status >= 400 {
        return Err(HttpError::Status {
            method: "GET".to_owned(),
            url: url.to_owned(),
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| HttpError::DecodeJson {
        url: url.to_owned(),
        source,
    })
}

/// Perform an HTTP `POST` with a JSON request body and return the raw response body bytes.
pub async fn post_json<B: Serialize>(
    url: &str,
    body: &B,
    headers: &[(&str, &str)],
    timeout: Option<Duration>,
) -> Result<(u16, Vec<u8>), HttpError> {
    let payload = serde_json::to_vec(body).map_err(|source| HttpError::EncodeJson { source })?;
    let mut http = client();
    let mut builder = http
        .post(url)
        .map_err(|err| HttpError::Request {
            method: "POST".to_owned(),
            url: url.to_owned(),
            detail: err.to_string(),
        })?
        .header("content-type", "application/json")
        .map_err(|err| HttpError::Request {
            method: "POST".to_owned(),
            url: url.to_owned(),
            detail: err.to_string(),
        })?;
    for &(name, value) in headers {
        builder = builder
            .header(name, value)
            .map_err(|err| HttpError::Request {
                method: "POST".to_owned(),
                url: url.to_owned(),
                detail: err.to_string(),
            })?;
    }
    if let Some(dur) = timeout {
        builder = builder.connect_timeout(dur).response_head_timeout(dur);
    }
    let response = builder
        .bytes_body(payload)
        .await
        .map_err(|err| HttpError::Request {
            method: "POST".to_owned(),
            url: url.to_owned(),
            detail: err.to_string(),
        })?;
    let status = response.status().as_u16();
    let bytes = response
        .into_bytes()
        .await
        .map_err(|err| HttpError::Request {
            method: "POST".to_owned(),
            url: url.to_owned(),
            detail: err.to_string(),
        })?
        .to_vec();
    if status >= 400 {
        return Err(HttpError::Status {
            method: "POST".to_owned(),
            url: url.to_owned(),
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok((status, bytes))
}
