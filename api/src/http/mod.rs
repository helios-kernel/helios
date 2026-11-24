//! HTTP over `wasi:http@0.3.0`.
//!
//! The generated WIT bindings are re-exported as [`types`] for callers that
//! need the resources directly. On top of them this module provides the two
//! ergonomic halves of the interface:
//!
//! * The [`zenwave`] HTTP client (`WasiBackend` speaking `wasi:http/client` on
//!   Component Model WASI targets, native backend on host builds). Available
//!   when `feature = "http"` is enabled and `feature = "http-handler"` is not
//!   — the `http-client` kernel plugin *is* the client, so it cannot import
//!   one.
//! * [`handler`], the export side, available when the `http-handler` feature
//!   selects the plugin's world.

pub use crate::bindings::wasi::http::types;

pub use types::{
    DnsErrorPayload, ErrorCode, FieldSizePayload, Fields, HeaderError, Method, RequestOptions,
    RequestOptionsError, Scheme, StatusCode, TlsAlertReceivedPayload,
};

#[cfg(all(feature = "http", not(feature = "http-handler")))]
pub use zenwave::{
    self, Body, BodyError, Client, DefaultClient, Endpoint, Error, Request, Response, ResponseExt,
    Timeouts, Transport, TransportBuilder, Uri, backend, client, client_with, delete, get, post,
    put,
};

#[cfg(feature = "http-handler")]
pub mod handler;
