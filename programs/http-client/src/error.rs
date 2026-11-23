//! The `wasi:http` error code each failure of the client stands for.
//!
//! The client reports typed failures; this is the one place that decides
//! which RFC 9209 code a failure is, so the guest sees the same code whether
//! the exchange failed before its response head or while its body streamed.

use std::error::Error as StdError;
use std::io::{self, ErrorKind};
use std::ops::RangeInclusive;
use std::string::ToString;

use helios_api::http::{DnsErrorPayload, ErrorCode, TlsAlertReceivedPayload};
use zenwave::{
    Attempt, Cause, ConnectFailure, ConnectPhase, Error, ExchangeFailure, ReceiveError, TimedOut,
    TlsFailure,
};

use crate::request::BodyOutcome;

/// QUIC transport error codes carrying a TLS alert: `0x0100` plus the one-byte
/// TLS alert description (RFC 9001 §4.8).
const CRYPTO_ERROR: RangeInclusive<u64> = 0x100..=0x1ff;

/// The code for a failure of `respond`.
pub fn code(error: &Error, outcome: &BodyOutcome) -> ErrorCode {
    match error {
        Error::Timeout(TimedOut::Connect {
            during: ConnectPhase::Resolve,
        }) => ErrorCode::DnsTimeout,
        Error::Timeout(TimedOut::Connect {
            during: ConnectPhase::Queued,
        }) => ErrorCode::ConnectionLimitReached,
        Error::Timeout(TimedOut::Connect { .. }) => ErrorCode::ConnectionTimeout,
        Error::Timeout(TimedOut::ResponseHead | TimedOut::Request) => {
            ErrorCode::HttpResponseTimeout
        }
        Error::Timeout(TimedOut::BodyIdle) => ErrorCode::ConnectionReadTimeout,
        Error::Connect(connect) => match &connect.failure {
            ConnectFailure::Resolve(_) => ErrorCode::DnsError(DnsErrorPayload {
                rcode: None,
                info_code: None,
            }),
            ConnectFailure::Tcp(tcp) => tcp_code(&tcp.attempts),
            ConnectFailure::Tls(tls) => tls_code(tls.failure, &tls.cause),
            ConnectFailure::Quic(cause) => quic_code(cause, outcome),
            // No proxy is configured and `wasi:sockets` has no Unix sockets,
            // so these routes are never taken.
            other => internal(other),
        },
        Error::Exchange(exchange) => match exchange.failure {
            ExchangeFailure::Terminated => ErrorCode::ConnectionTerminated,
            ExchangeFailure::Incomplete => ErrorCode::HttpResponseIncomplete,
            ExchangeFailure::HeadTooLarge { limit } => {
                ErrorCode::HttpResponseHeaderSectionSize(u32::try_from(limit).ok())
            }
            ExchangeFailure::TooManyFields { .. } => ErrorCode::HttpResponseHeaderSectionSize(None),
            ExchangeFailure::TransferCoding => ErrorCode::HttpResponseTransferCoding(None),
            ExchangeFailure::Protocol | ExchangeFailure::InvalidRequest => {
                ErrorCode::HttpProtocolError
            }
            ExchangeFailure::TrailersTooLarge { limit } => {
                ErrorCode::HttpResponseTrailerSectionSize(u32::try_from(limit).ok())
            }
            ExchangeFailure::TooManyTrailers { .. } => {
                ErrorCode::HttpResponseTrailerSectionSize(None)
            }
            ExchangeFailure::RequestBodyLength { .. } => {
                ErrorCode::HttpRequestBodySize(Some(outcome.sent()))
            }
            // The caller's own body stream failed: its code is the verdict.
            ExchangeFailure::RequestBody => outcome.failure().unwrap_or_else(|| internal(error)),
            ExchangeFailure::Tls => exchange_tls_code(&exchange.cause),
            ExchangeFailure::Io => exchange_io_code(&exchange.cause, error),
            _ => internal(error),
        },
        Error::InvalidUri(_) => ErrorCode::HttpRequestUriInvalid,
        Error::InvalidRequest(_) => ErrorCode::HttpProtocolError,
        Error::Config(_) => ErrorCode::ConfigurationError,
        _ => internal(error),
    }
}

/// The code for a failure of the response body, `https` saying whether the
/// connection under it carries TLS: its records fail as `InvalidData`.
pub fn body_code(error: &zenwave::BodyError, https: bool) -> ErrorCode {
    match error {
        zenwave::BodyError::Receive(receive) => match receive {
            ReceiveError::Stalled => ErrorCode::ConnectionReadTimeout,
            ReceiveError::Incomplete => ErrorCode::HttpResponseIncomplete,
            ReceiveError::Framing { .. } => ErrorCode::HttpProtocolError,
            ReceiveError::TrailersTooLarge { limit } => {
                ErrorCode::HttpResponseTrailerSectionSize(u32::try_from(*limit).ok())
            }
            ReceiveError::TooManyTrailers { .. } => ErrorCode::HttpResponseTrailerSectionSize(None),
            ReceiveError::Connection(error) => io_code(error, https, error),
            _ => internal(error),
        },
        zenwave::BodyError::Other(other) => {
            if let Some(h2) = other.downcast_ref::<http_kit_h2::Error>() {
                h2_body_code(h2, https, error)
            } else if let Some(h3) = other.downcast_ref::<http_kit_h3::Error>() {
                h3_body_code(h3, https, error)
            } else {
                internal(error)
            }
        }
        _ => internal(error),
    }
}

fn crypto_alert(code: u64) -> Option<u8> {
    CRYPTO_ERROR
        .contains(&code)
        .then(|| u8::try_from(code - *CRYPTO_ERROR.start()).ok())
        .flatten()
}

/// Whether `alert` is an RFC 8446 §6.2 certificate verification alert.
const fn is_certificate_alert(alert: u8) -> bool {
    matches!(
        alert,
        // bad_certificate (42) ..= certificate_unknown (46), unknown_ca (48),
        // bad_certificate_status_response (113), certificate_required (116).
        42..=46 | 48 | 113 | 116
    )
}

fn h3_crypto_alert_code(h3: &http_kit_h3::Error, detail: &impl ToString) -> Option<ErrorCode> {
    match h3 {
        http_kit_h3::Error::PeerClosed {
            application: false,
            code,
        } => crypto_alert(*code).map(|alert| {
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(alert),
                alert_message: Some(detail.to_string()),
            })
        }),
        http_kit_h3::Error::LocallyClosed {
            application: false,
            code,
        } => crypto_alert(*code).map(|alert| {
            if is_certificate_alert(alert) {
                ErrorCode::TlsCertificateError
            } else {
                ErrorCode::TlsProtocolError
            }
        }),
        _ => None,
    }
}

fn quic_code(cause: &Cause, outcome: &BodyOutcome) -> ErrorCode {
    match cause {
        Cause::H3(h3) => quic_h3_code(h3, cause, outcome),
        Cause::Io(io) => quic_io_code(io, outcome),
        _ => internal(cause),
    }
}

fn quic_h3_code(h3: &http_kit_h3::Error, cause: &Cause, outcome: &BodyOutcome) -> ErrorCode {
    if let Some(code) = h3_crypto_alert_code(h3, cause) {
        return code;
    }
    match h3 {
        http_kit_h3::Error::Timeout(_) => ErrorCode::ConnectionTimeout,
        http_kit_h3::Error::NoCertificate => ErrorCode::TlsCertificateError,
        http_kit_h3::Error::Tls(_) => ErrorCode::TlsProtocolError,
        http_kit_h3::Error::ConnectionClosed
        | http_kit_h3::Error::StreamReset(_)
        | http_kit_h3::Error::RequestRejected
        | http_kit_h3::Error::PeerClosed { .. } => ErrorCode::ConnectionTerminated,
        http_kit_h3::Error::LocallyClosed { .. }
        | http_kit_h3::Error::Malformed(_)
        | http_kit_h3::Error::Quic(_)
        | http_kit_h3::Error::H3(_) => ErrorCode::HttpProtocolError,
        http_kit_h3::Error::Io(io) => quic_io_code(io, outcome),
        _ => internal(cause),
    }
}

fn quic_io_code(io: &io::Error, outcome: &BodyOutcome) -> ErrorCode {
    // Happy Eyeballs wraps each QUIC attempt's `zenwave::Error` inside
    // `io::Error::other(error)` so the dial race stays on `io::Result`.
    if let Some(inner) = io
        .get_ref()
        .and_then(|source| source.downcast_ref::<Error>())
    {
        return code(inner, outcome);
    }
    match io.kind() {
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
            ErrorCode::DestinationIpUnroutable
        }
        ErrorKind::PermissionDenied => ErrorCode::DestinationIpProhibited,
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => ErrorCode::ConnectionRefused,
        ErrorKind::TimedOut => ErrorCode::ConnectionTimeout,
        _ => internal(io),
    }
}

fn exchange_tls_code(cause: &Cause) -> ErrorCode {
    if let Cause::H3(h3) = cause
        && let Some(code) = h3_crypto_alert_code(h3, cause)
    {
        return code;
    }
    ErrorCode::TlsProtocolError
}

fn exchange_io_code(cause: &Cause, error: &Error) -> ErrorCode {
    let io = match cause {
        Cause::Io(io) => Some(io.as_ref()),
        Cause::Receive(ReceiveError::Connection(io)) => Some(io.as_ref()),
        Cause::H2(http_kit_h2::Error::Io(io)) => Some(io.as_ref()),
        Cause::H3(http_kit_h3::Error::Io(io)) => Some(io.as_ref()),
        Cause::H3(http_kit_h3::Error::Tls(_)) => return ErrorCode::TlsProtocolError,
        Cause::H3(http_kit_h3::Error::NoCertificate) => return ErrorCode::TlsCertificateError,
        Cause::H3(http_kit_h3::Error::Quic(_) | http_kit_h3::Error::H3(_)) => {
            return ErrorCode::HttpProtocolError;
        }
        _ => cause
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>()),
    };
    match io {
        Some(io) => io_code(io, false, error),
        None => internal(error),
    }
}

fn h3_body_code(h3: &http_kit_h3::Error, https: bool, error: &zenwave::BodyError) -> ErrorCode {
    if let Some(code) = h3_crypto_alert_code(h3, h3) {
        return code;
    }
    match h3 {
        http_kit_h3::Error::Timeout(http_kit_h3::Timeout::BodyIdle) => {
            ErrorCode::ConnectionReadTimeout
        }
        http_kit_h3::Error::Timeout(http_kit_h3::Timeout::ResponseHead) => {
            ErrorCode::HttpResponseTimeout
        }
        http_kit_h3::Error::ConnectionClosed
        | http_kit_h3::Error::StreamReset(_)
        | http_kit_h3::Error::PeerClosed { .. } => ErrorCode::HttpResponseIncomplete,
        http_kit_h3::Error::RequestRejected => ErrorCode::ConnectionTerminated,
        http_kit_h3::Error::NoCertificate => ErrorCode::TlsCertificateError,
        http_kit_h3::Error::Tls(_) => ErrorCode::TlsProtocolError,
        http_kit_h3::Error::LocallyClosed { .. }
        | http_kit_h3::Error::Malformed(_)
        | http_kit_h3::Error::Quic(_)
        | http_kit_h3::Error::H3(_)
        | http_kit_h3::Error::MissingAuthority
        | http_kit_h3::Error::InformationalResponse(_)
        | http_kit_h3::Error::UnsupportedFrame => ErrorCode::HttpProtocolError,
        http_kit_h3::Error::Io(io) => io_code(io, https, error),
        _ => internal(error),
    }
}

fn h2_body_code(h2: &http_kit_h2::Error, https: bool, error: &zenwave::BodyError) -> ErrorCode {
    match h2 {
        http_kit_h2::Error::Timeout(http_kit_h2::Timeout::BodyIdle) => {
            ErrorCode::ConnectionReadTimeout
        }
        http_kit_h2::Error::Timeout(http_kit_h2::Timeout::ResponseHead) => {
            ErrorCode::HttpResponseTimeout
        }
        http_kit_h2::Error::Timeout(_)
        | http_kit_h2::Error::ConnectionClosed
        | http_kit_h2::Error::StreamReset(_)
        | http_kit_h2::Error::RequestRejected
        | http_kit_h2::Error::PeerGoAway { .. }
        | http_kit_h2::Error::StreamsExhausted => ErrorCode::ConnectionTerminated,
        http_kit_h2::Error::Malformed(http_kit_h2::Malformed::HeaderListTooLarge { limit }) => {
            ErrorCode::HttpResponseTrailerSectionSize(Some(*limit))
        }
        http_kit_h2::Error::Protocol { .. }
        | http_kit_h2::Error::Malformed(_)
        | http_kit_h2::Error::MissingAuthority
        | http_kit_h2::Error::InformationalResponse(_)
        | http_kit_h2::Error::UnsupportedFrame
        | http_kit_h2::Error::UnsupportedExtendedConnect => ErrorCode::HttpProtocolError,
        http_kit_h2::Error::Io(io) => io_code(io, https, error),
        _ => internal(error),
    }
}

fn io_code(io: &io::Error, https: bool, fallback: &impl ToString) -> ErrorCode {
    match io.kind() {
        ErrorKind::InvalidData if https => ErrorCode::TlsProtocolError,
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => ErrorCode::ConnectionTerminated,
        ErrorKind::TimedOut => ErrorCode::ConnectionReadTimeout,
        _ => internal(fallback),
    }
}

fn internal(error: &impl ToString) -> ErrorCode {
    ErrorCode::InternalError(Some(error.to_string()))
}

/// RFC 8305 races several addresses, so the attempts can differ; the first
/// rule that holds names the failure.
fn tcp_code(attempts: &[Attempt]) -> ErrorCode {
    let all = |kinds: &[ErrorKind]| {
        !attempts.is_empty()
            && attempts
                .iter()
                .all(|attempt| kinds.contains(&attempt.error.kind()))
    };
    let any = |kinds: &[ErrorKind]| {
        attempts
            .iter()
            .any(|attempt| kinds.contains(&attempt.error.kind()))
    };
    if all(&[ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable]) {
        ErrorCode::DestinationIpUnroutable
    } else if all(&[ErrorKind::PermissionDenied]) {
        ErrorCode::DestinationIpProhibited
    } else if any(&[
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
    ]) {
        ErrorCode::ConnectionRefused
    } else if any(&[ErrorKind::TimedOut]) {
        ErrorCode::ConnectionTimeout
    } else {
        ErrorCode::InternalError(attempts.first().map(|attempt: &Attempt| {
            let error: &io::Error = &attempt.error;
            error.to_string()
        }))
    }
}

fn tls_code(failure: TlsFailure, cause: &Cause) -> ErrorCode {
    match failure {
        TlsFailure::Certificate => ErrorCode::TlsCertificateError,
        TlsFailure::AlertReceived { alert } => {
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(alert),
                alert_message: Some(cause.to_string()),
            })
        }
        _ => ErrorCode::TlsProtocolError,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, ErrorKind};
    use std::sync::Arc;

    use helios_api::http::{ErrorCode, TlsAlertReceivedPayload};
    use http::StatusCode;
    use http_kit_h2::{Error as H2Error, Malformed, Reason, StreamId, Timeout as H2Timeout};
    use http_kit_h3::{Error as H3Error, Malformed as H3Malformed, Timeout as H3Timeout};
    use zenwave::{
        BodyError, Cause, ConnectError, ConnectFailure, ConnectPhase, Error, ExchangeError,
        ExchangeFailure, Hop, ReceiveError, TimedOut,
    };

    use super::{body_code, code};
    use crate::request::BodyOutcome;

    fn exchange(failure: ExchangeFailure, cause: Cause) -> Error {
        Error::Exchange(Box::new(ExchangeError::new(failure, cause)))
    }

    fn quic_connect(cause: Cause) -> Error {
        Error::Connect(Box::new(ConnectError::new(
            Hop::Origin,
            "example.com",
            443,
            ConnectFailure::Quic(cause),
        )))
    }

    #[test]
    fn h2_exchange_terminated_causes_map_to_connection_terminated() {
        let outcome = BodyOutcome::default();
        let causes = [
            Cause::H2(H2Error::ConnectionClosed),
            Cause::H2(H2Error::StreamReset(Reason::CANCEL)),
            Cause::H2(H2Error::StreamReset(Reason::REFUSED_STREAM)),
            Cause::H2(H2Error::RequestRejected),
            Cause::H2(H2Error::PeerGoAway {
                last_stream_id: StreamId::new(1).expect("valid stream id"),
                reason: Reason::NO_ERROR,
                debug_data: Default::default(),
            }),
            Cause::H2(H2Error::StreamsExhausted),
            Cause::H2(H2Error::Timeout(H2Timeout::Handshake)),
            Cause::H2(H2Error::Timeout(H2Timeout::SettingsAck)),
            Cause::H2(H2Error::Timeout(H2Timeout::KeepAlive)),
        ];

        for cause in causes {
            let err = exchange(ExchangeFailure::Terminated, cause);
            assert!(
                matches!(code(&err, &outcome), ErrorCode::ConnectionTerminated),
                "expected ConnectionTerminated for {err:?}"
            );
        }
    }

    #[test]
    fn h2_exchange_protocol_header_and_timeout_mappings() {
        let outcome = BodyOutcome::default();

        let head_too_large = exchange(
            ExchangeFailure::HeadTooLarge { limit: 16_384 },
            Cause::H2(H2Error::Malformed(Malformed::HeaderListTooLarge {
                limit: 16_384,
            })),
        );
        assert!(matches!(
            code(&head_too_large, &outcome),
            ErrorCode::HttpResponseHeaderSectionSize(Some(16_384))
        ));

        let protocol = exchange(
            ExchangeFailure::Protocol,
            Cause::H2(H2Error::Protocol {
                reason: Reason::PROTOCOL_ERROR,
                detail: "invalid frame",
            }),
        );
        assert!(matches!(
            code(&protocol, &outcome),
            ErrorCode::HttpProtocolError
        ));

        let malformed = exchange(
            ExchangeFailure::Protocol,
            Cause::H2(H2Error::Malformed(Malformed::InvalidStatus)),
        );
        assert!(matches!(
            code(&malformed, &outcome),
            ErrorCode::HttpProtocolError
        ));

        let invalid_req_exchange = exchange(
            ExchangeFailure::InvalidRequest,
            Cause::H2(H2Error::InformationalResponse(
                StatusCode::SWITCHING_PROTOCOLS,
            )),
        );
        assert!(matches!(
            code(&invalid_req_exchange, &outcome),
            ErrorCode::HttpProtocolError
        ));

        let invalid_req = Error::InvalidRequest(String::from("bad request header"));
        assert!(matches!(
            code(&invalid_req, &outcome),
            ErrorCode::HttpProtocolError
        ));

        let tls = exchange(
            ExchangeFailure::Tls,
            Cause::H2(H2Error::Io(Arc::new(io::Error::new(
                ErrorKind::InvalidData,
                "bad tls record",
            )))),
        );
        assert!(matches!(code(&tls, &outcome), ErrorCode::TlsProtocolError));

        assert!(matches!(
            code(&Error::Timeout(TimedOut::ResponseHead), &outcome),
            ErrorCode::HttpResponseTimeout
        ));
        assert!(matches!(
            code(&Error::Timeout(TimedOut::BodyIdle), &outcome),
            ErrorCode::ConnectionReadTimeout
        ));
    }

    #[test]
    fn h2_exchange_request_body_mappings() {
        let outcome = BodyOutcome::default();
        outcome.record_sent(42);
        let length = exchange(
            ExchangeFailure::RequestBodyLength { declared: 100 },
            Cause::H2(H2Error::ContentLengthMismatch { declared: 100 }),
        );
        assert!(matches!(
            code(&length, &outcome),
            ErrorCode::HttpRequestBodySize(Some(42))
        ));

        let body_err = exchange(
            ExchangeFailure::RequestBody,
            Cause::H2(H2Error::Body(Arc::new(BodyError::BodyFrozen))),
        );
        assert!(matches!(
            code(&body_err, &outcome),
            ErrorCode::InternalError(Some(_))
        ));

        outcome.record_failure(ErrorCode::HttpRequestBodySize(Some(42)));
        assert!(matches!(
            code(&body_err, &outcome),
            ErrorCode::HttpRequestBodySize(Some(42))
        ));
    }

    #[test]
    fn exchange_io_maps_termination_and_timeout_kinds() {
        let outcome = BodyOutcome::default();

        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
        ] {
            let h2_io = exchange(
                ExchangeFailure::Io,
                Cause::H2(H2Error::Io(Arc::new(io::Error::new(kind, "peer gone")))),
            );
            assert!(
                matches!(code(&h2_io, &outcome), ErrorCode::ConnectionTerminated),
                "expected ConnectionTerminated for H2 Io({kind:?})"
            );

            let raw_io = exchange(
                ExchangeFailure::Io,
                Cause::Io(Arc::new(io::Error::new(kind, "peer gone"))),
            );
            assert!(
                matches!(code(&raw_io, &outcome), ErrorCode::ConnectionTerminated),
                "expected ConnectionTerminated for Cause::Io({kind:?})"
            );

            let receive_io = exchange(
                ExchangeFailure::Io,
                Cause::Receive(ReceiveError::Connection(Arc::new(io::Error::new(
                    kind,
                    "peer gone",
                )))),
            );
            assert!(
                matches!(code(&receive_io, &outcome), ErrorCode::ConnectionTerminated),
                "expected ConnectionTerminated for ReceiveError::Connection({kind:?})"
            );
        }

        let timed_out = exchange(
            ExchangeFailure::Io,
            Cause::H2(H2Error::Io(Arc::new(io::Error::new(
                ErrorKind::TimedOut,
                "socket timeout",
            )))),
        );
        assert!(matches!(
            code(&timed_out, &outcome),
            ErrorCode::ConnectionReadTimeout
        ));

        let other = exchange(
            ExchangeFailure::Io,
            Cause::H2(H2Error::Io(Arc::new(io::Error::other("unexpected")))),
        );
        assert!(matches!(
            code(&other, &outcome),
            ErrorCode::InternalError(Some(_))
        ));
    }

    #[test]
    fn h2_body_error_mappings() {
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Timeout(H2Timeout::BodyIdle)),
                true
            ),
            ErrorCode::ConnectionReadTimeout
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Timeout(H2Timeout::KeepAlive)),
                true
            ),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Timeout(H2Timeout::SettingsAck)),
                true
            ),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Timeout(H2Timeout::Handshake)),
                true
            ),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            body_code(&BodyError::from(H2Error::StreamsExhausted), true),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            body_code(&BodyError::from(H2Error::StreamReset(Reason::CANCEL)), true),
            ErrorCode::HttpResponseIncomplete
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::PeerGoAway {
                    last_stream_id: StreamId::new(1).expect("valid stream id"),
                    reason: Reason::NO_ERROR,
                    debug_data: Default::default(),
                }),
                true
            ),
            ErrorCode::HttpResponseIncomplete
        ));
        assert!(matches!(
            body_code(&BodyError::from(H2Error::ConnectionClosed), true),
            ErrorCode::HttpResponseIncomplete
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Malformed(Malformed::HeaderListTooLarge {
                    limit: 8192,
                })),
                true
            ),
            ErrorCode::HttpResponseTrailerSectionSize(Some(8192))
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Malformed(Malformed::InvalidField)),
                true
            ),
            ErrorCode::HttpProtocolError
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Protocol {
                    reason: Reason::FRAME_SIZE_ERROR,
                    detail: "bad frame",
                }),
                true
            ),
            ErrorCode::HttpProtocolError
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Io(Arc::new(io::Error::new(
                    ErrorKind::InvalidData,
                    "bad tls record",
                )))),
                true
            ),
            ErrorCode::TlsProtocolError
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Io(Arc::new(io::Error::new(
                    ErrorKind::InvalidData,
                    "plain invalid data",
                )))),
                false
            ),
            ErrorCode::InternalError(Some(_))
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Io(Arc::new(io::Error::new(
                    ErrorKind::ConnectionReset,
                    "reset",
                )))),
                true
            ),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H2Error::Io(Arc::new(io::Error::new(
                    ErrorKind::TimedOut,
                    "timed out",
                )))),
                true
            ),
            ErrorCode::ConnectionReadTimeout
        ));
    }

    #[test]
    fn quic_connect_crypto_alerts_and_timeouts_map_precisely() {
        let outcome = BodyOutcome::default();

        assert!(matches!(
            code(
                &Error::Timeout(TimedOut::Connect {
                    during: ConnectPhase::Quic,
                }),
                &outcome
            ),
            ErrorCode::ConnectionTimeout
        ));

        // Certificate verification alerts sent by our client (`LocallyClosed`).
        for alert in [42u64, 43, 44, 45, 46, 48, 113, 116] {
            let err = quic_connect(Cause::H3(H3Error::LocallyClosed {
                application: false,
                code: 0x100 + alert,
            }));
            assert!(
                matches!(code(&err, &outcome), ErrorCode::TlsCertificateError),
                "expected TlsCertificateError for local TLS alert {alert}"
            );
        }

        // Non-certificate local TLS alert (`handshake_failure` = 40).
        let local_proto = quic_connect(Cause::H3(H3Error::LocallyClosed {
            application: false,
            code: 0x100 + 40,
        }));
        assert!(matches!(
            code(&local_proto, &outcome),
            ErrorCode::TlsProtocolError
        ));

        // Peer TLS alert (`handshake_failure` = 40).
        let peer_alert = quic_connect(Cause::H3(H3Error::PeerClosed {
            application: false,
            code: 0x100 + 40,
        }));
        assert!(matches!(
            code(&peer_alert, &outcome),
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(40),
                alert_message: Some(_),
            })
        ));

        // HTTP/3 application error 0x100 (`H3_NO_ERROR`) must NOT be confused
        // with QUIC transport `CRYPTO_ERROR` (0x100..=0x1ff).
        let peer_app = quic_connect(Cause::H3(H3Error::PeerClosed {
            application: true,
            code: 0x100,
        }));
        assert!(matches!(
            code(&peer_app, &outcome),
            ErrorCode::ConnectionTerminated
        ));
        let local_app = quic_connect(Cause::H3(H3Error::LocallyClosed {
            application: true,
            code: 0x100,
        }));
        assert!(matches!(
            code(&local_app, &outcome),
            ErrorCode::HttpProtocolError
        ));

        assert!(matches!(
            code(
                &quic_connect(Cause::H3(H3Error::Timeout(H3Timeout::ResponseHead))),
                &outcome
            ),
            ErrorCode::ConnectionTimeout
        ));
        assert!(matches!(
            code(&quic_connect(Cause::H3(H3Error::NoCertificate)), &outcome),
            ErrorCode::TlsCertificateError
        ));
        assert!(matches!(
            code(
                &quic_connect(Cause::H3(H3Error::ConnectionClosed)),
                &outcome
            ),
            ErrorCode::ConnectionTerminated
        ));
        assert!(matches!(
            code(
                &quic_connect(Cause::H3(H3Error::Malformed(H3Malformed::InvalidStatus))),
                &outcome
            ),
            ErrorCode::HttpProtocolError
        ));
    }

    #[test]
    fn quic_connect_io_unwraps_happy_eyeballs_error_and_maps_socket_kinds() {
        let outcome = BodyOutcome::default();

        // Happy Eyeballs wraps a QUIC attempt's `zenwave::Error` inside
        // `io::Error::other(error)`.
        let wrapped_cert = quic_connect(Cause::Io(Arc::new(io::Error::other(quic_connect(
            Cause::H3(H3Error::LocallyClosed {
                application: false,
                code: 0x100 + 48, // unknown_ca
            }),
        )))));
        assert!(matches!(
            code(&wrapped_cert, &outcome),
            ErrorCode::TlsCertificateError
        ));

        let wrapped_timeout = quic_connect(Cause::Io(Arc::new(io::Error::other(Error::Timeout(
            TimedOut::Connect {
                during: ConnectPhase::Quic,
            },
        )))));
        assert!(matches!(
            code(&wrapped_timeout, &outcome),
            ErrorCode::ConnectionTimeout
        ));

        for (kind, expected) in [
            (ErrorKind::HostUnreachable, "unroutable"),
            (ErrorKind::NetworkUnreachable, "unroutable"),
            (ErrorKind::PermissionDenied, "prohibited"),
            (ErrorKind::ConnectionRefused, "refused"),
            (ErrorKind::ConnectionReset, "refused"),
            (ErrorKind::ConnectionAborted, "refused"),
            (ErrorKind::TimedOut, "timeout"),
        ] {
            let err = quic_connect(Cause::Io(Arc::new(io::Error::new(kind, "udp failure"))));
            let mapped = code(&err, &outcome);
            match expected {
                "unroutable" => assert!(matches!(mapped, ErrorCode::DestinationIpUnroutable)),
                "prohibited" => assert!(matches!(mapped, ErrorCode::DestinationIpProhibited)),
                "refused" => assert!(matches!(mapped, ErrorCode::ConnectionRefused)),
                "timeout" => assert!(matches!(mapped, ErrorCode::ConnectionTimeout)),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn h3_exchange_and_body_error_mappings() {
        let outcome = BodyOutcome::default();

        let peer_tls = exchange(
            ExchangeFailure::Tls,
            Cause::H3(H3Error::PeerClosed {
                application: false,
                code: 0x100 + 42,
            }),
        );
        assert!(matches!(
            code(&peer_tls, &outcome),
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(42),
                alert_message: Some(_),
            })
        ));

        let local_cert_tls = exchange(
            ExchangeFailure::Tls,
            Cause::H3(H3Error::LocallyClosed {
                application: false,
                code: 0x100 + 48,
            }),
        );
        assert!(matches!(
            code(&local_cert_tls, &outcome),
            ErrorCode::TlsCertificateError
        ));

        let h3_io_reset = exchange(
            ExchangeFailure::Io,
            Cause::H3(H3Error::Io(Arc::new(io::Error::new(
                ErrorKind::ConnectionReset,
                "udp reset",
            )))),
        );
        assert!(matches!(
            code(&h3_io_reset, &outcome),
            ErrorCode::ConnectionTerminated
        ));

        let h3_io_timeout = exchange(
            ExchangeFailure::Io,
            Cause::H3(H3Error::Io(Arc::new(io::Error::new(
                ErrorKind::TimedOut,
                "udp timeout",
            )))),
        );
        assert!(matches!(
            code(&h3_io_timeout, &outcome),
            ErrorCode::ConnectionReadTimeout
        ));

        assert!(matches!(
            body_code(
                &BodyError::from(H3Error::Timeout(H3Timeout::BodyIdle)),
                true
            ),
            ErrorCode::ConnectionReadTimeout
        ));
        assert!(matches!(
            body_code(&BodyError::from(H3Error::StreamReset(0x10c)), true),
            ErrorCode::HttpResponseIncomplete
        ));
        assert!(matches!(
            body_code(&BodyError::from(H3Error::ConnectionClosed), true),
            ErrorCode::HttpResponseIncomplete
        ));
        assert!(matches!(
            body_code(
                &BodyError::from(H3Error::Malformed(H3Malformed::InvalidField)),
                true
            ),
            ErrorCode::HttpProtocolError
        ));
        assert!(matches!(
            body_code(
                &BodyError::Other(Box::new(H3Error::PeerClosed {
                    application: false,
                    code: 0x100 + 40,
                })),
                true
            ),
            ErrorCode::TlsAlertReceived(TlsAlertReceivedPayload {
                alert_id: Some(40),
                alert_message: Some(_),
            })
        ));
        assert!(matches!(
            body_code(
                &BodyError::Other(Box::new(H3Error::LocallyClosed {
                    application: false,
                    code: 0x100 + 45,
                })),
                true
            ),
            ErrorCode::TlsCertificateError
        ));
        assert!(matches!(
            body_code(
                &BodyError::Other(Box::new(H3Error::LocallyClosed {
                    application: true,
                    code: 0x102,
                })),
                true
            ),
            ErrorCode::HttpProtocolError
        ));
        assert!(matches!(
            body_code(&BodyError::Other(Box::new(H3Error::RequestRejected)), true),
            ErrorCode::ConnectionTerminated
        ));
    }
}
