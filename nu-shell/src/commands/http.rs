//! HTTP commands (`http`, `http get`, `http post`, `http put`, `http patch`,
//! `http delete`, `http head`, `http options`) backed uniformly by [`zenwave`]
//! (`WasiBackend` on Component Model WASI, native backend on host builds).

use core::time::Duration;

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};
use zenwave::{DefaultClient, Method, ResponseExt as _, Transport};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, HttpRedirectMode, HttpRequest, HttpResponse};
use crate::error::{EnvError, generic_error};
use crate::eval::eval_call_by_name_async;
use crate::pipeline::AsyncPipelineData;

/// Execute an [`HttpRequest`] directly using [`zenwave`]'s platform backend
/// (`WasiBackend` on WASI Preview 3, `HyperBackend` with `rustls-ring` on host).
pub async fn zenwave_send(request: HttpRequest) -> Result<HttpResponse, EnvError> {
    let method = Method::from_bytes(request.method.as_bytes()).map_err(|err| EnvError::Http {
        detail: format!("invalid HTTP method `{}`: {err}", request.method),
    })?;

    let response = match request.redirect_mode {
        HttpRedirectMode::Follow => {
            let mut client = DefaultClient::new(Transport::system());
            send_with_client(&mut client, method, &request).await?
        }
        HttpRedirectMode::Manual | HttpRedirectMode::Error => {
            let mut client = DefaultClient::raw(Transport::system());
            let resp = send_with_client(&mut client, method, &request).await?;
            if request.redirect_mode == HttpRedirectMode::Error && resp.status().is_redirection() {
                return Err(EnvError::Http {
                    detail: format!(
                        "redirect refused by redirect-mode=error (status {})",
                        resp.status()
                    ),
                });
            }
            resp
        }
    };

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = response
        .into_bytes()
        .await
        .map_err(|err| EnvError::Http {
            detail: format!("failed to read HTTP response body: {err}"),
        })?
        .to_vec();

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

async fn send_with_client<C: zenwave::Client>(
    client: &mut C,
    method: Method,
    request: &HttpRequest,
) -> Result<zenwave::Response, EnvError> {
    let mut builder =
        client
            .method(method, request.url.as_str())
            .map_err(|err| EnvError::Http {
                detail: err.to_string(),
            })?;

    for (name, value) in &request.headers {
        builder = builder
            .header(name.as_str(), value.as_str())
            .map_err(|err| EnvError::Http {
                detail: err.to_string(),
            })?;
    }
    if let Some(timeout) = request.timeout {
        builder = builder
            .connect_timeout(timeout)
            .response_head_timeout(timeout);
    }
    if let Some(body) = &request.body {
        builder = builder.bytes_body(body.clone());
    }

    builder.await.map_err(|err| EnvError::Http {
        detail: err.to_string(),
    })
}

/// Parent `http` command (displays subcommand overview).
#[derive(Debug, Clone, Copy)]
pub struct Http;

impl<E: HeliosEnv> AsyncCommand<E> for Http {
    fn name(&self) -> &str {
        "http"
    }

    fn description(&self) -> &str {
        "Perform HTTP requests via zenwave."
    }

    fn signature(&self) -> Signature {
        Signature::build("http")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .category(Category::Network)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let help = "HTTP subcommands: http get, http post, http put, http patch, http delete, http head, http options";
        Ok(AsyncPipelineData::value(
            Value::string(help, ctx.call.head),
            None,
        ))
    }
}

macro_rules! define_http_cmd {
    ($struct_name:ident, $cmd_name:literal, $method:literal, $desc:literal, $has_body:expr) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $struct_name;

        impl<E: HeliosEnv> AsyncCommand<E> for $struct_name {
            fn name(&self) -> &str {
                $cmd_name
            }

            fn description(&self) -> &str {
                $desc
            }

            fn search_terms(&self) -> Vec<&str> {
                vec!["network", "http", "zenwave", "request"]
            }

            fn signature(&self) -> Signature {
                http_signature($cmd_name, $has_body)
            }

            async fn run_async<'a>(
                &'a self,
                ctx: &'a mut AsyncCommandContext<'_, E>,
                input: AsyncPipelineData,
            ) -> Result<AsyncPipelineData, ShellError> {
                run_http(ctx, $method, $has_body, input).await
            }
        }
    };
}

define_http_cmd!(
    HttpGet,
    "http get",
    "GET",
    "Fetch the contents from a URL.",
    false
);
define_http_cmd!(HttpPost, "http post", "POST", "Post a body to a URL.", true);
define_http_cmd!(HttpPut, "http put", "PUT", "Put a body to a URL.", true);
define_http_cmd!(
    HttpPatch,
    "http patch",
    "PATCH",
    "Patch a resource at a URL.",
    true
);
define_http_cmd!(
    HttpDelete,
    "http delete",
    "DELETE",
    "Delete a resource at a URL.",
    true
);
define_http_cmd!(
    HttpHead,
    "http head",
    "HEAD",
    "Fetch only the headers from a URL.",
    false
);
define_http_cmd!(
    HttpOptions,
    "http options",
    "OPTIONS",
    "Query supported HTTP options for a URL.",
    false
);

fn http_signature(name: &str, accepts_body: bool) -> Signature {
    let mut sig = Signature::build(name)
        .input_output_types(vec![(Type::Any, Type::Any)])
        .required("URL", SyntaxShape::String, "The target URL.");
    if accepts_body {
        sig = sig.optional(
            "data",
            SyntaxShape::Any,
            "The body to send with the request.",
        );
        sig = sig.named(
            "content-type",
            SyntaxShape::String,
            "The MIME type of the request body.",
            Some('t'),
        );
    }
    sig.named(
        "headers",
        SyntaxShape::Any,
        "Custom headers as a record or key/value list.",
        Some('H'),
    )
    .named(
        "max-time",
        SyntaxShape::Duration,
        "Maximum duration before timing out.",
        Some('m'),
    )
    .named(
        "redirect-mode",
        SyntaxShape::String,
        "Redirect handling: follow (f), manual (m), or error (e).",
        Some('R'),
    )
    .switch("raw", "Return response body as raw text/bytes.", Some('r'))
    .switch(
        "full",
        "Return full response record (headers, body, status).",
        Some('f'),
    )
    .switch(
        "allow-errors",
        "Return error responses without raising a shell error.",
        Some('e'),
    )
    .category(Category::Network)
}

async fn run_http<E: HeliosEnv>(
    ctx: &mut AsyncCommandContext<'_, E>,
    method: &str,
    accepts_body: bool,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let head = ctx.call.head;
    let url: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
    let raw_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
    let full_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "full")?;
    let allow_errors = ctx
        .call
        .has_flag(ctx.engine_state, ctx.stack, "allow-errors")?;
    let headers_val: Option<Value> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "headers")?;
    let max_time: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "max-time")?;
    let redirect_str: Option<String> =
        ctx.call
            .get_flag(ctx.engine_state, ctx.stack, "redirect-mode")?;

    let redirect_mode = match redirect_str.as_deref() {
        None | Some("follow" | "f") => HttpRedirectMode::Follow,
        Some("manual" | "m") => HttpRedirectMode::Manual,
        Some("error" | "e") => HttpRedirectMode::Error,
        Some(other) => {
            return Err(generic_error(
                "invalid redirect-mode",
                format!("expected follow|manual|error, got `{other}`"),
                head,
            ));
        }
    };

    let timeout = match max_time {
        Some(ns) if ns < 0 => {
            return Err(generic_error(
                "invalid max-time",
                "timeout duration must be non-negative",
                head,
            ));
        }
        Some(ns) => Some(Duration::from_nanos(ns.cast_unsigned())),
        None => None,
    };

    let mut headers = parse_headers(headers_val.as_ref(), head)?;
    let mut body = None;

    if accepts_body {
        let content_type: Option<String> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "content-type")?;
        if let Some(ct) = &content_type {
            headers.push(("content-type".to_owned(), ct.clone()));
        }

        let body_arg: Option<Value> = ctx.call.opt(ctx.engine_state, ctx.stack, 1)?;
        let body_val = match body_arg {
            Some(v) => Some(v),
            None if !input.is_empty_or_nothing() => Some(input.into_value_async(head).await?),
            None => None,
        };

        if let Some(val) = body_val {
            let (encoded, inferred_ct) = encode_request_body(&val, head)?;
            if content_type.is_none()
                && !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                && let Some(ct) = inferred_ct
            {
                headers.push(("content-type".to_owned(), ct.to_owned()));
            }
            body = Some(encoded);
        }
    }

    let req_headers_snapshot = headers.clone();
    let response = ctx
        .env
        .http_send(HttpRequest {
            method: method.to_owned(),
            url: url.clone(),
            headers,
            body,
            timeout,
            redirect_mode,
        })
        .await
        .map_err(|err| err.into_shell_error(&format!("http {method} `{url}` failed"), head))?;

    if !allow_errors && response.status >= 400 {
        let preview = String::from_utf8_lossy(&response.body);
        return Err(generic_error(
            format!("HTTP {} error", response.status),
            if preview.is_empty() {
                format!("{method} {url} returned status {}", response.status)
            } else {
                preview.into_owned()
            },
            head,
        ));
    }

    if method == "HEAD" && !full_flag {
        return Ok(AsyncPipelineData::value(
            headers_to_table(&response.headers, head),
            None,
        ));
    }

    let body_value = decode_response_body(ctx, &response, raw_flag, head).await?;

    if full_flag {
        let mut headers_rec = Record::new();
        headers_rec.push("request", headers_to_table(&req_headers_snapshot, head));
        headers_rec.push("response", headers_to_table(&response.headers, head));

        let mut full = Record::new();
        full.push("headers", Value::record(headers_rec, head));
        full.push("body", body_value);
        full.push("status", Value::int(i64::from(response.status), head));
        Ok(AsyncPipelineData::value(Value::record(full, head), None))
    } else {
        Ok(AsyncPipelineData::value(body_value, None))
    }
}

async fn decode_response_body<E: HeliosEnv>(
    ctx: &mut AsyncCommandContext<'_, E>,
    response: &HttpResponse,
    raw_flag: bool,
    span: Span,
) -> Result<Value, ShellError> {
    if !raw_flag
        && let Some(ct) = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
        && let Some(converter) = converter_for_content_type(ct)
        && let Ok(text) = std::str::from_utf8(&response.body)
        && let Some(decoded) = eval_call_by_name_async(
            ctx.engine_state,
            ctx.stack,
            converter,
            span,
            AsyncPipelineData::value(Value::string(text, span), None),
            &mut crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            },
        )
        .await?
    {
        return decoded.into_value_async(span).await;
    }

    Ok(match String::from_utf8(response.body.clone()) {
        Ok(text) => Value::string(text, span),
        Err(err) => Value::binary(err.into_bytes(), span),
    })
}

fn converter_for_content_type(content_type: &str) -> Option<&'static str> {
    let mime = content_type.split(';').next()?.trim().to_ascii_lowercase();
    match mime.as_str() {
        "application/json" | "text/json" => Some("from json"),
        "text/csv" => Some("from csv"),
        "text/tab-separated-values" => Some("from tsv"),
        "application/toml" | "text/toml" => Some("from toml"),
        "application/yaml" | "text/yaml" | "application/x-yaml" => Some("from yaml"),
        "application/xml" | "text/xml" => Some("from xml"),
        _ if mime.ends_with("+json") => Some("from json"),
        _ => None,
    }
}

fn encode_request_body(
    val: &Value,
    span: Span,
) -> Result<(Vec<u8>, Option<&'static str>), ShellError> {
    match val {
        Value::Nothing { .. } => Ok((Vec::new(), None)),
        Value::String { val, .. } => Ok((val.as_bytes().to_vec(), Some("text/plain"))),
        Value::Binary { val, .. } => Ok((val.to_vec(), Some("application/octet-stream"))),
        Value::Record { .. } | Value::List { .. } => {
            let json = nu_value_to_json(val);
            let bytes = serde_json::to_vec(&json).map_err(|err| {
                generic_error("failed to encode JSON body", err.to_string(), span)
            })?;
            Ok((bytes, Some("application/json")))
        }
        other => Ok((other.coerce_str()?.as_bytes().to_vec(), Some("text/plain"))),
    }
}

fn nu_value_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::Nothing { .. } => serde_json::Value::Null,
        Value::Bool { val, .. } => serde_json::Value::Bool(*val),
        Value::Int { val, .. } => serde_json::Value::Number((*val).into()),
        Value::Float { val, .. } => serde_json::Number::from_f64(*val)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::String { val, .. } | Value::Glob { val, .. } => {
            serde_json::Value::String(val.clone())
        }
        Value::Binary { val, .. } => {
            serde_json::Value::Array(val.iter().map(|b| serde_json::Value::from(*b)).collect())
        }
        Value::List { vals, .. } => {
            serde_json::Value::Array(vals.iter().map(nu_value_to_json).collect())
        }
        Value::Record { val, .. } => {
            let mut map = serde_json::Map::new();
            for (k, v) in val.iter() {
                map.insert(k.clone(), nu_value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        other => {
            serde_json::Value::String(other.to_abbreviated_string(&nu_protocol::Config::default()))
        }
    }
}

fn parse_headers(val: Option<&Value>, span: Span) -> Result<Vec<(String, String)>, ShellError> {
    let Some(val) = val else {
        return Ok(Vec::new());
    };
    let mut headers = Vec::new();
    match val {
        Value::Record { val, .. } => {
            for (k, v) in val.iter() {
                headers.push((k.clone(), v.coerce_str()?.into_owned()));
            }
        }
        Value::List { vals, .. } => {
            if !vals.len().is_multiple_of(2) {
                return Err(generic_error(
                    "invalid headers list",
                    "headers list must contain alternating name/value pairs",
                    span,
                ));
            }
            for pair in vals.as_chunks::<2>().0 {
                headers.push((
                    pair[0].coerce_str()?.into_owned(),
                    pair[1].coerce_str()?.into_owned(),
                ));
            }
        }
        other => {
            return Err(generic_error(
                "invalid headers",
                format!("expected record or list, found {}", other.get_type()),
                other.span(),
            ));
        }
    }
    Ok(headers)
}

fn headers_to_table(headers: &[(String, String)], span: Span) -> Value {
    let rows = headers
        .iter()
        .map(|(name, value)| {
            let mut rec = Record::new();
            rec.push("name", Value::string(name, span));
            rec.push("value", Value::string(value, span));
            Value::record(rec, span)
        })
        .collect();
    Value::list(rows, span)
}
