//! CSPRNG `random` commands (`random`, `random int`, `random float`,
//! `random bool`, `random chars`, `random binary`, `random uuid`) backed by
//! `getrandom` (`wasi:random` on WASI, OS CSPRNG on host) with zero `wasm_js`.

use std::ops::Bound;

use nu_engine::CallExt;
use nu_protocol::{
    Category, Range, ShellError, Signature, Span, Spanned, SyntaxShape, Type, Value,
};
use uuid::Uuid;

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::HeliosEnv;
use crate::error::generic_error;
use crate::pipeline::AsyncPipelineData;

/// ASCII alphanumeric charset matching Nushell's `random chars`.
const CHARS_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn fill_random(buf: &mut [u8], span: Span) -> Result<(), ShellError> {
    getrandom::fill(buf).map_err(|err| {
        generic_error(
            "CSPRNG failure",
            format!("failed to read random bytes from platform entropy source: {err}"),
            span,
        )
    })
}

fn random_u64(span: Span) -> Result<u64, ShellError> {
    let mut bytes = [0_u8; 8];
    fill_random(&mut bytes, span)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Unbiased uniform sampling in `[0, range_len)` via Lemire / rejection sampling.
fn random_below(range_len: u128, span: Span) -> Result<u128, ShellError> {
    if range_len <= 1 {
        return Ok(0);
    }
    let zone = u128::MAX - (u128::MAX % range_len);
    loop {
        let mut bytes = [0_u8; 16];
        fill_random(&mut bytes, span)?;
        let candidate = u128::from_le_bytes(bytes);
        if candidate < zone {
            return Ok(candidate % range_len);
        }
    }
}

/// Uniform `f64` in `[0.0, 1.0)` using 53 random significand bits.
fn random_unit_f64(span: Span) -> Result<f64, ShellError> {
    let bits = random_u64(span)? >> 11;
    // IEEE-754 double has 53 bits of significand precision: 2^-53.
    const SCALE: f64 = 1.0 / ((1_u64 << 53) as f64);
    Ok((bits as f64) * SCALE)
}

/// `random`: overview parent command.
#[derive(Debug, Clone, Copy)]
pub struct Random;

impl<E: HeliosEnv> AsyncCommand<E> for Random {
    fn name(&self) -> &str {
        "random"
    }

    fn description(&self) -> &str {
        "Generate cryptographically random values via the platform CSPRNG."
    }

    fn signature(&self) -> Signature {
        Signature::build("random")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let help = "Random subcommands: random int, random float, random bool, random chars, random binary, random uuid";
        Ok(AsyncPipelineData::value(
            Value::string(help, ctx.call.head),
            None,
        ))
    }
}

/// `random int [range]`: uniform random integer in `[min..max]`.
#[derive(Debug, Clone, Copy)]
pub struct RandomInt;

impl<E: HeliosEnv> AsyncCommand<E> for RandomInt {
    fn name(&self) -> &str {
        "random int"
    }

    fn description(&self) -> &str {
        "Generate a random integer [min..max]."
    }

    fn signature(&self) -> Signature {
        Signature::build("random int")
            .input_output_types(vec![(Type::Nothing, Type::Int)])
            .optional("range", SyntaxShape::Range, "Range of potential values.")
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let range: Option<Spanned<Range>> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;

        let value = match range {
            None => i64::try_from(random_u64(head)? & (i64::MAX as u64)).unwrap_or(0),
            Some(spanned) => match spanned.item {
                Range::IntRange(int_range) => {
                    let start = int_range.start();
                    let end_inclusive = match int_range.end() {
                        Bound::Included(end) => end,
                        Bound::Excluded(end) => end.checked_sub(1).ok_or_else(|| {
                            generic_error(
                                "empty range",
                                "exclusive upper bound underflows i64",
                                spanned.span,
                            )
                        })?,
                        Bound::Unbounded => i64::MAX,
                    };
                    if end_inclusive < start {
                        return Err(generic_error(
                            "invalid range",
                            format!("range start {start} exceeds end {end_inclusive}"),
                            spanned.span,
                        ));
                    }
                    let span_len = (i128::from(end_inclusive) - i128::from(start) + 1) as u128;
                    let offset = random_below(span_len, head)?;
                    i64::try_from(i128::from(start) + offset as i128).unwrap_or(start)
                }
                Range::FloatRange(_) => {
                    return Err(generic_error(
                        "invalid range",
                        "`random int` requires an integer range",
                        spanned.span,
                    ));
                }
            },
        };

        Ok(AsyncPipelineData::value(Value::int(value, head), None))
    }
}

/// `random float [range]`: uniform random float.
#[derive(Debug, Clone, Copy)]
pub struct RandomFloat;

impl<E: HeliosEnv> AsyncCommand<E> for RandomFloat {
    fn name(&self) -> &str {
        "random float"
    }

    fn description(&self) -> &str {
        "Generate a random float within a range [min..max]."
    }

    fn signature(&self) -> Signature {
        Signature::build("random float")
            .input_output_types(vec![(Type::Nothing, Type::Float)])
            .optional("range", SyntaxShape::Range, "Range of potential values.")
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let range: Option<Spanned<Range>> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;

        let value = match range {
            None => random_unit_f64(head)?,
            Some(spanned) => {
                let (min, max) = match spanned.item {
                    Range::IntRange(r) => {
                        let start = r.start() as f64;
                        let end = match r.end() {
                            Bound::Included(e) | Bound::Excluded(e) => e as f64,
                            Bound::Unbounded => 1.0,
                        };
                        (start, end)
                    }
                    Range::FloatRange(r) => {
                        let start = r.start();
                        let end = match r.end() {
                            Bound::Included(e) | Bound::Excluded(e) => e,
                            Bound::Unbounded => start + 1.0,
                        };
                        (start, end)
                    }
                };
                if max < min {
                    return Err(generic_error(
                        "invalid range",
                        format!("range start {min} exceeds end {max}"),
                        spanned.span,
                    ));
                }
                min + random_unit_f64(head)? * (max - min)
            }
        };

        Ok(AsyncPipelineData::value(Value::float(value, head), None))
    }
}

/// `random bool [--bias <float>]`: random boolean.
#[derive(Debug, Clone, Copy)]
pub struct RandomBool;

impl<E: HeliosEnv> AsyncCommand<E> for RandomBool {
    fn name(&self) -> &str {
        "random bool"
    }

    fn description(&self) -> &str {
        "Generate a random boolean value."
    }

    fn signature(&self) -> Signature {
        Signature::build("random bool")
            .input_output_types(vec![(Type::Nothing, Type::Bool)])
            .named(
                "bias",
                SyntaxShape::Number,
                "Probability between 0.0 and 1.0 of returning true.",
                Some('b'),
            )
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let bias: Option<f64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "bias")?;
        let prob = bias.unwrap_or(0.5);
        if !(0.0..=1.0).contains(&prob) {
            return Err(generic_error(
                "invalid bias",
                format!("bias must be in 0.0..=1.0, got {prob}"),
                head,
            ));
        }
        let result = random_unit_f64(head)? < prob;
        Ok(AsyncPipelineData::value(Value::bool(result, head), None))
    }
}

/// `random chars [--length <int>]`: random ASCII alphanumeric string.
#[derive(Debug, Clone, Copy)]
pub struct RandomChars;

impl<E: HeliosEnv> AsyncCommand<E> for RandomChars {
    fn name(&self) -> &str {
        "random chars"
    }

    fn description(&self) -> &str {
        "Generate random alphanumeric characters."
    }

    fn signature(&self) -> Signature {
        Signature::build("random chars")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .named(
                "length",
                SyntaxShape::Int,
                "Number of characters to generate (default 25).",
                Some('l'),
            )
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let length: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "length")?;
        // Nushell default length for `random chars` is 25.
        let count = match length {
            None => 25_usize,
            Some(n) if n < 0 => {
                return Err(generic_error(
                    "invalid length",
                    "length must be non-negative",
                    head,
                ));
            }
            Some(n) => usize::try_from(n).unwrap_or(0),
        };

        let mut out = String::with_capacity(count);
        for _ in 0..count {
            let idx = random_below(CHARS_ALPHABET.len() as u128, head)? as usize;
            out.push(CHARS_ALPHABET[idx] as char);
        }
        Ok(AsyncPipelineData::value(Value::string(out, head), None))
    }
}

/// `random binary <length>`: random raw bytes.
#[derive(Debug, Clone, Copy)]
pub struct RandomBinary;

impl<E: HeliosEnv> AsyncCommand<E> for RandomBinary {
    fn name(&self) -> &str {
        "random binary"
    }

    fn description(&self) -> &str {
        "Generate random bytes."
    }

    fn signature(&self) -> Signature {
        Signature::build("random binary")
            .input_output_types(vec![(Type::Nothing, Type::Binary)])
            .required("length", SyntaxShape::Int, "Number of bytes to generate.")
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let length: i64 = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        if length < 0 {
            return Err(generic_error(
                "invalid length",
                "length must be non-negative",
                head,
            ));
        }
        let mut bytes = vec![0_u8; usize::try_from(length).unwrap_or(0)];
        fill_random(&mut bytes, head)?;
        Ok(AsyncPipelineData::value(Value::binary(bytes, head), None))
    }
}

/// `random uuid [-v <version>]`: generate a UUID v4 (or v7) from platform CSPRNG bytes.
#[derive(Debug, Clone, Copy)]
pub struct RandomUuid;

impl<E: HeliosEnv> AsyncCommand<E> for RandomUuid {
    fn name(&self) -> &str {
        "random uuid"
    }

    fn description(&self) -> &str {
        "Generate a random UUID (v4 by default, or v7)."
    }

    fn signature(&self) -> Signature {
        Signature::build("random uuid")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .named(
                "version",
                SyntaxShape::Int,
                "UUID version (4 or 7; default 4).",
                Some('v'),
            )
            .category(Category::Random)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let version: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "version")?;
        let mut raw = [0_u8; 16];
        fill_random(&mut raw, head)?;

        let uuid = match version.unwrap_or(4) {
            4 => uuid::Builder::from_random_bytes(raw).into_uuid(),
            7 => {
                let now_ms = chrono::Utc::now().timestamp_millis().max(0).cast_unsigned();
                let mut rand_tail = [0_u8; 10];
                rand_tail.copy_from_slice(&raw[..10]);
                Uuid::new_v7(uuid::Timestamp::from_unix_time(
                    now_ms / 1000,
                    ((now_ms % 1000) * 1_000_000) as u32,
                    u16::from_be_bytes([rand_tail[0], rand_tail[1]]).into(),
                    12,
                ))
            }
            other => {
                return Err(generic_error(
                    "unsupported uuid version",
                    format!("expected version 4 or 7, got {other}"),
                    head,
                ));
            }
        };

        Ok(AsyncPipelineData::value(
            Value::string(uuid.to_string(), head),
            None,
        ))
    }
}
