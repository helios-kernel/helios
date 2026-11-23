use std::path::PathBuf;

use proc_macro::TokenStream;
use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Path as SynPath, Token, braced};
use thiserror::Error;
use wit_parser::{PackageId, Resolve, UnresolvedPackageGroup, WorldId};

mod codegen;

#[derive(Debug, Error)]
pub(crate) enum CodegenError {
    #[error("`wit_rpc::generate!` requires at least `path` or `inline`")]
    MissingSource,

    #[error("failed to resolve `CARGO_MANIFEST_DIR`: {detail}")]
    ManifestDir { detail: String },

    #[error("failed to load WIT path `{path}`: {report}")]
    LoadPath { path: String, report: String },

    #[error("failed to parse inline WIT: {report}")]
    ParseInline { report: String },

    #[error("failed to resolve inline WIT package: {report}")]
    ResolveInline { report: String },

    #[error("failed to select WIT world `{world}`: {report}")]
    SelectWorld { world: String, report: String },

    #[error("WIT interface `{interface}` was not found in resolved packages")]
    UnknownInterface { interface: String },
}

struct MacroConfig {
    path: Option<LitStr>,
    inline: Option<LitStr>,
    world: Option<LitStr>,
    interface: Option<LitStr>,
    crate_path: Option<SynPath>,
}

impl Parse for MacroConfig {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let content_buf;
        let stream = if input.peek(syn::token::Brace) {
            braced!(content_buf in input);
            &content_buf
        } else {
            input
        };

        let mut config = Self {
            path: None,
            inline: None,
            world: None,
            interface: None,
            crate_path: None,
        };

        while !stream.is_empty() {
            let key: Ident = stream.parse()?;
            stream.parse::<Token![:]>()?;
            match key.to_string().as_str() {
                "path" => {
                    config.path = Some(stream.parse()?);
                }
                "inline" => {
                    config.inline = Some(stream.parse()?);
                }
                "world" => {
                    config.world = Some(stream.parse()?);
                }
                "interface" => {
                    config.interface = Some(stream.parse()?);
                }
                "crate_path" => {
                    config.crate_path = Some(stream.parse()?);
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        key,
                        format!(
                            "unknown `wit_rpc::generate!` option `{other}`; expected `path`, `inline`, `world`, `interface`, or `crate_path`"
                        ),
                    ));
                }
            }
            if stream.peek(Token![,]) {
                stream.parse::<Token![,]>()?;
            }
        }

        Ok(config)
    }
}

/// Generates transparent async WIT-RPC types, clients, resource handles, and
/// server dispatchers directly from WIT definitions at compile time.
#[proc_macro]
pub fn generate(input: TokenStream) -> TokenStream {
    let config = syn::parse_macro_input!(input as MacroConfig);
    expand(config)
        .unwrap_or_else(|err| {
            syn::Error::new(Span::call_site(), err.to_string()).into_compile_error()
        })
        .into()
}

fn expand(config: MacroConfig) -> Result<proc_macro2::TokenStream, CodegenError> {
    if config.path.is_none() && config.inline.is_none() {
        return Err(CodegenError::MissingSource);
    }

    let mut resolve = Resolve::default();
    let mut tracked_files: Vec<PathBuf> = Vec::new();
    let mut primary_pkg: Option<PackageId> = None;

    if let Some(path_lit) = &config.path {
        let raw_path = PathBuf::from(path_lit.value());
        let resolved_path = if raw_path.is_absolute() {
            raw_path
        } else {
            let manifest_dir =
                std::env::var("CARGO_MANIFEST_DIR").map_err(|err| CodegenError::ManifestDir {
                    detail: err.to_string(),
                })?;
            PathBuf::from(manifest_dir).join(raw_path)
        };
        let display_path = resolved_path.display().to_string();
        let (pkg_id, sources) =
            resolve
                .push_path(&resolved_path)
                .map_err(|err| CodegenError::LoadPath {
                    path: display_path,
                    report: format!("{err:#}"),
                })?;
        for file in sources.paths() {
            tracked_files.push(file.to_path_buf());
        }
        primary_pkg = Some(pkg_id);
    }

    if let Some(inline_lit) = &config.inline {
        let group = UnresolvedPackageGroup::parse("inline.wit", &inline_lit.value()).map_err(
            |(map, parse_err)| CodegenError::ParseInline {
                report: parse_err.render(&map),
            },
        )?;
        let pkg_id =
            resolve
                .push_group(group)
                .map_err(|resolve_err| CodegenError::ResolveInline {
                    report: resolve_err.render(&resolve.source_map),
                })?;
        primary_pkg = Some(pkg_id);
    }

    let main_pkg = primary_pkg.ok_or(CodegenError::MissingSource)?;

    let selected_world: Option<WorldId> = match &config.world {
        Some(world_lit) => {
            let name = world_lit.value();
            let id = resolve
                .select_world(&[main_pkg], Some(&name))
                .map_err(|err| CodegenError::SelectWorld {
                    world: name,
                    report: format!("{err:#}"),
                })?;
            Some(id)
        }
        None if config.interface.is_none() && resolve.packages[main_pkg].worlds.len() == 1 => {
            resolve.packages[main_pkg].worlds.values().next().copied()
        }
        None => None,
    };

    let selected_interface = config.interface.as_ref().map(LitStr::value);
    let rt_path: SynPath = config
        .crate_path
        .unwrap_or_else(|| syn::parse_quote!(::helios_wit_rpc));

    codegen::generate_bindings(
        &resolve,
        main_pkg,
        selected_world,
        selected_interface.as_deref(),
        &tracked_files,
        &rt_path,
    )
}
