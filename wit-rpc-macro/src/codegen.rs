use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use heck::{ToShoutySnakeCase as _, ToSnakeCase as _, ToUpperCamelCase as _};
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::{format_ident, quote};
use syn::Path as SynPath;
use wit_parser::{
    Enum, Flags, Function, FunctionKind, Handle, InterfaceId, PackageId, Record, Resolve, Result_,
    Tuple, Type, TypeDefKind, TypeId, TypeOwner, Variant, WorldId, WorldItem,
};

use crate::CodegenError;

pub(crate) fn generate_bindings(
    resolve: &Resolve,
    main_pkg: PackageId,
    selected_world: Option<WorldId>,
    selected_interface: Option<&str>,
    tracked_files: &[PathBuf],
    rt: &SynPath,
) -> Result<TokenStream, CodegenError> {
    let seed_interfaces =
        select_seed_interfaces(resolve, main_pkg, selected_world, selected_interface)?;
    let all_interfaces = collect_reachable_interfaces(resolve, &seed_interfaces);

    let mut tree: BTreeMap<String, BTreeMap<String, Vec<InterfaceId>>> = BTreeMap::new();
    for &iface_id in &all_interfaces {
        let iface = &resolve.interfaces[iface_id];
        let pkg_id = iface
            .package
            .expect("resolved WIT interface must have package");
        let pkg = &resolve.packages[pkg_id];
        tree.entry(pkg.name.namespace.clone())
            .or_default()
            .entry(pkg.name.name.clone())
            .or_default()
            .push(iface_id);
    }

    let mut ns_modules = Vec::new();
    for (ns_raw, pkg_map) in &tree {
        let ns_ident = to_snake_ident(ns_raw);
        let mut pkg_modules = Vec::new();
        for (pkg_raw, iface_ids) in pkg_map {
            let pkg_ident = to_snake_ident(pkg_raw);
            let mut iface_modules = Vec::new();
            for &iface_id in iface_ids {
                iface_modules.push(generate_interface_module(resolve, iface_id, rt));
            }
            pkg_modules.push(quote! {
                pub mod #pkg_ident {
                    #(#iface_modules)*
                }
            });
        }
        ns_modules.push(quote! {
            pub mod #ns_ident {
                #(#pkg_modules)*
            }
        });
    }

    let world_wrapper = selected_world
        .map(|world_id| generate_world_wrapper(resolve, world_id, &seed_interfaces, rt));

    let file_trackers = tracked_files.iter().filter_map(|path| {
        path.to_str().map(|s| {
            quote! {
                const _: &[u8] = include_bytes!(#s);
            }
        })
    });

    Ok(quote! {
        #(#file_trackers)*
        #(#ns_modules)*
        #world_wrapper
    })
}

fn select_seed_interfaces(
    resolve: &Resolve,
    main_pkg: PackageId,
    selected_world: Option<WorldId>,
    selected_interface: Option<&str>,
) -> Result<Vec<InterfaceId>, CodegenError> {
    if let Some(target) = selected_interface {
        for (id, iface) in &resolve.interfaces {
            let Some(iface_name) = &iface.name else {
                continue;
            };
            if iface.package == Some(main_pkg) && iface_name == target {
                return Ok(vec![id]);
            }
            if let Some(full_id) = resolve.id_of(id) {
                let unversioned = full_id.split('@').next().unwrap_or(&full_id);
                if full_id == target || unversioned == target {
                    return Ok(vec![id]);
                }
            }
        }
        return Err(CodegenError::UnknownInterface {
            interface: target.to_owned(),
        });
    }

    let mut seeds = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(world_id) = selected_world {
        let world = &resolve.worlds[world_id];
        for item in world.exports.values().chain(world.imports.values()) {
            if let WorldItem::Interface { id, .. } = item
                && seen.insert(id.index())
            {
                seeds.push(*id);
            }
        }
        if !seeds.is_empty() {
            return Ok(seeds);
        }
    }

    for &id in resolve.packages[main_pkg].interfaces.values() {
        if seen.insert(id.index()) {
            seeds.push(id);
        }
    }
    Ok(seeds)
}

fn collect_reachable_interfaces(resolve: &Resolve, seeds: &[InterfaceId]) -> Vec<InterfaceId> {
    let mut visited = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut stack: Vec<InterfaceId> = seeds.to_vec();

    while let Some(iface_id) = stack.pop() {
        if !visited.insert(iface_id.index()) {
            continue;
        }
        ordered.push(iface_id);
        let iface = &resolve.interfaces[iface_id];
        for &ty_id in iface.types.values() {
            collect_type_owners(resolve, Type::Id(ty_id), &mut stack);
        }
        for func in iface.functions.values() {
            for param in &func.params {
                collect_type_owners(resolve, param.ty, &mut stack);
            }
            if let Some(ret) = func.result {
                collect_type_owners(resolve, ret, &mut stack);
            }
        }
    }

    ordered.sort_by_key(|id| id.index());
    ordered
}

fn collect_type_owners(resolve: &Resolve, ty: Type, out: &mut Vec<InterfaceId>) {
    let Type::Id(id) = ty else {
        return;
    };
    let def = &resolve.types[id];
    if let TypeOwner::Interface(owner) = def.owner {
        out.push(owner);
    }
    match &def.kind {
        TypeDefKind::Record(rec) => {
            for field in &rec.fields {
                collect_type_owners(resolve, field.ty, out);
            }
        }
        TypeDefKind::Tuple(tup) => {
            for &inner in &tup.types {
                collect_type_owners(resolve, inner, out);
            }
        }
        TypeDefKind::Variant(var) => {
            for case in &var.cases {
                if let Some(inner) = case.ty {
                    collect_type_owners(resolve, inner, out);
                }
            }
        }
        TypeDefKind::Option(inner)
        | TypeDefKind::List(inner)
        | TypeDefKind::FixedLengthList(inner, _)
        | TypeDefKind::Type(inner) => collect_type_owners(resolve, *inner, out),
        TypeDefKind::Map(k, v) => {
            collect_type_owners(resolve, *k, out);
            collect_type_owners(resolve, *v, out);
        }
        TypeDefKind::Result(res) => {
            if let Some(ok) = res.ok {
                collect_type_owners(resolve, ok, out);
            }
            if let Some(err) = res.err {
                collect_type_owners(resolve, err, out);
            }
        }
        TypeDefKind::Future(Some(inner)) | TypeDefKind::Stream(Some(inner)) => {
            collect_type_owners(resolve, *inner, out);
        }
        TypeDefKind::Handle(Handle::Own(res_id) | Handle::Borrow(res_id)) => {
            collect_type_owners(resolve, Type::Id(*res_id), out);
        }
        TypeDefKind::Resource
        | TypeDefKind::Flags(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Future(None)
        | TypeDefKind::Stream(None)
        | TypeDefKind::Unknown => {}
    }
}

fn canonical_type_id(resolve: &Resolve, mut id: TypeId) -> TypeId {
    while let TypeDefKind::Type(Type::Id(target)) = resolve.types[id].kind {
        id = target;
    }
    id
}

#[derive(Clone)]
struct ResourceMeta {
    canon_id: TypeId,
    wit_name: String,
    assoc_ident: Ident,
    variant_ident: Ident,
    own_wrapper_ident: Ident,
    borrow_wrapper_ident: Ident,
    client_path: TokenStream,
}

struct IfaceContext<'a> {
    resolve: &'a Resolve,
    iface_id: InterfaceId,
    rt: &'a SynPath,
    resources: Vec<ResourceMeta>,
    res_by_canon: BTreeMap<usize, usize>,
}

impl<'a> IfaceContext<'a> {
    fn new(resolve: &'a Resolve, iface_id: InterfaceId, rt: &'a SynPath) -> Self {
        let iface = &resolve.interfaces[iface_id];
        let mut canon_ids = Vec::new();
        let mut seen = BTreeSet::new();

        for &ty_id in iface.types.values() {
            collect_resources_in_type(resolve, Type::Id(ty_id), &mut seen, &mut canon_ids);
        }
        for func in iface.functions.values() {
            if let Some(res_id) = func.kind.resource() {
                let canon = canonical_type_id(resolve, res_id);
                if seen.insert(canon.index()) {
                    canon_ids.push(canon);
                }
            }
            for param in &func.params {
                collect_resources_in_type(resolve, param.ty, &mut seen, &mut canon_ids);
            }
            if let Some(ret) = func.result {
                collect_resources_in_type(resolve, ret, &mut seen, &mut canon_ids);
            }
        }

        let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
        for &cid in &canon_ids {
            let raw = resolve.types[cid]
                .name
                .as_deref()
                .unwrap_or("resource")
                .to_upper_camel_case();
            *name_counts.entry(raw).or_insert(0) += 1;
        }

        let mut resources = Vec::new();
        let mut res_by_canon = BTreeMap::new();
        for (idx, cid) in canon_ids.into_iter().enumerate() {
            let def = &resolve.types[cid];
            let wit_name = def
                .name
                .clone()
                .unwrap_or_else(|| format!("resource-{idx}"));
            let base_pascal = wit_name.to_upper_camel_case();
            let disambiguated = if name_counts.get(&base_pascal).copied().unwrap_or(0) > 1
                && let TypeOwner::Interface(owner_iface) = def.owner
                && owner_iface != iface_id
            {
                let owner_name = resolve.interfaces[owner_iface]
                    .name
                    .as_deref()
                    .unwrap_or("ext")
                    .to_upper_camel_case();
                format!("{owner_name}{base_pascal}")
            } else {
                base_pascal
            };

            let assoc_ident = escape_type_ident(&disambiguated);
            let variant_ident = format_ident!("Res{}", idx);
            let own_wrapper_ident = format_ident!("__OwnRes{}", idx);
            let borrow_wrapper_ident = format_ident!("__BorrowRes{}", idx);
            let client_path = type_ref_from_iface(resolve, iface_id, cid);

            res_by_canon.insert(cid.index(), idx);
            resources.push(ResourceMeta {
                canon_id: cid,
                wit_name,
                assoc_ident,
                variant_ident,
                own_wrapper_ident,
                borrow_wrapper_ident,
                client_path,
            });
        }

        Self {
            resolve,
            iface_id,
            rt,
            resources,
            res_by_canon,
        }
    }

    fn resource_meta(&self, id: TypeId) -> &ResourceMeta {
        let canon = canonical_type_id(self.resolve, id);
        let idx = self.res_by_canon[&canon.index()];
        &self.resources[idx]
    }
}

fn collect_resources_in_type(
    resolve: &Resolve,
    ty: Type,
    seen: &mut BTreeSet<usize>,
    out: &mut Vec<TypeId>,
) {
    let Type::Id(id) = ty else {
        return;
    };
    let def = &resolve.types[id];
    match &def.kind {
        TypeDefKind::Resource => {
            let canon = canonical_type_id(resolve, id);
            if seen.insert(canon.index()) {
                out.push(canon);
            }
        }
        TypeDefKind::Handle(Handle::Own(r) | Handle::Borrow(r)) => {
            let canon = canonical_type_id(resolve, *r);
            if seen.insert(canon.index()) {
                out.push(canon);
            }
        }
        TypeDefKind::Record(rec) => {
            for field in &rec.fields {
                collect_resources_in_type(resolve, field.ty, seen, out);
            }
        }
        TypeDefKind::Tuple(tup) => {
            for &inner in &tup.types {
                collect_resources_in_type(resolve, inner, seen, out);
            }
        }
        TypeDefKind::Variant(var) => {
            for case in &var.cases {
                if let Some(inner) = case.ty {
                    collect_resources_in_type(resolve, inner, seen, out);
                }
            }
        }
        TypeDefKind::Option(inner)
        | TypeDefKind::List(inner)
        | TypeDefKind::FixedLengthList(inner, _)
        | TypeDefKind::Type(inner) => collect_resources_in_type(resolve, *inner, seen, out),
        TypeDefKind::Map(k, v) => {
            collect_resources_in_type(resolve, *k, seen, out);
            collect_resources_in_type(resolve, *v, seen, out);
        }
        TypeDefKind::Result(res) => {
            if let Some(ok) = res.ok {
                collect_resources_in_type(resolve, ok, seen, out);
            }
            if let Some(err) = res.err {
                collect_resources_in_type(resolve, err, seen, out);
            }
        }
        TypeDefKind::Future(Some(inner)) | TypeDefKind::Stream(Some(inner)) => {
            collect_resources_in_type(resolve, *inner, seen, out);
        }
        TypeDefKind::Flags(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Future(None)
        | TypeDefKind::Stream(None)
        | TypeDefKind::Unknown => {}
    }
}

fn own_resources_in_typedef(resolve: &Resolve, def_id: TypeId) -> Vec<TypeId> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    collect_own_handles(resolve, Type::Id(def_id), &mut seen, &mut out);
    out
}

fn collect_own_handles(
    resolve: &Resolve,
    ty: Type,
    seen: &mut BTreeSet<usize>,
    out: &mut Vec<TypeId>,
) {
    let Type::Id(id) = ty else {
        return;
    };
    match &resolve.types[id].kind {
        TypeDefKind::Handle(Handle::Own(r)) => {
            let canon = canonical_type_id(resolve, *r);
            if seen.insert(canon.index()) {
                out.push(canon);
            }
        }
        TypeDefKind::Record(rec) => {
            for f in &rec.fields {
                collect_own_handles(resolve, f.ty, seen, out);
            }
        }
        TypeDefKind::Tuple(tup) => {
            for &inner in &tup.types {
                collect_own_handles(resolve, inner, seen, out);
            }
        }
        TypeDefKind::Variant(var) => {
            for c in &var.cases {
                if let Some(inner) = c.ty {
                    collect_own_handles(resolve, inner, seen, out);
                }
            }
        }
        TypeDefKind::Option(inner)
        | TypeDefKind::List(inner)
        | TypeDefKind::FixedLengthList(inner, _)
        | TypeDefKind::Type(inner) => collect_own_handles(resolve, *inner, seen, out),
        TypeDefKind::Map(k, v) => {
            collect_own_handles(resolve, *k, seen, out);
            collect_own_handles(resolve, *v, seen, out);
        }
        TypeDefKind::Result(res) => {
            if let Some(ok) = res.ok {
                collect_own_handles(resolve, ok, seen, out);
            }
            if let Some(err) = res.err {
                collect_own_handles(resolve, err, seen, out);
            }
        }
        TypeDefKind::Resource
        | TypeDefKind::Handle(Handle::Borrow(_))
        | TypeDefKind::Flags(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Future(_)
        | TypeDefKind::Stream(_)
        | TypeDefKind::Unknown => {}
    }
}

#[derive(Clone, Copy)]
struct DeriveCaps {
    can_clone: bool,
    can_partial_eq: bool,
    can_eq: bool,
}

fn compute_derive_caps(resolve: &Resolve, ty: Type) -> DeriveCaps {
    match ty {
        Type::F32 | Type::F64 => DeriveCaps {
            can_clone: true,
            can_partial_eq: true,
            can_eq: false,
        },
        Type::Bool
        | Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::S8
        | Type::S16
        | Type::S32
        | Type::S64
        | Type::Char
        | Type::String
        | Type::ErrorContext => DeriveCaps {
            can_clone: true,
            can_partial_eq: true,
            can_eq: true,
        },
        Type::Id(id) => match &resolve.types[id].kind {
            TypeDefKind::Resource
            | TypeDefKind::Handle(_)
            | TypeDefKind::Future(_)
            | TypeDefKind::Stream(_)
            | TypeDefKind::Unknown => DeriveCaps {
                can_clone: false,
                can_partial_eq: false,
                can_eq: false,
            },
            TypeDefKind::Flags(_) | TypeDefKind::Enum(_) => DeriveCaps {
                can_clone: true,
                can_partial_eq: true,
                can_eq: true,
            },
            TypeDefKind::Record(rec) => merge_caps(
                rec.fields
                    .iter()
                    .map(|f| compute_derive_caps(resolve, f.ty)),
            ),
            TypeDefKind::Tuple(tup) => {
                merge_caps(tup.types.iter().map(|&t| compute_derive_caps(resolve, t)))
            }
            TypeDefKind::Variant(var) => merge_caps(
                var.cases
                    .iter()
                    .filter_map(|c| c.ty.map(|t| compute_derive_caps(resolve, t))),
            ),
            TypeDefKind::Option(inner)
            | TypeDefKind::List(inner)
            | TypeDefKind::FixedLengthList(inner, _)
            | TypeDefKind::Type(inner) => compute_derive_caps(resolve, *inner),
            TypeDefKind::Map(k, v) => merge_caps([
                compute_derive_caps(resolve, *k),
                compute_derive_caps(resolve, *v),
            ]),
            TypeDefKind::Result(res) => merge_caps(
                [res.ok, res.err]
                    .into_iter()
                    .flatten()
                    .map(|t| compute_derive_caps(resolve, t)),
            ),
        },
    }
}

fn merge_caps(iter: impl IntoIterator<Item = DeriveCaps>) -> DeriveCaps {
    let mut acc = DeriveCaps {
        can_clone: true,
        can_partial_eq: true,
        can_eq: true,
    };
    for cap in iter {
        acc.can_clone &= cap.can_clone;
        acc.can_partial_eq &= cap.can_partial_eq;
        acc.can_eq &= cap.can_eq;
    }
    acc
}

fn derive_attr(caps: DeriveCaps) -> TokenStream {
    match (caps.can_clone, caps.can_partial_eq, caps.can_eq) {
        (true, true, true) => quote!(#[derive(Debug, Clone, PartialEq, Eq)]),
        (true, true, false) => quote!(#[derive(Debug, Clone, PartialEq)]),
        (true, false, _) => quote!(#[derive(Debug, Clone)]),
        (false, _, _) => quote!(#[derive(Debug)]),
    }
}

#[derive(Clone, Copy)]
enum TypeMode<'a> {
    /// Client-facing Rust types (`Counter`, `&Counter`).
    Client,
    /// Type definition parameters (`__ParamRes0` for owned resources in `def_params`).
    Def(&'a BTreeMap<usize, Ident>),
    /// Server `Handler` trait signatures (`Self::Counter`, `&Self::Counter`).
    ServerTrait,
    /// Server wire decode/encode adapters (`__OwnRes0<H>`, `__BorrowRes0<H>`).
    ServerWire,
}

fn render_type(ctx: &IfaceContext<'_>, ty: Type, mode: TypeMode<'_>) -> TokenStream {
    let rt = ctx.rt;
    match ty {
        Type::Bool => quote!(bool),
        Type::U8 => quote!(u8),
        Type::U16 => quote!(u16),
        Type::U32 => quote!(u32),
        Type::U64 => quote!(u64),
        Type::S8 => quote!(i8),
        Type::S16 => quote!(i16),
        Type::S32 => quote!(i32),
        Type::S64 => quote!(i64),
        Type::F32 => quote!(f32),
        Type::F64 => quote!(f64),
        Type::Char => quote!(char),
        Type::String => quote!(::std::string::String),
        Type::ErrorContext => quote!(#rt::ErrorContext),
        Type::Id(id) => render_type_id(ctx, id, mode),
    }
}

fn render_type_id(ctx: &IfaceContext<'_>, id: TypeId, mode: TypeMode<'_>) -> TokenStream {
    let rt = ctx.rt;
    let def = &ctx.resolve.types[id];

    // Named user-defined types (`Record`, `Variant`, `Enum`, `Flags`, `Resource`, or named `Type` alias)
    // except anonymous inline types (`def.name.is_none()`).
    if def.name.is_some()
        && !matches!(
            def.kind,
            TypeDefKind::Handle(_)
                | TypeDefKind::Option(_)
                | TypeDefKind::Result(_)
                | TypeDefKind::List(_)
                | TypeDefKind::FixedLengthList(_, _)
                | TypeDefKind::Tuple(_)
                | TypeDefKind::Future(_)
                | TypeDefKind::Stream(_)
                | TypeDefKind::Map(_, _)
        )
    {
        if matches!(def.kind, TypeDefKind::Resource) {
            let meta = ctx.resource_meta(id);
            return match mode {
                TypeMode::Client => meta.client_path.clone(),
                TypeMode::Def(map) => {
                    let param = &map[&meta.canon_id.index()];
                    quote!(#param)
                }
                TypeMode::ServerTrait => {
                    let assoc = &meta.assoc_ident;
                    quote!(Self::#assoc)
                }
                TypeMode::ServerWire => {
                    let wrap = &meta.own_wrapper_ident;
                    quote!(#wrap<__H>)
                }
            };
        }

        let path = type_ref_from_iface(ctx.resolve, ctx.iface_id, id);
        let res_params = own_resources_in_typedef(ctx.resolve, id);
        if res_params.is_empty() {
            return path;
        }
        return match mode {
            TypeMode::Client => path,
            TypeMode::Def(map) => {
                let args = res_params.iter().map(|cid| {
                    let ident = &map[&cid.index()];
                    quote!(#ident)
                });
                quote!(#path<#(#args),*>)
            }
            TypeMode::ServerTrait => {
                let args = res_params.iter().map(|cid| {
                    let assoc = &ctx.resource_meta(*cid).assoc_ident;
                    quote!(Self::#assoc)
                });
                quote!(#path<#(#args),*>)
            }
            TypeMode::ServerWire => {
                let args = res_params.iter().map(|cid| {
                    let wrap = &ctx.resource_meta(*cid).own_wrapper_ident;
                    quote!(#wrap<__H>)
                });
                quote!(#path<#(#args),*>)
            }
        };
    }

    match &def.kind {
        TypeDefKind::Handle(Handle::Own(res_id)) => {
            let meta = ctx.resource_meta(*res_id);
            match mode {
                TypeMode::Client => meta.client_path.clone(),
                TypeMode::Def(map) => {
                    let param = &map[&meta.canon_id.index()];
                    quote!(#param)
                }
                TypeMode::ServerTrait => {
                    let assoc = &meta.assoc_ident;
                    quote!(Self::#assoc)
                }
                TypeMode::ServerWire => {
                    let wrap = &meta.own_wrapper_ident;
                    quote!(#wrap<__H>)
                }
            }
        }
        TypeDefKind::Handle(Handle::Borrow(res_id)) => {
            let meta = ctx.resource_meta(*res_id);
            match mode {
                TypeMode::Client => {
                    let p = &meta.client_path;
                    quote!(&#p)
                }
                TypeMode::Def(_) => {
                    let p = &meta.client_path;
                    quote!(&#p)
                }
                TypeMode::ServerTrait => {
                    let assoc = &meta.assoc_ident;
                    quote!(&'a Self::#assoc)
                }
                TypeMode::ServerWire => {
                    let wrap = &meta.borrow_wrapper_ident;
                    quote!(#wrap<__H>)
                }
            }
        }
        TypeDefKind::Option(inner) => {
            let inner_ts = render_type(ctx, *inner, mode);
            quote!(::core::option::Option<#inner_ts>)
        }
        TypeDefKind::List(inner) => {
            let inner_ts = render_type(ctx, *inner, mode);
            quote!(::std::vec::Vec<#inner_ts>)
        }
        TypeDefKind::FixedLengthList(inner, len) => {
            let inner_ts = render_type(ctx, *inner, mode);
            let len_usize = *len as usize;
            quote!([#inner_ts; #len_usize])
        }
        TypeDefKind::Map(k, v) => {
            let k_ts = render_type(ctx, *k, mode);
            let v_ts = render_type(ctx, *v, mode);
            quote!(::std::vec::Vec<(#k_ts, #v_ts)>)
        }
        TypeDefKind::Tuple(Tuple { types }) => {
            if types.is_empty() {
                quote!(())
            } else if types.len() == 1 {
                let t0 = render_type(ctx, types[0], mode);
                quote!((#t0,))
            } else {
                let elems = types.iter().map(|&t| render_type(ctx, t, mode));
                quote!((#(#elems),*))
            }
        }
        TypeDefKind::Result(Result_ { ok, err }) => {
            let ok_ts = ok.map_or_else(|| quote!(()), |t| render_type(ctx, t, mode));
            let err_ts = err.map_or_else(|| quote!(()), |t| render_type(ctx, t, mode));
            quote!(::core::result::Result<#ok_ts, #err_ts>)
        }
        TypeDefKind::Stream(payload) => {
            let inner_ts =
                payload.map_or_else(|| quote!(()), |t| render_type(ctx, t, TypeMode::Client));
            quote!(#rt::StreamReader<#inner_ts>)
        }
        TypeDefKind::Future(payload) => {
            let inner_ts =
                payload.map_or_else(|| quote!(()), |t| render_type(ctx, t, TypeMode::Client));
            quote!(#rt::FutureReader<#inner_ts>)
        }
        TypeDefKind::Type(inner) => render_type(ctx, *inner, mode),
        TypeDefKind::Record(_)
        | TypeDefKind::Resource
        | TypeDefKind::Flags(_)
        | TypeDefKind::Variant(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Unknown => unreachable!("named WIT types handled above"),
    }
}

fn type_ref_from_iface(
    resolve: &Resolve,
    from_iface: InterfaceId,
    target_id: TypeId,
) -> TokenStream {
    let def = &resolve.types[target_id];
    let ident = escape_type_ident(&def.name.as_deref().unwrap_or("Anon").to_upper_camel_case());
    match def.owner {
        TypeOwner::Interface(owner_iface) if owner_iface == from_iface => quote!(#ident),
        TypeOwner::Interface(owner_iface) => {
            let owner = &resolve.interfaces[owner_iface];
            let pkg = &resolve.packages[owner.package.expect("interface package")];
            let ns_mod = to_snake_ident(&pkg.name.namespace);
            let pkg_mod = to_snake_ident(&pkg.name.name);
            let iface_mod = to_snake_ident(owner.name.as_deref().expect("interface name"));
            quote!(super::super::super::#ns_mod::#pkg_mod::#iface_mod::#ident)
        }
        TypeOwner::World(_) | TypeOwner::None => quote!(#ident),
    }
}

fn generate_interface_module(
    resolve: &Resolve,
    iface_id: InterfaceId,
    rt: &SynPath,
) -> TokenStream {
    let iface = &resolve.interfaces[iface_id];
    let iface_raw_name = iface.name.as_deref().expect("named WIT interface");
    let iface_mod_ident = to_snake_ident(iface_raw_name);
    let pkg = &resolve.packages[iface.package.expect("interface package")];
    let versioned_instance = pkg.name.interface_id(iface_raw_name);
    let unversioned_instance = format!("{}:{}/{iface_raw_name}", pkg.name.namespace, pkg.name.name);

    let ctx = IfaceContext::new(resolve, iface_id, rt);

    let mut type_defs = Vec::new();
    let mut local_type_names = BTreeSet::new();

    for (wit_type_name, &ty_id) in &iface.types {
        let pascal = wit_type_name.to_upper_camel_case();
        local_type_names.insert(pascal);
        type_defs.push(generate_typedef(&ctx, wit_type_name, ty_id));
    }

    let resource_methods = generate_client_resource_methods(&ctx, &versioned_instance);
    let client_struct = generate_client_struct(&ctx, &versioned_instance, &local_type_names);
    let server_items = generate_server_items(
        &ctx,
        &versioned_instance,
        &unversioned_instance,
        &local_type_names,
    );

    quote! {
        pub mod #iface_mod_ident {
            pub const INSTANCE_NAME: &str = #versioned_instance;

            #(#type_defs)*
            #(#resource_methods)*
            #client_struct
            #server_items
        }
    }
}

fn generate_typedef(ctx: &IfaceContext<'_>, wit_name: &str, ty_id: TypeId) -> TokenStream {
    let rt = ctx.rt;
    let def = &ctx.resolve.types[ty_id];
    let ident = escape_type_ident(&wit_name.to_upper_camel_case());

    // Re-export cross-interface `use other.{item}` directly so types match across interfaces.
    if let TypeDefKind::Type(Type::Id(target_id)) = def.kind
        && let TypeOwner::Interface(owner_iface) = ctx.resolve.types[target_id].owner
        && owner_iface != ctx.iface_id
    {
        let target_path = type_ref_from_iface(ctx.resolve, ctx.iface_id, target_id);
        return quote! {
            pub use #target_path as #ident;
        };
    }

    let own_res = own_resources_in_typedef(ctx.resolve, ty_id);
    let mut param_map = BTreeMap::new();
    let mut decl_generics = Vec::new();
    let mut impl_encode_bounds = Vec::new();
    let mut impl_decode_bounds = Vec::new();
    let mut ty_param_idents = Vec::new();

    for (idx, &cid) in own_res.iter().enumerate() {
        let p_ident = format_ident!("__ResParam{}", idx);
        let default_ty = &ctx.resource_meta(cid).client_path;
        param_map.insert(cid.index(), p_ident.clone());
        decl_generics.push(quote!(#p_ident = #default_ty));
        impl_encode_bounds.push(quote!(#p_ident: #rt::__private::RpcEncode<__R>));
        impl_decode_bounds.push(quote!(#p_ident: #rt::__private::RpcDecode<__R>));
        ty_param_idents.push(p_ident);
    }

    let decl_gen_tokens = if decl_generics.is_empty() {
        quote!()
    } else {
        quote!(<#(#decl_generics),*>)
    };
    let use_gen_tokens = if ty_param_idents.is_empty() {
        quote!()
    } else {
        quote!(<#(#ty_param_idents),*>)
    };

    match &def.kind {
        TypeDefKind::Resource => generate_resource_proxy(ctx, &ident),
        TypeDefKind::Type(inner) => {
            let rhs = render_type(ctx, *inner, TypeMode::Def(&param_map));
            quote! {
                pub type #ident #decl_gen_tokens = #rhs;
            }
        }
        TypeDefKind::Record(Record { fields }) => {
            let derives = derive_attr(compute_derive_caps(ctx.resolve, Type::Id(ty_id)));
            let field_defs = fields.iter().map(|f| {
                let f_ident = to_snake_ident(&f.name);
                let f_ty = render_type(ctx, f.ty, TypeMode::Def(&param_map));
                quote!(pub #f_ident: #f_ty)
            });
            let encode_fields = fields.iter().map(|f| {
                let f_ident = to_snake_ident(&f.name);
                quote!(#rt::__private::RpcEncode::rpc_encode(self.#f_ident, __enc)?;)
            });
            let decode_fields = fields.iter().map(|f| {
                let f_ident = to_snake_ident(&f.name);
                quote!(#f_ident: #rt::__private::RpcDecode::rpc_decode(__dec)?)
            });

            quote! {
                #derives
                pub struct #ident #decl_gen_tokens {
                    #(#field_defs,)*
                }

                impl<__R: #rt::__private::ResourceEntry #(, #impl_encode_bounds)*> #rt::__private::RpcEncode<__R> for #ident #use_gen_tokens {
                    fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                        #(#encode_fields)*
                        ::core::result::Result::Ok(())
                    }
                }

                impl<__R: #rt::__private::ResourceEntry #(, #impl_decode_bounds)*> #rt::__private::RpcDecode<__R> for #ident #use_gen_tokens {
                    fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                        ::core::result::Result::Ok(Self {
                            #(#decode_fields,)*
                        })
                    }
                }
            }
        }
        TypeDefKind::Enum(Enum { cases }) => {
            let case_idents: Vec<Ident> = cases
                .iter()
                .map(|c| escape_type_ident(&c.name.to_upper_camel_case()))
                .collect();
            let use_u8 = cases.len() <= 256;
            let encode_arms = case_idents.iter().enumerate().map(|(idx, c_ident)| {
                if use_u8 {
                    let tag = idx as u8;
                    quote!(Self::#c_ident => __enc.write_u8(#tag))
                } else {
                    let tag = idx as u32;
                    quote!(Self::#c_ident => __enc.write_u32(#tag))
                }
            });
            let decode_arms = case_idents.iter().enumerate().map(|(idx, c_ident)| {
                if use_u8 {
                    let tag = idx as u8;
                    quote!(#tag => ::core::result::Result::Ok(Self::#c_ident))
                } else {
                    let tag = idx as u32;
                    quote!(#tag => ::core::result::Result::Ok(Self::#c_ident))
                }
            });
            let read_tag = if use_u8 {
                quote!(__dec.read_u8()?)
            } else {
                quote!(__dec.read_u32()?)
            };

            quote! {
                #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
                pub enum #ident {
                    #(#case_idents,)*
                }

                impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcEncode<__R> for #ident {
                    fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                        match self {
                            #(#encode_arms,)*
                        }
                        ::core::result::Result::Ok(())
                    }
                }

                impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcDecode<__R> for #ident {
                    fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                        match #read_tag {
                            #(#decode_arms,)*
                            __other => ::core::result::Result::Err(#rt::__private::WireError::MalformedPayload {
                                context: #wit_name.to_owned(),
                                detail: ::std::format!("invalid enum discriminant {__other}"),
                            }),
                        }
                    }
                }
            }
        }
        TypeDefKind::Variant(Variant { cases }) => {
            let derives = derive_attr(compute_derive_caps(ctx.resolve, Type::Id(ty_id)));
            let use_u8 = cases.len() <= 256;

            let mut case_defs = Vec::new();
            let mut encode_arms = Vec::new();
            let mut decode_arms = Vec::new();

            for (idx, case) in cases.iter().enumerate() {
                let c_ident = escape_type_ident(&case.name.to_upper_camel_case());
                let write_tag = if use_u8 {
                    let t = idx as u8;
                    quote!(__enc.write_u8(#t);)
                } else {
                    let t = idx as u32;
                    quote!(__enc.write_u32(#t);)
                };
                let pat_tag = if use_u8 {
                    let t = idx as u8;
                    quote!(#t)
                } else {
                    let t = idx as u32;
                    quote!(#t)
                };

                if let Some(payload_ty) = case.ty {
                    let ty_ts = render_type(ctx, payload_ty, TypeMode::Def(&param_map));
                    case_defs.push(quote!(#c_ident(#ty_ts)));
                    encode_arms.push(quote! {
                        Self::#c_ident(__val) => {
                            #write_tag
                            #rt::__private::RpcEncode::rpc_encode(__val, __enc)?;
                        }
                    });
                    decode_arms.push(quote! {
                        #pat_tag => ::core::result::Result::Ok(Self::#c_ident(#rt::__private::RpcDecode::rpc_decode(__dec)?))
                    });
                } else {
                    case_defs.push(quote!(#c_ident));
                    encode_arms.push(quote! {
                        Self::#c_ident => {
                            #write_tag
                        }
                    });
                    decode_arms.push(quote! {
                        #pat_tag => ::core::result::Result::Ok(Self::#c_ident)
                    });
                }
            }

            let read_tag = if use_u8 {
                quote!(__dec.read_u8()?)
            } else {
                quote!(__dec.read_u32()?)
            };

            quote! {
                #derives
                pub enum #ident #decl_gen_tokens {
                    #(#case_defs,)*
                }

                impl<__R: #rt::__private::ResourceEntry #(, #impl_encode_bounds)*> #rt::__private::RpcEncode<__R> for #ident #use_gen_tokens {
                    fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                        match self {
                            #(#encode_arms)*
                        }
                        ::core::result::Result::Ok(())
                    }
                }

                impl<__R: #rt::__private::ResourceEntry #(, #impl_decode_bounds)*> #rt::__private::RpcDecode<__R> for #ident #use_gen_tokens {
                    fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                        match #read_tag {
                            #(#decode_arms,)*
                            __other => ::core::result::Result::Err(#rt::__private::WireError::MalformedPayload {
                                context: #wit_name.to_owned(),
                                detail: ::std::format!("invalid variant discriminant {__other}"),
                            }),
                        }
                    }
                }
            }
        }
        TypeDefKind::Flags(Flags { flags }) => generate_flags_type(ctx, wit_name, &ident, flags),
        _ => {
            let rhs = render_type_id(ctx, ty_id, TypeMode::Def(&param_map));
            quote! {
                pub type #ident #decl_gen_tokens = #rhs;
            }
        }
    }
}

fn generate_flags_type(
    ctx: &IfaceContext<'_>,
    wit_name: &str,
    ident: &Ident,
    flags: &[wit_parser::Flag],
) -> TokenStream {
    let rt = ctx.rt;
    if flags.len() <= 64 {
        let use_u32 = flags.len() <= 32;
        let repr = if use_u32 { quote!(u32) } else { quote!(u64) };
        let mut all_mask: u64 = 0;
        let mut consts = Vec::new();
        for (idx, flag) in flags.iter().enumerate() {
            let bit: u64 = 1_u64 << idx;
            all_mask |= bit;
            let const_ident = format_ident!("{}", flag.name.to_shouty_snake_case());
            let lit = if use_u32 {
                Literal::u32_unsuffixed(bit as u32)
            } else {
                Literal::u64_unsuffixed(bit)
            };
            consts.push(quote!(pub const #const_ident: Self = Self(#lit);));
        }
        let all_lit = if use_u32 {
            Literal::u32_unsuffixed(all_mask as u32)
        } else {
            Literal::u64_unsuffixed(all_mask)
        };
        let encode_call = if use_u32 {
            quote!(__enc.write_u32(self.0))
        } else {
            quote!(__enc.write_u64(self.0))
        };
        let decode_call = if use_u32 {
            quote!(__dec.read_u32()?)
        } else {
            quote!(__dec.read_u64()?)
        };

        quote! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
            pub struct #ident(pub #repr);

            impl #ident {
                #(#consts)*

                pub const fn empty() -> Self {
                    Self(0)
                }

                pub const fn all() -> Self {
                    Self(#all_lit)
                }

                pub const fn bits(&self) -> #repr {
                    self.0
                }

                pub const fn from_bits_retain(bits: #repr) -> Self {
                    Self(bits)
                }

                pub const fn contains(&self, other: Self) -> bool {
                    (self.0 & other.0) == other.0
                }

                pub fn insert(&mut self, other: Self) {
                    self.0 |= other.0;
                }

                pub fn remove(&mut self, other: Self) {
                    self.0 &= !other.0;
                }
            }

            impl ::core::ops::BitOr for #ident {
                type Output = Self;
                fn bitor(self, rhs: Self) -> Self::Output {
                    Self(self.0 | rhs.0)
                }
            }

            impl ::core::ops::BitOrAssign for #ident {
                fn bitor_assign(&mut self, rhs: Self) {
                    self.0 |= rhs.0;
                }
            }

            impl ::core::ops::BitAnd for #ident {
                type Output = Self;
                fn bitand(self, rhs: Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl ::core::ops::BitAndAssign for #ident {
                fn bitand_assign(&mut self, rhs: Self) {
                    self.0 &= rhs.0;
                }
            }

            impl ::core::ops::BitXor for #ident {
                type Output = Self;
                fn bitxor(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl ::core::ops::Not for #ident {
                type Output = Self;
                fn not(self) -> Self::Output {
                    Self(!self.0 & #all_lit)
                }
            }

            impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcEncode<__R> for #ident {
                fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                    #encode_call;
                    ::core::result::Result::Ok(())
                }
            }

            impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcDecode<__R> for #ident {
                fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                    let __bits = #decode_call;
                    if (__bits & !#all_lit) != 0 {
                        return ::core::result::Result::Err(#rt::__private::WireError::MalformedPayload {
                            context: #wit_name.to_owned(),
                            detail: ::std::format!("unknown flag bits {__bits:#x}"),
                        });
                    }
                    ::core::result::Result::Ok(Self(__bits))
                }
            }
        }
    } else {
        let words = flags.len().div_ceil(32);
        quote! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub struct #ident(pub [u32; #words]);

            impl Default for #ident {
                fn default() -> Self {
                    Self([0; #words])
                }
            }

            impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcEncode<__R> for #ident {
                fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                    #rt::__private::RpcEncode::rpc_encode(self.0, __enc)
                }
            }

            impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcDecode<__R> for #ident {
                fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                    ::core::result::Result::Ok(Self(#rt::__private::RpcDecode::rpc_decode(__dec)?))
                }
            }
        }
    }
}

fn generate_resource_proxy(ctx: &IfaceContext<'_>, ident: &Ident) -> TokenStream {
    let rt = ctx.rt;
    quote! {
        #[derive(Debug)]
        pub struct #ident {
            inner: #rt::__private::RemoteResource,
        }

        impl #ident {
            pub fn from_remote(inner: #rt::__private::RemoteResource) -> Self {
                Self { inner }
            }

            /// Constructs a resource handle carrying a raw `u32` wire handle ID.
            pub fn from_raw_handle(
                peer: #rt::__private::PeerHandle,
                handle: u32,
                emit_drop: bool,
            ) -> Self {
                Self {
                    inner: #rt::__private::RemoteResource::from_raw_parts(peer, handle, emit_drop),
                }
            }

            pub fn handle_id(&self) -> u32 {
                self.inner.handle_id()
            }

            pub fn rpc_peer(&self) -> &#rt::__private::PeerHandle {
                self.inner.peer()
            }

            pub fn into_remote(self) -> #rt::__private::RemoteResource {
                self.inner
            }
        }

        impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcEncode<__R> for #ident {
            const MIN_WIRE_SIZE: usize = 4;

            fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                self.inner.rpc_encode(__enc)
            }
        }

        impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcEncode<__R> for &#ident {
            const MIN_WIRE_SIZE: usize = 4;

            fn rpc_encode(self, __enc: &mut #rt::__private::Encoder<'_, __R>) -> ::core::result::Result<(), #rt::__private::WireError> {
                (&self.inner).rpc_encode(__enc)
            }
        }

        impl<__R: #rt::__private::ResourceEntry> #rt::__private::RpcDecode<__R> for #ident {
            const MIN_WIRE_SIZE: usize = 4;

            fn rpc_decode(__dec: &mut #rt::__private::Decoder<'_, __R>) -> ::core::result::Result<Self, #rt::__private::WireError> {
                #rt::__private::RemoteResource::rpc_decode(__dec).map(Self::from_remote)
            }
        }
    }
}

fn generate_client_resource_methods(
    ctx: &IfaceContext<'_>,
    instance_name: &str,
) -> Vec<TokenStream> {
    let rt = ctx.rt;
    let iface = &ctx.resolve.interfaces[ctx.iface_id];
    let mut methods_by_res: BTreeMap<usize, (Ident, Vec<TokenStream>)> = BTreeMap::new();

    for func in iface.functions.values() {
        let Some(res_id) = func.kind.resource() else {
            continue;
        };
        if ctx.resolve.types[res_id].owner != TypeOwner::Interface(ctx.iface_id) {
            continue;
        }
        let res_ident = escape_type_ident(
            &ctx.resolve.types[res_id]
                .name
                .as_deref()
                .unwrap_or("Resource")
                .to_upper_camel_case(),
        );
        let wire_func = &func.name;
        let ret_ty = func
            .result
            .map_or_else(|| quote!(()), |t| render_type(ctx, t, TypeMode::Client));

        let method_tokens = match func.kind {
            FunctionKind::Constructor(_) => {
                let (sig_params, encode_expr) = render_client_params(ctx, &func.params, None);
                quote! {
                    pub async fn new(
                        __peer: &#rt::__private::PeerHandle,
                        #(#sig_params),*
                    ) -> #rt::__private::Result<#ret_ty> {
                        let mut __call = __peer.open_call(#instance_name, #wire_func).await?;
                        let __req = #rt::__private::encode_client_value(&__call, #encode_expr).await?;
                        __call.send_root_request(&__req).await?;
                        let __resp = __call.recv_root_response().await?;
                        #rt::__private::decode_client_value::<#ret_ty>(&__call, &__resp).await
                    }
                }
            }
            FunctionKind::Static(_)
            | FunctionKind::AsyncStatic(_)
            | FunctionKind::StaticGetter(_)
            | FunctionKind::StaticSetter(_) => {
                let fn_ident = client_item_fn_ident(func);
                let (sig_params, encode_expr) = render_client_params(ctx, &func.params, None);
                quote! {
                    pub async fn #fn_ident(
                        __peer: &#rt::__private::PeerHandle,
                        #(#sig_params),*
                    ) -> #rt::__private::Result<#ret_ty> {
                        let mut __call = __peer.open_call(#instance_name, #wire_func).await?;
                        let __req = #rt::__private::encode_client_value(&__call, #encode_expr).await?;
                        __call.send_root_request(&__req).await?;
                        let __resp = __call.recv_root_response().await?;
                        #rt::__private::decode_client_value::<#ret_ty>(&__call, &__resp).await
                    }
                }
            }
            FunctionKind::Method(_)
            | FunctionKind::AsyncMethod(_)
            | FunctionKind::MethodGetter(_)
            | FunctionKind::MethodSetter(_) => {
                let fn_ident = client_item_fn_ident(func);
                let (sig_params, encode_expr) =
                    render_client_params(ctx, &func.params[1..], Some(quote!(self)));
                quote! {
                    pub async fn #fn_ident(
                        &self,
                        #(#sig_params),*
                    ) -> #rt::__private::Result<#ret_ty> {
                        let mut __call = self.rpc_peer().open_call(#instance_name, #wire_func).await?;
                        let __req = #rt::__private::encode_client_value(&__call, #encode_expr).await?;
                        __call.send_root_request(&__req).await?;
                        let __resp = __call.recv_root_response().await?;
                        #rt::__private::decode_client_value::<#ret_ty>(&__call, &__resp).await
                    }
                }
            }
            FunctionKind::Freestanding
            | FunctionKind::AsyncFreestanding
            | FunctionKind::Getter
            | FunctionKind::Setter => unreachable!(),
        };

        methods_by_res
            .entry(res_id.index())
            .or_insert_with(|| (res_ident, Vec::new()))
            .1
            .push(method_tokens);
    }

    methods_by_res
        .into_values()
        .map(|(res_ident, methods)| {
            quote! {
                impl #res_ident {
                    #(#methods)*
                }
            }
        })
        .collect()
}

fn generate_client_struct(
    ctx: &IfaceContext<'_>,
    instance_name: &str,
    local_type_names: &BTreeSet<String>,
) -> TokenStream {
    let rt = ctx.rt;
    let iface = &ctx.resolve.interfaces[ctx.iface_id];
    let mut methods = Vec::new();

    for func in iface.functions.values() {
        let wire_func = &func.name;
        let ret_ty = func
            .result
            .map_or_else(|| quote!(()), |t| render_type(ctx, t, TypeMode::Client));

        match func.kind {
            FunctionKind::Freestanding
            | FunctionKind::AsyncFreestanding
            | FunctionKind::Getter
            | FunctionKind::Setter => {
                let fn_ident = client_item_fn_ident(func);
                let (sig_params, encode_expr) = render_client_params(ctx, &func.params, None);
                methods.push(quote! {
                    pub async fn #fn_ident(
                        &self,
                        #(#sig_params),*
                    ) -> #rt::__private::Result<#ret_ty> {
                        let mut __call = self.peer.open_call(#instance_name, #wire_func).await?;
                        let __req = #rt::__private::encode_client_value(&__call, #encode_expr).await?;
                        __call.send_root_request(&__req).await?;
                        let __resp = __call.recv_root_response().await?;
                        #rt::__private::decode_client_value::<#ret_ty>(&__call, &__resp).await
                    }
                });
            }
            FunctionKind::Constructor(res_id) => {
                let res_snake = ctx.resolve.types[res_id]
                    .name
                    .as_deref()
                    .unwrap_or("resource")
                    .to_snake_case();
                let fn_ident = to_snake_ident(&format!("{res_snake}_new"));
                let (sig_params, encode_expr) = render_client_params(ctx, &func.params, None);
                methods.push(quote! {
                    pub async fn #fn_ident(
                        &self,
                        #(#sig_params),*
                    ) -> #rt::__private::Result<#ret_ty> {
                        let mut __call = self.peer.open_call(#instance_name, #wire_func).await?;
                        let __req = #rt::__private::encode_client_value(&__call, #encode_expr).await?;
                        __call.send_root_request(&__req).await?;
                        let __resp = __call.recv_root_response().await?;
                        #rt::__private::decode_client_value::<#ret_ty>(&__call, &__resp).await
                    }
                });
            }
            FunctionKind::Static(_)
            | FunctionKind::AsyncStatic(_)
            | FunctionKind::StaticGetter(_)
            | FunctionKind::StaticSetter(_)
            | FunctionKind::Method(_)
            | FunctionKind::AsyncMethod(_)
            | FunctionKind::MethodGetter(_)
            | FunctionKind::MethodSetter(_) => {}
        }
    }

    let alias = if !local_type_names.contains("Client") {
        quote!(
            pub type Client = RpcClient;
        )
    } else {
        quote!()
    };

    quote! {
        #[derive(Clone, Debug)]
        pub struct RpcClient {
            peer: #rt::__private::PeerHandle,
        }

        impl RpcClient {
            pub fn new(peer: #rt::__private::PeerHandle) -> Self {
                Self { peer }
            }

            pub fn peer(&self) -> &#rt::__private::PeerHandle {
                &self.peer
            }

            #(#methods)*
        }

        #alias
    }
}

fn render_client_params(
    ctx: &IfaceContext<'_>,
    params: &[wit_parser::Param],
    leading_self: Option<TokenStream>,
) -> (Vec<TokenStream>, TokenStream) {
    let mut sig = Vec::new();
    let mut exprs = Vec::new();
    if let Some(self_ts) = leading_self {
        exprs.push(self_ts);
    }
    for (idx, param) in params.iter().enumerate() {
        let p_ident = format_ident!("__arg{}_{}", idx, param.name.to_snake_case());
        let p_ty = render_type(ctx, param.ty, TypeMode::Client);
        sig.push(quote!(#p_ident: #p_ty));
        exprs.push(quote!(#p_ident));
    }
    let encode_expr = if exprs.is_empty() {
        quote!(())
    } else if exprs.len() == 1 {
        let e0 = &exprs[0];
        quote!((#e0,))
    } else {
        quote!((#(#exprs),*))
    };
    (sig, encode_expr)
}

fn generate_server_items(
    ctx: &IfaceContext<'_>,
    versioned_instance: &str,
    unversioned_instance: &str,
    local_type_names: &BTreeSet<String>,
) -> TokenStream {
    let rt = ctx.rt;
    let iface = &ctx.resolve.interfaces[ctx.iface_id];

    let assoc_types = ctx.resources.iter().map(|meta| {
        let assoc = &meta.assoc_ident;
        quote!(type #assoc: #rt::__private::MaybeSend + #rt::__private::MaybeSync + 'static;)
    });

    let mut trait_methods = Vec::new();
    let mut wire_func_names = Vec::new();
    let mut dispatch_arms = Vec::new();

    for func in iface.functions.values() {
        let wire_func = &func.name;
        wire_func_names.push(wire_func.clone());
        let handler_fn_ident = server_handler_fn_ident(ctx, func);

        let mut trait_params = Vec::new();
        let mut wire_param_tys = Vec::new();
        let mut wire_bind_idents = Vec::new();
        let mut call_arg_exprs = Vec::new();

        for (idx, param) in func.params.iter().enumerate() {
            let p_name = if idx == 0 && param.name == "self" {
                format_ident!("self_")
            } else {
                to_snake_ident(&param.name)
            };
            let trait_ty = render_type(ctx, param.ty, TypeMode::ServerTrait);
            trait_params.push(quote!(#p_name: #trait_ty));

            let wire_ty = render_type(ctx, param.ty, TypeMode::ServerWire);
            wire_param_tys.push(wire_ty);
            let bind_ident = format_ident!("__wparam{}", idx);
            call_arg_exprs.push(wire_to_server_expr(ctx, param.ty, quote!(#bind_ident)));
            wire_bind_idents.push(bind_ident);
        }

        let trait_ret_ty = func.result.map_or_else(
            || quote!(()),
            |t| render_type(ctx, t, TypeMode::ServerTrait),
        );

        trait_methods.push(quote! {
            fn #handler_fn_ident<'a>(
                &'a self,
                #(#trait_params),*
            ) -> impl ::core::future::Future<Output = #trait_ret_ty> + #rt::__private::MaybeSend + 'a;
        });

        let decode_stmt = if wire_param_tys.is_empty() {
            quote! {
                __ctx.decode_request::<()>().await?;
            }
        } else if wire_param_tys.len() == 1 {
            let w0 = &wire_param_tys[0];
            let b0 = &wire_bind_idents[0];
            quote! {
                let (#b0,) = __ctx.decode_request::<(#w0,)>().await?;
            }
        } else {
            quote! {
                let (#(#wire_bind_idents),*) = __ctx.decode_request::<(#(#wire_param_tys),*)>().await?;
            }
        };

        let dispatch_body = match func.result {
            None => {
                quote! {
                    {
                        #decode_stmt
                        self.0.#handler_fn_ident(#(#call_arg_exprs),*).await;
                    }
                    __ctx.encode_response(()).await
                }
            }
            Some(ret_ty) => {
                let wrapped_ret = server_to_wire_expr(ctx, ret_ty, quote!(__ret));
                quote! {
                    let __wire_ret = {
                        #decode_stmt
                        let __ret = self.0.#handler_fn_ident(#(#call_arg_exprs),*).await;
                        #wrapped_ret
                    };
                    __ctx.encode_response(__wire_ret).await
                }
            }
        };

        dispatch_arms.push(quote! {
            #wire_func => {
                #dispatch_body
            }
        });
    }

    let resource_support = generate_server_resource_enum(ctx);

    let handler_alias = if !local_type_names.contains("Handler") {
        quote!(
            pub use RpcHandler as Handler;
        )
    } else {
        quote!()
    };
    let server_alias = if !local_type_names.contains("Server") {
        quote!(
            pub type Server<__H> = RpcServer<__H>;
        )
    } else {
        quote!()
    };

    let supports_body = if wire_func_names.is_empty() {
        quote! {
            let _ = (__instance, __func);
            false
        }
    } else {
        quote! {
            (__instance == #versioned_instance || __instance == #unversioned_instance)
                && matches!(__func, #(#wire_func_names)|*)
        }
    };

    let shared_bounds = ctx.resources.iter().map(|meta| {
        let assoc = &meta.assoc_ident;
        let marker = &meta.client_path;
        quote!(#rt::__private::ResourceSlotAccess<#marker, __H::#assoc>)
    });
    let shared_where = if ctx.resources.is_empty() {
        quote!(where __R: #rt::__private::ResourceEntry)
    } else {
        quote!(where __R: #rt::__private::ResourceEntry #(+ #shared_bounds)*)
    };

    quote! {
        pub trait RpcHandler: #rt::__private::MaybeSend + #rt::__private::MaybeSync + 'static {
            #(#assoc_types)*
            #(#trait_methods)*
        }

        #handler_alias

        #resource_support

        pub struct RpcServer<__H: RpcHandler>(pub __H);

        impl<__H: RpcHandler> RpcServer<__H> {
            pub fn new(handler: __H) -> Self {
                Self(handler)
            }

            pub fn supports_call(&self, __instance: &str, __func: &str) -> bool {
                #supports_body
            }

            pub async fn dispatch_with<'a, __R>(
                &'a self,
                __ctx: #rt::__private::ServerInvocation<'a, __R>,
                __instance: &'a str,
                __func: &'a str,
            ) -> ::core::result::Result<(), #rt::__private::WireError>
            #shared_where
            {
                match __func {
                    #(#dispatch_arms,)*
                    _ => ::core::result::Result::Err(#rt::__private::WireError::MalformedPayload {
                        context: "Dispatcher::dispatch".to_owned(),
                        detail: ::std::format!("unsupported method {__instance}.{__func}"),
                    }),
                }
            }
        }

        #server_alias

        impl<__H: RpcHandler> #rt::__private::Dispatcher for RpcServer<__H> {
            type Resource = RpcServerResource<__H>;

            fn supports(&self, __instance: &str, __func: &str) -> bool {
                self.supports_call(__instance, __func)
            }

            async fn dispatch<'a>(
                &'a self,
                __ctx: #rt::__private::ServerInvocation<'a, Self::Resource>,
                __instance: &'a str,
                __func: &'a str,
            ) -> ::core::result::Result<(), #rt::__private::WireError> {
                self.dispatch_with(__ctx, __instance, __func).await
            }
        }
    }
}

fn generate_server_resource_enum(ctx: &IfaceContext<'_>) -> TokenStream {
    let rt = ctx.rt;
    if ctx.resources.is_empty() {
        return quote! {
            pub enum RpcServerResource<__H: RpcHandler> {
                #[doc(hidden)]
                __Uninhabited(::core::convert::Infallible, ::core::marker::PhantomData<__H>),
            }

            impl<__H: RpcHandler> #rt::__private::ResourceEntry for RpcServerResource<__H> {
                fn kind_name(&self) -> &'static str {
                    match *self {
                        Self::__Uninhabited(never, _) => match never {},
                    }
                }
            }
        };
    }

    let variants = ctx.resources.iter().map(|meta| {
        let var = &meta.variant_ident;
        let assoc = &meta.assoc_ident;
        quote!(#var(::std::sync::Arc<__H::#assoc>))
    });
    let kind_arms = ctx.resources.iter().map(|meta| {
        let var = &meta.variant_ident;
        let wit_name = &meta.wit_name;
        quote!(Self::#var(_) => #wit_name)
    });

    let wrappers = ctx.resources.iter().map(|meta| {
        let var = &meta.variant_ident;
        let assoc = &meta.assoc_ident;
        let wit_name = &meta.wit_name;
        let own_wrap = &meta.own_wrapper_ident;
        let borrow_wrap = &meta.borrow_wrapper_ident;
        let multi_res = ctx.resources.len() > 1;
        let project_arm = if multi_res {
            quote! {
                RpcServerResource::#var(__arc) => ::core::option::Option::Some(__arc),
                _ => ::core::option::Option::None,
            }
        } else {
            quote! {
                RpcServerResource::#var(__arc) => ::core::option::Option::Some(__arc),
            }
        };
        let extract_arm = if multi_res {
            quote! {
                RpcServerResource::#var(__arc) => ::core::result::Result::Ok(__arc),
                __other => ::core::result::Result::Err(__other),
            }
        } else {
            quote! {
                RpcServerResource::#var(__arc) => ::core::result::Result::Ok(__arc),
            }
        };

        let marker = &meta.client_path;
        quote! {
            impl<__H: RpcHandler> #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>
                for RpcServerResource<__H>
            {
                fn into_entry(__arc: ::std::sync::Arc<__H::#assoc>) -> Self {
                    Self::#var(__arc)
                }

                fn borrow_entry(&self) -> ::core::option::Option<&::std::sync::Arc<__H::#assoc>> {
                    match self {
                        #project_arm
                    }
                }

                fn take_entry(
                    self,
                ) -> ::core::result::Result<::std::sync::Arc<__H::#assoc>, Self> {
                    match self {
                        #extract_arm
                    }
                }
            }

            #[doc(hidden)]
            pub struct #own_wrap<__H: RpcHandler>(pub __H::#assoc);

            impl<__H: RpcHandler, __R> #rt::__private::RpcEncode<__R> for #own_wrap<__H>
            where
                __R: #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>,
            {
                const MIN_WIRE_SIZE: usize = 4;

                fn rpc_encode(
                    self,
                    __enc: &mut #rt::__private::Encoder<'_, __R>,
                ) -> ::core::result::Result<(), #rt::__private::WireError> {
                    let __handle = __enc.insert_resource(
                        <__R as #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>>::into_entry(
                            ::std::sync::Arc::new(self.0),
                        ),
                    )?;
                    __enc.write_u32(__handle);
                    ::core::result::Result::Ok(())
                }
            }

            impl<__H: RpcHandler, __R> #rt::__private::RpcDecode<__R> for #own_wrap<__H>
            where
                __R: #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>,
            {
                const MIN_WIRE_SIZE: usize = 4;

                fn rpc_decode(
                    __dec: &mut #rt::__private::Decoder<'_, __R>,
                ) -> ::core::result::Result<Self, #rt::__private::WireError> {
                    let __handle = __dec.read_u32()?;
                    let __owned = __dec.resources_mut()?.take(
                        __handle,
                        #wit_name,
                        <__R as #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>>::take_entry,
                        <__R as #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>>::into_entry,
                    )?;
                    ::core::result::Result::Ok(Self(__owned))
                }
            }

            #[doc(hidden)]
            pub struct #borrow_wrap<__H: RpcHandler>(
                pub #rt::__private::ResourceBorrow<__H::#assoc>,
            );

            impl<__H: RpcHandler, __R> #rt::__private::RpcDecode<__R> for #borrow_wrap<__H>
            where
                __R: #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>,
            {
                const MIN_WIRE_SIZE: usize = 4;

                fn rpc_decode(
                    __dec: &mut #rt::__private::Decoder<'_, __R>,
                ) -> ::core::result::Result<Self, #rt::__private::WireError> {
                    let __handle = __dec.read_u32()?;
                    let __borrow = __dec.resources()?.borrow(
                        __handle,
                        #wit_name,
                        <__R as #rt::__private::ResourceSlotAccess<#marker, __H::#assoc>>::borrow_entry,
                    )?;
                    ::core::result::Result::Ok(Self(__borrow))
                }
            }
        }
    });

    quote! {
        pub enum RpcServerResource<__H: RpcHandler> {
            #(#variants,)*
        }

        impl<__H: RpcHandler> #rt::__private::ResourceEntry for RpcServerResource<__H> {
            fn kind_name(&self) -> &'static str {
                match self {
                    #(#kind_arms,)*
                }
            }
        }

        #(#wrappers)*
    }
}

fn contains_any_handle(resolve: &Resolve, ty: Type) -> bool {
    let Type::Id(id) = ty else {
        return false;
    };
    match &resolve.types[id].kind {
        TypeDefKind::Resource | TypeDefKind::Handle(_) => true,
        TypeDefKind::Record(rec) => rec
            .fields
            .iter()
            .any(|f| contains_any_handle(resolve, f.ty)),
        TypeDefKind::Tuple(tup) => tup.types.iter().any(|&t| contains_any_handle(resolve, t)),
        TypeDefKind::Variant(var) => var
            .cases
            .iter()
            .any(|c| c.ty.is_some_and(|t| contains_any_handle(resolve, t))),
        TypeDefKind::Option(inner)
        | TypeDefKind::List(inner)
        | TypeDefKind::FixedLengthList(inner, _)
        | TypeDefKind::Type(inner) => contains_any_handle(resolve, *inner),
        TypeDefKind::Map(k, v) => {
            contains_any_handle(resolve, *k) || contains_any_handle(resolve, *v)
        }
        TypeDefKind::Result(res) => {
            res.ok.is_some_and(|t| contains_any_handle(resolve, t))
                || res.err.is_some_and(|t| contains_any_handle(resolve, t))
        }
        TypeDefKind::Flags(_)
        | TypeDefKind::Enum(_)
        | TypeDefKind::Future(_)
        | TypeDefKind::Stream(_)
        | TypeDefKind::Unknown => false,
    }
}

fn wire_to_server_expr(ctx: &IfaceContext<'_>, ty: Type, expr: TokenStream) -> TokenStream {
    if !contains_any_handle(ctx.resolve, ty) {
        return expr;
    }
    let Type::Id(id) = ty else {
        return expr;
    };
    match &ctx.resolve.types[id].kind {
        TypeDefKind::Resource | TypeDefKind::Handle(Handle::Own(_)) => quote!(#expr.0),
        TypeDefKind::Handle(Handle::Borrow(_)) => quote!(&*#expr.0),
        TypeDefKind::Type(inner) => wire_to_server_expr(ctx, *inner, expr),
        TypeDefKind::Option(inner) => {
            let body = wire_to_server_expr(ctx, *inner, quote!(__v));
            quote!(#expr.map(|__v| #body))
        }
        TypeDefKind::List(inner) => {
            let body = wire_to_server_expr(ctx, *inner, quote!(__v));
            quote!(#expr.into_iter().map(|__v| #body).collect::<::std::vec::Vec<_>>())
        }
        TypeDefKind::FixedLengthList(inner, _) => {
            let body = wire_to_server_expr(ctx, *inner, quote!(__v));
            quote!(#expr.map(|__v| #body))
        }
        TypeDefKind::Map(k, v) => {
            let kb = wire_to_server_expr(ctx, *k, quote!(__k));
            let vb = wire_to_server_expr(ctx, *v, quote!(__v));
            quote!(#expr.into_iter().map(|(__k, __v)| (#kb, #vb)).collect::<::std::vec::Vec<_>>())
        }
        TypeDefKind::Tuple(Tuple { types }) => {
            if types.len() == 1 {
                let b0 = wire_to_server_expr(ctx, types[0], quote!(__t.0));
                quote!({ let __t = #expr; (#b0,) })
            } else {
                let elems = types.iter().enumerate().map(|(i, &t)| {
                    let idx = syn::Index::from(i);
                    wire_to_server_expr(ctx, t, quote!(__t.#idx))
                });
                quote!({ let __t = #expr; (#(#elems),*) })
            }
        }
        TypeDefKind::Result(Result_ { ok, err }) => {
            let mut out = expr;
            if let Some(ok_ty) = ok
                && contains_any_handle(ctx.resolve, *ok_ty)
            {
                let body = wire_to_server_expr(ctx, *ok_ty, quote!(__ok));
                out = quote!(#out.map(|__ok| #body));
            }
            if let Some(err_ty) = err
                && contains_any_handle(ctx.resolve, *err_ty)
            {
                let body = wire_to_server_expr(ctx, *err_ty, quote!(__err));
                out = quote!(#out.map_err(|__err| #body));
            }
            out
        }
        TypeDefKind::Record(Record { fields }) => {
            let path = type_ref_from_iface(ctx.resolve, ctx.iface_id, id);
            let field_inits = fields.iter().map(|f| {
                let f_ident = to_snake_ident(&f.name);
                let conv = wire_to_server_expr(ctx, f.ty, quote!(__rec.#f_ident));
                quote!(#f_ident: #conv)
            });
            quote!({
                let __rec = #expr;
                #path { #(#field_inits),* }
            })
        }
        TypeDefKind::Variant(Variant { cases }) => {
            let path = type_ref_from_iface(ctx.resolve, ctx.iface_id, id);
            let arms = cases.iter().map(|c| {
                let c_ident = escape_type_ident(&c.name.to_upper_camel_case());
                match c.ty {
                    Some(inner) => {
                        let conv = wire_to_server_expr(ctx, inner, quote!(__val));
                        quote!(#path::#c_ident(__val) => #path::#c_ident(#conv))
                    }
                    None => quote!(#path::#c_ident => #path::#c_ident),
                }
            });
            quote!(match #expr { #(#arms),* })
        }
        _ => expr,
    }
}

fn server_to_wire_expr(ctx: &IfaceContext<'_>, ty: Type, expr: TokenStream) -> TokenStream {
    if !contains_any_handle(ctx.resolve, ty) {
        return expr;
    }
    let Type::Id(id) = ty else {
        return expr;
    };
    match &ctx.resolve.types[id].kind {
        TypeDefKind::Resource => {
            let wrap = &ctx.resource_meta(id).own_wrapper_ident;
            quote!(#wrap::<__H>(#expr))
        }
        TypeDefKind::Handle(Handle::Own(res_id)) => {
            let wrap = &ctx.resource_meta(*res_id).own_wrapper_ident;
            quote!(#wrap::<__H>(#expr))
        }
        TypeDefKind::Type(inner) => server_to_wire_expr(ctx, *inner, expr),
        TypeDefKind::Option(inner) => {
            let body = server_to_wire_expr(ctx, *inner, quote!(__v));
            quote!(#expr.map(|__v| #body))
        }
        TypeDefKind::List(inner) => {
            let body = server_to_wire_expr(ctx, *inner, quote!(__v));
            quote!(#expr.into_iter().map(|__v| #body).collect::<::std::vec::Vec<_>>())
        }
        TypeDefKind::FixedLengthList(inner, _) => {
            let body = server_to_wire_expr(ctx, *inner, quote!(__v));
            quote!(#expr.map(|__v| #body))
        }
        TypeDefKind::Map(k, v) => {
            let kb = server_to_wire_expr(ctx, *k, quote!(__k));
            let vb = server_to_wire_expr(ctx, *v, quote!(__v));
            quote!(#expr.into_iter().map(|(__k, __v)| (#kb, #vb)).collect::<::std::vec::Vec<_>>())
        }
        TypeDefKind::Tuple(Tuple { types }) => {
            if types.len() == 1 {
                let b0 = server_to_wire_expr(ctx, types[0], quote!(__t.0));
                quote!({ let __t = #expr; (#b0,) })
            } else {
                let elems = types.iter().enumerate().map(|(i, &t)| {
                    let idx = syn::Index::from(i);
                    server_to_wire_expr(ctx, t, quote!(__t.#idx))
                });
                quote!({ let __t = #expr; (#(#elems),*) })
            }
        }
        TypeDefKind::Result(Result_ { ok, err }) => {
            let mut out = expr;
            if let Some(ok_ty) = ok
                && contains_any_handle(ctx.resolve, *ok_ty)
            {
                let body = server_to_wire_expr(ctx, *ok_ty, quote!(__ok));
                out = quote!(#out.map(|__ok| #body));
            }
            if let Some(err_ty) = err
                && contains_any_handle(ctx.resolve, *err_ty)
            {
                let body = server_to_wire_expr(ctx, *err_ty, quote!(__err));
                out = quote!(#out.map_err(|__err| #body));
            }
            out
        }
        TypeDefKind::Record(Record { fields }) => {
            let path = type_ref_from_iface(ctx.resolve, ctx.iface_id, id);
            let field_inits = fields.iter().map(|f| {
                let f_ident = to_snake_ident(&f.name);
                let conv = server_to_wire_expr(ctx, f.ty, quote!(__rec.#f_ident));
                quote!(#f_ident: #conv)
            });
            quote!({
                let __rec = #expr;
                #path { #(#field_inits),* }
            })
        }
        TypeDefKind::Variant(Variant { cases }) => {
            let path = type_ref_from_iface(ctx.resolve, ctx.iface_id, id);
            let arms = cases.iter().map(|c| {
                let c_ident = escape_type_ident(&c.name.to_upper_camel_case());
                match c.ty {
                    Some(inner) => {
                        let conv = server_to_wire_expr(ctx, inner, quote!(__val));
                        quote!(#path::#c_ident(__val) => #path::#c_ident(#conv))
                    }
                    None => quote!(#path::#c_ident => #path::#c_ident),
                }
            });
            quote!(match #expr { #(#arms),* })
        }
        _ => expr,
    }
}

fn generate_world_wrapper(
    resolve: &Resolve,
    world_id: WorldId,
    seed_interfaces: &[InterfaceId],
    rt: &SynPath,
) -> TokenStream {
    let world = &resolve.worlds[world_id];
    let client_ident = format_ident!("{}Client", world.name.to_upper_camel_case());

    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for &iface_id in seed_interfaces {
        if let Some(name) = &resolve.interfaces[iface_id].name {
            *name_counts.entry(name.to_snake_case()).or_insert(0) += 1;
        }
    }

    let mut accessors = Vec::new();
    for &iface_id in seed_interfaces {
        let iface = &resolve.interfaces[iface_id];
        let Some(iface_name) = &iface.name else {
            continue;
        };
        let pkg = &resolve.packages[iface.package.expect("interface package")];
        let ns_mod = to_snake_ident(&pkg.name.namespace);
        let pkg_mod = to_snake_ident(&pkg.name.name);
        let iface_mod = to_snake_ident(iface_name);

        let short_snake = iface_name.to_snake_case();
        let method_ident = if name_counts.get(&short_snake).copied().unwrap_or(0) > 1 {
            to_snake_ident(&format!("{}_{}", pkg.name.name, iface_name))
        } else {
            to_snake_ident(iface_name)
        };

        accessors.push(quote! {
            pub fn #method_ident(&self) -> #ns_mod::#pkg_mod::#iface_mod::RpcClient {
                #ns_mod::#pkg_mod::#iface_mod::RpcClient::new(self.peer.clone())
            }
        });
    }

    quote! {
        #[derive(Clone, Debug)]
        pub struct #client_ident {
            peer: #rt::__private::PeerHandle,
        }

        impl #client_ident {
            pub fn new(peer: #rt::__private::PeerHandle) -> Self {
                Self { peer }
            }

            pub fn peer(&self) -> &#rt::__private::PeerHandle {
                &self.peer
            }

            #(#accessors)*
        }
    }
}

fn client_item_fn_ident(func: &Function) -> Ident {
    let base = func.item_name();
    match func.kind.accessor() {
        Some(wit_parser::AccessorKind::Getter) => to_snake_ident(&format!("get_{base}")),
        Some(wit_parser::AccessorKind::Setter) => to_snake_ident(&format!("set_{base}")),
        None => to_snake_ident(base),
    }
}

fn server_handler_fn_ident(ctx: &IfaceContext<'_>, func: &Function) -> Ident {
    match func.kind {
        FunctionKind::Freestanding
        | FunctionKind::AsyncFreestanding
        | FunctionKind::Getter
        | FunctionKind::Setter => client_item_fn_ident(func),
        FunctionKind::Constructor(res_id) => {
            let r_snake = ctx.resolve.types[res_id]
                .name
                .as_deref()
                .unwrap_or("resource")
                .to_snake_case();
            to_snake_ident(&format!("{r_snake}_new"))
        }
        FunctionKind::Method(res_id)
        | FunctionKind::AsyncMethod(res_id)
        | FunctionKind::Static(res_id)
        | FunctionKind::AsyncStatic(res_id)
        | FunctionKind::MethodGetter(res_id)
        | FunctionKind::MethodSetter(res_id)
        | FunctionKind::StaticGetter(res_id)
        | FunctionKind::StaticSetter(res_id) => {
            let r_snake = ctx.resolve.types[res_id]
                .name
                .as_deref()
                .unwrap_or("resource")
                .to_snake_case();
            let item = match func.kind.accessor() {
                Some(wit_parser::AccessorKind::Getter) => format!("get_{}", func.item_name()),
                Some(wit_parser::AccessorKind::Setter) => format!("set_{}", func.item_name()),
                None => func.item_name().to_snake_case(),
            };
            to_snake_ident(&format!("{r_snake}_{item}"))
        }
    }
}

fn to_snake_ident(raw: &str) -> Ident {
    let mut s = raw.to_snake_case();
    if s.is_empty() || s.as_bytes()[0].is_ascii_digit() {
        s.insert(0, '_');
    }
    match s.as_str() {
        "self" | "super" | "crate" | "Self" => format_ident!("{s}_"),
        _ if is_rust_keyword(&s) => Ident::new_raw(&s, Span::call_site()),
        _ => Ident::new(&s, Span::call_site()),
    }
}

fn escape_type_ident(pascal: &str) -> Ident {
    let mut s = pascal.to_owned();
    if s.is_empty() || s.as_bytes()[0].is_ascii_digit() {
        s.insert(0, '_');
    }
    if s == "Self" {
        format_ident!("Self_")
    } else if is_rust_keyword(&s) {
        Ident::new_raw(&s, Span::call_site())
    } else {
        Ident::new(&s, Span::call_site())
    }
}

fn is_rust_keyword(word: &str) -> bool {
    matches!(
        word,
        "abstract"
            | "as"
            | "async"
            | "await"
            | "become"
            | "box"
            | "break"
            | "const"
            | "continue"
            | "do"
            | "dyn"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "final"
            | "fn"
            | "for"
            | "gen"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "macro"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "override"
            | "priv"
            | "pub"
            | "ref"
            | "return"
            | "static"
            | "struct"
            | "trait"
            | "true"
            | "try"
            | "type"
            | "typeof"
            | "unsafe"
            | "unsized"
            | "use"
            | "virtual"
            | "where"
            | "while"
            | "yield"
    )
}
