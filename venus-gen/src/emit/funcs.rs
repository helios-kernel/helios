//! The generated functions: per type (structs, unions, handles, pNext
//! chains) and per command.

use proc_macro2::{Literal, TokenStream};
use quote::quote;

use super::names::{base_type, decl_type, func, ident};
use super::wire::{Access, Frame, Validity, Wire};
use crate::analysis::{ChainCondition, ExtExpr};
use crate::registry::{Category, RegistryError, TypeId, TypeRef, Variable};

type Result<T> = std::result::Result<T, RegistryError>;

/// Which of the three walks of a struct a function is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Encode,
    EncodePartial,
    Decode,
}

impl Variant {
    fn suffix(self) -> &'static str {
        match self {
            Self::EncodePartial => "_partial",
            _ => "",
        }
    }
    fn is_encode(self) -> bool {
        self != Self::Decode
    }
}

impl<'a> Wire<'a> {
    pub(super) fn command_entry(&self, id: TypeId) -> Result<Option<TokenStream>> {
        let command = &self.an.reg.types[id];
        // These commands alter guest ownership or synchronize GPU work;
        // their entry points live in the hand-written driver modules.
        if command.name.ends_with("MESA")
            || matches!(
                command.name.as_str(),
                "vkDestroyInstance"
                    | "vkDestroyDevice"
                    | "vkAllocateMemory"
                    | "vkFreeMemory"
                    | "vkUnmapMemory"
                    | "vkUnmapMemory2"
                    | "vkFlushMappedMemoryRanges"
                    | "vkInvalidateMappedMemoryRanges"
                    | "vkFreeCommandBuffers"
                    | "vkCreateCommandPool"
                    | "vkDestroyCommandPool"
                    | "vkQueueWaitIdle"
                    | "vkDeviceWaitIdle"
                    | "vkCreateFence"
                    | "vkDestroyFence"
                    | "vkResetFences"
                    | "vkGetFenceStatus"
                    | "vkCreateSemaphore"
                    | "vkDestroySemaphore"
                    | "vkGetSemaphoreCounterValue"
                    | "vkSignalSemaphore"
                    | "vkQueueSubmit"
                    | "vkQueueSubmit2"
                    | "vkWaitForFences"
                    | "vkWaitSemaphores"
                    | "vkEnumeratePhysicalDeviceGroups"
            )
        {
            return Ok(None);
        }
        let Some(first) = command.variables.first() else {
            return Ok(None);
        };
        let dispatch_type = &self.an.reg.types[first.ty.base];
        if first.ty.is_pointer() || !dispatch_type.dispatchable {
            return Ok(None);
        }
        if command
            .variables
            .iter()
            .any(|var| var.attrs.var_out && self.an.reg.types[var.ty.base].dispatchable)
        {
            return Ok(None);
        }
        let invocation = match command
            .ret
            .as_ref()
            .map(|ret| self.an.reg.types[ret.base].name.as_str())
        {
            Some("VkResult") => quote!(invoke_result),
            None => quote!(invoke_void),
            _ => return Ok(None),
        };
        let mut params = Vec::new();
        let mut args = Vec::new();
        for var in &command.variables {
            let name = ident(&var.name);
            let declared = decl_type(self.an, &var.ty, &var.name)?;
            if var.ty.is_static_array() {
                let mut element = var.ty.clone();
                element.decor.dim = None;
                let element = decl_type(self.an, &element, &var.name)?;
                // C parameters declared as fixed arrays decay to pointers;
                // the Rust wire helper takes a copied array value instead.
                params.push(quote!(#name: *const #element));
                args.push(quote!(*#name.cast::<#declared>()));
            } else {
                params.push(quote!(#name: #declared));
                args.push(quote!(#name));
            }
        }
        let dispatch = ident(&first.name);
        let entry = ident(&command.name);
        let call = func("call", &command.name);
        let ret = match &command.ret {
            Some(ret) => {
                let ret = decl_type(self.an, ret, "entry result")?;
                quote!(-> #ret)
            }
            None => TokenStream::new(),
        };
        let clear = isolate_stmts(self.entry_output_handles(id, false)?)?;
        let assign = isolate_stmts(self.entry_output_handles(id, true)?)?;
        let call_stmt = isolate_stmts(quote!(#call(&mut venus_state.connection, #(#args),*)))?;
        let body = if assign.is_empty() {
            call_stmt
        } else {
            quote! {
                let venus_result = (|| {
                    #assign
                    #call_stmt
                })();
                venus_result.inspect_err(|_| { #clear })
            }
        };
        // Visible to the driver, whose hand-written entry points rewrite an
        // input before forwarding it to the generated one.
        Ok(Some(quote! {
            /// Dispatch through the instance's renderer connection.
            ///
            /// # Safety
            /// Pointer and handle arguments must satisfy the Vulkan command's specification.
            pub(super) unsafe extern "system" fn #entry<F: Factory>(#(#params),*) #ret {
                #clear
                let venus_call = |venus_state: &mut super::instance::State<F>| {
                    #body
                };
                #[comment = " SAFETY: dispatchable handle and arguments satisfy the Vulkan command contract."]
                unsafe { super::instance::#invocation::<F>(#dispatch.0, venus_call) }
            }
        }))
    }
    /// Everything generated for a struct or union that was reached by a
    /// command: the walks its `need_*` flags ask for.
    pub fn type_functions(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let mut out = TokenStream::new();
        match ty.category() {
            Category::Struct => {
                // Mesa's driver emits `sizeof` for every struct and `encode`
                // only for those an input reaches. One walk is both here, and
                // `sizeof_reply` measures the outputs, so every struct gets it.
                out.extend(self.struct_functions(id, Variant::Encode)?);
                if ty.need_decode {
                    out.extend(self.struct_functions(id, Variant::Decode)?);
                }
                if ty.need_partial {
                    out.extend(self.struct_functions(id, Variant::EncodePartial)?);
                }
            }
            Category::Union => {
                out.extend(self.union_encode(id)?);
                if ty.need_decode {
                    out.extend(self.union_decode(id)?);
                }
            }
            other => {
                return Err(RegistryError::unsupported(format!(
                    "no functions for the {other:?} type {}",
                    ty.name
                )));
            }
        }
        Ok(out)
    }

    fn encode_members(&self, id: TypeId, skip: usize, partial: bool) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let frame = Frame {
            container: id,
            access: Access::Val,
        };
        let mut body = TokenStream::new();
        for var in &ty.variables[skip..] {
            let validity = self.validity(id, var, !partial);
            body.extend(self.encode_var(frame, var, validity)?);
        }
        Ok(body)
    }

    fn decode_members(&self, id: TypeId, skip: usize) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let frame = Frame {
            container: id,
            access: Access::Val,
        };
        let (capacities, body) =
            self.decode_outputs(frame, ty.variables[skip..].iter(), TokenStream::new())?;
        Ok(quote!(#capacities #body))
    }

    fn decode_outputs<'v>(
        &self,
        frame: Frame,
        variables: impl Iterator<Item = &'v Variable>,
        failure_return: TokenStream,
    ) -> Result<(TokenStream, TokenStream)> {
        let mut capacities = TokenStream::new();
        let mut body = TokenStream::new();
        for var in variables {
            if let Some((capacity, value)) = self.reply_array_capacity(frame, var)? {
                capacities.extend(quote!(let #capacity: u64 = #value;));
                body.extend(quote! {
                    let venus_found = peek_array_size(dec);
                    if venus_found > #capacity {
                        dec.fail(DecodeError::ArrayCapacity {
                            capacity: #capacity,
                            found: venus_found,
                        });
                        return #failure_return;
                    }
                });
            }
            body.extend(self.decode_var(frame, var)?);
        }
        Ok((capacities, body))
    }

    fn struct_functions(&self, id: TypeId, variant: Variant) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let name = ident(&ty.name);
        let suffix = variant.suffix();
        let partial = variant == Variant::EncodePartial;
        let Some(s_type) = &ty.s_type else {
            // A plain struct: just its members.
            return Ok(if variant.is_encode() {
                let function = func("encode", &format!("{}{suffix}", ty.name));
                let body = isolate_stmts(self.encode_members(id, 0, partial)?)?;
                let doc = format!(" Encode `{}` into `enc`.", ty.name);
                let safety_doc = format!(
                    " `val` must be valid for reads of `{}` and all reachable Vulkan inputs.",
                    ty.name
                );
                quote! {
                    #[doc = #doc]
                    ///
                    /// # Safety
                    #[doc = #safety_doc]
                    pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                        #body
                    }
                }
            } else {
                let function = func("decode", &ty.name);
                let body = isolate_stmts(self.decode_members(id, 0)?)?;
                let doc = format!(" Decode `{}` from `dec`.", ty.name);
                let safety_doc = format!(
                    " `val` must be valid for writes of `{}` and all reachable Vulkan outputs.",
                    ty.name
                );
                quote! {
                    #[doc = #doc]
                    ///
                    /// # Safety
                    #[doc = #safety_doc]
                    pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                        #body
                    }
                }
            });
        };
        let s_type = ident(s_type);
        let pnext = self.pnext_function(id, variant)?;
        let self_function = func(
            if variant.is_encode() {
                "encode"
            } else {
                "decode"
            },
            &format!("{}_self{suffix}", ty.name),
        );
        let pnext_name = func(
            if variant.is_encode() {
                "encode"
            } else {
                "decode"
            },
            &format!("{}_pnext{suffix}", ty.name),
        );
        let function = func(
            if variant.is_encode() {
                "encode"
            } else {
                "decode"
            },
            &format!("{}{suffix}", ty.name),
        );
        Ok(if variant.is_encode() {
            let body = isolate_stmts(self.encode_members(id, 2, partial)?)?;
            let self_doc = format!(
                " Encode `{}`'s own members (after `sType` and `pNext`) into `enc`.",
                ty.name
            );
            let self_safety_doc = format!(
                " `val` must be valid for reads of `{}`'s own members and reachable inputs.",
                ty.name
            );
            let doc = format!(" Encode `{}` and its `pNext` chain into `enc`.", ty.name);
            let safety_doc = format!(
                " `val` must be valid for reads of `{}` and all reachable Vulkan inputs and `pNext` chains.",
                ty.name
            );
            quote! {
                #pnext
                #[doc = #self_doc]
                ///
                /// # Safety
                #[doc = #self_safety_doc]
                pub unsafe fn #self_function<S: Sink>(enc: &mut S, val: *const #name) {
                    #body
                }
                #[doc = #doc]
                ///
                /// # Safety
                #[doc = #safety_doc]
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                    #[comment = " SAFETY: `val` points to a readable struct header."]
                    let s_type = unsafe { (*val).sType };
                    if s_type != #s_type {
                        enc.fail(EncodeError::StructureType {
                            expected: #s_type.0,
                            found: s_type.0,
                        });
                    }
                    #[comment = " SAFETY: the struct's expected `VkStructureType` constant is initialized."]
                    unsafe { encode_scalar::<_, VkStructureType>(enc, &#s_type) };
                    #[comment = " SAFETY: `val` points to a readable struct header."]
                    let pnext = unsafe { (*val).pNext };
                    #[comment = " SAFETY: `pnext` is null or points to a readable Vulkan `pNext` chain."]
                    unsafe { #pnext_name(enc, PtrExt::into_const(pnext)) };
                    #[comment = " SAFETY: `val` points to valid struct storage for encoding."]
                    unsafe { #self_function(enc, val) };
                }
            }
        } else {
            let body = isolate_stmts(self.decode_members(id, 2)?)?;
            let self_doc = format!(
                " Decode `{}`'s own members (after `sType` and `pNext`) from `dec`.",
                ty.name
            );
            let self_safety_doc = format!(
                " `val` must be valid for writes of `{}`'s own members and reachable outputs.",
                ty.name
            );
            let doc = format!(" Decode `{}` and its `pNext` chain from `dec`.", ty.name);
            let safety_doc = format!(
                " `val` must be valid for writes of `{}` and all reachable Vulkan outputs and `pNext` chains.",
                ty.name
            );
            quote! {
                #pnext
                #[doc = #self_doc]
                ///
                /// # Safety
                #[doc = #self_safety_doc]
                pub unsafe fn #self_function(dec: &mut Decoder<'_>, val: *mut #name) {
                    #body
                }
                #[doc = #doc]
                ///
                /// # Safety
                #[doc = #safety_doc]
                pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                    let mut s_type = VkStructureType(0);
                    #[comment = " SAFETY: `s_type` is a local writable `VkStructureType`."]
                    unsafe { decode_scalar::<VkStructureType>(dec, &mut s_type) };
                    if s_type != #s_type {
                        dec.fail(DecodeError::StructureType {
                            expected: #s_type.0,
                            found: s_type.0,
                        });
                    }
                    #[comment = " SAFETY: `val` points to a readable struct header."]
                    let pnext = unsafe { (*val).pNext };
                    #[comment = " SAFETY: `pnext` is null or points to a writable Vulkan `pNext` chain."]
                    unsafe { #pnext_name(dec, PtrExt::into_mut(pnext)) };
                    #[comment = " SAFETY: `val` points to writable struct storage."]
                    unsafe { #self_function(dec, val) };
                }
            }
        })
    }

    /// `vn_{encode,decode}_<ty>_pnext`: the chain of a struct, dispatching on
    /// the chained struct's sType.
    fn pnext_function(&self, id: TypeId, variant: Variant) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let suffix = variant.suffix();
        let (next_types, _skipped) = self.an.chain(id);
        let encode = variant.is_encode();
        let name = format!("{}_pnext{suffix}", ty.name);
        let function = func(if encode { "encode" } else { "decode" }, &name);
        if next_types.is_empty() {
            return Ok(if encode {
                quote! {
                    /// Encode an empty `pNext` chain terminator.
                    ///
                    /// # Safety
                    /// `_val` must be null or point to a valid Vulkan `pNext` chain.
                    pub unsafe fn #function<S: Sink>(enc: &mut S, _val: *const ::core::ffi::c_void) {
                        encode_simple_pointer(enc, ::core::ptr::null::<::core::ffi::c_void>());
                    }
                }
            } else {
                quote! {
                    /// Decode an empty `pNext` chain terminator.
                    ///
                    /// # Safety
                    /// `_val` must be null or point to a valid Vulkan `pNext` chain.
                    pub unsafe fn #function(dec: &mut Decoder<'_>, _val: *mut ::core::ffi::c_void) {
                        if decode_simple_pointer(dec) {
                            dec.fail(DecodeError::UnexpectedChainedStructure { s_type: -1 });
                        }
                    }
                }
            });
        }
        if encode {
            // A chained struct is sent unless the renderer protocol lacks
            // what introduced it: the arm's guard.
            let mut cases = Vec::new();
            for next in next_types {
                let next_ty = &self.an.reg.types[next];
                let next_name = ident(&next_ty.name);
                let s_type = ident(next_ty.s_type.as_ref().ok_or_else(|| {
                    RegistryError::inconsistent(format!("chained {} has no sType", next_ty.name))
                })?);
                let self_function = func("encode", &format!("{}_self{suffix}", next_ty.name));
                let guard = self.an.type_condition(next)?.map(|condition| {
                    let skip = condition_tokens(&condition);
                    quote!(!(#skip))
                });
                let body = quote! {
                    encode_simple_pointer(enc, pnext);
                    #[comment = " SAFETY: non-null `pnext` starts with an initialized `VkStructureType`."]
                    unsafe { encode_scalar::<_, VkStructureType>(enc, pnext.cast::<VkStructureType>()) };
                    #[comment = " SAFETY: `pnext` points to a readable chained struct header."]
                    let next_pnext = unsafe { (*pnext.cast::<#next_name>()).pNext };
                    #[comment = " SAFETY: `next_pnext` is null or points to a readable Vulkan `pNext` chain."]
                    unsafe { #function(enc, PtrExt::into_const(next_pnext)) };
                    #[comment = " SAFETY: `pnext` points to readable chained struct storage."]
                    unsafe { #self_function(enc, pnext.cast::<#next_name>()) };
                    return;
                };
                cases.push((s_type, guard, body));
            }
            let dispatch = if let [(s_type, guard, body)] = &cases[..] {
                // One chained struct: a comparison, not a `match`.
                let guard = guard.as_ref().map(|guard| quote!(&& #guard));
                quote! {
                    if s_type == #s_type #guard {
                        #body
                    }
                }
            } else {
                let arms = cases.iter().map(|(s_type, guard, body)| {
                    let guard = guard.as_ref().map(|guard| quote!(if #guard));
                    quote!(#s_type #guard => { #body })
                });
                quote! {
                    match s_type {
                        #(#arms)*
                        // Unknown and unsupported structs are ignored.
                        _ => {}
                    }
                }
            };
            Ok(quote! {
                /// Encode a Vulkan `pNext` chain.
                ///
                /// # Safety
                /// `val` must be null or point to a valid readable Vulkan `pNext` chain.
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const ::core::ffi::c_void) {
                    let mut pnext = val;
                    while !pnext.is_null() {
                        #[comment = " SAFETY: non-null `pnext` points to a readable `VkStructureType` header."]
                        let s_type = unsafe { *pnext.cast::<VkStructureType>() };
                        #dispatch
                        #[comment = " SAFETY: non-null `pnext` points to a readable `BaseStructure` header."]
                        let next = unsafe { (*pnext.cast::<BaseStructure>()).pNext };
                        pnext = next;
                    }
                    encode_simple_pointer(enc, ::core::ptr::null::<::core::ffi::c_void>());
                }
            })
        } else {
            let mut arms = TokenStream::new();
            for next in next_types {
                let next_ty = &self.an.reg.types[next];
                let next_name = ident(&next_ty.name);
                let s_type = ident(next_ty.s_type.as_ref().ok_or_else(|| {
                    RegistryError::inconsistent(format!("chained {} has no sType", next_ty.name))
                })?);
                let self_function = func("decode", &format!("{}_self", next_ty.name));
                arms.extend(quote! {
                    #s_type => {
                        #[comment = " SAFETY: `pnext` points to a readable chained struct header."]
                        let next_pnext = unsafe { (*pnext.cast::<#next_name>()).pNext };
                        #[comment = " SAFETY: `next_pnext` is null or points to a writable Vulkan `pNext` chain."]
                        unsafe { #function(dec, PtrExt::into_mut(next_pnext)) };
                        #[comment = " SAFETY: `pnext` points to writable chained struct storage."]
                        unsafe { #self_function(dec, pnext.cast::<#next_name>()) };
                    }
                });
            }
            Ok(quote! {
                /// Decode a Vulkan `pNext` chain.
                ///
                /// # Safety
                /// `val` must be null or point to a valid writable Vulkan `pNext` chain.
                pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut ::core::ffi::c_void) {
                    if !decode_simple_pointer(dec) {
                        return;
                    }
                    let mut s_type = VkStructureType(0);
                    #[comment = " SAFETY: `s_type` is a local writable `VkStructureType`."]
                    unsafe { decode_scalar::<VkStructureType>(dec, &mut s_type) };
                    let mut pnext = val;
                    loop {
                        if pnext.is_null() {
                            dec.fail(DecodeError::UnexpectedChainedStructure { s_type: s_type.0 });
                            return;
                        }
                        #[comment = " SAFETY: non-null `pnext` points to a readable `VkStructureType` header."]
                        let current_type = unsafe { *pnext.cast::<VkStructureType>() };
                        if current_type == s_type {
                            break;
                        }
                        #[comment = " SAFETY: non-null `pnext` points to a readable `BaseStructure` header."]
                        let next = unsafe { (*pnext.cast::<BaseStructure>()).pNext };
                        pnext = PtrExt::into_mut(next);
                    }
                    match s_type {
                        #arms
                        _ => dec.fail(DecodeError::UnexpectedChainedStructure { s_type: s_type.0 }),
                    }
                }
            })
        }
    }

    fn union_tag_type(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        if ty.is_valid_union() {
            let selector = ty.selector_type.as_ref().ok_or_else(|| {
                RegistryError::inconsistent(format!("union {} has no selector type", ty.name))
            })?;
            base_type(self.an, selector.base)
        } else {
            Ok(quote!(u32))
        }
    }

    fn union_encode(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let name = ident(&ty.name);
        let function = func("encode", &ty.name);
        let frame = Frame {
            container: id,
            access: Access::Val,
        };
        let tag_ty = self.union_tag_type(id)?;
        let mut arms = TokenStream::new();
        if ty.is_valid_union() {
            for (pattern, index) in self.union_cases(id)? {
                let var = &ty.variables[index];
                let body = isolate_union_stmts(self.encode_var(
                    frame,
                    var,
                    self.validity(id, var, true),
                )?)?;
                arms.extend(quote!(#pattern => { #body }));
            }
            Ok(quote! {
                /// Encode the union member selected by `tag` into `enc`.
                ///
                /// # Safety
                /// `val` must be valid for reads of the active union member indicated by `tag`.
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name, tag: #tag_ty) {
                    #[comment = " SAFETY: `tag` is a local initialized union selector."]
                    unsafe { encode_scalar::<_, #tag_ty>(enc, &tag) };
                    match tag {
                        #arms
                        _ => enc.fail(EncodeError::UnionTag),
                    }
                }
            })
        } else {
            // The union has no selector: it is encoded as the member its
            // default tag names.
            let (_, tag) = crate::policy::UNION_DEFAULT_TAGS
                .iter()
                .find(|(n, _)| *n == ty.name)
                .ok_or_else(|| {
                    RegistryError::inconsistent(format!("union {} has no default tag", ty.name))
                })?;
            let var = &ty.variables[*tag as usize];
            let body =
                isolate_union_stmts(self.encode_var(frame, var, self.validity(id, var, true))?)?;
            let tag = Literal::u32_suffixed(*tag);
            Ok(quote! {
                /// Encode the default-selected union member into `enc`.
                ///
                /// # Safety
                /// `val` must be valid for reads of the union's default-selected member.
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                    // A union with a default tag.
                    let tag: u32 = #tag;
                    #[comment = " SAFETY: `tag` is a local initialized `u32`."]
                    unsafe { encode_scalar::<_, u32>(enc, &tag) };
                    #body
                }
            })
        }
    }

    fn union_decode(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let name = ident(&ty.name);
        let function = func("decode", &ty.name);
        let frame = Frame {
            container: id,
            access: Access::Val,
        };
        let tag_ty = self.union_tag_type(id)?;
        let mut arms = TokenStream::new();
        for (pattern, index) in self.union_cases(id)? {
            let body = isolate_stmts(self.decode_var(frame, &ty.variables[index])?)?;
            arms.extend(quote!(#pattern => { #body }));
        }
        let zero = if ty.is_valid_union() {
            let selector = ty
                .selector_type
                .as_ref()
                .expect("checked by union_tag_type");
            if self.an.reg.types[selector.base].category() == Category::Enum {
                quote!(#tag_ty(0))
            } else {
                quote!(0)
            }
        } else {
            quote!(0)
        };
        Ok(quote! {
            /// Decode a tagged union from `dec`.
            ///
            /// # Safety
            /// `val` must be valid for writes of the decoded union member.
            pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                let mut tag: #tag_ty = #zero;
                #[comment = " SAFETY: `tag` is a local writable union selector."]
                unsafe { decode_scalar::<#tag_ty>(dec, &mut tag) };
                match tag {
                    #arms
                    _ => dec.fail(DecodeError::UnionTag),
                }
            }
        })
    }

    // -- handles --------------------------------------------------------------

    pub fn handle_functions(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let name = ident(&ty.name);
        let encode = func("encode", &ty.name);
        let decode = func("decode", &ty.name);
        Ok(if ty.dispatchable {
            let safety_doc = format!(
                " `val` must point to an initialized `{}` whose inner pointer is null or valid.",
                ty.name
            );
            quote! {
                /// Encode a dispatchable Vulkan handle into `enc`.
                ///
                /// # Safety
                #[doc = #safety_doc]
                pub unsafe fn #encode<S: Sink>(enc: &mut S, val: *const #name) {
                    #[comment = " SAFETY: `val` points to an initialized dispatchable handle."]
                    let handle = unsafe { (*val).0 };
                    #[comment = " SAFETY: `handle` is null or points to a live `ObjectBase`."]
                    let id: u64 = unsafe { handle_id(handle) };
                    #[comment = " SAFETY: `id` is a local initialized `u64`."]
                    unsafe { encode_scalar::<_, u64>(enc, &id) };
                }
                /// Decode a dispatchable Vulkan handle from `dec`.
                ///
                /// # Safety
                #[doc = #safety_doc]
                pub unsafe fn #decode(dec: &mut Decoder<'_>, val: *mut #name) {
                    let mut id: u64 = 0;
                    #[comment = " SAFETY: `id` is a local writable `u64`."]
                    unsafe { decode_scalar::<u64>(dec, &mut id) };
                    #[comment = " SAFETY: `val` points to an initialized dispatchable handle."]
                    let handle = unsafe { (*val).0 };
                    #[comment = " SAFETY: `handle` is null or points to a live `ObjectBase`."]
                    unsafe { store_handle_id(dec, handle, id) };
                }
            }
        } else {
            let encode_doc = format!(" `val` must point to an initialized `{}`.", ty.name);
            let decode_doc = format!(" `val` must point to writable `{}` storage.", ty.name);
            quote! {
                /// Encode a non-dispatchable Vulkan handle into `enc`.
                ///
                /// # Safety
                #[doc = #encode_doc]
                pub unsafe fn #encode<S: Sink>(enc: &mut S, val: *const #name) {
                    #[comment = " SAFETY: the handle is `#[repr(transparent)]` over `u64` and `val` is valid for reads."]
                    unsafe { encode_scalar::<_, u64>(enc, val.cast::<u64>()) };
                }
                /// Decode a non-dispatchable Vulkan handle from `dec`.
                ///
                /// # Safety
                #[doc = #decode_doc]
                pub unsafe fn #decode(dec: &mut Decoder<'_>, val: *mut #name) {
                    #[comment = " SAFETY: the handle is `#[repr(transparent)]` over `u64` and `val` is valid for writes."]
                    unsafe { decode_scalar::<u64>(dec, val.cast::<u64>()) };
                }
            }
        })
    }

    // -- commands -------------------------------------------------------------

    fn command_params(&self, id: TypeId) -> Result<Vec<TokenStream>> {
        let ty = &self.an.reg.types[id];
        ty.variables
            .iter()
            .map(|var| {
                let name = ident(&var.name);
                let ty = decl_type(self.an, &var.ty, &var.name)?;
                Ok(quote!(#name: #ty))
            })
            .collect()
    }

    fn command_args(&self, id: TypeId) -> Vec<TokenStream> {
        self.an.reg.types[id]
            .variables
            .iter()
            .map(|var| {
                let name = ident(&var.name);
                quote!(#name)
            })
            .collect()
    }

    fn return_variable(ret: &TypeRef) -> Variable {
        Variable {
            name: "ret".into(),
            ty: ret.clone(),
            attrs: crate::registry::VarAttrs {
                var_out: true,
                ..Default::default()
            },
        }
    }

    /// Driver calls use the same wire walks as the parity-tested codec.
    pub fn command_call(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        if ty.name.ends_with("MESA") {
            return Ok(TokenStream::new());
        }
        let params = self.command_params(id)?;
        let args = self.command_args(id);
        let call = func("call", &ty.name);
        let encode = func("encode", &ty.name);
        let sizeof = func("sizeof", &ty.name);
        let sizeof_reply = func("sizeof", &format!("{}_reply", ty.name));
        let decode_reply = func("decode", &format!("{}_reply", ty.name));
        let ret = match &ty.ret {
            Some(ret) => decl_type(self.an, ret, "the return value")?,
            None => quote!(()),
        };
        let reply = ty.ret.is_some() || ty.variables.iter().any(|var| var.attrs.var_out);
        let flags = if reply {
            quote!(VK_COMMAND_GENERATE_REPLY_BIT_EXT.0 as u32)
        } else {
            quote!(0)
        };
        let decode = if ty.ret.is_some() {
            quote! {
                #[comment = " SAFETY: caller guarantees output arguments satisfy the reply decoder contract."]
                let venus_result = unsafe { #decode_reply(&mut venus_decoder, #(#args),*) };
            }
        } else {
            quote! {
                #[comment = " SAFETY: caller guarantees output arguments satisfy the reply decoder contract."]
                unsafe { #decode_reply(&mut venus_decoder, #(#args),*) };
            }
        };
        let result = if ty.ret.is_some() {
            quote!(venus_result)
        } else {
            quote!(())
        };
        let finish = if reply {
            quote! {
                #[comment = " SAFETY: caller guarantees arguments satisfy the reply sizer contract."]
                let venus_reply_size = unsafe { #sizeof_reply(venus_connection.protocol(), #(#args),*) }?;
                let venus_reply = venus_connection.call(&venus_bytes, venus_reply_size)?;
                let mut venus_decoder = Decoder::new(venus_reply);
                #decode
                venus_decoder.finish()?;
                Ok(#result)
            }
        } else {
            quote! {
                venus_connection.send(&venus_bytes)?;
                Ok(())
            }
        };
        Ok(quote! {
            /// Submit through the connection, decoding outputs when present.
            ///
            /// # Safety
            /// Pointers and handles satisfy the Vulkan command's contracts;
            /// output handles have already been assigned renderer object ids.
            pub unsafe fn #call<T: crate::transport::Transport>(
                venus_connection: &mut crate::connection::Connection<T>, #(#params),*
            ) -> Result<#ret, crate::connection::Error<T::Error>> {
                #[comment = " SAFETY: caller guarantees arguments satisfy the request sizer contract."]
                let venus_size = unsafe { #sizeof(venus_connection.protocol(), #(#args),*) }?;
                let mut venus_bytes = vec![0; venus_size];
                let mut venus_encoder = Encoder::new(&mut venus_bytes, venus_connection.protocol());
                #[comment = " SAFETY: caller guarantees arguments satisfy the request encoder contract."]
                unsafe { #encode(&mut venus_encoder, #flags, #(#args),*) };
                venus_encoder.finish()?;
                #finish
            }
        })
    }

    /// `sizeof`, `encode`, `sizeof_reply`, `encode_reply` and `decode_reply`
    /// of a command.
    pub fn command_functions(&self, id: TypeId) -> Result<TokenStream> {
        let ty = &self.an.reg.types[id];
        let frame = Frame {
            container: id,
            access: Access::Param,
        };
        let command_const = ident(&format!("VK_COMMAND_TYPE_{}_EXT", ty.name));
        let params = self.command_params(id)?;
        let args = self.command_args(id);
        let encode = func("encode", &ty.name);
        let sizeof = func("sizeof", &ty.name);
        let encode_reply = func("encode", &format!("{}_reply", ty.name));
        let sizeof_reply = func("sizeof", &format!("{}_reply", ty.name));
        let decode_reply = func("decode", &format!("{}_reply", ty.name));

        let mut encode_body = TokenStream::new();
        for var in &ty.variables {
            let validity = self.validity(id, var, var.attrs.var_in);
            encode_body.extend(self.encode_var(frame, var, validity)?);
        }
        let encode_body = isolate_stmts(encode_body)?;

        let ret = ty.ret.as_ref();
        let ret_var = ret.map(Self::return_variable);
        let ret_ty = match ret {
            Some(ret) => Some(decl_type(self.an, ret, "the return value")?),
            None => None,
        };

        let mut reply_encode_body = TokenStream::new();
        let mut reply_decode_body = TokenStream::new();
        let failure_return = ret_ty.as_ref().map(|_| quote!(ret)).unwrap_or_default();
        if let Some(var) = &ret_var {
            reply_encode_body.extend(self.encode_var(frame, var, Validity::Valid)?);
            reply_decode_body.extend(self.decode_var(frame, var)?);
        }
        for var in ty.variables.iter().filter(|v| v.attrs.var_out) {
            reply_encode_body.extend(self.encode_var(frame, var, Validity::Valid)?);
        }
        let (reply_capacities, outputs) = self.decode_outputs(
            frame,
            ty.variables.iter().filter(|v| v.attrs.var_out),
            failure_return,
        )?;
        reply_decode_body.extend(outputs);
        let reply_encode_body = isolate_stmts(reply_encode_body)?;
        let reply_capacities = isolate_stmts(reply_capacities)?;
        let reply_decode_body = isolate_stmts(reply_decode_body)?;

        let ret_param = ret_ty.as_ref().map(|ret_ty| quote!(ret: #ret_ty,));
        let ret_arg = ret_ty.as_ref().map(|_| quote!(ret,));
        let ret_zero = ret_ty.as_ref().map(|ret_ty| {
            quote! {
                #[comment = " SAFETY: the return type is a C-layout scalar/enum where zeroed bytes are valid for sizing."]
                let ret: #ret_ty = unsafe { ::core::mem::zeroed() };
            }
        });
        let ret_local = ret_ty.as_ref().map(|ret_ty| {
            quote! {
                #[comment = " SAFETY: the return type is a C-layout scalar/enum where zeroed bytes are valid."]
                let mut ret: #ret_ty = unsafe { ::core::mem::zeroed() };
            }
        });
        let ret_value = ret_ty.as_ref().map(|_| quote!(ret));
        let decode_return = ret_ty.as_ref().map(|ret_ty| quote!(-> #ret_ty));

        Ok(quote! {
            /// Encode the command's request stream into `enc`.
            ///
            /// # Safety
            /// All pointer, array, and `pNext` arguments must satisfy the Vulkan command's input contract.
            pub unsafe fn #encode<S: Sink>(enc: &mut S, cmd_flags: VkCommandFlagsEXT, #(#params),*) {
                let cmd_type = #command_const;
                #[comment = " SAFETY: `cmd_type` is a local initialized `VkCommandTypeEXT`."]
                unsafe { encode_scalar::<_, VkCommandTypeEXT>(enc, &cmd_type) };
                #[comment = " SAFETY: `cmd_flags` is a local initialized `VkFlags`."]
                unsafe { encode_scalar::<_, VkFlags>(enc, &cmd_flags) };
                #encode_body
            }
            /// Measure the encoded size of the command's request stream.
            ///
            /// # Safety
            /// All pointer, array, and `pNext` arguments must satisfy the Vulkan command's input contract.
            pub unsafe fn #sizeof(protocol: &RendererProtocol, #(#params),*) -> Result<usize, EncodeError> {
                let mut enc = Sizer::new(protocol);
                #[comment = " SAFETY: caller guarantees arguments satisfy the request encoder contract."]
                unsafe { #encode(&mut enc, 0, #(#args),*) };
                enc.finish()
            }
            /// Encode the command's reply stream into `enc`.
            ///
            /// # Safety
            /// All pointer, array, and `pNext` arguments must satisfy the Vulkan command's reply contract.
            pub unsafe fn #encode_reply<S: Sink>(enc: &mut S, #ret_param #(#params),*) {
                let cmd_type = #command_const;
                #[comment = " SAFETY: `cmd_type` is a local initialized `VkCommandTypeEXT`."]
                unsafe { encode_scalar::<_, VkCommandTypeEXT>(enc, &cmd_type) };
                #reply_encode_body
            }
            /// Measure the encoded size of the command's reply stream.
            ///
            /// # Safety
            /// All pointer, array, and `pNext` arguments must satisfy the Vulkan command's reply contract.
            pub unsafe fn #sizeof_reply(protocol: &RendererProtocol, #(#params),*) -> Result<usize, EncodeError> {
                let mut enc = Sizer::new(protocol);
                #ret_zero
                #[comment = " SAFETY: caller guarantees arguments satisfy the reply encoder contract."]
                unsafe { #encode_reply(&mut enc, #ret_arg #(#args),*) };
                enc.finish()
            }
            /// Decode the command's reply stream from `dec`.
            ///
            /// # Safety
            /// All output pointer, array, and `pNext` arguments must point to valid writable Vulkan storage.
            pub unsafe fn #decode_reply(dec: &mut Decoder<'_>, #(#params),*) #decode_return {
                #reply_capacities
                let mut command_type = VkCommandTypeEXT(0);
                #[comment = " SAFETY: `command_type` is a local writable `VkCommandTypeEXT`."]
                unsafe { decode_scalar::<VkCommandTypeEXT>(dec, &mut command_type) };
                if command_type != #command_const {
                    dec.fail(DecodeError::CommandType {
                        expected: #command_const.0,
                        found: command_type.0,
                    });
                }
                #ret_local
                #reply_decode_body
                #ret_value
            }
        })
    }
}

fn ext_expr_tokens(expr: &ExtExpr) -> TokenStream {
    match expr {
        ExtExpr::Has(number) => {
            let number = Literal::u32_suffixed(*number);
            quote!(enc.protocol().has_extension(#number))
        }
        ExtExpr::And(items) => {
            let items = items.iter().map(ext_expr_tokens);
            quote!((#(#items)&&*))
        }
        ExtExpr::Or(items) => {
            let items = items.iter().map(ext_expr_tokens);
            quote!((#(#items)||*))
        }
    }
}

/// The condition under which a chained struct is skipped.
fn condition_tokens(condition: &ChainCondition) -> TokenStream {
    match condition {
        ChainCondition::ApiVersion { major, minor } => {
            let (major, minor) = (Literal::u32_suffixed(*major), Literal::u32_suffixed(*minor));
            quote!(!enc.protocol().has_api_version(api_version(#major, #minor)))
        }
        ChainCondition::Extensions { exts, pairs } => {
            let mut terms: Vec<TokenStream> = Vec::new();
            for number in exts {
                let number = Literal::u32_suffixed(*number);
                terms.push(quote!(!enc.protocol().has_extension(#number)));
            }
            for (number, deps) in pairs {
                let number = Literal::u32_suffixed(*number);
                let deps = ext_expr_tokens(deps);
                terms.push(quote!(!(enc.protocol().has_extension(#number) && #deps)));
            }
            quote!(#(#terms)&&*)
        }
    }
}

const DEREF_SAFETY: &str =
    " SAFETY: pointer is valid for reads under the caller's Vulkan contract.";
const ADD_SAFETY: &str = " SAFETY: offset is within the bounds of the Vulkan array.";
const WRITE_SAFETY: &str =
    " SAFETY: destination pointer is valid for writes of the Vulkan output handle.";
const ADDR_OF_SAFETY: &str = " SAFETY: pointer is valid for the Vulkan place address taken here.";
const CSTR_SAFETY: &str = " SAFETY: pointer references a NUL-terminated C string.";
const ENCODE_SAFETY: &str =
    " SAFETY: source pointer and length satisfy the encoder's wire contract.";
const DECODE_SAFETY: &str =
    " SAFETY: destination pointer and length satisfy the decoder's wire contract.";
const CALL_SAFETY: &str =
    " SAFETY: arguments and output handles satisfy the Vulkan command's contract.";
const UNION_REF_SAFETY: &str = " SAFETY: `val` points to a readable Vulkan union.";

/// Splits generated statement streams so every unsafe operation sits in its
/// own `unsafe` block preceded by a `// SAFETY:` comment.
fn isolate_stmts(tokens: TokenStream) -> Result<TokenStream> {
    isolate_stmts_with(tokens, false)
}

fn isolate_union_stmts(tokens: TokenStream) -> Result<TokenStream> {
    isolate_stmts_with(tokens, true)
}

fn isolate_stmts_with(tokens: TokenStream, val_is_union: bool) -> Result<TokenStream> {
    if tokens.is_empty() {
        return Ok(tokens);
    }
    let mut block: syn::Block = syn::parse2(quote!({ #tokens })).map_err(|error| {
        RegistryError::inconsistent(format!(
            "generated wire statements failed to parse: {error}"
        ))
    })?;
    let mut isolator = Isolator {
        next_id: 0,
        val_is_union,
    };
    isolator.isolate_block(&mut block);
    let stmts = block.stmts;
    Ok(quote!(#(#stmts)*))
}

struct Isolator {
    next_id: usize,
    val_is_union: bool,
}

impl Isolator {
    fn temp_ident(&mut self) -> proc_macro2::Ident {
        let id = self.next_id;
        self.next_id += 1;
        quote::format_ident!("venus_u{id}")
    }

    fn isolate_block(&mut self, block: &mut syn::Block) {
        let mut out = Vec::with_capacity(block.stmts.len());
        for stmt in core::mem::take(&mut block.stmts) {
            self.isolate_stmt(stmt, &mut out);
        }
        block.stmts = out;
    }

    fn isolate_stmt(&mut self, stmt: syn::Stmt, out: &mut Vec<syn::Stmt>) {
        match stmt {
            syn::Stmt::Local(mut local) => {
                if let Some(init) = &mut local.init {
                    let mut pre = Vec::new();
                    if init.diverge.is_none()
                        && let Some(msg) = direct_unsafe_safety(&init.expr)
                    {
                        self.isolate_operands(&mut init.expr, &mut pre);
                        let inner = take_expr(&mut init.expr);
                        local.attrs.push(make_comment_attr(msg));
                        *init.expr = wrap_unsafe_expr(inner);
                    } else {
                        self.isolate_expr(&mut init.expr, &mut pre);
                        if let Some((_, diverge)) = &mut init.diverge {
                            self.isolate_scoped_expr(diverge);
                        }
                    }
                    out.extend(pre);
                }
                out.push(syn::Stmt::Local(local));
            }
            syn::Stmt::Expr(mut expr, semi) => {
                let mut pre = Vec::new();
                if let Some(msg) = direct_unsafe_safety(&expr) {
                    self.isolate_operands(&mut expr, &mut pre);
                    expr = wrap_unsafe_expr_with_comment(expr, msg);
                } else {
                    self.isolate_expr(&mut expr, &mut pre);
                }
                out.extend(pre);
                out.push(syn::Stmt::Expr(expr, semi));
            }
            other => out.push(other),
        }
    }

    fn isolate_scoped_expr(&mut self, expr: &mut syn::Expr) {
        match expr {
            syn::Expr::Block(b) => self.isolate_block(&mut b.block),
            _ => {
                let mut pre = Vec::new();
                self.isolate_expr(expr, &mut pre);
                if !pre.is_empty() {
                    let inner = take_expr(expr);
                    *expr = syn::Expr::Block(syn::ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: syn::Block {
                            brace_token: Default::default(),
                            stmts: {
                                pre.push(syn::Stmt::Expr(inner, None));
                                pre
                            },
                        },
                    });
                }
            }
        }
    }

    fn isolate_operands(&mut self, expr: &mut syn::Expr, pre: &mut Vec<syn::Stmt>) {
        match expr {
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                self.isolate_expr(&mut u.expr, pre);
            }
            syn::Expr::Field(f) if self.val_is_union && is_deref_val(&f.base) => {
                let tmp = self.temp_ident();
                let ref_expr: syn::Expr =
                    syn::parse2(quote!(&*val)).expect("union ref expr parses");
                pre.push(make_let_unsafe(&tmp, ref_expr, UNION_REF_SAFETY));
                *f.base = syn::parse2(quote!(#tmp)).expect("temp ident parses");
            }
            syn::Expr::Field(_) | syn::Expr::Index(_) if is_deref_place(expr) => {
                self.isolate_deref_place_operands(expr, pre);
            }
            syn::Expr::MethodCall(mc) => {
                self.isolate_expr(&mut mc.receiver, pre);
                for arg in &mut mc.args {
                    self.isolate_expr(arg, pre);
                }
            }
            syn::Expr::Call(call) => {
                self.isolate_expr(&mut call.func, pre);
                for arg in &mut call.args {
                    self.isolate_expr(arg, pre);
                }
            }
            syn::Expr::Macro(m) if is_addr_of_macro(&m.mac) => {
                let mut place: syn::Expr =
                    syn::parse2(m.mac.tokens.clone()).expect("addr_of operand parses");
                self.isolate_deref_place_operands(&mut place, pre);
                m.mac.tokens = quote!(#place);
            }
            _ => self.isolate_expr(expr, pre),
        }
    }

    fn isolate_deref_place_operands(&mut self, expr: &mut syn::Expr, pre: &mut Vec<syn::Stmt>) {
        match expr {
            syn::Expr::Field(f) => self.isolate_deref_place_operands(&mut f.base, pre),
            syn::Expr::Index(ix) => {
                self.isolate_deref_place_operands(&mut ix.expr, pre);
                self.isolate_expr(&mut ix.index, pre);
            }
            syn::Expr::Paren(p) => self.isolate_deref_place_operands(&mut p.expr, pre),
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                self.isolate_expr(&mut u.expr, pre);
            }
            _ => {}
        }
    }

    fn isolate_expr(&mut self, expr: &mut syn::Expr, pre: &mut Vec<syn::Stmt>) {
        if let Some(msg) = direct_unsafe_safety(expr) {
            self.isolate_operands(expr, pre);
            let inner = take_expr(expr);
            let tmp = self.temp_ident();
            pre.push(make_let_unsafe(&tmp, inner, msg));
            *expr = syn::parse2(quote!(#tmp)).expect("temp ident parses");
            return;
        }
        match expr {
            syn::Expr::Unary(u) => self.isolate_expr(&mut u.expr, pre),
            syn::Expr::Field(f) => self.isolate_expr(&mut f.base, pre),
            syn::Expr::Index(ix) => {
                self.isolate_expr(&mut ix.expr, pre);
                self.isolate_expr(&mut ix.index, pre);
            }
            syn::Expr::Paren(p) => self.isolate_expr(&mut p.expr, pre),
            syn::Expr::Cast(c) => self.isolate_expr(&mut c.expr, pre),
            syn::Expr::Reference(r) => self.isolate_expr(&mut r.expr, pre),
            syn::Expr::Binary(b) => {
                self.isolate_expr(&mut b.left, pre);
                if matches!(b.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
                    self.isolate_scoped_expr(&mut b.right);
                } else {
                    self.isolate_expr(&mut b.right, pre);
                }
            }
            syn::Expr::Range(r) => {
                if let Some(start) = &mut r.start {
                    self.isolate_expr(start, pre);
                }
                if let Some(end) = &mut r.end {
                    self.isolate_expr(end, pre);
                }
            }
            syn::Expr::Tuple(t) => {
                for elem in &mut t.elems {
                    self.isolate_expr(elem, pre);
                }
            }
            syn::Expr::Array(a) => {
                for elem in &mut a.elems {
                    self.isolate_expr(elem, pre);
                }
            }
            syn::Expr::Macro(m) if is_addr_of_macro(&m.mac) => {
                let mut place: syn::Expr =
                    syn::parse2(m.mac.tokens.clone()).expect("addr_of operand parses");
                self.isolate_deref_place_operands(&mut place, pre);
                m.mac.tokens = quote!(#place);
            }
            syn::Expr::MethodCall(mc) => {
                self.isolate_expr(&mut mc.receiver, pre);
                for arg in &mut mc.args {
                    self.isolate_expr(arg, pre);
                }
            }
            syn::Expr::Call(call) => {
                self.isolate_expr(&mut call.func, pre);
                for arg in &mut call.args {
                    self.isolate_expr(arg, pre);
                }
            }
            syn::Expr::Block(b) => self.isolate_block(&mut b.block),
            syn::Expr::If(ie) => {
                self.isolate_expr(&mut ie.cond, pre);
                self.isolate_block(&mut ie.then_branch);
                if let Some((_, else_expr)) = &mut ie.else_branch {
                    self.isolate_scoped_expr(else_expr);
                }
            }
            syn::Expr::ForLoop(fl) => {
                self.isolate_expr(&mut fl.expr, pre);
                self.isolate_block(&mut fl.body);
            }
            syn::Expr::While(wl) => {
                self.isolate_scoped_expr(&mut wl.cond);
                self.isolate_block(&mut wl.body);
            }
            syn::Expr::Loop(lp) => self.isolate_block(&mut lp.body),
            syn::Expr::Match(m) => {
                self.isolate_expr(&mut m.expr, pre);
                for arm in &mut m.arms {
                    self.isolate_scoped_expr(&mut arm.body);
                }
            }
            syn::Expr::Closure(cl) => self.isolate_scoped_expr(&mut cl.body),
            syn::Expr::Return(ret) => {
                if let Some(val) = &mut ret.expr {
                    self.isolate_expr(val, pre);
                }
            }
            syn::Expr::Assign(a) => self.isolate_expr(&mut a.right, pre),
            syn::Expr::Try(t) => self.isolate_expr(&mut t.expr, pre),
            syn::Expr::Group(g) => self.isolate_expr(&mut g.expr, pre),
            _ => {}
        }
    }
}

fn direct_unsafe_safety(expr: &syn::Expr) -> Option<&'static str> {
    match expr {
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => Some(DEREF_SAFETY),
        syn::Expr::Field(_) | syn::Expr::Index(_) if is_deref_place(expr) => Some(DEREF_SAFETY),
        syn::Expr::MethodCall(mc) => match mc.method.to_string().as_str() {
            "add" => Some(ADD_SAFETY),
            "write" => Some(WRITE_SAFETY),
            _ => None,
        },
        syn::Expr::Call(call) => unsafe_call_safety(&call.func),
        syn::Expr::Macro(m) if is_addr_of_macro(&m.mac) => {
            let place: syn::Expr =
                syn::parse2(m.mac.tokens.clone()).expect("addr_of operand parses");
            (matches!(place, syn::Expr::Field(_) | syn::Expr::Index(_)) && is_deref_place(&place))
                .then_some(ADDR_OF_SAFETY)
        }
        _ => None,
    }
}

fn is_deref_val(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Paren(p) => is_deref_val(&p.expr),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
            matches!(&*u.expr, syn::Expr::Path(p) if p.path.is_ident("val"))
        }
        _ => false,
    }
}

fn is_deref_place(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Field(f) => is_deref_place(&f.base),
        syn::Expr::Index(ix) => is_deref_place(&ix.expr),
        syn::Expr::Paren(p) => is_deref_place(&p.expr),
        syn::Expr::Unary(u) => matches!(u.op, syn::UnOp::Deref(_)),
        _ => false,
    }
}

fn is_addr_of_macro(mac: &syn::Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|seg| matches!(seg.ident.to_string().as_str(), "addr_of" | "addr_of_mut"))
}

fn unsafe_call_safety(func: &syn::Expr) -> Option<&'static str> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let name = path.path.segments.last()?.ident.to_string();
    if name == "cstr_size" {
        Some(CSTR_SAFETY)
    } else if name.starts_with("vn_encode_")
        || matches!(
            name.as_str(),
            "encode_scalar"
                | "encode_array"
                | "encode_blob_array"
                | "encode_char_array"
                | "encode_widened_array"
                | "handle_id"
        )
    {
        Some(ENCODE_SAFETY)
    } else if name.starts_with("vn_decode_")
        || matches!(
            name.as_str(),
            "decode_scalar"
                | "decode_array"
                | "decode_blob_array"
                | "decode_char_array"
                | "decode_widened_array"
                | "store_handle_id"
        )
    {
        Some(DECODE_SAFETY)
    } else if name.starts_with("vn_call_") || name.starts_with("vn_sizeof_") {
        Some(CALL_SAFETY)
    } else {
        None
    }
}

fn take_expr(expr: &mut syn::Expr) -> syn::Expr {
    core::mem::replace(expr, syn::Expr::PLACEHOLDER)
}

fn make_comment_attr(msg: &str) -> syn::Attribute {
    let syn::Stmt::Local(local) = syn::parse2::<syn::Stmt>(quote!(#[comment = #msg] let _;))
        .expect("comment attribute parses")
    else {
        unreachable!("parsed statement is always a local binding");
    };
    local.attrs.into_iter().next().expect("one attribute")
}

fn wrap_unsafe_expr(expr: syn::Expr) -> syn::Expr {
    syn::parse2(quote!(unsafe { #expr })).expect("unsafe block parses")
}

fn wrap_unsafe_expr_with_comment(expr: syn::Expr, msg: &str) -> syn::Expr {
    syn::parse2(quote!(#[comment = #msg] unsafe { #expr })).expect("unsafe block parses")
}

fn make_let_unsafe(ident: &proc_macro2::Ident, expr: syn::Expr, msg: &str) -> syn::Stmt {
    syn::parse2(quote!(#[comment = #msg] let #ident = unsafe { #expr };))
        .expect("let-unsafe statement parses")
}
