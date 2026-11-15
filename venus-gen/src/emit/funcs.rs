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
                    | "vkFreeCommandBuffers"
                    | "vkDestroyCommandPool"
                    | "vkQueueWaitIdle"
                    | "vkDeviceWaitIdle"
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
        let clear = self.entry_output_handles(id, false)?;
        let assign = self.entry_output_handles(id, true)?;
        let body = if assign.is_empty() {
            quote!(#call(&mut venus_state.connection, #(#args),*))
        } else {
            quote! {
                let venus_result = (|| {
                    #assign
                    #call(&mut venus_state.connection, #(#args),*)
                })();
                venus_result.inspect_err(|_| { #clear })
            }
        };
        Ok(Some(quote! {
            unsafe extern "system" fn #entry<F: Factory>(#(#params),*) #ret {
                unsafe {
                    #clear
                    super::instance::#invocation::<F>(#dispatch.0, |venus_state| {
                        #body
                    })
                }
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
                let body = self.encode_members(id, 0, partial)?;
                quote! {
                    pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                        unsafe { #body }
                    }
                }
            } else {
                let function = func("decode", &ty.name);
                let body = self.decode_members(id, 0)?;
                quote! {
                    pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                        unsafe { #body }
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
            let body = self.encode_members(id, 2, partial)?;
            quote! {
                #pnext
                pub unsafe fn #self_function<S: Sink>(enc: &mut S, val: *const #name) {
                    unsafe { #body }
                }
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                    unsafe {
                        if (*val).sType != #s_type {
                            enc.fail(EncodeError::StructureType {
                                expected: #s_type.0,
                                found: (*val).sType.0,
                            });
                        }
                        encode_scalar::<_, VkStructureType>(enc, &#s_type);
                        #pnext_name(enc, PtrExt::into_const((*val).pNext));
                        #self_function(enc, val);
                    }
                }
            }
        } else {
            let body = self.decode_members(id, 2)?;
            quote! {
                #pnext
                pub unsafe fn #self_function(dec: &mut Decoder<'_>, val: *mut #name) {
                    unsafe { #body }
                }
                pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                    unsafe {
                        let mut s_type = VkStructureType(0);
                        decode_scalar::<VkStructureType>(dec, &mut s_type);
                        if s_type != #s_type {
                            dec.fail(DecodeError::StructureType {
                                expected: #s_type.0,
                                found: s_type.0,
                            });
                        }
                        #pnext_name(dec, PtrExt::into_mut((*val).pNext));
                        #self_function(dec, val);
                    }
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
                    pub unsafe fn #function<S: Sink>(enc: &mut S, _val: *const ::core::ffi::c_void) {
                        encode_simple_pointer(enc, ::core::ptr::null::<::core::ffi::c_void>());
                    }
                }
            } else {
                quote! {
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
                    encode_scalar::<_, VkStructureType>(enc, pnext.cast::<VkStructureType>());
                    #function(enc, PtrExt::into_const((*pnext.cast::<#next_name>()).pNext));
                    #self_function(enc, pnext.cast::<#next_name>());
                    return;
                };
                cases.push((s_type, guard, body));
            }
            let dispatch = if let [(s_type, guard, body)] = &cases[..] {
                // One chained struct: a comparison, not a `match`.
                let guard = guard.as_ref().map(|guard| quote!(&& #guard));
                quote! {
                    if *pnext.cast::<VkStructureType>() == #s_type #guard {
                        #body
                    }
                }
            } else {
                let arms = cases.iter().map(|(s_type, guard, body)| {
                    let guard = guard.as_ref().map(|guard| quote!(if #guard));
                    quote!(#s_type #guard => { #body })
                });
                quote! {
                    match *pnext.cast::<VkStructureType>() {
                        #(#arms)*
                        // Unknown and unsupported structs are ignored.
                        _ => {}
                    }
                }
            };
            Ok(quote! {
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const ::core::ffi::c_void) {
                    unsafe {
                        let mut pnext = val;
                        while !pnext.is_null() {
                            #dispatch
                            pnext = (*pnext.cast::<BaseStructure>()).pNext;
                        }
                        encode_simple_pointer(enc, ::core::ptr::null::<::core::ffi::c_void>());
                    }
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
                        #function(dec, PtrExt::into_mut((*pnext.cast::<#next_name>()).pNext));
                        #self_function(dec, pnext.cast::<#next_name>());
                    }
                });
            }
            Ok(quote! {
                pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut ::core::ffi::c_void) {
                    unsafe {
                        if !decode_simple_pointer(dec) {
                            return;
                        }
                        let mut s_type = VkStructureType(0);
                        decode_scalar::<VkStructureType>(dec, &mut s_type);
                        let mut pnext = val;
                        loop {
                            if pnext.is_null() {
                                dec.fail(DecodeError::UnexpectedChainedStructure { s_type: s_type.0 });
                                return;
                            }
                            if *pnext.cast::<VkStructureType>() == s_type {
                                break;
                            }
                            pnext = PtrExt::into_mut((*pnext.cast::<BaseStructure>()).pNext);
                        }
                        match s_type {
                            #arms
                            _ => dec.fail(DecodeError::UnexpectedChainedStructure { s_type: s_type.0 }),
                        }
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
                let body = self.encode_var(frame, var, self.validity(id, var, true))?;
                arms.extend(quote!(#pattern => { #body }));
            }
            Ok(quote! {
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name, tag: #tag_ty) {
                    unsafe {
                        encode_scalar::<_, #tag_ty>(enc, &tag);
                        match tag {
                            #arms
                            _ => enc.fail(EncodeError::UnionTag),
                        }
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
            let body = self.encode_var(frame, var, self.validity(id, var, true))?;
            let tag = Literal::u32_suffixed(*tag);
            Ok(quote! {
                pub unsafe fn #function<S: Sink>(enc: &mut S, val: *const #name) {
                    unsafe {
                        // A union with a default tag.
                        let tag: u32 = #tag;
                        encode_scalar::<_, u32>(enc, &tag);
                        #body
                    }
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
            let body = self.decode_var(frame, &ty.variables[index])?;
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
            pub unsafe fn #function(dec: &mut Decoder<'_>, val: *mut #name) {
                unsafe {
                    let mut tag: #tag_ty = #zero;
                    decode_scalar::<#tag_ty>(dec, &mut tag);
                    match tag {
                        #arms
                        _ => dec.fail(DecodeError::UnionTag),
                    }
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
            quote! {
                pub unsafe fn #encode<S: Sink>(enc: &mut S, val: *const #name) {
                    unsafe {
                        let id: u64 = handle_id((*val).0);
                        encode_scalar::<_, u64>(enc, &id);
                    }
                }
                pub unsafe fn #decode(dec: &mut Decoder<'_>, val: *mut #name) {
                    unsafe {
                        let mut id: u64 = 0;
                        decode_scalar::<u64>(dec, &mut id);
                        store_handle_id(dec, (*val).0, id);
                    }
                }
            }
        } else {
            quote! {
                pub unsafe fn #encode<S: Sink>(enc: &mut S, val: *const #name) {
                    unsafe {
                        encode_scalar::<_, u64>(enc, &(*val).0);
                    }
                }
                pub unsafe fn #decode(dec: &mut Decoder<'_>, val: *mut #name) {
                    unsafe {
                        decode_scalar::<u64>(dec, &mut (*val).0);
                    }
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
            quote!(let venus_result = #decode_reply(&mut venus_decoder, #(#args),*);)
        } else {
            quote!(#decode_reply(&mut venus_decoder, #(#args),*);)
        };
        let result = if ty.ret.is_some() {
            quote!(venus_result)
        } else {
            quote!(())
        };
        let finish = if reply {
            quote! {
                let venus_reply_size = #sizeof_reply(venus_connection.protocol(), #(#args),*)?;
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
                unsafe {
                    let venus_size = #sizeof(venus_connection.protocol(), #(#args),*)?;
                    let mut venus_bytes = vec![0; venus_size];
                    let mut venus_encoder = Encoder::new(&mut venus_bytes, venus_connection.protocol());
                    #encode(&mut venus_encoder, #flags, #(#args),*);
                    venus_encoder.finish()?;
                    #finish
                }
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

        let ret_param = ret_ty.as_ref().map(|ret_ty| quote!(ret: #ret_ty,));
        let ret_arg = ret_ty.as_ref().map(|_| quote!(ret,));
        let ret_zero = ret_ty
            .as_ref()
            .map(|ret_ty| quote!(let ret: #ret_ty = ::core::mem::zeroed();));
        let ret_local = ret_ty
            .as_ref()
            .map(|ret_ty| quote!(let mut ret: #ret_ty = ::core::mem::zeroed();));
        let ret_value = ret_ty.as_ref().map(|_| quote!(ret));
        let decode_return = ret_ty.as_ref().map(|ret_ty| quote!(-> #ret_ty));

        Ok(quote! {
            pub unsafe fn #encode<S: Sink>(enc: &mut S, cmd_flags: VkCommandFlagsEXT, #(#params),*) {
                unsafe {
                    let cmd_type = #command_const;
                    encode_scalar::<_, VkCommandTypeEXT>(enc, &cmd_type);
                    encode_scalar::<_, VkFlags>(enc, &cmd_flags);
                    #encode_body
                }
            }
            pub unsafe fn #sizeof(protocol: &RendererProtocol, #(#params),*) -> Result<usize, EncodeError> {
                unsafe {
                    let mut enc = Sizer::new(protocol);
                    #encode(&mut enc, 0, #(#args),*);
                    enc.finish()
                }
            }
            pub unsafe fn #encode_reply<S: Sink>(enc: &mut S, #ret_param #(#params),*) {
                unsafe {
                    let cmd_type = #command_const;
                    encode_scalar::<_, VkCommandTypeEXT>(enc, &cmd_type);
                    #reply_encode_body
                }
            }
            pub unsafe fn #sizeof_reply(protocol: &RendererProtocol, #(#params),*) -> Result<usize, EncodeError> {
                unsafe {
                    let mut enc = Sizer::new(protocol);
                    #ret_zero
                    #encode_reply(&mut enc, #ret_arg #(#args),*);
                    enc.finish()
                }
            }
            pub unsafe fn #decode_reply(dec: &mut Decoder<'_>, #(#params),*) #decode_return {
                unsafe {
                    #reply_capacities
                    let mut command_type = VkCommandTypeEXT(0);
                    decode_scalar::<VkCommandTypeEXT>(dec, &mut command_type);
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
