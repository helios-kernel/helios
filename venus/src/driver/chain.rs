//! `pNext` chains: finding a member, and rewriting one without writing any
//! structure the caller owns.

use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::NonNull;

use ash::vk;

use crate::protocol as wire;

/// The first member of `T`'s type in the chain that starts at `pointer`.
///
/// # Safety
/// `pointer` is null or the start of a live Vulkan `pNext` chain that remains
/// valid and immutable for `'a`.
pub(super) unsafe fn next<'a, T: vk::TaggedStructure>(pointer: *const c_void) -> Option<&'a T> {
    // SAFETY: forwarded from the caller.
    let member = unsafe { find(pointer, T::STRUCTURE_TYPE) }?;
    // SAFETY: `find` returned a live member whose `sType` is `T::STRUCTURE_TYPE`.
    Some(unsafe { &*member.cast::<T>() })
}

/// The first member of `T`'s type in an output chain, for the driver to
/// amend what the renderer wrote there.
///
/// # Safety
/// `pointer` is null or the start of a live, writable Vulkan `pNext` chain
/// that nothing else references for `'a`.
pub(super) unsafe fn next_mut<'a, T: vk::TaggedStructure>(
    pointer: *mut c_void,
) -> Option<&'a mut T> {
    // SAFETY: forwarded from the caller.
    let member = unsafe { find(pointer, T::STRUCTURE_TYPE) }?;
    // SAFETY: `find` returned a live, writable member that nothing else references for `'a`.
    Some(unsafe { &mut *member.cast_mut().cast::<T>() })
}

/// # Safety
/// `pointer` is null or the start of a live Vulkan `pNext` chain.
unsafe fn find(mut pointer: *const c_void, s_type: vk::StructureType) -> Option<*const c_void> {
    while !pointer.is_null() {
        // SAFETY: Vulkan pNext chains contain live structures with this common header.
        let header = unsafe { &*pointer.cast::<vk::BaseInStructure<'_>>() };
        if header.s_type == s_type {
            return Some(pointer);
        }
        pointer = header.p_next.cast();
    }
    None
}

/// One copied chain member, in storage of the member's own layout.
struct Member {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl Member {
    /// # Safety
    /// `source` is live for `layout.size()` bytes.
    unsafe fn copy(source: *const u8, layout: Layout) -> Self {
        // SAFETY: every chain member begins with its sType, so the size is
        // nonzero.
        let pointer = unsafe { std::alloc::alloc(layout) };
        let Some(pointer) = NonNull::new(pointer) else {
            std::alloc::handle_alloc_error(layout)
        };
        // SAFETY: both ranges are `layout.size()` bytes and the new
        // allocation cannot overlap the caller's structure.
        unsafe { core::ptr::copy_nonoverlapping(source, pointer.as_ptr(), layout.size()) };
        Self { pointer, layout }
    }

    fn header(&self) -> *mut vk::BaseOutStructure<'static> {
        self.pointer.as_ptr().cast()
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        // SAFETY: allocated in `copy` with this layout.
        unsafe { std::alloc::dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

/// A caller's input structure with one member of its chain rewritten.
///
/// Mesa's Venus driver copies the head and the members it knows into local
/// storage before changing one (`vn_image_fix_create_info` and its kin).
/// Here the head and the members before the rewritten one are copied, with
/// the layouts the encoders know (`protocol::struct_layout`), and the
/// members after it stay the caller's, shared unchanged: no structure the
/// caller owns is written. A member before it that no encoder knows is left
/// out of the copy, which changes nothing the renderer receives.
pub(super) struct Rewritten<H> {
    head: H,
    _members: Vec<Member>,
}

impl<H> Rewritten<H> {
    /// The rewritten structure, valid while `self` is neither moved nor dropped.
    pub(super) fn head(&self) -> *const H {
        &self.head
    }
}

/// Copy `head` with the first chain member of `T`'s type passed through
/// `edit`, or `None` when the chain has no such member.
///
/// # Safety
/// `head` is a live Vulkan input structure whose `pNext` chain is valid.
pub(super) unsafe fn rewrite<H, T>(head: &H, edit: impl FnOnce(&mut T)) -> Option<Rewritten<H>>
where
    H: vk::TaggedStructure + Copy,
    T: vk::TaggedStructure + Copy,
{
    let mut head = *head;
    let mut members = Vec::new();
    // Every Vulkan structure with an sType starts with the common header.
    let header = (&raw mut head).cast::<vk::BaseOutStructure<'static>>();
    // SAFETY: header addresses `head`'s sType and pNext.
    let mut member = unsafe { (*header).p_next }.cast_const();
    // The pNext slot the next copied member is linked into.
    // SAFETY: `header` points to `head`'s initialized common header.
    let mut link = unsafe { &raw mut (*header).p_next };
    while !member.is_null() {
        // SAFETY: the caller's chain members are live and share the header.
        let header_ref = unsafe { &*member };
        let (s_type, next) = (header_ref.s_type, header_ref.p_next);
        if s_type == T::STRUCTURE_TYPE {
            // SAFETY: a member with T's sType is a T.
            let mut target = unsafe { *member.cast::<T>() };
            edit(&mut target);
            // SAFETY: target is a live local of T's layout.
            let copy = unsafe { Member::copy((&raw const target).cast(), Layout::new::<T>()) };
            // SAFETY: `copy` owns a freshly allocated `T` whose `pNext` slot is writable.
            unsafe { (*copy.header()).p_next = next };
            // SAFETY: `link` is a `pNext` slot of `head` or of a copied member;
            // the tail after the target remains the caller's.
            unsafe { *link = copy.header() };
            members.push(copy);
            return Some(Rewritten {
                head,
                _members: members,
            });
        }
        if let Some(layout) = wire::struct_layout(wire::VkStructureType(s_type.as_raw())) {
            // SAFETY: the encoders' layout for this sType is the member's.
            let copy = unsafe { Member::copy(member.cast(), layout) };
            // SAFETY: as above; the copy's pNext is relinked on the next copy.
            unsafe { *link = copy.header() };
            // SAFETY: `copy.header()` points to the newly allocated member's header.
            link = unsafe { &raw mut (*copy.header()).p_next };
            members.push(copy);
        }
        member = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_copies_the_prefix_and_shares_the_tail() {
        // head -> list -> external -> tail.
        let tail =
            vk::ImageStencilUsageCreateInfo::default().stencil_usage(vk::ImageUsageFlags::SAMPLED);
        let mut external = vk::ExternalMemoryImageCreateInfo::default()
            .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);
        external.p_next = (&raw const tail).cast();
        let formats = [vk::Format::B8G8R8A8_UNORM];
        let mut list = vk::ImageFormatListCreateInfo::default().view_formats(&formats);
        list.p_next = (&raw const external).cast();
        let mut info = vk::ImageCreateInfo::default().format(vk::Format::B8G8R8A8_UNORM);
        info.p_next = (&raw const list).cast();
        let original_next = info.p_next;

        // SAFETY: info's chain is live for the test.
        let rewritten = unsafe {
            rewrite(
                &info,
                |member: &mut vk::ExternalMemoryImageCreateInfo<'_>| {
                    member.handle_types = vk::ExternalMemoryHandleTypeFlags::OPAQUE_FD;
                },
            )
        }
        .expect("the chain carries external memory info");

        // The caller's structures are untouched.
        assert_eq!(info.p_next, original_next);
        assert_eq!(
            external.handle_types,
            vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT
        );
        assert_eq!(list.p_next, (&raw const external).cast());

        // SAFETY: the rewritten head lives as long as `rewritten`.
        let head = unsafe { &*rewritten.head() };
        assert_eq!(head.format, vk::Format::B8G8R8A8_UNORM);
        assert_ne!(head.p_next, original_next);
        // SAFETY: `head.p_next` points to the copied `ImageFormatListCreateInfo`.
        let copied_list = unsafe { &*head.p_next.cast::<vk::ImageFormatListCreateInfo<'_>>() };
        assert_eq!(
            copied_list.s_type,
            vk::StructureType::IMAGE_FORMAT_LIST_CREATE_INFO
        );
        assert_eq!(copied_list.view_format_count, 1);
        assert_eq!(copied_list.p_view_formats, formats.as_ptr());
        // SAFETY: `copied_list.p_next` points to the copied `ExternalMemoryImageCreateInfo`.
        let copied_external = unsafe {
            &*copied_list
                .p_next
                .cast::<vk::ExternalMemoryImageCreateInfo<'_>>()
        };
        assert_eq!(
            copied_external.handle_types,
            vk::ExternalMemoryHandleTypeFlags::OPAQUE_FD
        );
        assert_ne!(
            (copied_external as *const vk::ExternalMemoryImageCreateInfo<'_>).cast(),
            (&raw const external).cast::<c_void>()
        );
        assert_eq!(copied_external.p_next, (&raw const tail).cast());
        // SAFETY: the rewritten chain lives as long as `rewritten`.
        let found = unsafe { next::<vk::ImageStencilUsageCreateInfo<'_>>(head.p_next) }
            .expect("the shared tail stays in the chain");
        assert_eq!(found.stencil_usage, vk::ImageUsageFlags::SAMPLED);
    }

    #[test]
    fn rewrite_of_the_first_member_links_the_head_to_its_copy() {
        let export = vk::ExportMemoryAllocateInfo::default()
            .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);
        let mut info = vk::MemoryAllocateInfo::default().allocation_size(4096);
        info.p_next = (&raw const export).cast();
        // SAFETY: info's chain is live for the test.
        let rewritten = unsafe {
            rewrite(&info, |member: &mut vk::ExportMemoryAllocateInfo<'_>| {
                member.handle_types = vk::ExternalMemoryHandleTypeFlags::OPAQUE_FD;
            })
        }
        .unwrap();
        // SAFETY: the rewritten head lives as long as `rewritten`.
        let head = unsafe { &*rewritten.head() };
        assert_eq!(head.allocation_size, 4096);
        // SAFETY: the rewritten chain lives as long as `rewritten`.
        let copy = unsafe { next::<vk::ExportMemoryAllocateInfo<'_>>(head.p_next) }.unwrap();
        assert_eq!(
            copy.handle_types,
            vk::ExternalMemoryHandleTypeFlags::OPAQUE_FD
        );
        assert!(copy.p_next.is_null());
        assert_eq!(
            export.handle_types,
            vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT
        );
    }

    #[test]
    fn rewrite_without_the_member_is_none() {
        let dedicated = vk::MemoryDedicatedAllocateInfo::default();
        let info = vk::MemoryAllocateInfo {
            p_next: (&raw const dedicated).cast(),
            ..Default::default()
        };
        // SAFETY: info's chain is live for the test.
        let rewritten = unsafe {
            rewrite(
                &info,
                |_: &mut vk::ExportMemoryAllocateInfo<'_>| unreachable!(),
            )
        };
        assert!(rewritten.is_none());
    }

    #[test]
    fn a_member_no_encoder_sends_is_left_out_of_the_copy() {
        // Venus serializes no Win32 structure, so no encoder sends this sType.
        let mut unknown = vk::BaseInStructure {
            s_type: vk::StructureType::WIN32_KEYED_MUTEX_ACQUIRE_RELEASE_INFO_KHR,
            ..Default::default()
        };
        let export = vk::ExportMemoryAllocateInfo::default()
            .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);
        unknown.p_next = (&raw const export).cast();
        let info = vk::MemoryAllocateInfo {
            p_next: (&raw const unknown).cast(),
            ..Default::default()
        };
        assert!(
            wire::struct_layout(wire::VkStructureType(unknown.s_type.as_raw())).is_none(),
            "the test needs an sType no encoder sends"
        );
        // SAFETY: info's chain is live for the test.
        let rewritten = unsafe {
            rewrite(&info, |member: &mut vk::ExportMemoryAllocateInfo<'_>| {
                member.handle_types = vk::ExternalMemoryHandleTypeFlags::OPAQUE_FD;
            })
        }
        .unwrap();
        // SAFETY: the rewritten head lives as long as `rewritten`.
        let head = unsafe { &*rewritten.head() };
        // SAFETY: `head.p_next` points to the copied `ExportMemoryAllocateInfo`.
        let first = unsafe { &*head.p_next.cast::<vk::BaseInStructure<'_>>() };
        assert_eq!(first.s_type, vk::StructureType::EXPORT_MEMORY_ALLOCATE_INFO);
    }
}
