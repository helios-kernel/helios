//! External memory handle types: what the guest offers the application and
//! what reaches the renderer in their place.
//!
//! This follows Mesa's Venus driver. The guest exports an allocation by
//! turning the renderer's `VkDeviceMemory` into a virtio-gpu blob, so the
//! handle type the application names is not the one the renderer exports
//! through. The guest determines the renderer's own exportable handle type
//! once per physical device (`vn_physical_device_init_external_memory`),
//! advertises the external memory extensions itself
//! (`vn_physical_device_get_native_extensions`), translates the application's
//! handle type into the renderer's in every structure that carries one to the
//! renderer (`vn_physical_device_fix_image_format_info`,
//! `vn_image_fix_create_info`, `vn_buffer_fix_create_info`,
//! `vn_device_memory_fix_alloc_info`, `vn_device_fix_create_info`), and
//! answers the application's queries in terms of the handle types the guest
//! offers (`vn_sanitize_image_format_properties`,
//! `vn_GetPhysicalDeviceExternalBufferProperties`).
//!
//! The renderer's handle type is DMA_BUF or nothing, as in Mesa: a blob the
//! guest exports may be scanned out, and the host's display imports a
//! scanout blob as a dma-buf (QEMU's `virgl_cmd_set_scanout_blob` hands the
//! blob's fd to an `EGL_LINUX_DMA_BUF_EXT` import), so an allocation exported
//! through any other handle type would reach scanout and never be shown.
//! Mesa takes DMA_BUF whenever the renderer's driver advertises
//! `VK_EXT_external_memory_dma_buf`, which a driver also advertises when it
//! can only import dma-bufs (lavapipe without `/dev/udmabuf`); the guest asks
//! instead whether the renderer can export one, the test virglrenderer itself
//! applies before it exports a blob
//! (`vkr_physical_device_init_memory_properties`), so such a renderer offers
//! no external memory and a program that needs it is refused up front.

use core::ffi::{CStr, c_char};
use core::ptr::{null, null_mut};

use ash::vk;

use super::Factory;
use super::chain::{self, Rewritten};
use super::device::Device;
use super::instance::{State, TransportError, invoke, invoke_result, object, write_properties};
use crate::connection::{Connection, Error};
use crate::protocol as wire;
use crate::transport::Transport;

type HandleTypes = vk::ExternalMemoryHandleTypeFlags;

/// The handle types the guest offers once the renderer exports at all: any
/// exported renderer allocation becomes a blob, whatever the application
/// called it (Mesa's `supported_handle_types` off Android).
const OFFERED: HandleTypes =
    HandleTypes::from_raw(HandleTypes::OPAQUE_FD.as_raw() | HandleTypes::DMA_BUF_EXT.as_raw());

/// The device extensions the guest implements for external memory, with the
/// spec versions it implements.
const EXTENSIONS: [(&CStr, u32); 2] = [
    (
        ash::khr::external_memory_fd::NAME,
        ash::khr::external_memory_fd::SPEC_VERSION,
    ),
    (
        ash::ext::external_memory_dma_buf::NAME,
        ash::ext::external_memory_dma_buf::SPEC_VERSION,
    ),
];

/// A physical device's external memory: the one handle type the renderer's
/// allocations export through, empty when the renderer exports none.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct ExternalMemory {
    renderer: HandleTypes,
}

impl ExternalMemory {
    /// No external memory: the device enabled no external memory extension,
    /// or the renderer exports nothing.
    pub(super) const NONE: Self = Self {
        renderer: HandleTypes::empty(),
    };

    /// The renderer's handle type, from its answer for an exportable
    /// dma-buf transfer buffer, `None` when its driver has no dma-buf
    /// extension.
    pub(super) fn choose(dma_buf: Option<vk::ExternalMemoryProperties>) -> Self {
        let exports = dma_buf.is_some_and(|properties| {
            properties
                .external_memory_features
                .contains(vk::ExternalMemoryFeatureFlags::EXPORTABLE)
                && properties
                    .export_from_imported_handle_types
                    .contains(HandleTypes::DMA_BUF_EXT)
        });
        if exports {
            Self {
                renderer: HandleTypes::DMA_BUF_EXT,
            }
        } else {
            Self::NONE
        }
    }

    /// The handle types the guest offers the application.
    pub(super) fn offered(self) -> HandleTypes {
        if self.renderer.is_empty() {
            HandleTypes::empty()
        } else {
            OFFERED
        }
    }

    /// The handle types to send the renderer in place of `requested`, when
    /// they differ.
    pub(super) fn rewrite(self, requested: HandleTypes) -> Option<HandleTypes> {
        (!requested.is_empty() && requested != self.renderer).then_some(self.renderer)
    }

    /// Restate the renderer's answer for its own handle type in terms of the
    /// handle types the guest offers.
    pub(super) fn answer(self, properties: &mut vk::ExternalMemoryProperties) {
        // The guest exports through blobs and has no import path: a Helios
        // program holds no file descriptor to import from.
        properties.external_memory_features &= !vk::ExternalMemoryFeatureFlags::IMPORTABLE;
        properties.compatible_handle_types = self.offered();
        properties.export_from_imported_handle_types = if properties
            .export_from_imported_handle_types
            .intersects(self.renderer)
        {
            self.offered()
        } else {
            HandleTypes::empty()
        };
    }

    /// The answer for a handle type the guest does not offer.
    pub(super) fn unsupported(requested: HandleTypes) -> vk::ExternalMemoryProperties {
        vk::ExternalMemoryProperties {
            external_memory_features: vk::ExternalMemoryFeatureFlags::empty(),
            export_from_imported_handle_types: HandleTypes::empty(),
            compatible_handle_types: requested,
        }
    }

    /// The renderer device extensions its handle type needs.
    fn renderer_extensions(self) -> &'static [&'static CStr] {
        if self.renderer.is_empty() {
            &[]
        } else {
            // VK_EXT_external_memory_dma_buf requires VK_KHR_external_memory_fd.
            &[
                ash::ext::external_memory_dma_buf::NAME,
                ash::khr::external_memory_fd::NAME,
            ]
        }
    }
}

fn is_memory_extension(name: &CStr) -> bool {
    EXTENSIONS.iter().any(|(extension, _)| *extension == name)
}

/// The device extensions the guest advertises: the renderer's, with its
/// external memory extensions replaced by the guest's own when the renderer
/// exports.
pub(super) fn advertised_extensions(
    renderer: &[vk::ExtensionProperties],
    memory: ExternalMemory,
) -> Vec<vk::ExtensionProperties> {
    let mut extensions: Vec<_> = renderer
        .iter()
        .filter(|extension| {
            !extension
                .extension_name_as_c_str()
                .is_ok_and(is_memory_extension)
        })
        .copied()
        .collect();
    if memory != ExternalMemory::NONE {
        extensions.extend(EXTENSIONS.iter().map(|&(name, version)| {
            vk::ExtensionProperties::default()
                .extension_name(name)
                .expect("extension names fit VK_MAX_EXTENSION_NAME_SIZE")
                .spec_version(version)
        }));
    }
    extensions
}

/// Whether the application enables an external memory extension, which the
/// guest implements.
pub(super) fn enables_external_memory(application: &[&CStr]) -> bool {
    application.iter().any(|name| is_memory_extension(name))
}

/// The extensions the renderer device enables for the application's, or
/// `None` when they reach it unchanged.
pub(super) fn renderer_device_extensions<'a>(
    application: &[&'a CStr],
    memory: ExternalMemory,
) -> Result<Option<Vec<&'a CStr>>, vk::Result> {
    if !enables_external_memory(application) {
        return Ok(None);
    }
    if memory == ExternalMemory::NONE {
        return Err(vk::Result::ERROR_EXTENSION_NOT_PRESENT);
    }
    let mut extensions: Vec<&CStr> = application
        .iter()
        .copied()
        .filter(|name| !is_memory_extension(name))
        .collect();
    extensions.extend_from_slice(memory.renderer_extensions());
    Ok(Some(extensions))
}

/// What a physical device's renderer driver offers for external memory.
pub(super) struct PhysicalExternal {
    /// The device extensions the guest advertises.
    pub(super) extensions: Vec<vk::ExtensionProperties>,
    pub(super) memory: ExternalMemory,
}

/// The renderer's answer for an exportable transfer buffer of `handle`.
fn buffer_export<T: Transport>(
    connection: &mut Connection<T>,
    physical: wire::VkPhysicalDevice,
    handle: HandleTypes,
) -> Result<vk::ExternalMemoryProperties, Error<T::Error>> {
    let info = vk::PhysicalDeviceExternalBufferInfo::default()
        .usage(vk::BufferUsageFlags::TRANSFER_SRC)
        .handle_type(handle);
    let mut properties = vk::ExternalBufferProperties::default();
    // SAFETY: both structures are live and have the Vulkan ABI layout.
    unsafe {
        wire::vn_call_vkGetPhysicalDeviceExternalBufferProperties(
            connection,
            physical,
            (&raw const info).cast(),
            (&raw mut properties).cast(),
        )
    }?;
    Ok(properties.external_memory_properties)
}

fn probe<T: Transport>(
    connection: &mut Connection<T>,
    physical: wire::VkPhysicalDevice,
) -> Result<Result<PhysicalExternal, vk::Result>, Error<T::Error>> {
    let mut count = 0;
    // SAFETY: the count-only query on a live physical device.
    let result = unsafe {
        wire::vn_call_vkEnumerateDeviceExtensionProperties(
            connection,
            physical,
            null(),
            &mut count,
            null_mut(),
        )
    }?;
    if result != wire::VK_SUCCESS {
        return Ok(Err(vk::Result::from_raw(result.0)));
    }
    let mut renderer = vec![vk::ExtensionProperties::default(); count as usize];
    // SAFETY: the output array holds count elements of the Vulkan layout.
    let result = unsafe {
        wire::vn_call_vkEnumerateDeviceExtensionProperties(
            connection,
            physical,
            null(),
            &mut count,
            renderer.as_mut_ptr().cast(),
        )
    }?;
    if result != wire::VK_SUCCESS {
        return Ok(Err(vk::Result::from_raw(result.0)));
    }
    renderer.truncate(count as usize);
    let has = |name: &CStr| {
        renderer
            .iter()
            .any(|extension| extension.extension_name_as_c_str() == Ok(name))
    };
    let dma_buf = if has(ash::ext::external_memory_dma_buf::NAME) {
        Some(buffer_export(
            connection,
            physical,
            HandleTypes::DMA_BUF_EXT,
        )?)
    } else {
        None
    };
    let memory = ExternalMemory::choose(dma_buf);
    Ok(Ok(PhysicalExternal {
        extensions: advertised_extensions(&renderer, memory),
        memory,
    }))
}

impl<F: Factory> State<F> {
    /// A physical device's external memory, determined from the renderer on
    /// first use.
    pub(super) fn physical_external(
        &mut self,
        physical: vk::PhysicalDevice,
    ) -> Result<Result<&PhysicalExternal, vk::Result>, Error<TransportError<F>>> {
        // SAFETY: the caller supplies a live physical device of this instance.
        let id = unsafe { (*object(physical)).id };
        if !self.external.contains_key(&id) {
            match probe(
                &mut self.connection,
                wire::VkPhysicalDevice(object(physical)),
            )? {
                Ok(external) => {
                    self.external.insert(id, external);
                }
                Err(result) => return Ok(Err(result)),
            }
        }
        Ok(Ok(&self.external[&id]))
    }
}

unsafe fn physical_memory<F: Factory>(
    physical: vk::PhysicalDevice,
) -> Result<ExternalMemory, vk::Result> {
    // SAFETY: the Vulkan caller supplies a live physical device.
    unsafe {
        invoke::<F, _>(object(physical), |state| {
            let memory = state
                .physical_external(physical)?
                .map(|external| external.memory);
            Ok(memory.map_err(|result| state.finish(Ok(result))))
        })
    }?
}

fn device_memory<F: Factory>(device: vk::Device) -> ExternalMemory {
    // SAFETY: a live device handle addresses its Device, whose external
    // memory is immutable after creation.
    unsafe { (*object(device).cast::<Device<F>>()).external }
}

unsafe extern "system" fn enumerate_device_extensions<F: Factory>(
    physical: vk::PhysicalDevice,
    layer: *const c_char,
    count: *mut u32,
    properties: *mut vk::ExtensionProperties,
) -> vk::Result {
    // Devices have no layers; a loader handles layer queries.
    if !layer.is_null() {
        return vk::Result::ERROR_LAYER_NOT_PRESENT;
    }
    // SAFETY: Vulkan supplies a live physical device, a writable count and
    // the declared output capacity.
    let result = unsafe {
        invoke_result::<F>(object(physical), |state| {
            Ok(match state.physical_external(physical)? {
                Ok(external) => wire::VkResult(
                    write_properties(count, properties, &external.extensions).as_raw(),
                ),
                Err(result) => wire::VkResult(result.as_raw()),
            })
        })
    };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn image_format_properties2<F: Factory>(
    physical: vk::PhysicalDevice,
    info: *const vk::PhysicalDeviceImageFormatInfo2<'_>,
    properties: *mut vk::ImageFormatProperties2<'_>,
) -> vk::Result {
    // SAFETY: Vulkan supplies live input and output chains.
    unsafe {
        let requested =
            chain::next::<vk::PhysicalDeviceExternalImageFormatInfo<'_>>((*info).p_next)
                .map(|external| external.handle_type)
                .filter(|handle| !handle.is_empty());
        let forward = |info: *const vk::PhysicalDeviceImageFormatInfo2<'_>| {
            vk::Result::from_raw(
                super::generated::vkGetPhysicalDeviceImageFormatProperties2::<F>(
                    wire::VkPhysicalDevice(object(physical)),
                    info.cast(),
                    properties.cast(),
                )
                .0,
            )
        };
        let Some(requested) = requested else {
            return forward(info);
        };
        let memory = match physical_memory::<F>(physical) {
            Ok(memory) => memory,
            Err(result) => return result,
        };
        if !requested.intersects(memory.offered()) {
            return vk::Result::ERROR_FORMAT_NOT_SUPPORTED;
        }
        let rewritten = memory.rewrite(requested).and_then(|handle| {
            chain::rewrite(
                &*info,
                |external: &mut vk::PhysicalDeviceExternalImageFormatInfo<'_>| {
                    external.handle_type = handle;
                },
            )
        });
        let result = forward(rewritten.as_ref().map_or(info, Rewritten::head));
        if result == vk::Result::SUCCESS
            && let Some(external) =
                chain::next_mut::<vk::ExternalImageFormatProperties<'_>>((*properties).p_next)
        {
            memory.answer(&mut external.external_memory_properties);
        }
        result
    }
}

unsafe extern "system" fn external_buffer_properties<F: Factory>(
    physical: vk::PhysicalDevice,
    info: *const vk::PhysicalDeviceExternalBufferInfo<'_>,
    properties: *mut vk::ExternalBufferProperties<'_>,
) {
    // SAFETY: Vulkan supplies a live input structure and writable output.
    unsafe {
        let requested = (*info).handle_type;
        // A failed query records device loss, observable by later results.
        let Ok(memory) = physical_memory::<F>(physical) else {
            return;
        };
        if !requested.intersects(memory.offered()) {
            (*properties).external_memory_properties = ExternalMemory::unsupported(requested);
            return;
        }
        let mut renderer_info = *info;
        if let Some(handle) = memory.rewrite(requested) {
            renderer_info.handle_type = handle;
        }
        super::generated::vkGetPhysicalDeviceExternalBufferProperties::<F>(
            wire::VkPhysicalDevice(object(physical)),
            (&raw const renderer_info).cast(),
            properties.cast(),
        );
        memory.answer(&mut (*properties).external_memory_properties);
    }
}

/// An image create-info with the renderer's handle types, or `None` when the
/// application's reaches the renderer unchanged.
///
/// # Safety
/// `info` is a live create-info with a valid chain.
unsafe fn image_info<'a>(
    memory: ExternalMemory,
    info: &vk::ImageCreateInfo<'a>,
) -> Option<Rewritten<vk::ImageCreateInfo<'a>>> {
    // SAFETY: forwarded from the caller.
    unsafe {
        let requested =
            chain::next::<vk::ExternalMemoryImageCreateInfo<'_>>(info.p_next)?.handle_types;
        let handle = memory.rewrite(requested)?;
        chain::rewrite(
            info,
            |external: &mut vk::ExternalMemoryImageCreateInfo<'_>| {
                external.handle_types = handle;
            },
        )
    }
}

/// A buffer create-info with the renderer's handle types, or `None` when the
/// application's reaches the renderer unchanged.
///
/// # Safety
/// `info` is a live create-info with a valid chain.
unsafe fn buffer_info<'a>(
    memory: ExternalMemory,
    info: &vk::BufferCreateInfo<'a>,
) -> Option<Rewritten<vk::BufferCreateInfo<'a>>> {
    // SAFETY: forwarded from the caller.
    unsafe {
        let requested =
            chain::next::<vk::ExternalMemoryBufferCreateInfo<'_>>(info.p_next)?.handle_types;
        let handle = memory.rewrite(requested)?;
        chain::rewrite(
            info,
            |external: &mut vk::ExternalMemoryBufferCreateInfo<'_>| {
                external.handle_types = handle;
            },
        )
    }
}

/// An allocate-info with the renderer's export handle types, or `None` when
/// the application's reaches the renderer unchanged.
///
/// # Safety
/// `info` is a live allocate-info with a valid chain.
pub(super) unsafe fn allocate_info<'a>(
    memory: ExternalMemory,
    info: &vk::MemoryAllocateInfo<'a>,
) -> Option<Rewritten<vk::MemoryAllocateInfo<'a>>> {
    // SAFETY: forwarded from the caller.
    unsafe {
        let requested = chain::next::<vk::ExportMemoryAllocateInfo<'_>>(info.p_next)?.handle_types;
        let handle = memory.rewrite(requested)?;
        chain::rewrite(info, |export: &mut vk::ExportMemoryAllocateInfo<'_>| {
            export.handle_types = handle;
        })
    }
}

unsafe extern "system" fn create_image<F: Factory>(
    device: vk::Device,
    info: *const vk::ImageCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Image,
) -> vk::Result {
    // SAFETY: Vulkan supplies a live device, create-info and output slot.
    unsafe {
        let rewritten = image_info(device_memory::<F>(device), &*info);
        let info = rewritten.as_ref().map_or(info, Rewritten::head);
        let result = super::generated::vkCreateImage::<F>(
            wire::VkDevice(object(device)),
            info.cast(),
            allocator.cast(),
            output.cast(),
        );
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn create_buffer<F: Factory>(
    device: vk::Device,
    info: *const vk::BufferCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Buffer,
) -> vk::Result {
    // SAFETY: Vulkan supplies a live device, create-info and output slot.
    unsafe {
        let rewritten = buffer_info(device_memory::<F>(device), &*info);
        let info = rewritten.as_ref().map_or(info, Rewritten::head);
        let result = super::generated::vkCreateBuffer::<F>(
            wire::VkDevice(object(device)),
            info.cast(),
            allocator.cast(),
            output.cast(),
        );
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn device_image_memory_requirements<F: Factory>(
    device: vk::Device,
    info: *const vk::DeviceImageMemoryRequirements<'_>,
    requirements: *mut vk::MemoryRequirements2<'_>,
) {
    // SAFETY: Vulkan supplies a live device, query and output chain.
    unsafe {
        let rewritten = image_info(device_memory::<F>(device), &*(*info).p_create_info);
        let mut renderer_info = *info;
        if let Some(rewritten) = &rewritten {
            renderer_info.p_create_info = rewritten.head();
        }
        super::generated::vkGetDeviceImageMemoryRequirements::<F>(
            wire::VkDevice(object(device)),
            (&raw const renderer_info).cast(),
            requirements.cast(),
        );
    }
}

unsafe extern "system" fn device_buffer_memory_requirements<F: Factory>(
    device: vk::Device,
    info: *const vk::DeviceBufferMemoryRequirements<'_>,
    requirements: *mut vk::MemoryRequirements2<'_>,
) {
    // SAFETY: Vulkan supplies a live device, query and output chain.
    unsafe {
        let rewritten = buffer_info(device_memory::<F>(device), &*(*info).p_create_info);
        let mut renderer_info = *info;
        if let Some(rewritten) = &rewritten {
            renderer_info.p_create_info = rewritten.head();
        }
        super::generated::vkGetDeviceBufferMemoryRequirements::<F>(
            wire::VkDevice(object(device)),
            (&raw const renderer_info).cast(),
            requirements.cast(),
        );
    }
}

/// Physical-device commands, resolved only through an instance.
pub(super) fn instance_lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkEnumerateDeviceExtensionProperties" => enumerate_device_extensions::<F> as *const (),
        b"vkGetPhysicalDeviceImageFormatProperties2"
        | b"vkGetPhysicalDeviceImageFormatProperties2KHR" => {
            image_format_properties2::<F> as *const ()
        }
        b"vkGetPhysicalDeviceExternalBufferProperties"
        | b"vkGetPhysicalDeviceExternalBufferPropertiesKHR" => {
            external_buffer_properties::<F> as *const ()
        }
        _ => return None,
    };
    // SAFETY: Vulkan restores the function signature named by the lookup.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}

pub(super) fn lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkCreateImage" => create_image::<F> as *const (),
        b"vkCreateBuffer" => create_buffer::<F> as *const (),
        b"vkGetDeviceImageMemoryRequirements" | b"vkGetDeviceImageMemoryRequirementsKHR" => {
            device_image_memory_requirements::<F> as *const ()
        }
        b"vkGetDeviceBufferMemoryRequirements" | b"vkGetDeviceBufferMemoryRequirementsKHR" => {
            device_buffer_memory_requirements::<F> as *const ()
        }
        _ => return None,
    };
    // SAFETY: Vulkan restores the function signature named by the lookup.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn properties(
        features: vk::ExternalMemoryFeatureFlags,
        exports: HandleTypes,
    ) -> vk::ExternalMemoryProperties {
        vk::ExternalMemoryProperties {
            external_memory_features: features,
            export_from_imported_handle_types: exports,
            compatible_handle_types: exports,
        }
    }

    const BOTH: vk::ExternalMemoryFeatureFlags = vk::ExternalMemoryFeatureFlags::from_raw(
        vk::ExternalMemoryFeatureFlags::EXPORTABLE.as_raw()
            | vk::ExternalMemoryFeatureFlags::IMPORTABLE.as_raw(),
    );

    const DMA_BUF: ExternalMemory = ExternalMemory {
        renderer: HandleTypes::DMA_BUF_EXT,
    };

    #[test]
    fn an_exporting_dma_buf_renderer_takes_every_offered_handle_type() {
        let memory = ExternalMemory::choose(Some(properties(BOTH, HandleTypes::DMA_BUF_EXT)));
        assert_eq!(memory, DMA_BUF);
        assert_eq!(memory.offered(), OFFERED);
        assert_eq!(memory.rewrite(HandleTypes::DMA_BUF_EXT), None);
        assert_eq!(
            memory.rewrite(HandleTypes::OPAQUE_FD),
            Some(HandleTypes::DMA_BUF_EXT)
        );
        assert_eq!(memory.rewrite(HandleTypes::empty()), None);
    }

    #[test]
    fn an_import_only_dma_buf_renderer_exports_nothing() {
        // lavapipe without /dev/udmabuf: dma-bufs import only. Its memfds
        // export, but the host's display cannot scan one out.
        let memory = ExternalMemory::choose(Some(properties(
            vk::ExternalMemoryFeatureFlags::IMPORTABLE,
            HandleTypes::DMA_BUF_EXT,
        )));
        assert_eq!(memory, ExternalMemory::NONE);
        assert_eq!(memory.offered(), HandleTypes::empty());
    }

    #[test]
    fn exportability_needs_the_handle_type_among_the_exportable_ones() {
        let memory = ExternalMemory::choose(Some(properties(
            vk::ExternalMemoryFeatureFlags::EXPORTABLE,
            HandleTypes::empty(),
        )));
        assert_eq!(memory, ExternalMemory::NONE);
    }

    #[test]
    fn a_renderer_without_the_dma_buf_extension_exports_nothing() {
        assert_eq!(ExternalMemory::choose(None), ExternalMemory::NONE);
    }

    #[test]
    fn answers_name_the_offered_handle_types_and_never_import() {
        let memory = DMA_BUF;
        let mut answer = properties(BOTH, HandleTypes::DMA_BUF_EXT);
        memory.answer(&mut answer);
        assert_eq!(
            answer.external_memory_features,
            vk::ExternalMemoryFeatureFlags::EXPORTABLE
        );
        assert_eq!(answer.compatible_handle_types, OFFERED);
        assert_eq!(answer.export_from_imported_handle_types, OFFERED);

        let mut refused = properties(
            vk::ExternalMemoryFeatureFlags::empty(),
            HandleTypes::empty(),
        );
        memory.answer(&mut refused);
        assert_eq!(
            refused.external_memory_features,
            vk::ExternalMemoryFeatureFlags::empty()
        );
        assert_eq!(
            refused.export_from_imported_handle_types,
            HandleTypes::empty()
        );

        let unsupported = ExternalMemory::unsupported(HandleTypes::HOST_ALLOCATION_EXT);
        assert_eq!(
            unsupported.compatible_handle_types,
            HandleTypes::HOST_ALLOCATION_EXT
        );
        assert_eq!(
            unsupported.external_memory_features,
            vk::ExternalMemoryFeatureFlags::empty()
        );
    }

    fn extension(name: &CStr, version: u32) -> vk::ExtensionProperties {
        vk::ExtensionProperties::default()
            .extension_name(name)
            .unwrap()
            .spec_version(version)
    }

    fn names(extensions: &[vk::ExtensionProperties]) -> Vec<&CStr> {
        extensions
            .iter()
            .map(|extension| extension.extension_name_as_c_str().unwrap())
            .collect()
    }

    #[test]
    fn the_guest_advertises_its_own_external_memory_extensions() {
        let renderer = [
            extension(ash::ext::queue_family_foreign::NAME, 1),
            extension(ash::ext::external_memory_dma_buf::NAME, 1),
            extension(ash::khr::external_memory_fd::NAME, 1),
        ];
        let exporting = DMA_BUF;
        assert_eq!(
            names(&advertised_extensions(&renderer, exporting)),
            [
                ash::ext::queue_family_foreign::NAME,
                ash::khr::external_memory_fd::NAME,
                ash::ext::external_memory_dma_buf::NAME,
            ]
        );
        assert_eq!(
            names(&advertised_extensions(&renderer, ExternalMemory::NONE)),
            [ash::ext::queue_family_foreign::NAME]
        );
    }

    #[test]
    fn device_creation_enables_the_renderer_handle_type_extensions() {
        let foreign = ash::ext::queue_family_foreign::NAME;
        let dma_buf = ash::ext::external_memory_dma_buf::NAME;
        let fd = ash::khr::external_memory_fd::NAME;
        let native = DMA_BUF;
        assert_eq!(renderer_device_extensions(&[foreign], native), Ok(None));
        assert_eq!(
            renderer_device_extensions(&[foreign, dma_buf], native),
            Ok(Some(vec![foreign, dma_buf, fd]))
        );
        assert_eq!(
            renderer_device_extensions(&[dma_buf, fd], native),
            Ok(Some(vec![dma_buf, fd]))
        );
        assert_eq!(
            renderer_device_extensions(&[fd], native),
            Ok(Some(vec![dma_buf, fd]))
        );
        assert_eq!(
            renderer_device_extensions(&[dma_buf], ExternalMemory::NONE),
            Err(vk::Result::ERROR_EXTENSION_NOT_PRESENT)
        );
    }

    #[test]
    fn create_infos_carry_the_renderer_handle_type() {
        let memory = DMA_BUF;
        let external =
            vk::ExternalMemoryImageCreateInfo::default().handle_types(HandleTypes::OPAQUE_FD);
        let mut image = vk::ImageCreateInfo::default().tiling(vk::ImageTiling::LINEAR);
        image.p_next = (&raw const external).cast();
        let external_buffer =
            vk::ExternalMemoryBufferCreateInfo::default().handle_types(HandleTypes::OPAQUE_FD);
        let mut buffer = vk::BufferCreateInfo::default().size(64);
        buffer.p_next = (&raw const external_buffer).cast();
        // An export, then a dedicated allocation, as the WebGPU provider
        // allocates, naming the handle type the renderer does not export.
        let dedicated = vk::MemoryDedicatedAllocateInfo::default();
        let mut export =
            vk::ExportMemoryAllocateInfo::default().handle_types(HandleTypes::OPAQUE_FD);
        export.p_next = (&raw const dedicated).cast();
        let allocation = vk::MemoryAllocateInfo {
            p_next: (&raw const export).cast(),
            ..Default::default()
        };
        // SAFETY: every chain is live for the test.
        unsafe {
            let image = image_info(memory, &image).unwrap();
            let image = &*image.head();
            assert_eq!(image.tiling, vk::ImageTiling::LINEAR);
            let external = chain::next::<vk::ExternalMemoryImageCreateInfo<'_>>(image.p_next);
            assert_eq!(external.unwrap().handle_types, HandleTypes::DMA_BUF_EXT);

            let buffer = buffer_info(memory, &buffer).unwrap();
            let buffer = &*buffer.head();
            assert_eq!(buffer.size, 64);
            let external = chain::next::<vk::ExternalMemoryBufferCreateInfo<'_>>(buffer.p_next);
            assert_eq!(external.unwrap().handle_types, HandleTypes::DMA_BUF_EXT);

            let rewritten = allocate_info(memory, &allocation).unwrap();
            let allocation = &*rewritten.head();
            let export = chain::next::<vk::ExportMemoryAllocateInfo<'_>>(allocation.p_next);
            assert_eq!(export.unwrap().handle_types, HandleTypes::DMA_BUF_EXT);
            assert!(
                chain::next::<vk::MemoryDedicatedAllocateInfo<'_>>(allocation.p_next).is_some()
            );
        }
        assert_eq!(external.handle_types, HandleTypes::OPAQUE_FD);
        assert_eq!(export.handle_types, HandleTypes::OPAQUE_FD);

        // The renderer's own handle type reaches it unchanged.
        let own = vk::ExportMemoryAllocateInfo::default().handle_types(HandleTypes::DMA_BUF_EXT);
        let allocation = vk::MemoryAllocateInfo {
            p_next: (&raw const own).cast(),
            ..Default::default()
        };
        // SAFETY: the chain is live for the test.
        assert!(unsafe { allocate_info(memory, &allocation) }.is_none());
    }
}
