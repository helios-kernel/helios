pub mod debugger {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "debugger",
            imports: {
                "helios:system/serial.debug-port": immediate | trappable,
                "helios:system/serial.[method]serial-port.rights": immediate | trappable,
                "helios:system/serial.[method]serial-port.flush": immediate | trappable,
                "helios:system/programs.[method]child.stdin": store | trappable,
                "helios:system/programs.[method]child.stdout": store | trappable,
                "helios:system/programs.[method]child.stderr": store | trappable,
                default: store | trappable
            },
            exports: { default: async },
            with: {
                "helios:system/programs.child": crate::ChildHandle,
                "helios:system/programs.container": crate::ContainerHandle,
                "helios:system/inspect.publication": crate::wasmtime_adapter::component_host::InspectPublicationHandle,
                "helios:system/ipc.endpoint": crate::IpcEndpoint,
                "helios:system/snapshot.snapshot-hold": crate::ComponentSnapshotHold,
                "helios:system/profiling.sampling-session": crate::ComponentSamplingSession,
                "helios:system/serial.serial-port": crate::ComponentSerialPort,
                "helios:system/vsock.vsock-stream": crate::wasmtime_adapter::component_host::ComponentVsockStream,
                "helios:system/vsock.vsock-listener": crate::wasmtime_adapter::component_host::ComponentVsockListener,
                "helios:system/sync.timeline": crate::SharedTimeline,
                "helios:system/sync.signal-source": crate::TimelineSource,
                "helios:system/sync.raw-mutex": crate::ComponentRawMutex,
                "helios:system/sync.raw-mutex-guard": crate::ComponentRawMutexGuard,
                "helios:system/sync.raw-rw-lock": crate::ComponentRawRwLock,
                "helios:system/sync.raw-rw-lock-read-guard": crate::ComponentRawRwLockReadGuard,
                "helios:system/sync.raw-rw-lock-write-guard": crate::ComponentRawRwLockWriteGuard,
            },
            require_store_data_send: true,
        });
    }
}

pub mod program {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "init",
            imports: {
                "helios:system/serial.debug-port": immediate | trappable,
                "helios:system/serial.[method]serial-port.rights": immediate | trappable,
                "helios:system/serial.[method]serial-port.flush": immediate | trappable,
                "helios:system/programs.[method]child.stdin": store | trappable,
                "helios:system/programs.[method]child.stdout": store | trappable,
                "helios:system/programs.[method]child.stderr": store | trappable,
                default: store | trappable
            },
            exports: { default: async },
            with: {
                "helios:system/programs.child": crate::ChildHandle,
                "helios:system/programs.container": crate::ContainerHandle,
                "helios:system/inspect.publication": crate::wasmtime_adapter::component_host::InspectPublicationHandle,
                "helios:system/ipc.endpoint": crate::IpcEndpoint,
                "helios:system/snapshot.snapshot-hold": crate::ComponentSnapshotHold,
                "helios:system/profiling.sampling-session": crate::ComponentSamplingSession,
                "helios:system/serial.serial-port": crate::ComponentSerialPort,
                "helios:system/vsock.vsock-stream": crate::wasmtime_adapter::component_host::ComponentVsockStream,
                "helios:system/vsock.vsock-listener": crate::wasmtime_adapter::component_host::ComponentVsockListener,
                "helios:system/sync.timeline": crate::SharedTimeline,
                "helios:system/sync.signal-source": crate::TimelineSource,
                "helios:system/sync.raw-mutex": crate::ComponentRawMutex,
                "helios:system/sync.raw-mutex-guard": crate::ComponentRawMutexGuard,
                "helios:system/sync.raw-rw-lock": crate::ComponentRawRwLock,
                "helios:system/sync.raw-rw-lock-read-guard": crate::ComponentRawRwLockReadGuard,
                "helios:system/sync.raw-rw-lock-write-guard": crate::ComponentRawRwLockWriteGuard,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a driver plugin reaches its device through.
///
/// Generated from the `device-host` world rather than from `device-driver`:
/// the kernel implements this one interface and the program bindings above
/// already provide every `wasi:cli` import a driver also has.
pub mod device {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "device-host",
            imports: {
                // The call that hands back a stream has to see the store,
                // so it can build the reader against it; the two that
                // take a span have to see it to read the memory's base
                // and current size at the call.
                "helios:system/device.[method]grant.interrupts": store | trappable,
                "helios:system/device.[method]grant.map-region": store | trappable,
                "helios:system/device.[method]grant.dma-alloc": store | trappable,
                default: trappable,
            },
            with: {
                "helios:system/device.grant": crate::GrantHandle,
                "helios:system/device.dma-buffer": crate::DmaBufferHandle,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a compositor reaches the display through.
///
/// Generated from the `display-host` world rather than from a program
/// world for the same reason `device-host` is: the kernel implements
/// this one interface, and the program bindings above already provide
/// every `wasi:cli` import a compositor also has.
pub mod display {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "display-host",
            imports: {
                // The three calls that hand back a reader have to see
                // the store, so they can build it against one; they
                // return the reader immediately rather than awaiting.
                "helios:system/display.[method]display.changed": store | trappable,
                "helios:system/display.[method]surface.present": store | trappable,
                "helios:system/display.[method]surface.vsync": store | trappable,
                // Everything else that reaches the display engine is an
                // `async func` in the WIT and is generated against the
                // store on its own account. What is left — claiming,
                // reading back where a frame buffer landed, dropping a
                // handle — is store bookkeeping and answers without
                // waiting.
                default: trappable,
            },
            with: {
                "helios:system/display.display":
                    crate::wasmtime_adapter::component_host::DisplayHandle,
                "helios:system/display.surface":
                    crate::wasmtime_adapter::component_host::SurfaceHandle,
                // A blob surface names a `gpu.blob`, which is the gpu
                // bindings' resource: one type for one handle, whichever
                // interface the guest passes it through.
                "helios:system/gpu":
                    crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::gpu,
                "helios:system/memory":
                    crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::memory,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a program reaches the machine's input
/// devices through.
///
/// Generated from the `input-host` world, for the reason `display-host`
/// is: the kernel implements this one interface, and the program
/// bindings above already provide every `wasi:cli` import a compositor
/// also has.
pub mod input {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "input-host",
            imports: {
                // The call that hands back a reader has to see the store,
                // so it can build one against it; it returns the reader
                // immediately rather than awaiting.
                "helios:system/input.[method]device.events": store | trappable,
                // `set-led` is the one call that reaches the device and
                // is an `async func` in the WIT, generated against the
                // store on its own account. What is left — claiming,
                // listing, reading capabilities back, dropping a handle
                // — is store bookkeeping and answers without waiting.
                default: trappable,
            },
            with: {
                "helios:system/input.device":
                    crate::wasmtime_adapter::component_host::InputDeviceHandle,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a program reaches its windows on the
/// desktop through.
///
/// Generated from the `surface-host` world, for the reason
/// `display-host` is: the kernel implements this one interface — it
/// serves none of it, it forwards — and the program bindings above
/// already provide every `wasi:cli` import a client also has.
pub mod surface {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "surface-host",
            imports: {
                // The call that hands back a reader has to see the store,
                // so it can build one against it; it returns the reader
                // immediately rather than awaiting.
                "helios:system/surface.[method]surface.events": store | trappable,
                "helios:system/surface.[method]image-surface.events": store | trappable,
                // `create`, `commit` and `deliver` all reach the
                // compositor and are `async func` in the WIT, generated
                // against the store on their own account. What is left —
                // reading back where a frame buffer landed, the geometry,
                // dropping a handle — is store bookkeeping and answers
                // without waiting.
                default: trappable,
            },
            with: {
                "helios:system/surface.image-surface": crate::wasmtime_adapter::component_host::ClientImageSurfaceHandle,
                "helios:system/gpu": crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::gpu,
                "helios:system/sync": crate::wasmtime_adapter::bindings::debugger::bindings::helios::system::sync,
                "helios:system/surface.surface":
                    crate::wasmtime_adapter::component_host::ClientSurfaceHandle,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a rendering plugin reaches the 3D engine
/// through.
///
/// Generated from the `gpu-host` world, for the reason `display-host`
/// is: the kernel implements this one interface, and the program
/// bindings above already provide every `wasi:cli` import a plugin also
/// has.
pub mod gpu {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "gpu-host",
            imports: {
                // The call that hands back a reader has to see the store,
                // so it can build one against it; it returns the reader
                // immediately rather than awaiting.
                "helios:system/gpu.[method]context.fences": store | trappable,
                // Everything that reaches the display engine is an
                // `async func` in the WIT and is generated against the
                // store on its own account. What is left — opening,
                // reading back a blob's resource id, dropping a handle
                // — is store bookkeeping and answers without waiting.
                default: trappable,
            },
            with: {
                "helios:system/sync": crate::wasmtime_adapter::bindings::debugger::bindings::helios::system::sync,
                "helios:system/gpu.gpu":
                    crate::wasmtime_adapter::component_host::GpuHandle,
                "helios:system/gpu.context":
                    crate::wasmtime_adapter::component_host::ContextHandle,
                "helios:system/gpu.command-buffer":
                    crate::wasmtime_adapter::component_host::CommandBufferHandle,
                "helios:system/gpu.image": crate::gpu::GpuImage,
                "helios:system/gpu.blob":
                    crate::wasmtime_adapter::component_host::BlobHandle,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a player reaches the machine's sound
/// device through.
///
/// Generated from the `audio-host` world, for the reason `input-host`
/// is: the kernel implements this one interface, and the program
/// bindings above already provide every `wasi:cli` import a player also
/// has.
pub mod audio {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "audio-host",
            imports: {
                // The two calls that hand a reader over — the samples
                // the guest writes and the feedback it reads — have to
                // see the store, so they can pipe against one; they
                // answer immediately rather than awaiting.
                "helios:system/audio.[method]playback.samples": store | trappable,
                "helios:system/audio.[method]playback.feedback": store | trappable,
                // `negotiate` and `stop` reach the device and are
                // `async func` in the WIT, generated against the store
                // on their own account. What is left — claiming,
                // listing, reading the topology back, dropping a handle
                // — is store bookkeeping and answers without waiting.
                default: trappable,
            },
            with: {
                "helios:system/audio.playback":
                    crate::wasmtime_adapter::component_host::PlaybackHandle,
            },
            require_store_data_send: true,
        });
    }
}

/// Hardware virtualization resources shared by both program worlds.
pub mod hv {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "hv-host",
            imports: { default: trappable },
            require_store_data_send: true,
        });
    }
}

/// Bindings for the interface a program reaches the machine's processor
/// lifecycle through.
///
/// Generated from the `processors-host` world, for the reason
/// `audio-host` is: the kernel implements this one interface for both
/// program worlds, and the program bindings above already provide every
/// `wasi:cli` import a caller also has.
pub mod processors {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "processors-host",
            imports: {
                // The transitions are `async func` in the WIT and are
                // generated against the store on their own account;
                // reading the sets is two atomic loads per processor
                // and answers without waiting.
                default: trappable,
            },
            // The answers are compared case for case where the
            // lifecycle's results are mapped onto them.
            additional_derives: [PartialEq, Eq],
            require_store_data_send: true,
        });
    }
}

/// Bindings for the btrfs volume management interface served to both program
/// worlds (`init` and `debugger`).
pub mod btrfs {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "btrfs-host",
            imports: {
                default: trappable,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for bounded duplex capability channels (`helios:system/ipc`)
/// served identically across both program worlds.
pub mod ipc {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "ipc-host",
            imports: {
                default: trappable,
            },
            with: {
                "helios:system/ipc.endpoint": crate::IpcEndpoint,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for Ed25519 machine-identity challenge signing
/// (`helios:system/machine-identity`).
pub mod machine_identity {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "machine-identity-host",
            imports: {
                default: trappable,
            },
            additional_derives: [PartialEq, Eq],
            require_store_data_send: true,
        });
    }
}

/// Bindings for scoped live instance inspection and kill
/// (`helios:system/instances`).
pub mod instances {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "instances-host",
            imports: {
                default: trappable,
            },
            additional_derives: [PartialEq, Eq],
            require_store_data_send: true,
        });
    }
}

/// Bindings for RAII host-share snapshot preparation
/// (`helios:system/snapshot`).
pub mod snapshot {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "snapshot-host",
            imports: {
                default: trappable,
            },
            with: {
                "helios:system/snapshot.snapshot-hold": crate::ComponentSnapshotHold,
            },
            require_store_data_send: true,
        });
    }
}

/// Bindings for lock-free component and kernel state inspection
/// (`helios:system/inspect`), served identically across every component world.
pub mod inspect {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "inspect-host",
            imports: {
                // `publish` needs `Access::caller_memory()` to validate the
                // span against the calling subcomponent's unshared linear
                // memory.
                "helios:system/inspect.publish": store | trappable,
                default: trappable,
            },
            with: {
                "helios:system/inspect.publication": crate::wasmtime_adapter::component_host::InspectPublicationHandle,
                "helios:system/memory":
                    crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::memory,
            },
            additional_derives: [PartialEq],
            require_store_data_send: true,
        });
    }
}

/// Bindings for the export the compositor plugin answers on.
///
/// Generated from the `compositor-host` world rather than from
/// `compositor`, the way `http-host` is separate from `http-handler`:
/// this is the one interface the kernel *calls*, and the plugin's own
/// imports are the program bindings above.
pub mod compositor {
    pub mod bindings {
        use wasmtime;

        wasmtime::component::bindgen!({
            path: "../wit",
            world: "compositor-host",
            with: {
                "helios:system/gpu": crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::gpu,
                "helios:system/sync": crate::wasmtime_adapter::bindings::debugger::bindings::helios::system::sync,
            },
            exports: { default: async | store },
            require_store_data_send: true,
        });
    }
}
