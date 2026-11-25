wit_bindgen::generate!({
    path: "../wit",
    world: "inspector-system",
    generate_all,
    additional_derives: [serde::Serialize, serde::Deserialize],
    // Local WIT resources and records containing resource handles are not
    // serialized directly over postcard; `system::programs` defines the
    // serializable wire subset for `programs.exec`.
    additional_derives_ignore: [
        "timeline-point",
        "signal-point",
        "completion",
        "endpoint",
        "tcp-stream",
        "tcp-listener",
        "udp-socket",
        "vsock-stream",
        "vsock-listener",
        "inherited-socket",
        "ipc-grant",
        "capability-grant",
        "spawn-request",
        "exec-request",
        "container-config",
        "container-spawn-request",
        "snapshot-hold",
        "sampling-session",
        "publication",
    ],
});
