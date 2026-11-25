use crate::wit_bindgen;

#[cfg(all(
    feature = "hv",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`hv` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "btrfs",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`btrfs` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "mounts",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`mounts` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "processors",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`processors` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "ipc",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`ipc` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "machine-identity",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`machine-identity` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(all(
    feature = "snapshot",
    any(
        feature = "http-handler",
        feature = "compositor",
        feature = "webgpu",
        feature = "webgpu-provider"
    )
))]
compile_error!(
    "`snapshot` is part of the `init` and `root-supervisor` worlds; `http-handler`, `compositor`, `webgpu` and `webgpu-provider` do not import it"
);

#[cfg(any(
    all(
        feature = "webgpu-provider",
        any(
            feature = "root-supervisor",
            feature = "http-handler",
            feature = "compositor",
            feature = "webgpu"
        )
    ),
    all(
        feature = "webgpu",
        any(
            feature = "root-supervisor",
            feature = "http-handler",
            feature = "compositor"
        )
    ),
    all(feature = "root-supervisor", feature = "http-handler"),
    all(feature = "root-supervisor", feature = "compositor"),
    all(feature = "http-handler", feature = "compositor"),
))]
compile_error!(
    "a component implements exactly one world: `root-supervisor` selects `root-supervisor`, `http-handler` selects `http-handler`, `compositor` selects `compositor`, `webgpu` selects `webgpu` and `webgpu-provider` selects `webgpu-provider`, so enable at most one"
);

#[cfg(feature = "compositor")]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "compositor",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});

#[cfg(all(feature = "http-handler", not(feature = "compositor")))]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "http-handler",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});

#[cfg(all(
    feature = "root-supervisor",
    not(feature = "http-handler"),
    not(feature = "compositor"),
    not(feature = "webgpu"),
    not(feature = "webgpu-provider")
))]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "root-supervisor",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});

#[cfg(all(
    not(feature = "root-supervisor"),
    not(feature = "http-handler"),
    not(feature = "compositor"),
    not(feature = "webgpu"),
    not(feature = "webgpu-provider")
))]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "init",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});

#[cfg(feature = "webgpu")]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "webgpu",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});

#[cfg(feature = "webgpu-provider")]
crate::wit_bindgen::generate!({
    path: "../wit",
    world: "webgpu-provider",
    generate_all,
    default_bindings_module: "bindings",
    pub_export_macro: true,
});
