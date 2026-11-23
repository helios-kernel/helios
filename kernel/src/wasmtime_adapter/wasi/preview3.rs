use crate::ComponentHostNetwork;
use helios_hal::cpu::Cpu;
use wasmtime::Result;
use wasmtime::component::HasSelf;

use super::WasiImportSet;
use super::bindings as wasi;
use crate::wasmtime_adapter::component_host::StoreData;

#[cfg(test)]
pub(crate) const WIT_PACKAGES: &[(&str, &str)] = &[
    ("wasi:cli", include_str!("../../../../wit/deps/cli.wit")),
    (
        "wasi:clocks",
        include_str!("../../../../wit/deps/clocks.wit"),
    ),
    (
        "wasi:filesystem",
        include_str!("../../../../wit/deps/filesystem.wit"),
    ),
    (
        "wasi:random",
        include_str!("../../../../wit/deps/random.wit"),
    ),
    (
        "wasi:sockets",
        include_str!("../../../../wit/deps/sockets.wit"),
    ),
    ("wasi:http", include_str!("../../../../wit/deps/http.wit")),
];

linked_interfaces! {
    linker, imports;
    "wasi:clocks/monotonic-clock" => wasi::clocks::monotonic_clock::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:clocks/system-clock" => wasi::clocks::system_clock::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:clocks/timezone" => {
        // Every member of `wasi:clocks/timezone` is gated behind the
        // `clocks-timezone` unstable feature, so the generated link options
        // must opt in or the interface links with no functions at all.
        let mut options = wasi::clocks::timezone::LinkOptions::default();
        options.clocks_timezone(true);
        wasi::clocks::timezone::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
            linker,
            &options,
            |state| state,
        )
    };
    "wasi:cli/environment" => wasi::cli::environment::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/exit" => wasi::cli::exit::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/stdin" => wasi::cli::stdin::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/stdout" => wasi::cli::stdout::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/stderr" => wasi::cli::stderr::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/terminal-input" => wasi::cli::terminal_input::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/terminal-output" => wasi::cli::terminal_output::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/terminal-stdin" => wasi::cli::terminal_stdin::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/terminal-stdout" => wasi::cli::terminal_stdout::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:cli/terminal-stderr" => wasi::cli::terminal_stderr::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:random/random" => wasi::random::random::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:random/insecure" => wasi::random::insecure::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:random/insecure-seed" => wasi::random::insecure_seed::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:filesystem/types" => wasi::filesystem::types::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:filesystem/preopens" => wasi::filesystem::preopens::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:sockets/types" => wasi::sockets::types::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
    "wasi:sockets/ip-name-lookup" => wasi::sockets::ip_name_lookup::add_to_linker::<
        _,
        HasSelf<StoreData<CpuImpl, Net, StorageImpl>>,
    >(linker, |state| state);
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::WIT_PACKAGES;

    #[test]
    fn preview3_wit_packages_use_expected_release_version() {
        for (package, wit) in WIT_PACKAGES {
            let expected = {
                let mut expected = String::from("package ");
                expected.push_str(package);
                expected.push_str("@0.3.0;");
                expected
            };
            assert!(
                wit.lines().any(|line| line.trim() == expected),
                "preview3 WIT package {package} does not declare @0.3.0"
            );
        }
    }
}
