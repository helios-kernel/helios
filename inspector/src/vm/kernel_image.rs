//! Re-exports of `helios_ops::symbolize` for kernel ELF symbols and DWARF
//! inline-chain resolution used by `vm` diagnostics and audits.

#[cfg(test)]
pub(crate) use helios_ops::symbolize::{DwarfReader, Function, KernelDebugInfo};
pub(crate) use helios_ops::symbolize::{
    KernelSymbols, KernelSymbolsError, LoadedKernelSymbols, SymbolizedAddress, function_symbols,
    parse_image, read_image,
};

#[cfg(test)]
mod tests {
    use super::{Function, KernelSymbols, SymbolizedAddress};

    fn function(name: &str, address: u64, size: u64) -> Function {
        Function {
            name: name.to_owned(),
            address,
            size,
        }
    }

    fn table() -> KernelSymbols {
        let text = 0xffff_ffff_8000_1000..0xffff_ffff_8000_2080;
        KernelSymbols::new(
            0xffff_ffff_8000_0000,
            vec![text],
            vec![
                function("memcpy", 0xffff_ffff_8000_2000, 0x80),
                function(
                    "_ZN10helios_x863smp12wait_for_ack17h0123456789abcdefE",
                    0xffff_ffff_8000_1100,
                    0x40,
                ),
                function(
                    "_RNvNtCs1234_13helios_kernel4exec4park",
                    0xffff_ffff_8000_1000,
                    0xc0,
                ),
                function("label_inside_park", 0xffff_ffff_8000_1010, 0),
            ],
        )
    }

    #[test]
    fn the_slide_is_the_runtime_base_minus_the_link_base() {
        let table = table();
        let loaded = table.loaded_at(0xffff_ffff_8120_0000);
        assert_eq!(loaded.slide(), 0x120_0000);
        let below = table.loaded_at(0xffff_ffff_7fe0_0000);
        assert_eq!(
            below.symbolize(0xffff_ffff_7fe0_1004),
            Some(SymbolizedAddress {
                function: "helios_kernel::exec::park".to_owned(),
                offset: 4,
            })
        );
    }

    #[test]
    fn a_runtime_address_names_the_function_that_contains_it() {
        let table = table();
        let loaded = table.loaded_at(0xffff_ffff_8120_0000);
        let park = loaded
            .symbolize(0xffff_ffff_8120_101c)
            .expect("inside park, past the zero-sized label");
        assert_eq!(park.to_string(), "helios_kernel::exec::park+0x1c");
        let ack = loaded
            .symbolize(0xffff_ffff_8120_1100)
            .expect("the first byte of wait_for_ack");
        assert_eq!(ack.to_string(), "helios_x86::smp::wait_for_ack+0x0");
        let copy = loaded
            .symbolize(0xffff_ffff_8120_207f)
            .expect("the last byte of memcpy");
        assert_eq!(copy.to_string(), "memcpy+0x7f");
    }

    #[test]
    fn an_address_outside_every_function_is_unnamed() {
        let table = table();
        let loaded = table.loaded_at(0xffff_ffff_8120_0000);
        assert_eq!(loaded.symbolize(0xffff_ffff_8120_1100 - 1), None);
        assert_eq!(loaded.symbolize(0xffff_ffff_8120_2080), None);
        assert_eq!(loaded.symbolize(0xffff_ffff_8120_0000), None);
    }

    #[test]
    fn only_an_address_inside_an_executable_segment_is_text() {
        let table = KernelSymbols::new(
            0xffff_ffff_8000_0000,
            vec![
                0xffff_ffff_8000_1000..0xffff_ffff_8000_2000,
                0xffff_ffff_8000_8000..0xffff_ffff_8000_9000,
            ],
            Vec::new(),
        );
        let loaded = table.loaded_at(0xffff_ffff_8120_0000);
        assert!(loaded.contains_text(0xffff_ffff_8120_1000));
        assert!(loaded.contains_text(0xffff_ffff_8120_1fff));
        assert!(loaded.contains_text(0xffff_ffff_8120_8800));
        assert!(!loaded.contains_text(0xffff_ffff_8120_2000));
        assert!(!loaded.contains_text(0xffff_ffff_8120_9000));
        assert!(!loaded.contains_text(0xffff_ffff_8000_1000));
        assert!(!loaded.contains_text(0x246));
        assert!(!loaded.contains_text(0x0000_7f00_0010_2030));
    }
}
