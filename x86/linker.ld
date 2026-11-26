/* Section boundary symbols for x86_64-unknown-none.
 *
 * Intentionally omits a SECTIONS block so LLD keeps its default
 * static-PIE/RELRO layout and orphan section placement (including
 * `--profile-generate` `__llvm_prf_*` sections).
 */
PROVIDE(__helios_text_start   = ADDR(.text));
PROVIDE(__helios_text_end     = ADDR(.text) + SIZEOF(.text));
PROVIDE(__helios_rodata_start = ADDR(.rodata));
PROVIDE(__helios_rodata_end   = ADDR(.rodata) + SIZEOF(.rodata));
PROVIDE(__helios_data_start   = ADDR(.data));
PROVIDE(__helios_data_end     = ADDR(.data) + SIZEOF(.data));
PROVIDE(__helios_bss_start    = ADDR(.bss));
PROVIDE(__helios_bss_end      = ADDR(.bss) + SIZEOF(.bss));
