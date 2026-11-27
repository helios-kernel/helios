OUTPUT_ARCH(riscv)
ENTRY(_start)

KERNEL_VMA = 0xffffffff80000000;
KERNEL_LMA = 0x00200000;
PAGE_SIZE = 0x1000;

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    __helios_text_start = KERNEL_VMA;
    . = KERNEL_VMA + SIZEOF_HEADERS;

    .text : AT(ADDR(.text) - KERNEL_VMA + KERNEL_LMA) {
        *(.text._start)
        *(.text .text.*)
    } :text

    . = ALIGN(PAGE_SIZE);
    __helios_text_end = .;
    __helios_rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_VMA + KERNEL_LMA) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.eh_frame_hdr)
        *(.eh_frame)
    } :rodata

    . = ALIGN(PAGE_SIZE);
    __helios_rodata_end = .;
    __helios_data_start = .;
    .data.rel.ro : AT(ADDR(.data.rel.ro) - KERNEL_VMA + KERNEL_LMA) {
        *(.data.rel.ro.local*) *(.data.rel.ro .data.rel.ro.*)
    } :data

    .dynamic : AT(ADDR(.dynamic) - KERNEL_VMA + KERNEL_LMA) {
        *(.dynamic)
    } :data

    .got : AT(ADDR(.got) - KERNEL_VMA + KERNEL_LMA) {
        *(.got .got.*)
    } :data

    .rela.dyn : AT(ADDR(.rela.dyn) - KERNEL_VMA + KERNEL_LMA) {
        *(.rela.dyn)
    } :data

    .data : AT(ADDR(.data) - KERNEL_VMA + KERNEL_LMA) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    PROVIDE(__global_pointer$ = __helios_data_start + 0x800);

    . = ALIGN(PAGE_SIZE);
    __helios_data_end = .;
    __helios_bss_start = .;
    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VMA + KERNEL_LMA) {
        *(COMMON)
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    } :data
    . = ALIGN(PAGE_SIZE);
    __helios_bss_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
    }
}
