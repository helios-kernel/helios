#![no_main]
mod support;
libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let _ = helios_btrfs::testing::image(input);
});
