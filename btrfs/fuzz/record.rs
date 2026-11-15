#![no_main]
mod support;
libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    helios_btrfs::testing::record(input);
});
