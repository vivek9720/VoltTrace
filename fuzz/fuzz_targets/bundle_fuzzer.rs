#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = volttrace::decode_and_analyze_bundle(data);
});
