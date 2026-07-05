#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = volttrace::script::compile_and_run(data);
});
