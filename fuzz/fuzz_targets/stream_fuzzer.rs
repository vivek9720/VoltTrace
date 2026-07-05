#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut decoder = volttrace::stream::StreamDecoder::new();
    let _ = decoder.feed(data);
    let _ = decoder.finish();
});
