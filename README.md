# VoltTrace

VoltTrace is a Rust library for decoding offline EV charging operations bundles.
A bundle can contain a site manifest, token dictionary, telemetry records,
offline receipt batches, attachment operations, nested streams, and station
command bytecode.

The repository is structured for Fenrir/ClusterFuzzLite submission:

- first-party Rust source lives under `src/`
- cargo-fuzz targets live under `fuzz/fuzz_targets/`
- seed inputs live under `fuzz/corpus/`
- `.clusterfuzzlite/build.sh` builds all harnesses into `$OUT` without network access

The crate intentionally uses no third-party runtime dependencies. The fuzz crate
uses a local `libfuzzer-sys` shim so `cargo rustc --offline --locked` does not
fetch crates.
