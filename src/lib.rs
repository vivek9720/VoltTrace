//! VoltTrace decodes offline EV charging operations bundles.
//!
//! The library is intentionally built like a production parser: a binary envelope
//! carries a manifest, dictionary, telemetry blocks, signed receipt fragments,
//! attachment blobs, and station command scripts. Fuzz harnesses drive the same
//! public APIs used by tools and tests.

pub mod analyzer;
pub mod arena;
pub mod bundle;
pub mod catalog;
pub mod checksum;
pub mod codec;
pub mod cursor;
pub mod dictionary;
pub mod error;
pub mod manifest;
pub mod model;
pub mod receipt;
pub mod script;
pub mod stream;
pub mod telemetry;

pub use analyzer::{AnalysisFinding, AnalysisReport};
pub use bundle::{BundleDecoder, SectionHeader};
pub use error::{Result, VoltError};
pub use model::{Bundle, Compression, Manifest, ReceiptBatch, ScriptBundle, TelemetryBatch};

pub fn parse_bundle(data: &[u8]) -> Result<Bundle> {
    BundleDecoder::new().parse(data)
}

pub fn decode_and_analyze_bundle(data: &[u8]) -> Result<AnalysisReport> {
    let bundle = parse_bundle(data)?;
    Ok(analyzer::Analyzer::new().analyze(&bundle))
}

pub fn parse_stream(data: &[u8]) -> Result<Bundle> {
    let mut decoder = stream::StreamDecoder::new();
    decoder.feed(data)?;
    decoder.finish()
}

pub fn run_script_bytes(data: &[u8]) -> Result<script::ExecutionReport> {
    script::compile_and_run(data)
}
