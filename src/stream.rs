use crate::arena::AttachmentArena;
use crate::bundle::BundleDecoder;
use crate::cursor::ByteCursor;
use crate::dictionary::Dictionary;
use crate::error::Result;
use crate::manifest;
use crate::model::{Bundle, Compression, ScriptBundle};
use crate::{receipt, script, telemetry};

#[derive(Debug, Clone)]
pub struct StreamDecoder {
    state: StreamState,
    pending: Vec<u8>,
}

#[derive(Debug, Clone)]
struct StreamState {
    version: u8,
    flags: u8,
    sequence: u32,
    dictionary: Dictionary,
    arena: AttachmentArena,
    bundle: Bundle,
    frame_counter: u32,
}

impl StreamDecoder {
    pub fn new() -> Self {
        let bundle = Bundle::new(1, 0, 0);
        Self { state: StreamState { version: 1, flags: 0, sequence: 0, dictionary: Dictionary::new(), arena: AttachmentArena::new(), bundle, frame_counter: 0 }, pending: Vec::new() }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        self.pending.extend_from_slice(data);
        loop {
            if self.pending.len() < 4 {
                return Ok(());
            }
            let kind = self.pending[0];
            let flags = self.pending[1];
            let len = u16::from_le_bytes([self.pending[2], self.pending[3]]) as usize;
            if self.pending.len() < 4 + len {
                return Ok(());
            }
            let frame = self.pending[4..4 + len].to_vec();
            self.pending.drain(0..4 + len);
            self.process_frame(kind, flags, &frame)?;
        }
    }

    pub fn finish(mut self) -> Result<Bundle> {
        self.state.bundle.dictionary = self.state.dictionary.clone();
        Ok(self.state.bundle)
    }

    fn process_frame(&mut self, kind: u8, flags: u8, frame: &[u8]) -> Result<()> {
        self.state.frame_counter = self.state.frame_counter.wrapping_add(1);
        match kind {
            0x01 => self.process_hello(frame),
            0x02 => self.state.dictionary.parse_ops(frame),
            0x03 => {
                let compression = Compression::from_flags(flags);
                let batch = telemetry::parse_telemetry(frame, compression, &mut self.state.dictionary)?;
                self.state.bundle.telemetry.push(batch);
                Ok(())
            }
            0x04 => {
                let receipts = receipt::parse_receipts(frame, &mut self.state.dictionary)?;
                self.state.bundle.receipts.push(receipts);
                Ok(())
            }
            0x05 => self.state.arena.parse_ops(frame),
            0x06 => self.process_script(frame),
            0x07 => self.process_nested_bundle(frame),
            0x08 => {
                self.state.bundle.manifest = manifest::parse_manifest(frame, &mut self.state.dictionary)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn process_hello(&mut self, frame: &[u8]) -> Result<()> {
        let mut cur = ByteCursor::new(frame, "stream hello");
        if cur.remaining() >= 6 {
            self.state.version = cur.read_u8()?;
            self.state.flags = cur.read_u8()?;
            self.state.sequence = cur.read_u32()?;
            self.state.bundle.version = self.state.version;
            self.state.bundle.flags = self.state.flags;
            self.state.bundle.sequence = self.state.sequence;
        }
        Ok(())
    }

    fn process_script(&mut self, frame: &[u8]) -> Result<()> {
        let report = script::compile_and_run(frame)?;
        self.state.bundle.scripts.push(ScriptBundle { script_id: report.script_id, priority: (report.steps & 0xff) as u8, bytecode: frame.to_vec() });
        Ok(())
    }

    fn process_nested_bundle(&mut self, frame: &[u8]) -> Result<()> {
        let nested = BundleDecoder::new().parse(frame)?;
        self.state.bundle.telemetry.extend(nested.telemetry);
        self.state.bundle.receipts.extend(nested.receipts);
        self.state.bundle.scripts.extend(nested.scripts);
        Ok(())
    }
}

impl Default for StreamDecoder {
    fn default() -> Self { Self::new() }
}
