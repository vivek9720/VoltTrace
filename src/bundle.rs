use crate::arena::AttachmentArena;
use crate::checksum;
use crate::cursor::ByteCursor;
use crate::error::{Result, VoltError};
use crate::manifest;
use crate::model::{AttachmentRecord, Bundle, Compression, ScriptBundle, SectionKind};
use crate::{receipt, script, telemetry};

const MAGIC: &[u8; 4] = b"VTRC";

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub kind: SectionKind,
    pub flags: u8,
    pub id: u16,
    pub length: u32,
    pub checksum: u32,
}

#[derive(Debug, Clone)]
pub struct BundleDecoder {
    max_sections: usize,
    max_section_size: usize,
}

impl BundleDecoder {
    pub fn new() -> Self {
        Self { max_sections: 128, max_section_size: 1 << 20 }
    }

    pub fn parse(&self, data: &[u8]) -> Result<Bundle> {
        let mut cur = ByteCursor::new(data, "bundle");
        let magic = cur.take(4)?;
        if magic != &MAGIC[..] {
            return Err(VoltError::BadMagic);
        }
        let version = cur.read_u8()?;
        if version == 0 || version > 3 {
            return Err(VoltError::UnsupportedVersion(version));
        }
        let flags = cur.read_u8()?;
        let section_count = cur.read_u16()? as usize;
        let sequence = cur.read_u32()?;
        if section_count > self.max_sections {
            return Err(VoltError::LimitExceeded("section count"));
        }
        let mut bundle = Bundle::new(version, flags, sequence);
        let mut arena = AttachmentArena::new();
        for _ in 0..section_count {
            if cur.remaining() < 12 {
                break;
            }
            let header = self.read_section_header(&mut cur)?;
            if header.length as usize > self.max_section_size {
                return Err(VoltError::LimitExceeded("section size"));
            }
            let payload = cur.take((header.length as usize).min(cur.remaining()))?;
            if header.flags & 0x01 != 0 {
                let actual = checksum::crc32(payload);
                if actual != header.checksum {
                    return Err(VoltError::Checksum { expected: header.checksum, actual });
                }
            }
            self.dispatch_section(header, payload, &mut bundle, &mut arena)?;
            bundle.section_count += 1;
        }
        Ok(bundle)
    }

    fn read_section_header(&self, cur: &mut ByteCursor<'_>) -> Result<SectionHeader> {
        let kind = SectionKind::from_byte(cur.read_u8()?);
        let flags = cur.read_u8()?;
        let id = cur.read_u16()?;
        let length = cur.read_u32()?;
        let checksum = cur.read_u32()?;
        Ok(SectionHeader { kind, flags, id, length, checksum })
    }

    fn dispatch_section(&self, header: SectionHeader, payload: &[u8], bundle: &mut Bundle, arena: &mut AttachmentArena) -> Result<()> {
        match header.kind {
            SectionKind::Manifest => {
                bundle.manifest = manifest::parse_manifest(payload, &mut bundle.dictionary)?;
            }
            SectionKind::Dictionary => {
                bundle.dictionary.parse_ops(payload)?;
            }
            SectionKind::Telemetry => {
                let compression = Compression::from_flags(header.flags);
                let batch = telemetry::parse_telemetry(payload, compression, &mut bundle.dictionary)?;
                bundle.telemetry.push(batch);
            }
            SectionKind::Receipts => {
                let batch = receipt::parse_receipts(payload, &mut bundle.dictionary)?;
                bundle.receipts.push(batch);
            }
            SectionKind::Attachment => {
                arena.parse_ops(payload)?;
                for slot in 0..8 {
                    if let Some(digest) = arena.handle_digest(slot) {
                        bundle.attachments.push(AttachmentRecord {
                            attachment_id: header.id as u32 * 100 + slot as u32,
                            kind: arena.handle_kind(slot).map(|k| k.code()).unwrap_or(255),
                            digest,
                            len: arena.read_handle(slot).map(|v| v.len()).unwrap_or(0),
                        });
                    }
                }
            }
            SectionKind::Script => {
                let report = script::compile_and_run(payload)?;
                bundle.scripts.push(ScriptBundle { script_id: report.script_id ^ header.id as u32, priority: (report.checksum & 0xff) as u8, bytecode: payload.to_vec() });
            }
            SectionKind::Stream => {
                let mut decoder = crate::stream::StreamDecoder::new();
                decoder.feed(payload)?;
                let nested = decoder.finish()?;
                bundle.telemetry.extend(nested.telemetry);
                bundle.receipts.extend(nested.receipts);
                bundle.scripts.extend(nested.scripts);
            }
            SectionKind::Unknown(_) => {}
        }
        Ok(())
    }
}

impl Default for BundleDecoder {
    fn default() -> Self { Self::new() }
}
