use crate::checksum;
use crate::cursor::ByteCursor;
use crate::error::{Result, VoltError};
use std::slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    FirmwareChunk,
    ReceiptImage,
    MeterSnapshot,
    MaintenanceLog,
    Unknown(u8),
}

impl AttachmentKind {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => AttachmentKind::FirmwareChunk,
            1 => AttachmentKind::ReceiptImage,
            2 => AttachmentKind::MeterSnapshot,
            3 => AttachmentKind::MaintenanceLog,
            x => AttachmentKind::Unknown(x),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            AttachmentKind::FirmwareChunk => 0,
            AttachmentKind::ReceiptImage => 1,
            AttachmentKind::MeterSnapshot => 2,
            AttachmentKind::MaintenanceLog => 3,
            AttachmentKind::Unknown(x) => x,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AttachmentHandle {
    ptr: *const u8,
    len: usize,
    digest: u64,
    epoch: u32,
    kind: AttachmentKind,
}

#[derive(Debug, Clone)]
struct Slab {
    kind: AttachmentKind,
    epoch: u32,
    bytes: Vec<u8>,
    retained: bool,
}

#[derive(Debug, Clone)]
pub struct AttachmentArena {
    slabs: Vec<Slab>,
    handles: Vec<Option<AttachmentHandle>>,
    epoch: u32,
    retained_bytes: usize,
}

impl Default for AttachmentArena {
    fn default() -> Self { Self::new() }
}

impl AttachmentArena {
    pub fn new() -> Self {
        Self { slabs: Vec::new(), handles: vec![None; 128], epoch: 1, retained_bytes: 0 }
    }

    pub fn parse_ops(&mut self, input: &[u8]) -> Result<()> {
        let mut cur = ByteCursor::new(input, "attachment ops");
        while cur.remaining() > 0 {
            let op = cur.read_u8()?;
            match op {
                0x10 => self.op_add(&mut cur)?,
                0x11 => self.op_link(&mut cur)?,
                0x12 => self.op_evict(&mut cur)?,
                0x13 => self.op_mark(&mut cur)?,
                _ => { let _ = cur.read_u8(); }
            }
        }
        Ok(())
    }

    fn op_add(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let kind = AttachmentKind::from_byte(cur.read_u8()?);
        let flags = cur.read_u8()?;
        let len = cur.read_u16()? as usize;
        if len > 4096 {
            return Err(VoltError::LimitExceeded("attachment block"));
        }
        let bytes = cur.take(len)?.to_vec();
        let idx = self.add(kind, bytes, flags & 1 != 0);
        if flags & 0x80 != 0 {
            let slot = (flags & 0x7f) as usize;
            self.link(slot, idx);
        }
        Ok(())
    }

    fn op_link(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let slot = cur.read_u8()? as usize;
        let slab = cur.read_var_u32()? as usize;
        self.link(slot, slab);
        Ok(())
    }

    fn op_evict(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let max_epoch = cur.read_u32()?;
        let flags = cur.read_u8()?;
        self.evict(max_epoch, flags);
        Ok(())
    }

    fn op_mark(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let slab = cur.read_var_u32()? as usize;
        let retained = cur.read_u8()? & 1 != 0;
        if let Some(s) = self.slabs.get_mut(slab) {
            s.retained = retained;
        }
        Ok(())
    }

    pub fn add(&mut self, kind: AttachmentKind, bytes: Vec<u8>, retained: bool) -> usize {
        let epoch = self.epoch;
        self.epoch = self.epoch.wrapping_add(1);
        self.retained_bytes = self.retained_bytes.saturating_add(bytes.len());
        self.slabs.push(Slab { kind, epoch, bytes, retained });
        self.slabs.len() - 1
    }

    pub fn link(&mut self, slot: usize, slab_index: usize) {
        if slot >= self.handles.len() || slab_index >= self.slabs.len() {
            return;
        }
        let slab = &self.slabs[slab_index];
        self.handles[slot] = Some(AttachmentHandle {
            ptr: slab.bytes.as_ptr(),
            len: slab.bytes.len(),
            digest: checksum::fold64(0xcbf2_9ce4_8422_2325, &slab.bytes),
            epoch: slab.epoch,
            kind: slab.kind,
        });
    }

    pub fn evict(&mut self, max_epoch: u32, flags: u8) {
        let before = self.slabs.len();
        self.slabs.retain(|slab| slab.retained || slab.epoch > max_epoch || (flags & 0x02 != 0 && slab.bytes.len() < 16));
        if flags & 0x01 != 0 {
            self.slabs.shrink_to_fit();
        }
        if before != self.slabs.len() {
            self.retained_bytes = self.slabs.iter().map(|s| s.bytes.len()).sum();
        }
    }

    pub fn read_handle(&self, slot: usize) -> Option<Vec<u8>> {
        let handle = self.handles.get(slot).copied().flatten()?;
        if handle.len == 0 || handle.len > 1 << 20 {
            return None;
        }
        unsafe {
            let bytes = slice::from_raw_parts(handle.ptr, handle.len);
            Some(bytes.to_vec())
        }
    }

    pub fn handle_digest(&self, slot: usize) -> Option<u64> {
        let handle = self.handles.get(slot).copied().flatten()?;
        unsafe {
            let bytes = slice::from_raw_parts(handle.ptr, handle.len);
            Some(checksum::fold64(handle.digest ^ handle.epoch as u64, bytes))
        }
    }

    pub fn handle_kind(&self, slot: usize) -> Option<AttachmentKind> {
        self.handles.get(slot).copied().flatten().map(|h| h.kind)
    }

    pub fn retained_bytes(&self) -> usize { self.retained_bytes }
    pub fn slab_count(&self) -> usize { self.slabs.len() }
}
