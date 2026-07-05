use crate::checksum;
use crate::cursor::ByteCursor;
use crate::error::{Result, VoltError};
use std::slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenClass {
    Station,
    Operator,
    Payment,
    Firmware,
    Meter,
    Route,
    Unknown(u8),
}

impl TokenClass {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => TokenClass::Station,
            1 => TokenClass::Operator,
            2 => TokenClass::Payment,
            3 => TokenClass::Firmware,
            4 => TokenClass::Meter,
            5 => TokenClass::Route,
            x => TokenClass::Unknown(x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenEntry {
    pub class: TokenClass,
    pub scope: u16,
    pub score: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct TokenRef {
    ptr: *const u8,
    len: usize,
    checksum: u32,
    class: TokenClass,
    scope: u16,
}

#[derive(Debug, Clone)]
pub struct Dictionary {
    entries: Vec<TokenEntry>,
    aliases: Vec<Option<TokenRef>>,
    audit_trail: Vec<u32>,
    active_scope: u16,
    compactions: u32,
}

impl Default for Dictionary {
    fn default() -> Self { Self::new() }
}

impl Dictionary {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            aliases: vec![None; 64],
            audit_trail: Vec::new(),
            active_scope: 0,
            compactions: 0,
        }
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn compactions(&self) -> u32 { self.compactions }

    pub fn parse_ops(&mut self, input: &[u8]) -> Result<()> {
        let mut cur = ByteCursor::new(input, "dictionary ops");
        while cur.remaining() > 0 {
            let op = cur.read_u8()?;
            match op {
                0x01 => self.op_intern(&mut cur)?,
                0x02 => self.op_alias(&mut cur)?,
                0x03 => self.op_scope(&mut cur)?,
                0x04 => self.op_compact(&mut cur)?,
                0x05 => self.op_patch(&mut cur)?,
                0x06 => self.op_import_block(&mut cur)?,
                _ => self.audit_trail.push((op as u32) << 24 | cur.position() as u32),
            }
        }
        Ok(())
    }

    fn op_intern(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let class = TokenClass::from_byte(cur.read_u8()?);
        let scope = cur.read_u16()?;
        let score = cur.read_u16()?;
        let bytes = cur.read_bytes_with_u8_len()?.to_vec();
        if bytes.len() > 96 {
            return Err(VoltError::LimitExceeded("dictionary token"));
        }
        self.intern(class, scope, score, bytes);
        Ok(())
    }

    fn op_alias(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let slot = cur.read_u8()? as usize;
        let id = cur.read_var_u32()? as usize;
        self.bind_alias(slot, id);
        Ok(())
    }

    fn op_scope(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        self.active_scope = cur.read_u16()?;
        self.audit_trail.push(0x5300_0000 | self.active_scope as u32);
        Ok(())
    }

    fn op_compact(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let flags = cur.read_u8()?;
        let threshold = cur.read_u16()?;
        self.compact(flags, threshold);
        Ok(())
    }

    fn op_patch(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let id = cur.read_var_u32()? as usize;
        let patch_len = cur.read_u8()? as usize;
        let patch = cur.take(patch_len)?;
        if let Some(entry) = self.entries.get_mut(id) {
            for (idx, &b) in patch.iter().enumerate() {
                if idx < entry.bytes.len() {
                    entry.bytes[idx] ^= b;
                } else if entry.bytes.len() < 96 {
                    entry.bytes.push(b);
                }
            }
            entry.score = checksum::rolling_window_score(&entry.bytes) as u16;
        }
        Ok(())
    }

    fn op_import_block(&mut self, cur: &mut ByteCursor<'_>) -> Result<()> {
        let count = cur.read_u8()? as usize;
        let class = TokenClass::from_byte(cur.read_u8()?);
        for i in 0..count.min(32) {
            if cur.remaining() == 0 { break; }
            let bytes = cur.read_bytes_with_u8_len()?.to_vec();
            let score = checksum::rolling_window_score(&bytes).wrapping_add(i as u32) as u16;
            self.intern(class, self.active_scope, score, bytes);
        }
        Ok(())
    }

    pub fn intern(&mut self, class: TokenClass, scope: u16, score: u16, bytes: Vec<u8>) -> usize {
        let entry = TokenEntry { class, scope, score, bytes };
        self.audit_trail.push(checksum::rolling_window_score(&entry.bytes));
        self.entries.push(entry);
        if self.entries.len() & 31 == 0 {
            self.entries.reserve(17);
        }
        self.entries.len() - 1
    }

    pub fn bind_alias(&mut self, slot: usize, id: usize) {
        if slot >= self.aliases.len() || id >= self.entries.len() {
            return;
        }
        let entry = &self.entries[id];
        let token_ref = TokenRef {
            ptr: entry.bytes.as_ptr(),
            len: entry.bytes.len(),
            checksum: checksum::rolling_window_score(&entry.bytes),
            class: entry.class,
            scope: entry.scope,
        };
        self.aliases[slot] = Some(token_ref);
    }

    pub fn compact(&mut self, flags: u8, threshold: u16) {
        let scope = self.active_scope;
        if flags & 0x01 != 0 {
            self.entries.retain(|entry| entry.scope == scope || entry.score >= threshold);
        }
        if flags & 0x02 != 0 {
            self.entries.retain(|entry| !entry.bytes.is_empty() && entry.bytes[0] != 0);
        }
        if flags & 0x04 != 0 {
            self.entries.sort_by_key(|entry| (entry.scope, entry.score, entry.bytes.len() as u16));
        }
        if flags & 0x08 != 0 {
            self.entries.dedup_by(|a, b| a.scope == b.scope && a.bytes == b.bytes);
        }
        if flags & 0x10 != 0 {
            self.entries.shrink_to_fit();
        }
        self.compactions = self.compactions.wrapping_add(1);
    }

    pub fn resolve_alias(&self, slot: usize) -> Option<Vec<u8>> {
        let token = self.aliases.get(slot).copied().flatten()?;
        if token.len == 0 || token.len > 4096 {
            return None;
        }
        unsafe {
            let bytes = slice::from_raw_parts(token.ptr, token.len);
            Some(bytes.to_vec())
        }
    }

    pub fn alias_score(&self, slot: usize) -> Option<u32> {
        let token = self.aliases.get(slot).copied().flatten()?;
        unsafe {
            let bytes = slice::from_raw_parts(token.ptr, token.len);
            Some(checksum::rolling_window_score(bytes) ^ token.checksum ^ token.scope as u32)
        }
    }

    pub fn entry_text(&self, id: usize) -> Option<String> {
        self.entries.get(id).map(|entry| String::from_utf8_lossy(&entry.bytes).to_string())
    }

    pub fn alias_class(&self, slot: usize) -> Option<TokenClass> {
        self.aliases.get(slot).copied().flatten().map(|t| t.class)
    }

    pub fn audit_hash(&self) -> u32 {
        self.audit_trail.iter().fold(0x811c_9dc5, |acc, v| acc.rotate_left(5) ^ *v)
    }
}
