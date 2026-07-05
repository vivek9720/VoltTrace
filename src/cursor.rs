use crate::error::{Result, VoltError};

#[derive(Clone)]
pub struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
    context: &'static str,
}

impl<'a> ByteCursor<'a> {
    pub fn new(data: &'a [u8], context: &'static str) -> Self {
        Self { data, pos: 0, context }
    }

    pub fn len(&self) -> usize { self.data.len() }
    pub fn position(&self) -> usize { self.pos }
    pub fn is_empty(&self) -> bool { self.remaining() == 0 }
    pub fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }
    pub fn context(&self) -> &'static str { self.context }

    pub fn set_context(&mut self, context: &'static str) { self.context = context; }

    pub fn peek_u8(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or(VoltError::Truncated {
            needed: 1,
            remaining: self.remaining(),
            context: self.context,
        })
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.peek_u8()?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_i8(&mut self) -> Result<i8> { Ok(self.read_u8()? as i8) }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        let bytes = self.take(2)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u24(&mut self) -> Result<u32> {
        let bytes = self.take(3)?;
        Ok((bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_var_u32(&mut self) -> Result<u32> {
        let mut shift = 0;
        let mut value = 0u32;
        for _ in 0..5 {
            let b = self.read_u8()?;
            value |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(VoltError::InvalidValue("varint too long"))
    }

    pub fn read_var_i32(&mut self) -> Result<i32> {
        let raw = self.read_var_u32()?;
        Ok(((raw >> 1) as i32) ^ (-((raw & 1) as i32)))
    }

    pub fn read_bytes_with_u8_len(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u8()? as usize;
        self.take(len)
    }

    pub fn read_bytes_with_u16_len(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u16()? as usize;
        self.take(len)
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(VoltError::Truncated { needed: len, remaining: self.remaining(), context: self.context });
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    pub fn take_remaining(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.data.len();
        &self.data[start..]
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len).map(|_| ())
    }

    pub fn fork(&self, len: usize, context: &'static str) -> Result<ByteCursor<'a>> {
        if self.remaining() < len {
            return Err(VoltError::Truncated { needed: len, remaining: self.remaining(), context: self.context });
        }
        Ok(ByteCursor::new(&self.data[self.pos..self.pos + len], context))
    }
}
