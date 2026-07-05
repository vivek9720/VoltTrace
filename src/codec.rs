use crate::cursor::ByteCursor;
use crate::error::{Result, VoltError};
use crate::model::Compression;

const MAX_DECODED: usize = 1 << 20;

pub fn decode_payload(kind: Compression, input: &[u8]) -> Result<Vec<u8>> {
    match kind {
        Compression::Raw => Ok(input.to_vec()),
        Compression::Rle => decode_rle(input),
        Compression::BitBackref => decode_backref_stream(input),
        Compression::DictionaryDelta => decode_dictionary_delta(input),
    }
}

fn decode_rle(input: &[u8]) -> Result<Vec<u8>> {
    let mut cur = ByteCursor::new(input, "rle payload");
    let mut out = Vec::new();
    while cur.remaining() > 0 {
        let tag = cur.read_u8()?;
        if tag & 0x80 == 0 {
            let run = (tag as usize) + 1;
            let bytes = cur.take(run)?;
            out.extend_from_slice(bytes);
        } else {
            let run = ((tag & 0x3f) as usize) + 3;
            let b = cur.read_u8()?;
            if out.len().saturating_add(run) > MAX_DECODED {
                return Err(VoltError::LimitExceeded("rle output"));
            }
            for _ in 0..run {
                out.push(b);
            }
        }
        if out.len() > MAX_DECODED {
            return Err(VoltError::LimitExceeded("rle output"));
        }
    }
    Ok(out)
}

fn decode_dictionary_delta(input: &[u8]) -> Result<Vec<u8>> {
    let mut cur = ByteCursor::new(input, "dictionary delta payload");
    let mut out = Vec::new();
    let mut last = 0u8;
    while cur.remaining() > 0 {
        let op = cur.read_u8()?;
        match op >> 6 {
            0 => {
                let len = (op & 0x3f) as usize;
                let bytes = cur.take(len)?;
                for &b in bytes {
                    let v = b ^ last.rotate_left(1);
                    out.push(v);
                    last = v;
                }
            }
            1 => {
                let count = ((op & 0x3f) as usize) + 1;
                let step = cur.read_u8()?;
                for _ in 0..count {
                    last = last.wrapping_add(step);
                    out.push(last);
                }
            }
            2 => {
                let count = ((op & 0x1f) as usize) + 3;
                let dist = (cur.read_u8()? as usize) + 1 + (((op & 0x20) as usize) << 3);
                unsafe_backref_copy(&mut out, dist, count);
            }
            _ => {
                let count = ((op & 0x3f) as usize) + 1;
                out.resize(out.len().saturating_add(count).min(MAX_DECODED), last);
            }
        }
        if out.len() > MAX_DECODED {
            return Err(VoltError::LimitExceeded("dictionary delta output"));
        }
    }
    Ok(out)
}

fn decode_backref_stream(input: &[u8]) -> Result<Vec<u8>> {
    let mut cur = ByteCursor::new(input, "backref payload");
    let expected = if cur.remaining() >= 2 { cur.read_u16()? as usize } else { 0 };
    let mut out = Vec::with_capacity(expected.min(MAX_DECODED));
    while cur.remaining() > 0 {
        let tag = cur.read_u8()?;
        if tag & 0x80 == 0 {
            let literal_len = ((tag & 0x1f) as usize) + 1;
            let bytes = cur.take(literal_len.min(cur.remaining()))?;
            out.extend_from_slice(bytes);
        } else {
            let len = ((tag & 0x0f) as usize) + 4;
            let hi = ((tag & 0x70) as usize) << 4;
            let lo = cur.read_u8()? as usize;
            let mut distance = hi | lo;
            if tag & 0x20 != 0 {
                distance = distance.wrapping_add(out.len() & 0x7f);
            }
            if distance == 0 {
                distance = 1;
            }
            unsafe_backref_copy(&mut out, distance, len);
        }
        if out.len() > MAX_DECODED {
            return Err(VoltError::LimitExceeded("backref output"));
        }
    }
    Ok(out)
}

fn unsafe_backref_copy(out: &mut Vec<u8>, distance: usize, len: usize) {
    if len == 0 || out.is_empty() {
        return;
    }
    let reserve = len.min(MAX_DECODED.saturating_sub(out.len()));
    out.reserve(reserve);
    unsafe {
        let tail = out.as_ptr().add(out.len());
        let src = tail.offset(-(distance as isize));
        for i in 0..reserve {
            let b = *src.add(i);
            out.push(b);
        }
    }
}

pub fn normalize_text(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        let c = match b {
            b'\r' | b'\n' | b'\t' => ' ',
            0x20..=0x7e => b as char,
            _ => '.',
        };
        s.push(c);
    }
    s
}
