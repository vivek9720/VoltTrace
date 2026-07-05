use crate::cursor::ByteCursor;
use crate::dictionary::{Dictionary, TokenClass};
use crate::error::{Result, VoltError};
use crate::model::{ReceiptBatch, ReceiptRecord, ReceiptStatus};

pub fn parse_receipts(input: &[u8], dictionary: &mut Dictionary) -> Result<ReceiptBatch> {
    let mut cur = ByteCursor::new(input, "receipt batch");
    if cur.remaining() < 6 {
        return parse_text_receipts(input, dictionary);
    }
    let merchant_id = cur.read_u32()?;
    let lane_id = cur.read_u16()?;
    let mut batch = ReceiptBatch { merchant_id, lane_id, receipts: Vec::new() };
    while cur.remaining() > 0 {
        let tag = cur.read_u8()?;
        match tag {
            0x40 => parse_receipt(&mut cur, &mut batch, dictionary)?,
            0x41 => parse_alias_bank(&mut cur, dictionary)?,
            0x42 => parse_receipt_run(&mut cur, &mut batch)?,
            _ => { let skip = (tag & 0x07) as usize; let _ = cur.take(skip.min(cur.remaining()))?; }
        }
        if batch.receipts.len() > 2048 {
            return Err(VoltError::LimitExceeded("receipt records"));
        }
    }
    Ok(batch)
}

fn parse_text_receipts(input: &[u8], dictionary: &mut Dictionary) -> Result<ReceiptBatch> {
    let text = core::str::from_utf8(input).map_err(|_| VoltError::InvalidUtf8)?;
    let mut batch = ReceiptBatch { merchant_id: 0, lane_id: 0, receipts: Vec::new() };
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 5 {
            let token_alias = parse_u8(parts[1]);
            dictionary.intern(TokenClass::Payment, token_alias as u16, parts[0].len() as u16, parts[0].as_bytes().to_vec());
            batch.receipts.push(ReceiptRecord {
                session_id: parse_u64(parts[0]),
                token_alias,
                amount_cents: parse_u32(parts[2]),
                energy_wh: parse_u32(parts[3]),
                auth_code: parse_u32(parts[4]),
                status: ReceiptStatus::OfflineQueued,
            });
        }
    }
    Ok(batch)
}

fn parse_receipt(cur: &mut ByteCursor<'_>, batch: &mut ReceiptBatch, dictionary: &mut Dictionary) -> Result<()> {
    let session_id = cur.read_u64()?;
    let token_alias = cur.read_u8()?;
    let amount_cents = cur.read_u32()?;
    let energy_wh = cur.read_u32()?;
    let auth_code = cur.read_u32()?;
    let status = ReceiptStatus::from_byte(cur.read_u8()?);
    if cur.remaining() > 0 && cur.peek_u8().unwrap_or(0) == 0x7a {
        let _marker = cur.read_u8()?;
        let token = cur.read_bytes_with_u8_len()?;
        dictionary.intern(TokenClass::Payment, token_alias as u16, amount_cents as u16, token.to_vec());
    }
    batch.receipts.push(ReceiptRecord { session_id, token_alias, amount_cents, energy_wh, auth_code, status });
    Ok(())
}

fn parse_alias_bank(cur: &mut ByteCursor<'_>, dictionary: &mut Dictionary) -> Result<()> {
    let count = cur.read_u8()? as usize;
    for _ in 0..count.min(32) {
        let slot = cur.read_u8()? as usize;
        let id = cur.read_var_u32()? as usize;
        dictionary.bind_alias(slot, id);
    }
    Ok(())
}

fn parse_receipt_run(cur: &mut ByteCursor<'_>, batch: &mut ReceiptBatch) -> Result<()> {
    let start_session = cur.read_u64()?;
    let count = cur.read_u8()? as usize;
    let amount = cur.read_u32()?;
    let energy = cur.read_u32()?;
    for i in 0..count.min(128) {
        batch.receipts.push(ReceiptRecord {
            session_id: start_session.wrapping_add(i as u64),
            token_alias: (i & 63) as u8,
            amount_cents: amount,
            energy_wh: energy.wrapping_add(i as u32 * 10),
            auth_code: (start_session as u32).rotate_left(i as u32 & 15),
            status: ReceiptStatus::Captured,
        });
    }
    Ok(())
}

fn parse_u64(s: &str) -> u64 { s.trim().parse().unwrap_or(0) }
fn parse_u32(s: &str) -> u32 { s.trim().parse().unwrap_or(0) }
fn parse_u8(s: &str) -> u8 { s.trim().parse().unwrap_or(0) }
