use crate::catalog;
use crate::codec;
use crate::cursor::ByteCursor;
use crate::dictionary::{Dictionary, TokenClass};
use crate::error::{Result, VoltError};
use crate::model::{Compression, MeterSummary, TelemetryBatch, TelemetrySample};

pub fn parse_telemetry(input: &[u8], compression: Compression, dictionary: &mut Dictionary) -> Result<TelemetryBatch> {
    let decoded = codec::decode_payload(compression, input)?;
    let mut cur = ByteCursor::new(&decoded, "telemetry batch");
    if cur.remaining() < 14 {
        return parse_line_telemetry(&decoded, dictionary);
    }
    let source_id = cur.read_u32()?;
    let port_id = cur.read_u16()?;
    let start_time = cur.read_u64()?;
    let mut batch = TelemetryBatch { source_id, port_id, start_time, samples: Vec::new(), summaries: Vec::new() };
    let mut last_voltage = 230_000i32;
    let mut last_current = 0i32;
    let mut last_temp = 25_000i32;
    while cur.remaining() > 0 {
        let tag = cur.read_u8()?;
        match tag {
            0x30 => parse_sample(&mut cur, &mut batch, &mut last_voltage, &mut last_current, &mut last_temp)?,
            0x31 => parse_summary(&mut cur, &mut batch)?,
            0x32 => parse_meter_dictionary(&mut cur, dictionary)?,
            0x33 => parse_sparse_samples(&mut cur, &mut batch)?,
            _ => { let skip = (tag & 0x0f) as usize; let _ = cur.take(skip.min(cur.remaining()))?; }
        }
        if batch.samples.len() > 4096 {
            return Err(VoltError::LimitExceeded("telemetry samples"));
        }
    }
    enrich_summaries(&mut batch);
    Ok(batch)
}

fn parse_line_telemetry(input: &[u8], dictionary: &mut Dictionary) -> Result<TelemetryBatch> {
    let text = core::str::from_utf8(input).map_err(|_| VoltError::InvalidUtf8)?;
    let mut batch = TelemetryBatch { source_id: 0, port_id: 0, start_time: 0, samples: Vec::new(), summaries: Vec::new() };
    for line in text.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 5 {
            let sample = TelemetrySample {
                delta_ms: parse_u32(parts[0]),
                channel: parse_u8(parts[1]),
                voltage_mv: parse_i32(parts[2]),
                current_ma: parse_i32(parts[3]),
                temperature_mc: parse_i32(parts[4]),
                flags: parts.get(5).map(|v| parse_u16(v)).unwrap_or(0),
            };
            dictionary.intern(TokenClass::Meter, sample.channel as u16, sample.flags, line.as_bytes().to_vec());
            batch.samples.push(sample);
        }
    }
    enrich_summaries(&mut batch);
    Ok(batch)
}

fn parse_sample(cur: &mut ByteCursor<'_>, batch: &mut TelemetryBatch, voltage: &mut i32, current: &mut i32, temp: &mut i32) -> Result<()> {
    let delta_ms = cur.read_var_u32()?;
    let channel = cur.read_u8()?;
    *voltage = voltage.wrapping_add(cur.read_var_i32()?);
    *current = current.wrapping_add(cur.read_var_i32()?);
    *temp = temp.wrapping_add(cur.read_var_i32()?);
    let flags = cur.read_u16()?;
    batch.samples.push(TelemetrySample { delta_ms, channel, voltage_mv: *voltage, current_ma: *current, temperature_mc: *temp, flags });
    Ok(())
}

fn parse_summary(cur: &mut ByteCursor<'_>, batch: &mut TelemetryBatch) -> Result<()> {
    let channel = cur.read_u8()?;
    let min_value = cur.read_i32()?;
    let max_value = cur.read_i32()?;
    let mean_value = cur.read_i32()?;
    let quality = cur.read_u16()?;
    batch.summaries.push(MeterSummary { channel, min_value, max_value, mean_value, quality });
    Ok(())
}

fn parse_meter_dictionary(cur: &mut ByteCursor<'_>, dictionary: &mut Dictionary) -> Result<()> {
    let count = cur.read_u8()? as usize;
    for _ in 0..count.min(24) {
        let channel = cur.read_u8()?;
        let label = cur.read_bytes_with_u8_len()?;
        dictionary.intern(TokenClass::Meter, channel as u16, label.len() as u16, label.to_vec());
    }
    Ok(())
}

fn parse_sparse_samples(cur: &mut ByteCursor<'_>, batch: &mut TelemetryBatch) -> Result<()> {
    let channel = cur.read_u8()?;
    let count = cur.read_u8()? as usize;
    let scale = cur.read_i16()? as i32;
    for idx in 0..count.min(64) {
        let packed = cur.read_i16()? as i32;
        batch.samples.push(TelemetrySample {
            delta_ms: (idx as u32) * 1000,
            channel,
            voltage_mv: 200_000i32.wrapping_add(packed.wrapping_mul(scale)),
            current_ma: packed.wrapping_mul(17),
            temperature_mc: 20_000i32.wrapping_add(packed.wrapping_mul(3)),
            flags: 0x40,
        });
    }
    Ok(())
}

fn enrich_summaries(batch: &mut TelemetryBatch) {
    if !batch.summaries.is_empty() || batch.samples.is_empty() {
        return;
    }
    for channel in 0..8u8 {
        let mut values = batch.samples.iter().filter(|s| s.channel == channel).map(|s| s.voltage_mv);
        if let Some(first) = values.next() {
            let mut min_value = first;
            let mut max_value = first;
            let mut total = first as i64;
            let mut count = 1i64;
            for v in values {
                min_value = min_value.min(v);
                max_value = max_value.max(v);
                total += v as i64;
                count += 1;
            }
            let profile_quality = catalog::meter_quality_hint(channel as u16).min(u16::MAX as u32) as u16;
            batch.summaries.push(MeterSummary { channel, min_value, max_value, mean_value: (total / count) as i32, quality: profile_quality });
        }
    }
}

fn parse_u32(s: &str) -> u32 { s.trim().parse().unwrap_or(0) }
fn parse_u16(s: &str) -> u16 { s.trim().parse().unwrap_or(0) }
fn parse_u8(s: &str) -> u8 { s.trim().parse().unwrap_or(0) }
fn parse_i32(s: &str) -> i32 { s.trim().parse().unwrap_or(0) }
