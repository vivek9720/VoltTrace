use crate::catalog;
use crate::cursor::ByteCursor;
use crate::dictionary::{Dictionary, TokenClass};
use crate::error::{Result, VoltError};
use crate::model::{CapabilityRecord, Manifest, OperatorRecord, RouteRecord};

pub fn parse_manifest(input: &[u8], dictionary: &mut Dictionary) -> Result<Manifest> {
    let mut cur = ByteCursor::new(input, "manifest");
    let mut manifest = Manifest::default();
    if cur.remaining() < 14 {
        return parse_text_manifest(input, dictionary);
    }
    manifest.site_id = cur.read_u32()?;
    manifest.station_model = cur.read_u16()?;
    manifest.firmware_major = cur.read_u16()?;
    manifest.firmware_minor = cur.read_u16()?;
    manifest.policy_epoch = cur.read_u32()?;
    while cur.remaining() > 0 {
        let tag = cur.read_u8()?;
        let len = cur.read_u16()? as usize;
        let body = cur.take(len.min(cur.remaining()))?;
        match tag {
            0x20 => parse_operator_records(body, &mut manifest, dictionary)?,
            0x21 => parse_route_records(body, &mut manifest)?,
            0x22 => parse_capability_records(body, &mut manifest, dictionary)?,
            0x23 => dictionary.parse_ops(body)?,
            _ => record_unknown_manifest_tag(tag, body, dictionary),
        }
    }
    enrich_manifest(&mut manifest);
    Ok(manifest)
}

fn parse_text_manifest(input: &[u8], dictionary: &mut Dictionary) -> Result<Manifest> {
    let text = core::str::from_utf8(input).map_err(|_| VoltError::InvalidUtf8)?;
    let mut manifest = Manifest::default();
    for line in text.lines() {
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        match key {
            "site" => manifest.site_id = parse_u32(value),
            "model" => manifest.station_model = parse_u16(value),
            "fw_major" => manifest.firmware_major = parse_u16(value),
            "fw_minor" => manifest.firmware_minor = parse_u16(value),
            "epoch" => manifest.policy_epoch = parse_u32(value),
            "operator" => {
                let id = parse_u32(value);
                manifest.operators.push(OperatorRecord { operator_id: id, region: 0, name: value.to_string(), trust_tier: 1 });
                dictionary.intern(TokenClass::Operator, 0, id as u16, value.as_bytes().to_vec());
            }
            _ if !key.is_empty() => {
                dictionary.intern(TokenClass::Station, 0, key.len() as u16, value.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    enrich_manifest(&mut manifest);
    Ok(manifest)
}

fn parse_operator_records(input: &[u8], manifest: &mut Manifest, dictionary: &mut Dictionary) -> Result<()> {
    let mut cur = ByteCursor::new(input, "manifest operators");
    while cur.remaining() >= 8 {
        let operator_id = cur.read_u32()?;
        let region = cur.read_u16()?;
        let trust_tier = cur.read_u8()?;
        let name_bytes = cur.read_bytes_with_u8_len()?;
        let name = String::from_utf8_lossy(name_bytes).to_string();
        dictionary.intern(TokenClass::Operator, region, trust_tier as u16, name_bytes.to_vec());
        manifest.operators.push(OperatorRecord { operator_id, region, name, trust_tier });
    }
    Ok(())
}

fn parse_route_records(input: &[u8], manifest: &mut Manifest) -> Result<()> {
    let mut cur = ByteCursor::new(input, "manifest routes");
    while cur.remaining() >= 12 {
        let route_id = cur.read_u16()?;
        let feeder_id = cur.read_u16()?;
        let transformer_id = cur.read_u32()?;
        let station_count = cur.read_u16()?;
        let risk_flags = cur.read_u16()?;
        manifest.routes.push(RouteRecord { route_id, feeder_id, transformer_id, station_count, risk_flags });
    }
    Ok(())
}

fn parse_capability_records(input: &[u8], manifest: &mut Manifest, dictionary: &mut Dictionary) -> Result<()> {
    let mut cur = ByteCursor::new(input, "manifest capabilities");
    while cur.remaining() >= 7 {
        let code = cur.read_u16()?;
        let min_fw = cur.read_u16()?;
        let flags = cur.read_u16()?;
        let description_bytes = cur.read_bytes_with_u8_len()?;
        let description = String::from_utf8_lossy(description_bytes).to_string();
        dictionary.intern(TokenClass::Firmware, min_fw, flags, description_bytes.to_vec());
        manifest.capabilities.push(CapabilityRecord { code, min_fw, flags, description });
    }
    Ok(())
}

fn record_unknown_manifest_tag(tag: u8, body: &[u8], dictionary: &mut Dictionary) {
    let scope = ((tag as u16) << 8) | body.len() as u16;
    let score = crate::checksum::rolling_window_score(body) as u16;
    dictionary.intern(TokenClass::Unknown(tag), scope, score, body.iter().copied().take(64).collect());
}

fn enrich_manifest(manifest: &mut Manifest) {
    if manifest.station_model == 0 {
        manifest.station_model = 0x1001;
    }
    if manifest.firmware_major == 0 {
        manifest.firmware_major = 1;
    }
    if let Some(profile) = catalog::station_by_model(manifest.station_model) {
        if manifest.capabilities.is_empty() {
            for cap in profile.capability_mask.trailing_zeros()..profile.capability_mask.count_ones().saturating_add(4) {
                let code = 0x3000 + cap as u16;
                manifest.capabilities.push(CapabilityRecord {
                    code,
                    min_fw: profile.min_fw,
                    flags: (profile.capability_mask as u16) ^ code,
                    description: format!("{} capability {}", profile.family, code),
                });
            }
        }
    }
}

fn parse_u32(s: &str) -> u32 { s.parse::<u32>().unwrap_or(0) }
fn parse_u16(s: &str) -> u16 { s.parse::<u16>().unwrap_or(0) }
