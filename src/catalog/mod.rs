pub mod firmware;
pub mod meters;
pub mod rules;
pub mod stations;

#[derive(Debug, Clone, Copy)]
pub struct StationProfile {
    pub vendor_id: u16,
    pub model_id: u16,
    pub family: &'static str,
    pub max_kw: u16,
    pub min_fw: u16,
    pub capability_mask: u32,
    pub region: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct FirmwareProfile {
    pub vendor_id: u16,
    pub branch: u16,
    pub build_floor: u32,
    pub signing_policy: u16,
    pub notes: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct MeterProfile {
    pub channel: u16,
    pub phase: u8,
    pub scale_mv: i32,
    pub scale_ma: i32,
    pub quality_hint: u32,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct RuleProfile {
    pub rule_id: u16,
    pub severity: u8,
    pub subject: &'static str,
    pub threshold: i32,
    pub cooldown_ms: u32,
}

pub fn station_by_model(model_id: u16) -> Option<&'static StationProfile> {
    stations::STATION_PROFILES.iter().find(|p| p.model_id == model_id)
}

pub fn firmware_policy(vendor_id: u16, branch: u16) -> Option<&'static FirmwareProfile> {
    firmware::FIRMWARE_PROFILES.iter().find(|p| p.vendor_id == vendor_id && p.branch == branch)
}

pub fn meter_quality_hint(channel: u16) -> u32 {
    meters::METER_PROFILES.iter().find(|p| p.channel == channel).map(|p| p.quality_hint).unwrap_or(100)
}

pub fn rule_by_id(rule_id: u16) -> Option<&'static RuleProfile> {
    rules::RULE_PROFILES.iter().find(|p| p.rule_id == rule_id)
}
