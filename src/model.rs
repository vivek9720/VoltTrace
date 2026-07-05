use crate::dictionary::Dictionary;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Raw,
    Rle,
    BitBackref,
    DictionaryDelta,
}

impl Compression {
    pub fn from_flags(flags: u8) -> Self {
        match (flags >> 1) & 0x03 {
            1 => Compression::Rle,
            2 => Compression::BitBackref,
            3 => Compression::DictionaryDelta,
            _ => Compression::Raw,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Manifest,
    Dictionary,
    Telemetry,
    Receipts,
    Attachment,
    Script,
    Stream,
    Unknown(u8),
}

impl SectionKind {
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => SectionKind::Manifest,
            2 => SectionKind::Dictionary,
            3 => SectionKind::Telemetry,
            4 => SectionKind::Receipts,
            5 => SectionKind::Attachment,
            6 => SectionKind::Script,
            7 => SectionKind::Stream,
            x => SectionKind::Unknown(x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub version: u8,
    pub flags: u8,
    pub sequence: u32,
    pub manifest: Manifest,
    pub dictionary: Dictionary,
    pub telemetry: Vec<TelemetryBatch>,
    pub receipts: Vec<ReceiptBatch>,
    pub scripts: Vec<ScriptBundle>,
    pub attachments: Vec<AttachmentRecord>,
    pub section_count: usize,
}

impl Bundle {
    pub fn new(version: u8, flags: u8, sequence: u32) -> Self {
        Self {
            version,
            flags,
            sequence,
            manifest: Manifest::default(),
            dictionary: Dictionary::new(),
            telemetry: Vec::new(),
            receipts: Vec::new(),
            scripts: Vec::new(),
            attachments: Vec::new(),
            section_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub site_id: u32,
    pub station_model: u16,
    pub firmware_major: u16,
    pub firmware_minor: u16,
    pub policy_epoch: u32,
    pub operators: Vec<OperatorRecord>,
    pub routes: Vec<RouteRecord>,
    pub capabilities: Vec<CapabilityRecord>,
}

#[derive(Debug, Clone)]
pub struct OperatorRecord {
    pub operator_id: u32,
    pub region: u16,
    pub name: String,
    pub trust_tier: u8,
}

#[derive(Debug, Clone)]
pub struct RouteRecord {
    pub route_id: u16,
    pub feeder_id: u16,
    pub transformer_id: u32,
    pub station_count: u16,
    pub risk_flags: u16,
}

#[derive(Debug, Clone)]
pub struct CapabilityRecord {
    pub code: u16,
    pub min_fw: u16,
    pub flags: u16,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct TelemetryBatch {
    pub source_id: u32,
    pub port_id: u16,
    pub start_time: u64,
    pub samples: Vec<TelemetrySample>,
    pub summaries: Vec<MeterSummary>,
}

#[derive(Debug, Clone)]
pub struct TelemetrySample {
    pub delta_ms: u32,
    pub channel: u8,
    pub voltage_mv: i32,
    pub current_ma: i32,
    pub temperature_mc: i32,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct MeterSummary {
    pub channel: u8,
    pub min_value: i32,
    pub max_value: i32,
    pub mean_value: i32,
    pub quality: u16,
}

#[derive(Debug, Clone)]
pub struct ReceiptBatch {
    pub merchant_id: u32,
    pub lane_id: u16,
    pub receipts: Vec<ReceiptRecord>,
}

#[derive(Debug, Clone)]
pub struct ReceiptRecord {
    pub session_id: u64,
    pub token_alias: u8,
    pub amount_cents: u32,
    pub energy_wh: u32,
    pub auth_code: u32,
    pub status: ReceiptStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    Authorized,
    Captured,
    OfflineQueued,
    Reversed,
    Unknown(u8),
}

impl ReceiptStatus {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => ReceiptStatus::Authorized,
            1 => ReceiptStatus::Captured,
            2 => ReceiptStatus::OfflineQueued,
            3 => ReceiptStatus::Reversed,
            x => ReceiptStatus::Unknown(x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptBundle {
    pub script_id: u32,
    pub priority: u8,
    pub bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttachmentRecord {
    pub attachment_id: u32,
    pub kind: u8,
    pub digest: u64,
    pub len: usize,
}
