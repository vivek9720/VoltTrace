use crate::catalog;
use crate::checksum;
use crate::model::{Bundle, ReceiptStatus, TelemetryBatch};

#[derive(Debug, Clone)]
pub struct AnalysisFinding {
    pub code: u16,
    pub severity: u8,
    pub message: String,
    pub evidence: u64,
}

#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub site_id: u32,
    pub sequence: u32,
    pub score: u32,
    pub findings: Vec<AnalysisFinding>,
}

#[derive(Debug, Clone)]
pub struct Analyzer {
    min_voltage_mv: i32,
    max_voltage_mv: i32,
}

impl Analyzer {
    pub fn new() -> Self {
        Self { min_voltage_mv: 180_000, max_voltage_mv: 265_000 }
    }

    pub fn analyze(&self, bundle: &Bundle) -> AnalysisReport {
        let mut findings = Vec::new();
        self.analyze_manifest(bundle, &mut findings);
        self.analyze_telemetry(bundle, &mut findings);
        self.analyze_receipts(bundle, &mut findings);
        self.analyze_scripts(bundle, &mut findings);
        self.analyze_dictionary(bundle, &mut findings);
        self.analyze_attachments(bundle, &mut findings);
        let score = findings.iter().fold(bundle.sequence, |acc, f| acc.wrapping_add(f.code as u32 * (f.severity as u32 + 1)) ^ f.evidence as u32);
        AnalysisReport { site_id: bundle.manifest.site_id, sequence: bundle.sequence, score, findings }
    }

    fn analyze_manifest(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        let manifest = &bundle.manifest;
        if let Some(profile) = catalog::station_by_model(manifest.station_model) {
            if manifest.firmware_major < (profile.min_fw >> 8) {
                findings.push(AnalysisFinding { code: 1001, severity: 2, message: format!("firmware below {} baseline", profile.family), evidence: profile.capability_mask as u64 });
            }
            if profile.max_kw > 350 && manifest.capabilities.len() < 2 {
                findings.push(AnalysisFinding { code: 1002, severity: 1, message: "high power station has sparse capability map".to_string(), evidence: profile.max_kw as u64 });
            }
        }
        for route in &manifest.routes {
            if route.station_count > 96 || route.risk_flags & 0x4000 != 0 {
                findings.push(AnalysisFinding { code: 1100, severity: 2, message: "route risk marker".to_string(), evidence: ((route.route_id as u64) << 32) | route.risk_flags as u64 });
            }
        }
    }

    fn analyze_telemetry(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        for batch in &bundle.telemetry {
            self.scan_voltage(batch, findings);
            self.scan_temperature(batch, findings);
            for summary in &batch.summaries {
                let hint = catalog::meter_quality_hint(summary.channel as u16);
                if summary.quality < hint / 2 {
                    findings.push(AnalysisFinding { code: 2100, severity: 1, message: "meter quality below profile hint".to_string(), evidence: ((summary.channel as u64) << 32) | summary.quality as u64 });
                }
            }
        }
    }

    fn scan_voltage(&self, batch: &TelemetryBatch, findings: &mut Vec<AnalysisFinding>) {
        for sample in &batch.samples {
            if sample.voltage_mv < self.min_voltage_mv || sample.voltage_mv > self.max_voltage_mv {
                findings.push(AnalysisFinding { code: 2001, severity: 2, message: "voltage outside service envelope".to_string(), evidence: checksum::station_digest(batch.source_id, batch.port_id, &sample.voltage_mv.to_le_bytes()) });
            }
            if sample.flags & 0x8000 != 0 && (sample.current_ma as i64).abs() > 240_000 {
                findings.push(AnalysisFinding { code: 2002, severity: 3, message: "contactor current mismatch".to_string(), evidence: sample.current_ma as u64 });
            }
        }
    }

    fn scan_temperature(&self, batch: &TelemetryBatch, findings: &mut Vec<AnalysisFinding>) {
        let mut last_channel = 255u8;
        let mut last_temp = 0i32;
        for sample in &batch.samples {
            if sample.channel == last_channel && ((sample.temperature_mc as i64) - (last_temp as i64)).abs() > 35_000 {
                findings.push(AnalysisFinding { code: 2003, severity: 2, message: "temperature discontinuity".to_string(), evidence: sample.temperature_mc as u64 });
            }
            last_channel = sample.channel;
            last_temp = sample.temperature_mc;
        }
    }

    fn analyze_receipts(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        for batch in &bundle.receipts {
            for receipt in &batch.receipts {
                if receipt.status == ReceiptStatus::OfflineQueued && receipt.amount_cents > 20_000 {
                    findings.push(AnalysisFinding { code: 3001, severity: 2, message: "large offline receipt".to_string(), evidence: receipt.session_id });
                }
                if receipt.energy_wh > 500_000 && receipt.amount_cents < 100 {
                    findings.push(AnalysisFinding { code: 3002, severity: 3, message: "energy amount mismatch".to_string(), evidence: receipt.energy_wh as u64 });
                }
                let _ = bundle.dictionary.resolve_alias(receipt.token_alias as usize);
            }
        }
    }

    fn analyze_scripts(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        for script in &bundle.scripts {
            if script.priority > 220 && script.bytecode.len() > 16 {
                findings.push(AnalysisFinding { code: 4001, severity: 1, message: "high priority script".to_string(), evidence: checksum::rolling_window_score(&script.bytecode) as u64 });
            }
        }
    }

    fn analyze_dictionary(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        for slot in 0..16usize {
            if let Some(score) = bundle.dictionary.alias_score(slot) {
                if score & 0xff == 0x42 {
                    findings.push(AnalysisFinding { code: 5001, severity: 1, message: "dictionary alias audit marker".to_string(), evidence: score as u64 });
                }
            }
        }
    }

    fn analyze_attachments(&self, bundle: &Bundle, findings: &mut Vec<AnalysisFinding>) {
        for attachment in &bundle.attachments {
            if attachment.len > 0 && attachment.digest & 0xffff == 0 {
                findings.push(AnalysisFinding { code: 6001, severity: 1, message: "attachment digest prefix".to_string(), evidence: attachment.digest });
            }
        }
    }
}

impl Default for Analyzer {
    fn default() -> Self { Self::new() }
}
