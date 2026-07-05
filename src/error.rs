use core::fmt;

pub type Result<T> = core::result::Result<T, VoltError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoltError {
    BadMagic,
    UnsupportedVersion(u8),
    Truncated { needed: usize, remaining: usize, context: &'static str },
    InvalidSection(u8),
    InvalidValue(&'static str),
    InvalidUtf8,
    Checksum { expected: u32, actual: u32 },
    LimitExceeded(&'static str),
    Decode(&'static str),
    Script(&'static str),
}

impl fmt::Display for VoltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoltError::BadMagic => write!(f, "bad VoltTrace magic"),
            VoltError::UnsupportedVersion(v) => write!(f, "unsupported VoltTrace version {v}"),
            VoltError::Truncated { needed, remaining, context } => {
                write!(f, "truncated {context}: needed {needed}, remaining {remaining}")
            }
            VoltError::InvalidSection(s) => write!(f, "invalid section type {s}"),
            VoltError::InvalidValue(v) => write!(f, "invalid value: {v}"),
            VoltError::InvalidUtf8 => write!(f, "invalid utf-8"),
            VoltError::Checksum { expected, actual } => {
                write!(f, "checksum mismatch: expected {expected:#010x}, actual {actual:#010x}")
            }
            VoltError::LimitExceeded(v) => write!(f, "limit exceeded: {v}"),
            VoltError::Decode(v) => write!(f, "decode error: {v}"),
            VoltError::Script(v) => write!(f, "script error: {v}"),
        }
    }
}

impl std::error::Error for VoltError {}
