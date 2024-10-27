#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsOpcode {
    Query = 0,
    Status = 2,
    Notify = 4,
}

impl DnsOpcode {
    pub fn from_u8(value: u8) -> Result<Self, HeaderParseError> {
        match value {
            0 => Ok(DnsOpcode::Query),
            2 => Ok(DnsOpcode::Status),
            4 => Ok(DnsOpcode::Notify),
            _ => Err(HeaderParseError::InvalidOpcode),
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsRcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl DnsRcode {
    pub fn from_u8(value: u8) -> Result<Self, HeaderParseError> {
        match value {
            0 => Ok(DnsRcode::NoError),
            1 => Ok(DnsRcode::FormatError),
            2 => Ok(DnsRcode::ServerFailure),
            3 => Ok(DnsRcode::NameError),
            4 => Ok(DnsRcode::NotImplemented),
            5 => Ok(DnsRcode::Refused),
            _ => Err(HeaderParseError::InvalidRcode),
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Flags {
    qr: bool,
    opcode: DnsOpcode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: DnsRcode,
}

impl Flags {
    pub fn from_u16(value: u16) -> Result<Self, HeaderParseError> {
        Ok(Flags {
            qr: value & 0x8000 != 0,
            opcode: DnsOpcode::from_u8(((value >> 11) & 0xF) as u8)?,
            aa: value & 0x0400 != 0,
            tc: value & 0x0200 != 0,
            rd: value & 0x0100 != 0,
            ra: value & 0x0080 != 0,
            rcode: DnsRcode::from_u8((value & 0x000F) as u8)?,
        })
    }
}
#[derive(Debug)]
pub(crate) struct QuestionCount(u16);
#[derive(Debug)]
pub(crate) struct AnswerCount(u16);
#[derive(Debug)]
pub(crate) struct AuthorityCount(u16);
#[derive(Debug)]
pub(crate) struct AdditionalCount(u16);

#[derive(Debug)]
pub(crate) struct DnsHeader {
    transaction_id: u16,
    flags: Flags,
    question_count: QuestionCount,
    answer_count: AnswerCount,
    authority_count: AuthorityCount,
    additional_count: AdditionalCount,
}

#[derive(Debug)]
pub enum HeaderParseError {
    InvalidOpcode,
    InvalidRcode,
    InvalidPacketLength,
}

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        Ok(DnsHeader {
            transaction_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: Flags::from_u16(u16::from_be_bytes([bytes[2], bytes[3]]))?,
            question_count: QuestionCount(u16::from_be_bytes([bytes[4], bytes[5]])),
            answer_count: AnswerCount(u16::from_be_bytes([bytes[6], bytes[7]])),
            authority_count: AuthorityCount(u16::from_be_bytes([bytes[8], bytes[9]])),
            additional_count: AdditionalCount(u16::from_be_bytes([bytes[10], bytes[11]])),
        })
    }
}
