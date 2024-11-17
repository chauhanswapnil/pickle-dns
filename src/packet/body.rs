use log::debug;

use crate::errors::ParseError;
use crate::errors::QuestionParseError;
use crate::helpers::bytes_to_hex;
use crate::helpers::bytes_to_u16_array;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::usize;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsType {
    /// a host address record
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IPv6 address record
    AAAA = 28,
    /// a domain name pointer
    PTR = 12,
    /// a pseudo-record type needed to support EDNS.
    OPT = 41,
}

impl DnsType {
    pub fn from_u16(value: u16) -> Result<Self, QuestionParseError> {
        match value {
            1 => Ok(DnsType::A),
            2 => Ok(DnsType::NS),
            5 => Ok(DnsType::CNAME),
            6 => Ok(DnsType::SOA),
            15 => Ok(DnsType::MX),
            16 => Ok(DnsType::TXT),
            28 => Ok(DnsType::AAAA),
            12 => Ok(DnsType::PTR),
            41 => Ok(DnsType::OPT),
            _ => Err(QuestionParseError::UnsupportedType),
        }
    }
    pub fn from(value: &DnsRecordData) -> Self {
        match value {
            DnsRecordData::A(_) => DnsType::A,
            DnsRecordData::AAAA(_) => DnsType::AAAA,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DnsClass {
    /// internet
    IN = 1,
}

impl DnsClass {
    pub fn from_u16(value: u16) -> Result<Self, QuestionParseError> {
        match value {
            1 => Ok(DnsClass::IN),
            _ => Err(QuestionParseError::UnsupportedClass),
        }
    }
}

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct DnsQuestion {
    /// a domain name represented as a sequence of labels, where
    /// each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.
    name: String,
    /// a two octet code which specifies the type of the query.
    question_type: DnsType,
    /// a two octet code that specifies the class of the query.
    question_class: DnsClass,
}

type RecordTTL = u32;
type RecordDataLength = u16;

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct DnsResourceRecord {
    /// the name of the node to which this resource record pertains.
    name: String,
    /// two octets containing one of the RR TYPE codes.
    record_type: DnsType,
    /// two octets containing one of the RR CLASS codes.
    record_class: DnsClass,
    /// a 32 bit signed integer that specifies the time interval
    /// that the resource record may be cached before the source
    /// of the information should again be consulted.  Zero
    /// values are interpreted to mean that the RR can only be
    /// used for the transaction in progress, and should not be
    /// cached.  For example, SOA records are always distributed
    /// with a zero TTL to prohibit caching.  Zero values can
    /// also be used for extremely volatile data
    record_ttl: RecordTTL,
    /// an unsigned 16 bit integer that specifies the length in octets
    record_rdlength: RecordDataLength,
    /// a variable length string of octets that describes the resource.
    record_rdata: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
}

pub(crate) struct DnsPacketBodyParser<'a> {
    raw_body: &'a [u8],
    cursor: usize,
}

impl<'a> DnsPacketBodyParser<'a> {
    pub fn new(raw_body: &'a [u8]) -> Self {
        Self {
            raw_body,
            cursor: 0,
        }
    }

    /// Parses a domain name at the current cursor position and returns it as a string.
    fn parse_name(&mut self) -> Result<String, ParseError> {
        let mut labels = Vec::new();

        loop {
            if self.cursor >= self.raw_body.len() {
                return Err(ParseError::UnexpectedEndOfInput);
            }

            // The first octet of the name is the length of the label
            let length = self.raw_body[self.cursor] as usize;
            self.cursor += 1;

            if length == 0 {
                break;
            } else if length & 0b1100_0000 == 0b1100_0000 {
                // Handle name compression
                if self.cursor >= self.raw_body.len() {
                    return Err(ParseError::UnexpectedEndOfInput);
                }

                // Calculate the offset from the next byte and move to that position
                let offset =
                    (((length & 0b0011_1111) as u16) << 8) | self.raw_body[self.cursor] as u16;
                self.cursor += 1;

                // Parse the compressed name at the offset (recursively)
                let mut sub_parser = DnsPacketBodyParser::new(self.raw_body);
                sub_parser.cursor = offset as usize;
                let compressed_name = sub_parser.parse_name()?;
                labels.push(compressed_name);
                break;
            } else {
                // Read the label and move the cursor
                if self.cursor + length > self.raw_body.len() {
                    return Err(ParseError::UnexpectedEndOfInput);
                }
                let label = &self.raw_body[self.cursor..self.cursor + length];
                labels.push(String::from_utf8_lossy(label).to_string());
                self.cursor += length;
            }
        }

        Ok(labels.join("."))
    }

    pub fn parse_question(&mut self) -> Result<DnsQuestion, ParseError> {
        debug!(
            "\n Question as hex:\n{:?}\n",
            bytes_to_hex(&self.raw_body[self.cursor..self.cursor + 6])
        );
        // Parse the name first, which will move the cursor past the name section
        let name = self.parse_name()?;

        // Parse the next 4 bytes as question type and question class
        let u16_values = bytes_to_u16_array(&self.raw_body[self.cursor..self.cursor + 4])?;
        self.cursor += 4;

        debug!("Question as u16: {:?}\n", u16_values);
        Ok(DnsQuestion {
            name,
            question_type: DnsType::from_u16(u16_values[0])?,
            question_class: DnsClass::from_u16(u16_values[1])?,
        })
    }

    fn parse_ipv4(&mut self, raw_record_data: &[u8]) -> u32 {
        if raw_record_data.len() != 4 {
            panic!("Should never happen!");
        }
        // Combine four u8 values into a single u32
        let ip_as_u32: u32 = ((raw_record_data[0] as u32) << 24)
            | ((raw_record_data[1] as u32) << 16)
            | ((raw_record_data[2] as u32) << 8)
            | (raw_record_data[3] as u32);
        return ip_as_u32;
    }

    pub fn parse_resource_record(&mut self) -> Result<DnsResourceRecord, ParseError> {
        // Parse the name first, which will move the cursor past the name section
        let name = self.parse_name()?;
        // Parse the next 4 bytes as type and class
        let u16_values = bytes_to_u16_array(&self.raw_body[self.cursor..self.cursor + 4])?;
        self.cursor += 4;
        let record_type = DnsType::from_u16(u16_values[0])?;
        let record_class = DnsClass::from_u16(u16_values[1])?;

        // Parse the next 4 bytes as TTL
        let ttl_bytes = bytes_to_u16_array(&self.raw_body[self.cursor..self.cursor + 4])?;
        let record_ttl: RecordTTL = (ttl_bytes[0] as u32) << 16 | (ttl_bytes[1] as u32);
        self.cursor += 4;
        // Parse the next 2 bytes as Record Data Length
        let record_rdlength_bytes =
            bytes_to_u16_array(&self.raw_body[self.cursor..self.cursor + 2])?;
        self.cursor += 2;
        let record_rdlength: RecordDataLength = record_rdlength_bytes[0];
        // rest is record data
        let raw_record_data =
            &self.raw_body[self.cursor..self.cursor + usize::from(record_rdlength)];
        self.cursor += usize::from(record_rdlength);

        // parse according to record type
        let record_rdata = match record_type {
            DnsType::A => DnsRecordData::A(Ipv4Addr::from(self.parse_ipv4(raw_record_data))),
            _ => todo!("Unhandled record type {record_type:?}"),
        };

        Ok(DnsResourceRecord {
            name,
            record_type,
            record_class,
            record_ttl,
            record_rdlength,
            record_rdata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_valid_question() {
        let raw_body = [
            14, 115, 119, 97, 112, 110, 105, 108, 99, 104, 97, 117, 104, 97, 110, 3, 99, 111, 109,
            0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0,
        ];

        let mut body_parser = DnsPacketBodyParser::new(&raw_body);
        let question = body_parser.parse_question().unwrap();
        assert_eq!(question.question_type, DnsType::A);
        assert_eq!(question.question_class, DnsClass::IN);
        assert_eq!(question.name, "swapnilchauhan.com");
        assert_eq!(body_parser.cursor, 24);
    }

    #[test]
    fn test_bytes_to_u16_array() {
        let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let result = bytes_to_u16_array(&bytes).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0x1234);
        assert_eq!(result[1], 0x5678);

        let invalid_bytes: [u8; 3] = [0x12, 0x34, 0x56]; // Invalid length
        assert!(bytes_to_u16_array(&invalid_bytes).is_err());
    }
}
