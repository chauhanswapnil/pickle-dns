use log::debug;

use crate::errors::ParseError;
use crate::errors::QuestionParseError;
use crate::helpers::bytes_to_hex;
use crate::helpers::bytes_to_u16_array;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
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
}

#[derive(Debug)]
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
#[derive(Debug)]
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
}
