#![allow(dead_code)]

use log::debug;

use crate::helpers;

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
pub(crate) enum DnsResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl DnsResponseCode {
    pub fn from_u8(value: u8) -> Result<Self, HeaderParseError> {
        match value {
            0 => Ok(DnsResponseCode::NoError),
            1 => Ok(DnsResponseCode::FormatError),
            2 => Ok(DnsResponseCode::ServerFailure),
            3 => Ok(DnsResponseCode::NameError),
            4 => Ok(DnsResponseCode::NotImplemented),
            5 => Ok(DnsResponseCode::Refused),
            _ => Err(HeaderParseError::InvalidRcode),
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Flags {
    /// A one bit field that specifies whether this message is a
    /// query (0), or a response (1).
    is_response: bool,
    /// A four bit field that specifies kind of query in this
    /// message.  This value is set by the originator of a query
    /// and copied into the response.
    opcode: DnsOpcode,
    /// Authoritative Answer - this bit is valid in responses,
    /// and specifies that the responding name server is an
    /// authority for the domain name in question section.
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases.  The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    is_authorative_answer: bool,
    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    is_truncated: bool,
    /// Recursion Desired - this bit may be set in a query and
    /// is copied into the response.  If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    is_recursion_desired: bool,
    /// Recursion Available - this be is set or cleared in a
    /// response, and denotes whether recursive query support is
    /// available in the name server.
    is_recursion_enabled: bool,
    /// Response code - this 4 bit field is set as part of responses.
    response_code: DnsResponseCode,
}

impl Flags {
    pub fn from_u16(value: u16) -> Result<Self, HeaderParseError> {
        Ok(Flags {
            is_response: Self::is_response(value),
            opcode: Self::get_opcode(value)?,
            is_authorative_answer: Self::is_authoritative_answer(value),
            is_truncated: Self::is_truncated(value),
            is_recursion_desired: Self::is_recursion_desired(value),
            is_recursion_enabled: Self::is_recursion_enabled(value),
            response_code: Self::get_response_code(value)?,
        })
    }

    fn is_response(value: u16) -> bool {
        value & 0x8000 != 0
    }

    fn get_opcode(value: u16) -> Result<DnsOpcode, HeaderParseError> {
        let opcode = ((value >> 11) & 0xF) as u8;
        DnsOpcode::from_u8(opcode)
    }

    fn is_authoritative_answer(value: u16) -> bool {
        value & 0x0400 != 0
    }

    fn is_truncated(value: u16) -> bool {
        value & 0x0200 != 0
    }

    fn is_recursion_desired(value: u16) -> bool {
        value & 0x0100 != 0
    }

    fn is_recursion_enabled(value: u16) -> bool {
        value & 0x0080 != 0
    }

    fn get_response_code(value: u16) -> Result<DnsResponseCode, HeaderParseError> {
        let response_code = (value & 0x000F) as u8;
        DnsResponseCode::from_u8(response_code)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QuestionCount(u16);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AnswerCount(u16);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorityCount(u16);
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdditionalCount(u16);

/*
The header contains the following fields:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
/// The header section of a DNS message
#[derive(Debug)]
pub(crate) struct DnsHeader {
    /// A 16 bit identifier assigned by the program that
    /// generates any kind of query.  This identifier is copied
    /// the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries.
    transaction_id: u16,
    /// 16 bits containing various flags
    flags: Flags,
    /// An unsigned 16 bit integer specifying the number of
    /// entries in the question section.
    question_count: QuestionCount,
    /// An unsigned 16 bit integer specifying the number of
    /// resource records in the answer section.
    answer_count: AnswerCount,
    /// An unsigned 16 bit integer specifying the number of name
    /// server resource records in the authority records section.
    authority_count: AuthorityCount,
    /// An unsigned 16 bit integer specifying the number of
    /// resource records in the additional records section.
    additional_count: AdditionalCount,
}

#[derive(Debug)]
pub enum HeaderParseError {
    InvalidOpcode,
    InvalidRcode,
    InvalidPacketLength,
    InvalidLength,
}

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        debug!("\n Header as hex:\n{:?}\n", helpers::bytes_to_hex(bytes));
        let u16_values = Self::bytes_to_u16_array(bytes)?;

        Ok(DnsHeader {
            transaction_id: u16_values[0],
            flags: Flags::from_u16(u16_values[1])?,
            question_count: QuestionCount(u16_values[2]),
            answer_count: AnswerCount(u16_values[3]),
            authority_count: AuthorityCount(u16_values[4]),
            additional_count: AdditionalCount(u16_values[5]),
        })
    }

    fn bytes_to_u16_array(bytes: &[u8]) -> Result<Vec<u16>, HeaderParseError> {
        if bytes.len() % 2 != 0 || bytes.len() < 2 {
            return Err(HeaderParseError::InvalidLength);
        }
        let mut u16_array = Vec::with_capacity(bytes.len() / 2);

        for chunk in bytes.chunks(2) {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]);
            u16_array.push(value);
        }
        Ok(u16_array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_opcode_from_u8() {
        assert_eq!(DnsOpcode::from_u8(0).unwrap(), DnsOpcode::Query);
        assert_eq!(DnsOpcode::from_u8(2).unwrap(), DnsOpcode::Status);
        assert_eq!(DnsOpcode::from_u8(4).unwrap(), DnsOpcode::Notify);
        assert!(DnsOpcode::from_u8(1).is_err());
        assert!(DnsOpcode::from_u8(3).is_err());
        assert!(DnsOpcode::from_u8(5).is_err());
    }

    #[test]
    fn test_dns_response_code_from_u8() {
        assert_eq!(
            DnsResponseCode::from_u8(0).unwrap(),
            DnsResponseCode::NoError
        );
        assert_eq!(
            DnsResponseCode::from_u8(1).unwrap(),
            DnsResponseCode::FormatError
        );
        assert_eq!(
            DnsResponseCode::from_u8(2).unwrap(),
            DnsResponseCode::ServerFailure
        );
        assert_eq!(
            DnsResponseCode::from_u8(3).unwrap(),
            DnsResponseCode::NameError
        );
        assert_eq!(
            DnsResponseCode::from_u8(4).unwrap(),
            DnsResponseCode::NotImplemented
        );
        assert_eq!(
            DnsResponseCode::from_u8(5).unwrap(),
            DnsResponseCode::Refused
        );
        assert!(DnsResponseCode::from_u8(6).is_err());
        assert!(DnsResponseCode::from_u8(255).is_err());
    }

    #[test]
    fn test_flags_from_u16() {
        // Test for a valid response with no authoritative answer, no truncation,
        // recursion not desired and recursion not enabled, and no error code.
        let flags_value = 0b1000000000000000; // QR bit set, response
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.opcode, DnsOpcode::Query);
        assert!(!flags.is_authorative_answer);
        assert!(!flags.is_truncated);
        assert!(!flags.is_recursion_desired);
        assert!(!flags.is_recursion_enabled);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response with the NoError response code
        let flags_value = 0b1000000000000000; // QR bit set, response, with NoError
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response with authoritative answer flag set
        let flags_value = 0b1000010000100000; // QR + AA
        let flags = Flags::from_u16(flags_value).unwrap();
        assert_eq!(flags.opcode, DnsOpcode::Query);
        assert!(flags.is_response);
        assert!(flags.is_authorative_answer);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response that is truncated
        let flags_value = 0b1000001000000000; // QR + TC
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert!(flags.is_truncated);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response with recursion desired
        let flags_value = 0b1000000100000000; // QR + RD
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert!(flags.is_recursion_desired);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response with recursion available
        let flags_value = 0b1000000010000000; // QR + RA
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert!(flags.is_recursion_enabled);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a valid response with multiple flags set
        let flags_value = 0b1000010110000000; // QR + AA + RD + RA
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert!(flags.is_authorative_answer);
        assert!(flags.is_recursion_desired);
        assert!(flags.is_recursion_enabled);
        assert_eq!(flags.response_code, DnsResponseCode::NoError);

        // Test for a response with FormatError response code
        let flags_value = 0b1000000000000001; // QR + RCODE = FormatError
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::FormatError);

        // Test for a response with ServerFailure response code
        let flags_value = 0b1000000000000010; // QR + RCODE = ServerFailure
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::ServerFailure);

        // Test for a response with NameError response code
        let flags_value = 0b1000000000000011; // QR + RCODE = NameError
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::NameError);

        // Test for a response with NotImplemented response code
        let flags_value = 0b1000000000000100; // QR + RCODE = NotImplemented
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::NotImplemented);

        // Test for a response with Refused response code
        let flags_value = 0b1000000000000101; // QR + RCODE = Refused
        let flags = Flags::from_u16(flags_value).unwrap();
        assert!(flags.is_response);
        assert_eq!(flags.response_code, DnsResponseCode::Refused);

        // Test for invalid flags (all bits set)
        let invalid_flags_value = 0b1111111111111111; // invalid flags, for testing error
        assert!(Flags::from_u16(invalid_flags_value).is_err());

        // Test for invalid opcode (if opcode value is out of valid range)
        let invalid_opcode_value = 0b1000000011111111; // QR + invalid opcode
        assert!(Flags::from_u16(invalid_opcode_value).is_err());
    }

    #[test]
    fn test_dns_header_from_bytes() {
        fn create_dns_header_bytes(
            transaction_id: u16,
            flags: u16,
            question_count: u16,
            answer_count: u16,
            authority_count: u16,
            additional_count: u16,
        ) -> [u8; 12] {
            [
                (transaction_id >> 8) as u8,     // High byte of transaction ID
                (transaction_id & 0xFF) as u8,   // Low byte of transaction ID
                (flags >> 8) as u8,              // High byte of flags
                (flags & 0xFF) as u8,            // Low byte of flags
                (question_count >> 8) as u8,     // High byte of question count
                (question_count & 0xFF) as u8,   // Low byte of question count
                (answer_count >> 8) as u8,       // High byte of answer count
                (answer_count & 0xFF) as u8,     // Low byte of answer count
                (authority_count >> 8) as u8,    // High byte of authority count
                (authority_count & 0xFF) as u8,  // Low byte of authority count
                (additional_count >> 8) as u8,   // High byte of additional count
                (additional_count & 0xFF) as u8, // Low byte of additional count
            ]
        }
        // Basic valid header
        let bytes = create_dns_header_bytes(0x1234, 0b0000000000000000, 1, 1, 0, 0);
        let header = DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.transaction_id, 0x1234);
        assert!(!header.flags.is_response);
        assert_eq!(header.flags.opcode, DnsOpcode::Query);
        assert_eq!(header.question_count, QuestionCount(1));
        assert_eq!(header.answer_count, AnswerCount(1));
        assert_eq!(header.authority_count, AuthorityCount(0));
        assert_eq!(header.additional_count, AdditionalCount(0));
    }

    #[test]
    fn test_dns_header_invalid_length() {
        let short_bytes = [0x12]; // Only 1 byte
        assert!(DnsHeader::from_bytes(&short_bytes).is_err());

        let long_bytes: [u8; 5] = [0x12, 0x34, 0x56, 0x78, 0x9A];
        assert!(DnsHeader::from_bytes(&long_bytes).is_err());
    }

    #[test]
    fn test_bytes_to_u16_array() {
        let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let result = DnsHeader::bytes_to_u16_array(&bytes).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0x1234);
        assert_eq!(result[1], 0x5678);

        let invalid_bytes: [u8; 3] = [0x12, 0x34, 0x56]; // Invalid length
        assert!(DnsHeader::bytes_to_u16_array(&invalid_bytes).is_err());
    }
}
