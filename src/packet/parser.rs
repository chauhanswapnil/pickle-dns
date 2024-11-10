use crate::errors::ParseError;

use super::body::{DnsPacketBodyParser, DnsQuestion};
use super::header::DnsHeader;
use std::fmt;

#[derive(Debug)]
pub(crate) struct DnsMessage {
    /*
    All communications inside of the domain protocol are carried in a single
    format called a message.  The top level format of message is divided
    into 5 sections (some of which are empty in certain cases) shown below:

        +---------------------+
        |        Header       |
        +---------------------+
        |       Question      | the question for the name server
        +---------------------+
        |        Answer       | RRs answering the question
        +---------------------+
        |      Authority      | RRs pointing toward an authority
        +---------------------+
        |      Additional     | RRs holding additional information
        +---------------------+
     */
    header: DnsHeader,
    question: Vec<DnsQuestion>,
    body: Vec<u8>,
}

impl fmt::Display for DnsMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "DNS Message:")?;
        writeln!(f, "Header: {:?}", self.header)?;
        writeln!(f, "Questions: {:?}", self.question)?;
        writeln!(f, "Body: {:?}", self.body)?;
        Ok(())
    }
}

pub(crate) struct DnsPacketParser;

impl DnsPacketParser {
    pub const MAX_DNS_PACKET_SIZE: usize = 512;

    pub fn parse(&self, packet_buffer: &[u8]) -> Result<DnsMessage, ParseError> {
        let (raw_header, raw_body) = packet_buffer.split_at(12);
        let header = DnsHeader::from_bytes(raw_header).unwrap();

        let mut body_parser = DnsPacketBodyParser::new(raw_body);

        // parse question
        let mut dns_questions = vec![];
        for _ in 0..header.question_count {
            let question = body_parser.parse_question()?;
            dns_questions.push(question);
        }

        Ok(DnsMessage {
            header,
            question: dns_questions,
            body: raw_body.to_vec(),
        })
    }
}
