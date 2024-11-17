use log::debug;

use crate::errors::ParseError;

use super::body::{DnsPacketBodyParser, DnsQuestion, DnsResourceRecord};
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
    answer: Option<DnsResourceRecord>,
    body: Vec<u8>,
}

impl fmt::Display for DnsMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "DNS Message:")?;
        writeln!(f, "Header: {:?}", self.header)?;
        writeln!(f, "Questions: {:?}", self.question)?;
        writeln!(f, "DNS Resource Record Answer: {:?}", self.answer)?;
        writeln!(f, "Body: {:?}", self.body)?;
        Ok(())
    }
}

pub(crate) struct DnsPacketParser;

impl DnsPacketParser {
    pub const MAX_DNS_PACKET_SIZE: usize = 512;

    pub fn parse(&self, packet_buffer: &[u8]) -> Result<DnsMessage, ParseError> {
        let packet_buffer: &[u8] = &[
            9, 91, 132, 0, 0, 1, 0, 1, 0, 2, 0, 0, 14, 115, 119, 97, 112, 110, 105, 108, 99, 104,
            97, 117, 104, 97, 110, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 14,
            16, 0, 4, 199, 36, 158, 100, 192, 12, 0, 2, 0, 1, 0, 0, 14, 16, 0, 21, 4, 110, 115, 52,
            57, 13, 100, 111, 109, 97, 105, 110, 99, 111, 110, 116, 114, 111, 108, 192, 27, 192,
            12, 0, 2, 0, 1, 0, 0, 14, 16, 0, 7, 4, 110, 115, 53, 48, 192, 69,
        ];
        let (raw_header, raw_body) = packet_buffer.split_at(12);
        let header = DnsHeader::from_bytes(raw_header).unwrap();
        debug!("Raw Body: {:?}", raw_body);
        let mut body_parser = DnsPacketBodyParser::new(raw_body);

        // parse question
        let mut dns_questions = vec![];
        for _ in 0..header.question_count {
            let question = body_parser.parse_question()?;
            dns_questions.push(question);
        }
        let mut answer = None;
        if header.flags.is_response == true {
            answer = Some(body_parser.parse_resource_record().unwrap());
        }

        Ok(DnsMessage {
            header,
            question: dns_questions,
            answer,
            body: raw_body.to_vec(),
        })
    }
}
