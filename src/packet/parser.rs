use super::header::DnsHeader;
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
#[derive(Debug)]
pub(crate) struct DnsPacket {
    header: DnsHeader,
    // TODO: Implement these sections
    body: Vec<u8>,
}

pub(crate) struct DnsPacketParser;

impl DnsPacketParser {
    pub fn parse(&self, packet_buffer: &[u8]) {
        let (header_raw, body_raw) = packet_buffer.split_at(12);
        let header = DnsHeader::from_bytes(header_raw).unwrap();
        println!("Parsed DNS Header: {:?}", header);
    }
}
