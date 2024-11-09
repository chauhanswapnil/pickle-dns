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

#[derive(Debug)]
pub(crate) enum DnsClass {
    /// internet
    IN = 1,
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
    pub fn new(raw_body: &[u8]) -> Self {
        Self {
            raw_body,
            cursor: 0,
        }
    }
    // pub fn parse(&self, raw_body: &[u8]) -> Result
}
