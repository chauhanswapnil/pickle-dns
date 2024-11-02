use crate::packet::parser::DnsPacketParser;
use env_logger;
use log::{debug, error};
use std::io;
use tokio::net::UdpSocket;

pub mod helpers;
pub mod packet;

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let sock = UdpSocket::bind("127.0.0.1:53").await?;
    let mut buf = [0; DnsPacketParser::MAX_DNS_PACKET_SIZE];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                debug!("{:?} bytes received from {:?}\n", len, addr);
                let packet = &buf[..len];

                match DnsPacketParser.parse(packet) {
                    Ok(dns_message) => {
                        debug!("{:?}\n\n", dns_message);
                        let len = sock.send_to(&buf[..len], addr).await?;
                        debug!("{:?} bytes sent to {:?}\n", len, addr);
                    }
                    Err(e) => {
                        error!("Error parsing DNS packet from {:?}: {:?}", addr, e);
                    }
                }
            }
            Err(e) => {
                error!("Error receiving data: {:?}", e);
            }
        }
    }
}
