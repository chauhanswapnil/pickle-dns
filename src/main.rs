use crate::packet::parser::DnsPacketParser;
use std::io;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub mod packet;
#[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:53").await?;
    const MAX_UDP_PACKET_SIZE: usize = 512;
    let mut buf = [0; MAX_UDP_PACKET_SIZE];
    loop {
        match timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
            Ok(Ok((len, addr))) => {
                println!("{:?} bytes received from {:?}", len, addr);
                let packet = &buf[..len];

                DnsPacketParser.parse(packet);

                // Sending a basic echo response for now
                let len = sock.send_to(&buf[..len], addr).await?;
                println!("{:?} bytes sent", len);
            }
            Ok(Err(e)) => {
                eprintln!("Error receiving data: {:?}", e);
            }
            Err(_) => {
                eprintln!("Timeout waiting for data");
            }
        }
    }
}
